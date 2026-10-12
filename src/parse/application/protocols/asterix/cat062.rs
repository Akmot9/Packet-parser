// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! CAT 062 — SDPS Track Messages (EUROCONTROL-SPEC-0149-9) : les pistes
//! systeme que le tracker multi-capteurs diffuse, fusion des plots radar,
//! ADS-B et multilateration. Seuls les items d'identification, de position
//! et d'altitude sont decodes en valeurs typees, ainsi que l'adresse et
//! l'identification aeronef de I062/380 et la mesure de I062/340 ; le reste
//! (ages, intentions, plan de vol, precisions) reste accessible en octets
//! via [`AsterixRecord::item`] et [`AsterixRecord::subfield`].

use super::{
    AsterixRecord,
    fields::{
        AircraftAddress, AircraftIdentification, DataSourceIdentifier, FlightLevel, Mode3ACode,
        TimeOfDay, sign_extend_24,
    },
};

/// Position calculee en WGS-84 (I062/105), LSB 180/2^25 degres.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Wgs84Position {
    pub latitude: i32,
    pub longitude: i32,
}

impl Wgs84Position {
    pub fn latitude_deg(self) -> f64 {
        f64::from(self.latitude) * 180.0 / 33_554_432.0
    }

    pub fn longitude_deg(self) -> f64 {
        f64::from(self.longitude) * 180.0 / 33_554_432.0
    }
}

/// Position calculee en coordonnees cartesiennes (I062/100), LSB 0,5 m sur
/// 24 bits signes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct CartesianPosition {
    pub x: i32,
    pub y: i32,
}

impl CartesianPosition {
    pub fn x_m(self) -> f64 {
        f64::from(self.x) / 2.0
    }

    pub fn y_m(self) -> f64 {
        f64::from(self.y) / 2.0
    }
}

/// Vitesse calculee en coordonnees cartesiennes (I062/185), LSB 0,25 m/s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct CartesianVelocity {
    pub vx: i16,
    pub vy: i16,
}

impl CartesianVelocity {
    pub fn vx_m_s(self) -> f64 {
        f64::from(self.vx) / 4.0
    }

    pub fn vy_m_s(self) -> f64 {
        f64::from(self.vy) / 4.0
    }
}

/// Acceleration calculee (I062/210), LSB 0,25 m/s².
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct CartesianAcceleration {
    pub ax: i8,
    pub ay: i8,
}

/// Code Mode 3/A de la piste (I062/060) : comme [`Mode3ACode`], mais le
/// troisieme indicateur signale un changement de code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct TrackMode3ACode {
    pub validated: bool,
    pub garbled: bool,
    /// CH : le code a change.
    pub changed: bool,
    pub code: u16,
}

impl core::fmt::Display for TrackMode3ACode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:04o}", self.code)
    }
}

/// Premier octet de I062/080, Track Status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct TrackStatus {
    /// MON = 1 : piste monocapteur.
    pub monosensor: bool,
    pub spi: bool,
    /// MRH = 1 : l'altitude geometrique est la plus fiable (sinon le
    /// barometrique).
    pub geometric_height_more_reliable: bool,
    /// SRC, trois bits : source de l'altitude calculee de I062/130.
    pub altitude_source: u8,
    /// CNF = 0 : piste confirmee.
    pub confirmed: bool,
    /// Le premier octet, tel quel (FX compris).
    pub raw: u8,
}

/// Mode de deplacement (I062/200).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ModeOfMovement {
    /// TRANS : 0 cap constant, 1 virage a droite, 2 a gauche, 3 indetermine.
    pub transversal: u8,
    /// LONG : 0 vitesse constante, 1 acceleration, 2 deceleration, 3
    /// indetermine.
    pub longitudinal: u8,
    /// VERT : 0 palier, 1 montee, 2 descente, 3 indetermine.
    pub vertical: u8,
    /// ADF : ecart d'altitude entre capteurs.
    pub altitude_discrepancy: bool,
}

/// Altitude barometrique calculee (I062/135).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct BarometricAltitude {
    /// QNH : correction QNH appliquee.
    pub qnh_corrected: bool,
    /// CTB, quinze bits signes, LSB 1/4 FL.
    pub quarter_levels: i16,
}

impl BarometricAltitude {
    pub fn flight_level(self) -> f64 {
        f64::from(self.quarter_levels) / 4.0
    }
}

/// Mesure du dernier capteur ayant mis la piste a jour (I062/340) :
/// sous-champs SID et POS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct MeasuredInformation {
    /// SID, le capteur.
    pub sensor: Option<DataSourceIdentifier>,
    /// POS, distance (LSB 1/256 NM) et azimut (LSB 360/2^16 degres)
    /// mesures.
    pub polar_position: Option<(u16, u16)>,
    /// MDC, niveau de vol mesure.
    pub flight_level: Option<FlightLevel>,
    /// MDA, code Mode 3/A mesure.
    pub mode_3a: Option<Mode3ACode>,
}

impl MeasuredInformation {
    pub fn range_nm(self) -> Option<f64> {
        self.polar_position.map(|(rho, _)| f64::from(rho) / 256.0)
    }

    pub fn azimuth_deg(self) -> Option<f64> {
        self.polar_position
            .map(|(_, theta)| f64::from(theta) * 360.0 / 65_536.0)
    }
}

/// Les items decodes d'un record CAT 062. Chaque champ est `None` quand
/// l'item est absent du FSPEC.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SystemTrack {
    pub data_source: Option<DataSourceIdentifier>,
    /// I062/015.
    pub service_identification: Option<u8>,
    /// I062/070, heure de l'information de piste.
    pub time_of_track: Option<TimeOfDay>,
    pub wgs84_position: Option<Wgs84Position>,
    pub cartesian_position: Option<CartesianPosition>,
    pub cartesian_velocity: Option<CartesianVelocity>,
    pub acceleration: Option<CartesianAcceleration>,
    pub mode_3a: Option<TrackMode3ACode>,
    /// I062/245, identification de la cible (huit caracteres).
    pub target_identification: Option<AircraftIdentification>,
    /// I062/380 ADR, adresse ICAO 24 bits.
    pub aircraft_address: Option<AircraftAddress>,
    /// I062/380 ID, identification aeronef (indicatif).
    pub aircraft_identification: Option<AircraftIdentification>,
    /// I062/380 MHG, cap magnetique, LSB 360/2^16 degres.
    pub magnetic_heading: Option<u16>,
    /// I062/040.
    pub track_number: Option<u16>,
    pub track_status: Option<TrackStatus>,
    pub mode_of_movement: Option<ModeOfMovement>,
    /// I062/136, niveau de vol mesure, LSB 1/4 FL.
    pub measured_flight_level: Option<i16>,
    /// I062/130, altitude geometrique calculee, LSB 6,25 ft.
    pub geometric_altitude: Option<i16>,
    pub barometric_altitude: Option<BarometricAltitude>,
    /// I062/220, vitesse verticale calculee, LSB 6,25 ft/min.
    pub rate_of_climb: Option<i16>,
    /// I062/120, code Mode 2 de la piste (douze bits).
    pub mode_2: Option<u16>,
    pub measured_information: Option<MeasuredInformation>,
}

impl SystemTrack {
    /// Decode les items typees d'un record CAT 062 ; `None` si le record est
    /// d'une autre categorie.
    pub fn from_record(record: &AsterixRecord<'_>) -> Option<Self> {
        if record.category != 62 {
            return None;
        }
        let i16_item = |id: &str| {
            record.item(id).and_then(|d| match d {
                [high, low] => Some(i16::from_be_bytes([*high, *low])),
                _ => None,
            })
        };
        Some(Self {
            data_source: record
                .item("I062/010")
                .and_then(DataSourceIdentifier::from_item),
            service_identification: record.item("I062/015").and_then(|d| d.first().copied()),
            time_of_track: record.item("I062/070").and_then(TimeOfDay::from_item),
            wgs84_position: record.item("I062/105").and_then(wgs84_position),
            cartesian_position: record.item("I062/100").and_then(cartesian_position),
            cartesian_velocity: record.item("I062/185").and_then(|d| match d {
                [x0, x1, y0, y1] => Some(CartesianVelocity {
                    vx: i16::from_be_bytes([*x0, *x1]),
                    vy: i16::from_be_bytes([*y0, *y1]),
                }),
                _ => None,
            }),
            acceleration: record.item("I062/210").and_then(|d| match d {
                [ax, ay] => Some(CartesianAcceleration {
                    ax: *ax as i8,
                    ay: *ay as i8,
                }),
                _ => None,
            }),
            mode_3a: record.item("I062/060").and_then(|d| match d {
                [high, low] => Some(TrackMode3ACode {
                    validated: high & 0x80 == 0,
                    garbled: high & 0x40 != 0,
                    changed: high & 0x20 != 0,
                    code: u16::from_be_bytes([high & 0x0f, *low]),
                }),
                _ => None,
            }),
            target_identification: record
                .item("I062/245")
                .and_then(|d| d.get(1..7))
                .and_then(AircraftIdentification::from_item),
            aircraft_address: record
                .subfield("I062/380", 1)
                .and_then(AircraftAddress::from_item),
            aircraft_identification: record
                .subfield("I062/380", 2)
                .and_then(AircraftIdentification::from_item),
            magnetic_heading: record.subfield("I062/380", 3).and_then(|d| match d {
                [high, low] => Some(u16::from_be_bytes([*high, *low])),
                _ => None,
            }),
            track_number: record.item("I062/040").and_then(|d| match d {
                [high, low] => Some(u16::from_be_bytes([*high, *low])),
                _ => None,
            }),
            track_status: record.item("I062/080").and_then(track_status),
            mode_of_movement: record.item("I062/200").and_then(|d| {
                d.first().map(|octet| ModeOfMovement {
                    transversal: octet >> 6,
                    longitudinal: (octet >> 4) & 0x03,
                    vertical: (octet >> 2) & 0x03,
                    altitude_discrepancy: octet & 0x02 != 0,
                })
            }),
            measured_flight_level: i16_item("I062/136"),
            geometric_altitude: i16_item("I062/130"),
            barometric_altitude: record.item("I062/135").and_then(|d| match d {
                [high, low] => Some(BarometricAltitude {
                    qnh_corrected: high & 0x80 != 0,
                    // Quinze bits signes : etendus depuis le bit 15.
                    quarter_levels: (u16::from_be_bytes([*high, *low]) << 1) as i16 >> 1,
                }),
                _ => None,
            }),
            rate_of_climb: i16_item("I062/220"),
            mode_2: record.item("I062/120").and_then(|d| match d {
                [high, low] => Some(u16::from_be_bytes([high & 0x0f, *low])),
                _ => None,
            }),
            measured_information: record.item("I062/340").map(|_| MeasuredInformation {
                sensor: record
                    .subfield("I062/340", 1)
                    .and_then(DataSourceIdentifier::from_item),
                polar_position: record.subfield("I062/340", 2).and_then(|d| match d {
                    [r0, r1, t0, t1] => Some((
                        u16::from_be_bytes([*r0, *r1]),
                        u16::from_be_bytes([*t0, *t1]),
                    )),
                    _ => None,
                }),
                flight_level: record
                    .subfield("I062/340", 4)
                    .and_then(FlightLevel::from_item),
                mode_3a: record
                    .subfield("I062/340", 5)
                    .and_then(Mode3ACode::from_item),
            }),
        })
    }
}

fn wgs84_position(data: &[u8]) -> Option<Wgs84Position> {
    let [a, b, c, d, e, f, g, h] = data else {
        return None;
    };
    Some(Wgs84Position {
        latitude: i32::from_be_bytes([*a, *b, *c, *d]),
        longitude: i32::from_be_bytes([*e, *f, *g, *h]),
    })
}

fn cartesian_position(data: &[u8]) -> Option<CartesianPosition> {
    match data {
        [x0, x1, x2, y0, y1, y2] => Some(CartesianPosition {
            x: sign_extend_24(u32::from_be_bytes([0, *x0, *x1, *x2])),
            y: sign_extend_24(u32::from_be_bytes([0, *y0, *y1, *y2])),
        }),
        _ => None,
    }
}

fn track_status(data: &[u8]) -> Option<TrackStatus> {
    let first = *data.first()?;
    Some(TrackStatus {
        monosensor: first & 0x80 != 0,
        spi: first & 0x40 != 0,
        geometric_height_more_reliable: first & 0x20 != 0,
        altitude_source: (first >> 2) & 0x07,
        confirmed: first & 0x02 == 0,
        raw: first,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::application::protocols::asterix::AsterixPacket;

    /// Trame 1 de pcaps_exemple/protocols/asterix/cat_062_065.pcap
    /// (CroatiaControlLtd, GPL-2.0) : deux pistes systeme CAT 062 puis un
    /// bloc CAT 065, recoupees avec tshark 4.6.6.
    const CAT_062_065_FRAME_1: &str = concat!(
        "3e00a1bfdffd021964015981b3007518fc002caed9ff196bf086600393ff43000002bdc1204ca7a849",
        "94b1df40e020f612691903010870170d0d00900d0d061816cd06180000dc190c93ba88e8061802bda0",
        "bfdffd021964015981b30075cee5003726bd08813bf18a9ffcbdfff10009087dc1204cac7f2534f2c3",
        "0de020f61aaf11030108702010104090101005f01a7505f00000dc190cb98e5eb505f0087da0",
        "41000cf8196402015981b301"
    );

    #[test]
    fn test_decodes_a_real_system_track_against_tshark() {
        let bytes = hex::decode(CAT_062_065_FRAME_1).unwrap();
        let packet = AsterixPacket::try_from(bytes.as_slice()).expect("trame 1");
        assert_eq!(
            packet
                .blocks
                .iter()
                .map(|block| (block.category, block.records.len()))
                .collect::<Vec<_>>(),
            [(62, 2), (65, 1)]
        );

        let record = &packet.blocks[0].records[0];
        let track = SystemTrack::from_record(record).expect("record CAT 062");
        assert_eq!(track.data_source.map(|d| (d.sac, d.sic)), Some((25, 100)));
        assert_eq!(track.service_identification, Some(1));
        assert_eq!(
            track.time_of_track.map(TimeOfDay::seconds),
            Some(45_827.398_437_5)
        );
        let position = track.wgs84_position.unwrap();
        assert_eq!(position.latitude_deg(), 41.167_123_317_718_506);
        assert_eq!(position.longitude_deg(), 15.708_866_715_431_213);
        let cartesian = track.cartesian_position.unwrap();
        assert_eq!((cartesian.x_m(), cartesian.y_m()), (-29_514.5, -507_088.0));
        let velocity = track.cartesian_velocity.unwrap();
        assert_eq!((velocity.vx_m_s(), velocity.vy_m_s()), (228.75, -47.25));
        assert_eq!(
            track.acceleration,
            Some(CartesianAcceleration { ax: 0, ay: 0 })
        );
        let mode_3a = track.mode_3a.unwrap();
        assert!(mode_3a.validated && !mode_3a.garbled && !mode_3a.changed);
        assert_eq!(mode_3a.to_string(), "1275");
        assert_eq!(track.target_identification, None);
        assert_eq!(track.aircraft_address.unwrap().to_string(), "4CA7A8");
        assert_eq!(track.aircraft_identification.unwrap().trimmed(), "RYR174C");
        assert_eq!(track.magnetic_heading, None);
        assert_eq!(track.track_number, Some(4713));
        let status = track.track_status.unwrap();
        assert!(!status.monosensor && !status.spi && !status.geometric_height_more_reliable);
        assert_eq!(status.altitude_source, 6);
        assert!(status.confirmed);
        assert_eq!(record.item("I062/080").map(<[u8]>::len), Some(4));
        assert_eq!(
            track.mode_of_movement,
            Some(ModeOfMovement {
                transversal: 0,
                longitudinal: 0,
                vertical: 0,
                altitude_discrepancy: false,
            })
        );
        assert_eq!(track.measured_flight_level, Some(1560)); // FL 390
        assert_eq!(track.geometric_altitude, Some(5837)); // 36 481,25 ft
        let barometric = track.barometric_altitude.unwrap();
        assert!(!barometric.qnh_corrected);
        assert_eq!(barometric.flight_level(), 390.0);
        assert_eq!(track.rate_of_climb, Some(0));
        assert_eq!(track.mode_2, None);
        let measured = track.measured_information.unwrap();
        assert_eq!(measured.sensor.map(|d| (d.sac, d.sic)), Some((25, 12)));
        assert_eq!(measured.range_nm(), Some(147.726_562_5));
        assert_eq!(measured.azimuth_deg(), Some(192.524_414_062_5));
        assert_eq!(
            measured.flight_level.map(FlightLevel::flight_level),
            Some(390.0)
        );
        assert_eq!(measured.mode_3a.unwrap().to_string(), "1275");
        // Les ages restent accessibles par sous-champ : PSR 5,75 s.
        assert_eq!(record.subfield("I062/290", 2), Some(&[0x17][..]));
        assert_eq!(record.subfield("I062/290", 1), None);

        let second = SystemTrack::from_record(&packet.blocks[0].records[1]).unwrap();
        let position = second.wgs84_position.unwrap();
        assert_eq!(position.latitude_deg(), 41.416_938_900_947_57);
        assert_eq!(position.longitude_deg(), 19.389_136_433_601_38);
        let cartesian = second.cartesian_position.unwrap();
        assert_eq!((cartesian.x_m(), cartesian.y_m()), (278_685.5, -473_776.5));
    }

    /// Octets synthetiques : identification de cible, cap magnetique
    /// (I062/380 MHG seul), altitude barometrique negative corrigee QNH et
    /// Mode 2 (FSPEC `01 31 09 10` : 245 au FRN 10, 380 au FRN 11, 135 au
    /// FRN 19, 120 au FRN 25).
    #[test]
    fn test_decodes_signed_altitudes_and_identifications() {
        let bytes = [
            0x3e, 0x00, 0x15, 0x01, 0x31, 0x09, 0x10, 0x00, 0x10, 0xc2, 0x36, 0xd4, 0x18, 0x20,
            0x20, 0x40, 0x00, 0xff, 0xfc, 0x05, 0x55,
        ];
        let packet = AsterixPacket::try_from(&bytes[..]).expect("synthetique");
        let track = SystemTrack::from_record(&packet.blocks[0].records[0]).unwrap();
        assert_eq!(track.target_identification.unwrap().trimmed(), "DLH65A");
        assert_eq!(track.magnetic_heading, Some(0x4000)); // 90 degres
        assert_eq!(track.aircraft_address, None);
        let barometric = track.barometric_altitude.unwrap();
        assert!(barometric.qnh_corrected);
        assert_eq!(barometric.quarter_levels, -4);
        assert_eq!(barometric.flight_level(), -1.0);
        assert_eq!(track.mode_2, Some(0o2525));
        assert_eq!(track.measured_information, None);
    }

    #[test]
    fn test_rejects_records_of_another_category() {
        let bytes = [0x22, 0x00, 0x06, 0x80, 0x00, 0x01];
        let packet = AsterixPacket::try_from(&bytes[..]).unwrap();
        assert_eq!(SystemTrack::from_record(&packet.blocks[0].records[0]), None);
    }
}
