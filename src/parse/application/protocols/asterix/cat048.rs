// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! CAT 048 — Monoradar Target Reports (EUROCONTROL-SPEC-0149-4) : un plot ou
//! une piste par record. Seuls les items d'identification et de position
//! sont decodes en valeurs typees ; les autres restent accessibles en
//! octets via [`AsterixRecord::item`].

use super::{
    AsterixRecord,
    fields::{
        AircraftAddress, AircraftIdentification, DataSourceIdentifier, FlightLevel, Mode3ACode,
        TimeOfDay, sign_extend_14, track_number,
    },
};

/// Type de detection (I048/020, bits 8 a 6 du premier octet).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DetectionType {
    NoDetection,
    SinglePsr,
    SingleSsr,
    SsrPlusPsr,
    SingleModeSAllCall,
    SingleModeSRollCall,
    ModeSAllCallPlusPsr,
    ModeSRollCallPlusPsr,
}

impl DetectionType {
    fn from_typ(typ: u8) -> Self {
        match typ & 0x07 {
            0 => Self::NoDetection,
            1 => Self::SinglePsr,
            2 => Self::SingleSsr,
            3 => Self::SsrPlusPsr,
            4 => Self::SingleModeSAllCall,
            5 => Self::SingleModeSRollCall,
            6 => Self::ModeSAllCallPlusPsr,
            _ => Self::ModeSRollCallPlusPsr,
        }
    }
}

/// Premier octet de I048/020, Target Report Descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct TargetReportDescriptor {
    pub detection: DetectionType,
    /// SIM : rapport simule.
    pub simulated: bool,
    /// RDP : chaine RDP 2 (sinon 1).
    pub rdp_chain_2: bool,
    /// SPI : Special Position Identification presente.
    pub spi: bool,
    /// RAB : rapport issu d'un transpondeur de site, pas d'un aeronef.
    pub field_monitor: bool,
    /// Le premier octet, tel quel (FX compris).
    pub raw: u8,
}

/// Position mesuree en coordonnees polaires (I048/040).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct PolarPosition {
    /// Distance, LSB 1/256 NM.
    pub rho: u16,
    /// Azimut, LSB 360/2^16 degres.
    pub theta: u16,
}

impl PolarPosition {
    pub fn range_nm(self) -> f64 {
        f64::from(self.rho) / 256.0
    }

    pub fn azimuth_deg(self) -> f64 {
        f64::from(self.theta) * 360.0 / 65_536.0
    }
}

/// Position calculee en coordonnees cartesiennes (I048/042), LSB 1/128 NM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct CartesianPosition {
    pub x: i16,
    pub y: i16,
}

/// Vitesse de piste calculee en coordonnees polaires (I048/200).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct PolarVelocity {
    /// Vitesse sol, LSB 2^-14 NM/s.
    pub ground_speed: u16,
    /// Cap, LSB 360/2^16 degres.
    pub heading: u16,
}

impl PolarVelocity {
    pub fn ground_speed_kt(self) -> f64 {
        f64::from(self.ground_speed) / 16_384.0 * 3_600.0
    }

    pub fn heading_deg(self) -> f64 {
        f64::from(self.heading) * 360.0 / 65_536.0
    }
}

/// Premier octet de I048/170, Track Status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct TrackStatus {
    /// CNF = 0 : piste confirmee (sinon provisoire).
    pub confirmed: bool,
    /// RAD : type de capteur (0 combine, 1 PSR, 2 SSR/Mode S, 3 invalide).
    pub sensor: u8,
    /// Le premier octet, tel quel (FX compris).
    pub raw: u8,
}

/// Les items decodes d'un record CAT 048. Chaque champ est `None` quand
/// l'item est absent du FSPEC.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TargetReport {
    pub data_source: Option<DataSourceIdentifier>,
    pub time_of_day: Option<TimeOfDay>,
    pub descriptor: Option<TargetReportDescriptor>,
    pub polar_position: Option<PolarPosition>,
    pub mode_3a: Option<Mode3ACode>,
    pub flight_level: Option<FlightLevel>,
    pub aircraft_address: Option<AircraftAddress>,
    pub aircraft_identification: Option<AircraftIdentification>,
    pub track_number: Option<u16>,
    pub cartesian_position: Option<CartesianPosition>,
    pub polar_velocity: Option<PolarVelocity>,
    pub track_status: Option<TrackStatus>,
    /// Hauteur mesuree par un radar 3D (I048/110), LSB 25 ft.
    pub height_3d: Option<i16>,
    /// Nombre de registres BDS portes par I048/250.
    pub mode_s_mb_data_count: Option<u8>,
}

impl TargetReport {
    /// Decode les items typees d'un record CAT 048 ; `None` si le record est
    /// d'une autre categorie.
    pub fn from_record(record: &AsterixRecord<'_>) -> Option<Self> {
        if record.category != 48 {
            return None;
        }
        Some(Self {
            data_source: record
                .item("I048/010")
                .and_then(DataSourceIdentifier::from_item),
            time_of_day: record.item("I048/140").and_then(TimeOfDay::from_item),
            descriptor: record.item("I048/020").and_then(descriptor),
            polar_position: record.item("I048/040").and_then(polar_position),
            mode_3a: record.item("I048/070").and_then(Mode3ACode::from_item),
            flight_level: record.item("I048/090").and_then(FlightLevel::from_item),
            aircraft_address: record.item("I048/220").and_then(AircraftAddress::from_item),
            aircraft_identification: record
                .item("I048/240")
                .and_then(AircraftIdentification::from_item),
            track_number: record.item("I048/161").and_then(track_number),
            cartesian_position: record.item("I048/042").and_then(cartesian_position),
            polar_velocity: record.item("I048/200").and_then(polar_velocity),
            track_status: record.item("I048/170").and_then(track_status),
            height_3d: record.item("I048/110").and_then(height_3d),
            mode_s_mb_data_count: record
                .item("I048/250")
                .and_then(|data| data.first().copied()),
        })
    }
}

fn descriptor(data: &[u8]) -> Option<TargetReportDescriptor> {
    let first = *data.first()?;
    Some(TargetReportDescriptor {
        detection: DetectionType::from_typ(first >> 5),
        simulated: first & 0x10 != 0,
        rdp_chain_2: first & 0x08 != 0,
        spi: first & 0x04 != 0,
        field_monitor: first & 0x02 != 0,
        raw: first,
    })
}

fn polar_position(data: &[u8]) -> Option<PolarPosition> {
    match data {
        [r0, r1, t0, t1] => Some(PolarPosition {
            rho: u16::from_be_bytes([*r0, *r1]),
            theta: u16::from_be_bytes([*t0, *t1]),
        }),
        _ => None,
    }
}

fn cartesian_position(data: &[u8]) -> Option<CartesianPosition> {
    match data {
        [x0, x1, y0, y1] => Some(CartesianPosition {
            x: i16::from_be_bytes([*x0, *x1]),
            y: i16::from_be_bytes([*y0, *y1]),
        }),
        _ => None,
    }
}

fn polar_velocity(data: &[u8]) -> Option<PolarVelocity> {
    match data {
        [s0, s1, h0, h1] => Some(PolarVelocity {
            ground_speed: u16::from_be_bytes([*s0, *s1]),
            heading: u16::from_be_bytes([*h0, *h1]),
        }),
        _ => None,
    }
}

fn track_status(data: &[u8]) -> Option<TrackStatus> {
    let first = *data.first()?;
    Some(TrackStatus {
        confirmed: first & 0x80 == 0,
        sensor: (first >> 5) & 0x03,
        raw: first,
    })
}

fn height_3d(data: &[u8]) -> Option<i16> {
    match data {
        [high, low] => Some(sign_extend_14(u16::from_be_bytes([high & 0x3f, *low]))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::application::protocols::asterix::AsterixPacket;

    /// `cat048.raw` des echantillons CroatiaControlLtd/asterix : un record
    /// CAT 048 complet, recoupe avec tshark 4.6.6.
    const CAT048_RAW: &str = "300030fdf70219c9356d4da0c5aff1e0020005283c660c10c236d4182001c0780031bc0000400deb07b9582e410020f5";

    #[test]
    fn test_decodes_the_public_sample_against_tshark() {
        let bytes = hex::decode(CAT048_RAW).unwrap();
        let packet = AsterixPacket::try_from(bytes.as_slice()).expect("cat048.raw decode");
        let record = &packet.blocks[0].records[0];
        let ids: Vec<&str> = record.items.iter().map(|item| item.id).collect();
        assert_eq!(
            ids,
            [
                "I048/010", "I048/140", "I048/020", "I048/040", "I048/070", "I048/090", "I048/220",
                "I048/240", "I048/250", "I048/161", "I048/200", "I048/170", "I048/230",
            ]
        );

        let report = TargetReport::from_record(record).expect("record CAT 048");
        assert_eq!(
            report.data_source,
            Some(DataSourceIdentifier {
                sac: 0x19,
                sic: 0xc9
            })
        );
        assert_eq!(
            report.time_of_day.map(TimeOfDay::seconds),
            Some(27_354.601_562_5)
        );
        let descriptor = report.descriptor.unwrap();
        assert_eq!(descriptor.detection, DetectionType::SingleModeSRollCall);
        assert!(!descriptor.simulated && !descriptor.spi && !descriptor.field_monitor);
        let position = report.polar_position.unwrap();
        assert_eq!(position.range_nm(), 197.683_593_75);
        assert_eq!(position.azimuth_deg(), 340.136_718_75);
        assert_eq!(report.mode_3a.unwrap().to_string(), "1000");
        assert_eq!(report.flight_level.unwrap().flight_level(), 330.0);
        assert_eq!(report.aircraft_address.unwrap().to_string(), "3C660C");
        assert_eq!(report.aircraft_identification.unwrap().trimmed(), "DLH65A");
        assert_eq!(report.mode_s_mb_data_count, Some(1));
        assert_eq!(report.track_number, Some(3563));
        let velocity = report.polar_velocity.unwrap();
        // tshark : 0.12066650390625 NM/s, 124.002685546875 deg.
        assert_eq!(
            f64::from(velocity.ground_speed) / 16_384.0,
            0.120_666_503_906_25
        );
        assert_eq!(velocity.heading_deg(), 124.002_685_546_875);
        let status = report.track_status.unwrap();
        assert!(status.confirmed);
        assert_eq!(status.sensor, 2);
        assert_eq!(report.cartesian_position, None);
        assert_eq!(report.height_3d, None);
    }

    #[test]
    fn test_rejects_records_of_another_category() {
        let bytes = [0x22, 0x00, 0x05, 0x80, 0x00, 0x01];
        let bytes = {
            let mut b = bytes.to_vec();
            b[2] = 6;
            b
        };
        let packet = AsterixPacket::try_from(bytes.as_slice()).unwrap();
        assert_eq!(
            TargetReport::from_record(&packet.blocks[0].records[0]),
            None
        );
    }

    #[test]
    fn test_height_3d_is_signed() {
        assert_eq!(height_3d(&[0x00, 0x5a]), Some(90)); // 2250 ft
        assert_eq!(height_3d(&[0x3f, 0xff]), Some(-1));
        assert_eq!(height_3d(&[0xc0, 0x00]), Some(0));
    }
}
