// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! CAT 001 — Monoradar Data Target Reports (EUROCONTROL-SPEC-0149-2a) : les
//! plots et pistes des radars de premiere generation, predecesseur de
//! CAT 048. Deux UAP, departages par le bit TYP de I001/020 (voir
//! [`super::uap::UapSelector`]) ; les items communs portent le meme
//! identifiant dans les deux. Seuls les items d'identification et de
//! position sont decodes en valeurs typees.

use super::{
    AsterixRecord,
    fields::{DataSourceIdentifier, FlightLevel, Mode2Code, Mode3ACode, track_number},
};

/// Detection radar lors du dernier balayage (I001/020, bits 6 et 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RadarDetection {
    NoDetection,
    PrimaryOnly,
    SecondaryOnly,
    Combined,
}

/// Premier octet de I001/020, Target Report Descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct TargetReportDescriptor {
    /// TYP = 1 : piste (UAP des pistes) ; 0 : plot.
    pub track: bool,
    /// SIM : plot ou piste simule.
    pub simulated: bool,
    pub detection: RadarDetection,
    /// ANT = 1 : rapport de l'antenne 2.
    pub antenna_2: bool,
    /// SPI : Special Position Identification.
    pub spi: bool,
    /// RAB : plot ou piste d'un transpondeur fixe.
    pub field_monitor: bool,
    /// Le premier octet, tel quel (FX compris).
    pub raw: u8,
}

/// Position mesuree en coordonnees polaires (I001/040).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct PolarPosition {
    /// Distance, LSB 1/128 NM.
    pub rho: u16,
    /// Azimut, LSB 360/2^16 degres.
    pub theta: u16,
}

impl PolarPosition {
    pub fn range_nm(self) -> f64 {
        f64::from(self.rho) / 128.0
    }

    pub fn azimuth_deg(self) -> f64 {
        f64::from(self.theta) * 360.0 / 65_536.0
    }
}

/// Position calculee en coordonnees cartesiennes (I001/042), LSB 1/64 NM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct CartesianPosition {
    pub x: i16,
    pub y: i16,
}

impl CartesianPosition {
    pub fn x_nm(self) -> f64 {
        f64::from(self.x) / 64.0
    }

    pub fn y_nm(self) -> f64 {
        f64::from(self.y) / 64.0
    }
}

/// Vitesse de piste calculee en coordonnees polaires (I001/200).
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

/// Premier octet de I001/170, Track Status (UAP des pistes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct TrackStatus {
    /// CON = 0 : piste confirmee (sinon provisoire).
    pub confirmed: bool,
    /// RAD = 1 : piste SSR ou combinee (sinon primaire seule).
    pub secondary: bool,
    /// MAN : manoeuvre en cours.
    pub manoeuvre: bool,
    /// DOU : association douteuse.
    pub doubtful: bool,
    /// GHO : piste fantome.
    pub ghost: bool,
    /// Le premier octet, tel quel (FX compris).
    pub raw: u8,
}

/// Les items decodes d'un record CAT 001, plot ou piste. Chaque champ est
/// `None` quand l'item est absent du FSPEC ; les items propres aux pistes
/// (161, 042, 200, 170) le sont toujours pour un plot.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TargetReport {
    pub data_source: Option<DataSourceIdentifier>,
    pub descriptor: Option<TargetReportDescriptor>,
    pub polar_position: Option<PolarPosition>,
    /// I001/070.
    pub mode_3a: Option<Mode3ACode>,
    /// I001/090, Mode-C en representation binaire.
    pub flight_level: Option<FlightLevel>,
    /// I001/141, Truncated Time of Day : seize bits de poids faible du
    /// temps, LSB 1/128 s.
    pub truncated_time_of_day: Option<u16>,
    /// I001/050, code Mode 2 (IFF militaire).
    pub mode_2: Option<Mode2Code>,
    /// I001/161, numero de piste.
    pub track_number: Option<u16>,
    pub cartesian_position: Option<CartesianPosition>,
    pub polar_velocity: Option<PolarVelocity>,
    pub track_status: Option<TrackStatus>,
}

impl TargetReport {
    /// Decode les items typees d'un record CAT 001 ; `None` si le record est
    /// d'une autre categorie.
    pub fn from_record(record: &AsterixRecord<'_>) -> Option<Self> {
        if record.category != 1 {
            return None;
        }
        Some(Self {
            data_source: record
                .item("I001/010")
                .and_then(DataSourceIdentifier::from_item),
            descriptor: record.item("I001/020").and_then(descriptor),
            polar_position: record.item("I001/040").and_then(polar_position),
            mode_3a: record.item("I001/070").and_then(Mode3ACode::from_item),
            flight_level: record.item("I001/090").and_then(FlightLevel::from_item),
            truncated_time_of_day: record.item("I001/141").and_then(|data| match data {
                [high, low] => Some(u16::from_be_bytes([*high, *low])),
                _ => None,
            }),
            mode_2: record.item("I001/050").and_then(Mode2Code::from_item),
            track_number: record.item("I001/161").and_then(track_number),
            cartesian_position: record.item("I001/042").and_then(cartesian_position),
            polar_velocity: record.item("I001/200").and_then(polar_velocity),
            track_status: record.item("I001/170").and_then(track_status),
        })
    }

    /// Temps tronque en secondes (modulo 512 s).
    pub fn truncated_time_of_day_seconds(&self) -> Option<f64> {
        self.truncated_time_of_day.map(|raw| f64::from(raw) / 128.0)
    }
}

fn descriptor(data: &[u8]) -> Option<TargetReportDescriptor> {
    let first = *data.first()?;
    Some(TargetReportDescriptor {
        track: first & 0x80 != 0,
        simulated: first & 0x40 != 0,
        detection: match (first >> 4) & 0x03 {
            0 => RadarDetection::NoDetection,
            1 => RadarDetection::PrimaryOnly,
            2 => RadarDetection::SecondaryOnly,
            _ => RadarDetection::Combined,
        },
        antenna_2: first & 0x08 != 0,
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
        secondary: first & 0x40 != 0,
        manoeuvre: first & 0x20 != 0,
        doubtful: first & 0x10 != 0,
        ghost: first & 0x02 != 0,
        raw: first,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::application::protocols::asterix::{AsterixPacket, uap};

    /// Trame 772 de pcaps_exemple/protocols/asterix/wireshark_8579_radardata.pcap
    /// (224.1.1.1:20101) : deux blocs CAT 001 autour d'un bloc CAT 002, recoupes
    /// avec tshark 4.6.6.
    const RADARDATA_FRAME_772: &str = concat!(
        "010014fb802daa301ca0aa1000c40578dc3e8000",
        "020014d9802daa0159ddc104a703041d08130c23",
        "01000ee22daa518000800000ddc1"
    );

    #[test]
    fn test_decodes_real_plots_against_tshark() {
        let bytes = hex::decode(RADARDATA_FRAME_772).unwrap();
        let packet = AsterixPacket::try_from(bytes.as_slice()).expect("trame 772");
        assert_eq!(
            packet
                .blocks
                .iter()
                .map(|block| block.category)
                .collect::<Vec<_>>(),
            [1, 2, 1]
        );

        // Premier bloc : plot combine, Mode 3/A 0304, FL 350, Mode 2 non
        // valide.
        let record = &packet.blocks[0].records[0];
        assert_eq!(record.uap(), Some(&uap::CAT001));
        let report = TargetReport::from_record(record).expect("record CAT 001");
        assert_eq!(report.data_source.map(|d| (d.sac, d.sic)), Some((45, 170)));
        let descriptor = report.descriptor.unwrap();
        assert!(!descriptor.track && !descriptor.simulated);
        assert_eq!(descriptor.detection, RadarDetection::Combined);
        assert!(!descriptor.antenna_2 && !descriptor.spi && !descriptor.field_monitor);
        let position = report.polar_position.unwrap();
        assert_eq!(position.range_nm(), 57.25);
        assert_eq!(position.azimuth_deg(), 239.150_390_625);
        assert_eq!(report.mode_3a.unwrap().to_string(), "0304");
        assert_eq!(report.flight_level.unwrap().flight_level(), 350.0);
        assert_eq!(report.truncated_time_of_day, Some(56_382));
        assert_eq!(report.truncated_time_of_day_seconds(), Some(440.484_375));
        let mode_2 = report.mode_2.unwrap();
        assert!(!mode_2.validated);
        assert_eq!(mode_2.to_string(), "0000");
        assert_eq!(report.track_number, None);
        assert_eq!(report.cartesian_position, None);
        assert_eq!(report.polar_velocity, None);
        assert_eq!(report.track_status, None);

        // Troisieme bloc : plot simule, detection primaire seule, cible de
        // test (second extent de I001/020), a 1 NM dans l'azimut 0.
        let record = &packet.blocks[2].records[0];
        let report = TargetReport::from_record(record).unwrap();
        let descriptor = report.descriptor.unwrap();
        assert!(descriptor.simulated);
        assert_eq!(descriptor.detection, RadarDetection::PrimaryOnly);
        assert_eq!(record.item("I001/020"), Some(&[0x51, 0x80][..]));
        let position = report.polar_position.unwrap();
        assert_eq!(position.range_nm(), 1.0);
        assert_eq!(position.azimuth_deg(), 0.0);
        assert_eq!(report.truncated_time_of_day_seconds(), Some(443.507_812_5));
        assert_eq!(report.mode_3a, None);
    }

    /// Octets synthetiques, le corpus ne portant aucune piste CAT 001 : UAP
    /// des pistes (TYP = 1), FSPEC `fd 05 01 80` — 010, 020, 161, 040, 042,
    /// 200, 170 (FRN 13), puis I001/150 au FRN 22 (quatrieme octet).
    #[test]
    fn test_decodes_a_synthetic_track() {
        let bytes = [
            0x01, 0x00, 0x1a, 0xfd, 0x05, 0x01, 0x80, 0x00, 0x01, 0x80, 0x01, 0x23, 0x10, 0x00,
            0x40, 0x00, 0x00, 0x40, 0xff, 0xc0, 0x07, 0xd0, 0x40, 0x00, 0x20, 0x05,
        ];
        let packet = AsterixPacket::try_from(&bytes[..]).expect("piste synthetique");
        let record = &packet.blocks[0].records[0];
        assert_eq!(record.uap(), Some(&uap::CAT001_TRACK));
        let report = TargetReport::from_record(record).unwrap();
        assert!(report.descriptor.unwrap().track);
        assert_eq!(report.track_number, Some(0x123));
        let position = report.polar_position.unwrap();
        assert_eq!(position.range_nm(), 32.0);
        assert_eq!(position.azimuth_deg(), 90.0);
        let cartesian = report.cartesian_position.unwrap();
        assert_eq!(cartesian.x_nm(), 1.0);
        assert_eq!(cartesian.y_nm(), -1.0);
        let velocity = report.polar_velocity.unwrap();
        assert_eq!(velocity.ground_speed, 2000);
        assert_eq!(velocity.heading_deg(), 90.0);
        let status = report.track_status.unwrap();
        assert!(status.confirmed && !status.secondary && status.manoeuvre);
        assert!(!status.doubtful && !status.ghost);
        assert_eq!(record.item("I001/150"), Some(&[0x05][..]));
        assert_eq!(
            report.polar_velocity.map(PolarVelocity::ground_speed_kt),
            Some(439.453_125)
        );
    }

    #[test]
    fn test_rejects_records_of_another_category() {
        let bytes = [0x30, 0x00, 0x06, 0x80, 0x00, 0x01];
        let packet = AsterixPacket::try_from(&bytes[..]).unwrap();
        assert_eq!(
            TargetReport::from_record(&packet.blocks[0].records[0]),
            None
        );
    }
}
