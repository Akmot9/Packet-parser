// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! CAT 002 — Monoradar Service Messages (EUROCONTROL-SPEC-0149-2b) : les
//! messages de service qui accompagnent un flux CAT 001 (top nord,
//! franchissement de secteur, comptes de plots), predecesseur de CAT 034.

use super::{
    AsterixRecord,
    fields::{DataSourceIdentifier, TimeOfDay},
};

/// Type de message de service (I002/000).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MessageType {
    NorthMarker,
    SectorCrossing,
    SouthMarker,
    ActivationOfBlindZoneFiltering,
    StopOfBlindZoneFiltering,
    Other(u8),
}

impl From<u8> for MessageType {
    fn from(code: u8) -> Self {
        match code {
            1 => Self::NorthMarker,
            2 => Self::SectorCrossing,
            3 => Self::SouthMarker,
            8 => Self::ActivationOfBlindZoneFiltering,
            9 => Self::StopOfBlindZoneFiltering,
            other => Self::Other(other),
        }
    }
}

/// Un compteur de plots (I002/070) : antenne, type de plots, nombre.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct PlotCount {
    /// A = 1 : compteur de l'antenne 2.
    pub antenna_2: bool,
    /// IDENT, cinq bits : 1 plots primaires seuls, 2 plots SSR seuls, 3
    /// plots combines, 4 reponses Mode S... (Part 2b, I002/070).
    pub identification: u8,
    /// Dix bits.
    pub counter: u16,
}

/// Erreur de collimation (I002/090).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct CollimationError {
    /// Erreur en distance, LSB 1/128 NM.
    pub range: i8,
    /// Erreur en azimut, LSB 360/2^14 degres.
    pub azimuth: i8,
}

/// Fenetre dynamique (I002/100) : distances et azimuts de debut et de fin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct DynamicWindow {
    /// LSB 1/128 NM.
    pub rho_start: u16,
    pub rho_end: u16,
    /// LSB 360/2^16 degres.
    pub theta_start: u16,
    pub theta_end: u16,
}

/// Les items decodes d'un record CAT 002.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ServiceMessage {
    pub data_source: Option<DataSourceIdentifier>,
    pub message_type: Option<MessageType>,
    /// I002/020, LSB 360/256 degres.
    pub sector_number: Option<u8>,
    /// I002/030.
    pub time_of_day: Option<TimeOfDay>,
    /// I002/041, periode de rotation d'antenne, LSB 1/128 s.
    pub antenna_rotation_period: Option<u16>,
    /// I002/070, dans l'ordre du wire ; vide quand l'item est absent.
    pub plot_counts: Vec<PlotCount>,
    pub collimation_error: Option<CollimationError>,
    pub dynamic_window: Option<DynamicWindow>,
}

impl ServiceMessage {
    /// Decode les items typees d'un record CAT 002 ; `None` si le record est
    /// d'une autre categorie.
    pub fn from_record(record: &AsterixRecord<'_>) -> Option<Self> {
        if record.category != 2 {
            return None;
        }
        Some(Self {
            data_source: record
                .item("I002/010")
                .and_then(DataSourceIdentifier::from_item),
            message_type: record
                .item("I002/000")
                .and_then(|d| d.first().map(|code| MessageType::from(*code))),
            sector_number: record.item("I002/020").and_then(|d| d.first().copied()),
            time_of_day: record.item("I002/030").and_then(TimeOfDay::from_item),
            antenna_rotation_period: record.item("I002/041").and_then(|d| match d {
                [high, low] => Some(u16::from_be_bytes([*high, *low])),
                _ => None,
            }),
            plot_counts: record.item("I002/070").map_or_else(Vec::new, plot_counts),
            collimation_error: record.item("I002/090").and_then(|d| match d {
                [range, azimuth] => Some(CollimationError {
                    range: *range as i8,
                    azimuth: *azimuth as i8,
                }),
                _ => None,
            }),
            dynamic_window: record.item("I002/100").and_then(|d| match d {
                [a, b, c, e, f, g, h, i] => Some(DynamicWindow {
                    rho_start: u16::from_be_bytes([*a, *b]),
                    rho_end: u16::from_be_bytes([*c, *e]),
                    theta_start: u16::from_be_bytes([*f, *g]),
                    theta_end: u16::from_be_bytes([*h, *i]),
                }),
                _ => None,
            }),
        })
    }

    /// Azimut du secteur, en degres.
    pub fn sector_azimuth_deg(&self) -> Option<f64> {
        self.sector_number
            .map(|sector| f64::from(sector) * 360.0 / 256.0)
    }

    /// Periode de rotation d'antenne, en secondes.
    pub fn antenna_rotation_period_seconds(&self) -> Option<f64> {
        self.antenna_rotation_period
            .map(|raw| f64::from(raw) / 128.0)
    }
}

/// REP compteurs de deux octets : A (bit 16), IDENT (bits 15 a 11),
/// COUNTER (bits 10 a 1). Le decoupage a deja verifie REP.
fn plot_counts(data: &[u8]) -> Vec<PlotCount> {
    data.get(1..)
        .unwrap_or_default()
        .chunks_exact(2)
        .map(|pair| {
            let word = u16::from_be_bytes([pair[0], pair[1]]);
            PlotCount {
                antenna_2: word & 0x8000 != 0,
                identification: ((word >> 10) & 0x1f) as u8,
                counter: word & 0x03ff,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::application::protocols::asterix::AsterixPacket;

    /// Bloc CAT 002 de la trame 772 de
    /// pcaps_exemple/protocols/asterix/wireshark_8579_radardata.pcap : top
    /// nord avec periode de rotation et trois compteurs de plots, recoupe
    /// avec tshark 4.6.6.
    const RADARDATA_FRAME_772_CAT002: &str = "020014d9802daa0159ddc104a703041d08130c23";

    #[test]
    fn test_decodes_a_real_north_marker_against_tshark() {
        let bytes = hex::decode(RADARDATA_FRAME_772_CAT002).unwrap();
        let packet = AsterixPacket::try_from(bytes.as_slice()).expect("bloc CAT 002");
        let message = ServiceMessage::from_record(&packet.blocks[0].records[0]).unwrap();
        assert_eq!(message.data_source.map(|d| (d.sac, d.sic)), Some((45, 170)));
        assert_eq!(message.message_type, Some(MessageType::NorthMarker));
        assert_eq!(message.sector_number, None);
        assert_eq!(
            message.time_of_day.map(TimeOfDay::seconds),
            Some(46_011.507_812_5)
        );
        assert_eq!(message.antenna_rotation_period, Some(0x04a7));
        assert_eq!(message.antenna_rotation_period_seconds(), Some(9.304_687_5));
        assert_eq!(
            message.plot_counts,
            [
                PlotCount {
                    antenna_2: false,
                    identification: 1,
                    counter: 29
                },
                PlotCount {
                    antenna_2: false,
                    identification: 2,
                    counter: 19
                },
                PlotCount {
                    antenna_2: false,
                    identification: 3,
                    counter: 35
                },
            ]
        );
        assert_eq!(message.collimation_error, None);
        assert_eq!(message.dynamic_window, None);
    }

    /// Octets synthetiques : franchissement de secteur avec fenetre
    /// dynamique et erreur de collimation (FSPEC `e1 60` : 010, 000, 020,
    /// 100 et 090).
    #[test]
    fn test_decodes_sector_crossing_with_window() {
        let bytes = [
            0x02, 0x00, 0x13, 0xe1, 0x60, 0x00, 0x01, 0x02, 0x40, 0x10, 0x00, 0x20, 0x40, 0x00,
            0x80, 0x00, 0xff, 0x02, 0x7f,
        ];
        let packet = AsterixPacket::try_from(&bytes[..]).expect("synthetique");
        let message = ServiceMessage::from_record(&packet.blocks[0].records[0]).unwrap();
        assert_eq!(message.message_type, Some(MessageType::SectorCrossing));
        assert_eq!(message.sector_azimuth_deg(), Some(90.0));
        assert!(message.plot_counts.is_empty());
        assert_eq!(
            message.dynamic_window,
            Some(DynamicWindow {
                rho_start: 0x1000,
                rho_end: 0x2040,
                theta_start: 0x0080,
                theta_end: 0x00ff,
            })
        );
        assert_eq!(
            message.collimation_error,
            Some(CollimationError {
                range: 2,
                azimuth: 127
            })
        );
    }

    #[test]
    fn test_message_type_mapping() {
        assert_eq!(MessageType::from(1), MessageType::NorthMarker);
        assert_eq!(MessageType::from(3), MessageType::SouthMarker);
        assert_eq!(MessageType::from(9), MessageType::StopOfBlindZoneFiltering);
        assert_eq!(MessageType::from(4), MessageType::Other(4));
    }

    #[test]
    fn test_rejects_records_of_another_category() {
        let bytes = [0x22, 0x00, 0x06, 0x80, 0x00, 0x01];
        let packet = AsterixPacket::try_from(&bytes[..]).unwrap();
        assert_eq!(
            ServiceMessage::from_record(&packet.blocks[0].records[0]),
            None
        );
    }
}
