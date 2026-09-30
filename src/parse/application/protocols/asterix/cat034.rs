// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! CAT 034 — Monoradar Service Messages (EUROCONTROL-SPEC-0149-2b) : les
//! messages de service qui accompagnent un flux CAT 048 sur le meme
//! transport (top nord, franchissement de secteur, filtrage, brouillage).

use super::{
    AsterixRecord,
    fields::{DataSourceIdentifier, TimeOfDay},
};

/// Type de message de service (I034/000).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MessageType {
    NorthMarker,
    SectorCrossing,
    GeographicalFiltering,
    JammingStrobe,
    SolarStorm,
    SsrJammingStrobe,
    ModeSJammingStrobe,
    Other(u8),
}

impl From<u8> for MessageType {
    fn from(code: u8) -> Self {
        match code {
            1 => Self::NorthMarker,
            2 => Self::SectorCrossing,
            3 => Self::GeographicalFiltering,
            4 => Self::JammingStrobe,
            5 => Self::SolarStorm,
            6 => Self::SsrJammingStrobe,
            7 => Self::ModeSJammingStrobe,
            other => Self::Other(other),
        }
    }
}

/// Les items decodes d'un record CAT 034.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ServiceMessage {
    pub data_source: Option<DataSourceIdentifier>,
    pub message_type: Option<MessageType>,
    /// I034/030.
    pub time_of_day: Option<TimeOfDay>,
    /// I034/020, LSB 360/256 degres.
    pub sector_number: Option<u8>,
    /// I034/041, periode de rotation d'antenne, LSB 1/128 s.
    pub antenna_rotation_period: Option<u16>,
}

impl ServiceMessage {
    /// Decode les items typees d'un record CAT 034 ; `None` si le record est
    /// d'une autre categorie.
    pub fn from_record(record: &AsterixRecord<'_>) -> Option<Self> {
        if record.category != 34 {
            return None;
        }
        Some(Self {
            data_source: record
                .item("I034/010")
                .and_then(DataSourceIdentifier::from_item),
            message_type: record
                .item("I034/000")
                .and_then(|d| d.first().map(|code| MessageType::from(*code))),
            time_of_day: record.item("I034/030").and_then(TimeOfDay::from_item),
            sector_number: record.item("I034/020").and_then(|d| d.first().copied()),
            antenna_rotation_period: record.item("I034/041").and_then(|d| match d {
                [high, low] => Some(u16::from_be_bytes([*high, *low])),
                _ => None,
            }),
        })
    }

    /// Azimut du secteur, en degres.
    pub fn sector_azimuth_deg(&self) -> Option<f64> {
        self.sector_number
            .map(|sector| f64::from(sector) * 360.0 / 256.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::application::protocols::asterix::AsterixPacket;

    #[test]
    fn test_sector_crossing_message() {
        // FSPEC 0xf0 : 010, 000, 030, 020.
        let bytes = [
            0x22, 0x00, 0x0b, 0xf0, 0x00, 0x01, 0x02, 0x38, 0x41, 0x76, 0x40,
        ];
        let packet = AsterixPacket::try_from(&bytes[..]).expect("record CAT 034");
        let message = ServiceMessage::from_record(&packet.blocks[0].records[0]).unwrap();
        assert_eq!(
            message.data_source,
            Some(DataSourceIdentifier { sac: 0, sic: 1 })
        );
        assert_eq!(message.message_type, Some(MessageType::SectorCrossing));
        assert_eq!(
            message.time_of_day.map(TimeOfDay::seconds),
            Some(28_802.921_875)
        );
        assert_eq!(message.sector_number, Some(0x40));
        assert_eq!(message.sector_azimuth_deg(), Some(90.0));
        assert_eq!(message.antenna_rotation_period, None);
    }

    #[test]
    fn test_message_type_mapping() {
        assert_eq!(MessageType::from(1), MessageType::NorthMarker);
        assert_eq!(MessageType::from(7), MessageType::ModeSJammingStrobe);
        assert_eq!(MessageType::from(0), MessageType::Other(0));
        assert_eq!(MessageType::from(8), MessageType::Other(8));
    }

    #[test]
    fn test_rejects_records_of_another_category() {
        let bytes = [0x30, 0x00, 0x06, 0x80, 0x00, 0x01];
        let packet = AsterixPacket::try_from(&bytes[..]).unwrap();
        assert_eq!(
            ServiceMessage::from_record(&packet.blocks[0].records[0]),
            None
        );
    }
}
