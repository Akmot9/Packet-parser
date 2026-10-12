// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! CAT 065 — SDPS Service Status Messages (EUROCONTROL-SPEC-0149-15) : l'etat
//! du systeme de traitement des donnees de surveillance qui emet les pistes
//! CAT 062, et les fins de lot qui rythment leur diffusion.

use super::{
    AsterixRecord,
    fields::{DataSourceIdentifier, TimeOfDay},
};

/// Type de message (I065/000).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MessageType {
    SdpsStatus,
    EndOfBatch,
    ServiceStatusReport,
    Other(u8),
}

impl From<u8> for MessageType {
    fn from(code: u8) -> Self {
        match code {
            1 => Self::SdpsStatus,
            2 => Self::EndOfBatch,
            3 => Self::ServiceStatusReport,
            other => Self::Other(other),
        }
    }
}

/// Configuration et etat du SDPS (I065/040).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SdpsConfiguration {
    /// NOGO, deux bits : 0 operationnel, 1 degrade, 2 non utilisable.
    pub nogo: u8,
    /// OVL : surcharge.
    pub overload: bool,
    /// TSV = 1 : source de temps invalide.
    pub time_source_invalid: bool,
    /// PSS, deux bits : 0 sans objet, 1 SDPS-1 selectionne, 2 SDPS-2, 3
    /// SDPS-3.
    pub processing_system_status: u8,
    /// STTN : renumerotation des pistes.
    pub track_renumbering: bool,
    /// L'octet, tel quel.
    pub raw: u8,
}

/// Les items decodes d'un record CAT 065.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ServiceStatus {
    pub data_source: Option<DataSourceIdentifier>,
    pub message_type: Option<MessageType>,
    /// I065/015.
    pub service_identification: Option<u8>,
    /// I065/030.
    pub time_of_message: Option<TimeOfDay>,
    /// I065/020, numero du lot qui vient de finir.
    pub batch_number: Option<u8>,
    pub sdps_configuration: Option<SdpsConfiguration>,
    /// I065/050, rapport d'etat du service : 1 demarre, 2 arrete, 3
    /// degrade, 4 ... (Part 15, I065/050).
    pub service_status_report: Option<u8>,
}

impl ServiceStatus {
    /// Decode les items typees d'un record CAT 065 ; `None` si le record est
    /// d'une autre categorie.
    pub fn from_record(record: &AsterixRecord<'_>) -> Option<Self> {
        if record.category != 65 {
            return None;
        }
        let octet = |id: &str| record.item(id).and_then(|d| d.first().copied());
        Some(Self {
            data_source: record
                .item("I065/010")
                .and_then(DataSourceIdentifier::from_item),
            message_type: octet("I065/000").map(MessageType::from),
            service_identification: octet("I065/015"),
            time_of_message: record.item("I065/030").and_then(TimeOfDay::from_item),
            batch_number: octet("I065/020"),
            sdps_configuration: octet("I065/040").map(|raw| SdpsConfiguration {
                nogo: raw >> 6,
                overload: raw & 0x20 != 0,
                time_source_invalid: raw & 0x10 != 0,
                processing_system_status: (raw >> 2) & 0x03,
                track_renumbering: raw & 0x02 != 0,
                raw,
            }),
            service_status_report: octet("I065/050"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::application::protocols::asterix::AsterixPacket;

    /// Trame 73 de pcaps_exemple/protocols/asterix/wireshark_8579_radardata.pcap
    /// (226.3.2.1:60202) : etat du SDPS SAC 147 / SIC 100, operationnel ; et
    /// bloc CAT 065 de la trame 1 de cat_062_065.pcap (CroatiaControlLtd) :
    /// fin du lot 1. Recoupes avec tshark 4.6.6.
    const RADARDATA_FRAME_73: &str = "41000cf49364010259dc6100";
    const CAT_062_065_FRAME_1_CAT065: &str = "41000cf8196402015981b301";

    #[test]
    fn test_decodes_real_sdps_status_and_end_of_batch_against_tshark() {
        let bytes = hex::decode(RADARDATA_FRAME_73).unwrap();
        let packet = AsterixPacket::try_from(bytes.as_slice()).expect("trame 73");
        let status = ServiceStatus::from_record(&packet.blocks[0].records[0]).unwrap();
        assert_eq!(status.data_source.map(|d| (d.sac, d.sic)), Some((147, 100)));
        assert_eq!(status.message_type, Some(MessageType::SdpsStatus));
        assert_eq!(status.service_identification, Some(2));
        assert_eq!(
            status.time_of_message.map(TimeOfDay::seconds),
            Some(46_008.757_812_5)
        );
        assert_eq!(status.batch_number, None);
        let configuration = status.sdps_configuration.unwrap();
        assert_eq!(configuration.nogo, 0);
        assert!(!configuration.overload && !configuration.time_source_invalid);
        assert_eq!(configuration.processing_system_status, 0);
        assert!(!configuration.track_renumbering);
        assert_eq!(status.service_status_report, None);

        let bytes = hex::decode(CAT_062_065_FRAME_1_CAT065).unwrap();
        let packet = AsterixPacket::try_from(bytes.as_slice()).expect("fin de lot");
        let status = ServiceStatus::from_record(&packet.blocks[0].records[0]).unwrap();
        assert_eq!(status.data_source.map(|d| (d.sac, d.sic)), Some((25, 100)));
        assert_eq!(status.message_type, Some(MessageType::EndOfBatch));
        assert_eq!(status.service_identification, Some(1));
        assert_eq!(
            status.time_of_message.map(TimeOfDay::seconds),
            Some(45_827.398_437_5)
        );
        assert_eq!(status.batch_number, Some(1));
        assert_eq!(status.sdps_configuration, None);
    }

    #[test]
    fn test_rejects_records_of_another_category() {
        let bytes = [0x22, 0x00, 0x06, 0x80, 0x00, 0x01];
        let packet = AsterixPacket::try_from(&bytes[..]).unwrap();
        assert_eq!(
            ServiceStatus::from_record(&packet.blocks[0].records[0]),
            None
        );
    }
}
