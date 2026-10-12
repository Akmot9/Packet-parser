// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! CAT 247 — Version Number Exchange (EUROCONTROL-SPEC-0149-17) : les
//! editions des categories qu'un emetteur diffuse, pour que le recepteur
//! choisisse ses UAP.

use super::{
    AsterixRecord,
    fields::{DataSourceIdentifier, TimeOfDay},
};

/// Une entree de I247/550 : la categorie et son edition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct CategoryVersion {
    pub category: u8,
    pub main_version: u8,
    pub sub_version: u8,
}

/// Les items decodes d'un record CAT 247.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VersionReport {
    pub data_source: Option<DataSourceIdentifier>,
    /// I247/015.
    pub service_identification: Option<u8>,
    /// I247/140.
    pub time_of_day: Option<TimeOfDay>,
    /// I247/550, dans l'ordre du wire ; vide quand l'item est absent.
    pub category_versions: Vec<CategoryVersion>,
}

impl VersionReport {
    /// Decode les items typees d'un record CAT 247 ; `None` si le record est
    /// d'une autre categorie.
    pub fn from_record(record: &AsterixRecord<'_>) -> Option<Self> {
        if record.category != 247 {
            return None;
        }
        Some(Self {
            data_source: record
                .item("I247/010")
                .and_then(DataSourceIdentifier::from_item),
            service_identification: record.item("I247/015").and_then(|d| d.first().copied()),
            time_of_day: record.item("I247/140").and_then(TimeOfDay::from_item),
            category_versions: record
                .item("I247/550")
                .map_or_else(Vec::new, category_versions),
        })
    }
}

/// REP triplets (categorie, version principale, sous-version). Le
/// decoupage a deja verifie REP.
fn category_versions(data: &[u8]) -> Vec<CategoryVersion> {
    data.get(1..)
        .unwrap_or_default()
        .as_chunks::<3>()
        .0
        .iter()
        .map(|entry| CategoryVersion {
            category: entry[0],
            main_version: entry[1],
            sub_version: entry[2],
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::application::protocols::asterix::AsterixPacket;

    /// Trame 428 de pcaps_exemple/protocols/asterix/wireshark_9953_cat021023.pcap
    /// (239.1.20.1:56610) : CAT 021 ed. 0.26 et CAT 023 ed. 1.20, recoupe
    /// avec tshark 4.6.6.
    const CAT021023_FRAME_428: &str = "f70011f0930d015d1d280215001a170114";

    #[test]
    fn test_decodes_a_real_version_report_against_tshark() {
        let bytes = hex::decode(CAT021023_FRAME_428).unwrap();
        let packet = AsterixPacket::try_from(bytes.as_slice()).expect("trame 428");
        let report = VersionReport::from_record(&packet.blocks[0].records[0]).unwrap();
        assert_eq!(report.data_source.map(|d| (d.sac, d.sic)), Some((147, 13)));
        assert_eq!(report.service_identification, Some(1));
        assert_eq!(
            report.time_of_day.map(TimeOfDay::seconds),
            Some(47_674.312_5)
        );
        assert_eq!(
            report.category_versions,
            [
                CategoryVersion {
                    category: 21,
                    main_version: 0,
                    sub_version: 26
                },
                CategoryVersion {
                    category: 23,
                    main_version: 1,
                    sub_version: 20
                },
            ]
        );
    }

    #[test]
    fn test_rejects_records_of_another_category() {
        let bytes = [0x22, 0x00, 0x06, 0x80, 0x00, 0x01];
        let packet = AsterixPacket::try_from(&bytes[..]).unwrap();
        assert_eq!(
            VersionReport::from_record(&packet.blocks[0].records[0]),
            None
        );
    }
}
