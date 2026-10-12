// Fuzz du decodeur ASTERIX : en-tetes de data block, FSPEC extensibles,
// items fixes, extensibles (bornes ou non), repetitifs, composes,
// explicites et RFS, sur onze categories dont les deux UAP de CAT 001. Ni
// panic ni boucle infinie ; quand le decodage reussit, les data blocks
// pavent exactement l'entree, chaque record porte au moins un item, chaque
// item pointe dans le buffer d'origine, et les decodeurs types comme les
// accesseurs de sous-champs et de RFS acceptent tout record.
#![no_main]

use libfuzzer_sys::fuzz_target;
use packet_parser::parse::application::protocols::asterix::{
    AsterixPacket, cat001, cat002, cat008, cat021, cat023, cat034, cat048, cat062, cat063,
    cat065, cat247,
};

fuzz_target!(|data: &[u8]| {
    let Ok(packet) = AsterixPacket::try_from(data) else {
        return;
    };
    let total: usize = packet.blocks.iter().map(|block| usize::from(block.length)).sum();
    assert_eq!(total, data.len());
    for block in &packet.blocks {
        assert!(!block.records.is_empty());
        let mut covered = 3;
        for record in &block.records {
            assert!(!record.items.is_empty());
            assert_eq!(record.category, block.category);
            assert!(record.uap().is_some(), "categorie decodee sans UAP");
            covered += record.fspec.len();
            for item in &record.items {
                assert!(!item.data.is_empty());
                assert!(data.as_ptr_range().contains(&item.data.as_ptr()));
                covered += item.data.len();
                // Un sous-champ ou un item de RFS pointe lui aussi dans l'entree.
                for number in 1..=4 {
                    if let Some(bytes) = record.subfield(item.id, number) {
                        assert!(data.as_ptr_range().contains(&bytes.as_ptr()));
                    }
                }
            }
            for inner in record.rfs_items() {
                assert!(!inner.data.is_empty());
                assert!(data.as_ptr_range().contains(&inner.data.as_ptr()));
                assert_eq!(record.item(inner.id), Some(inner.data));
            }
            let _ = cat001::TargetReport::from_record(record);
            let _ = cat002::ServiceMessage::from_record(record);
            let _ = cat008::WeatherMessage::from_record(record);
            let _ = cat021::TargetReport::from_record(record);
            let _ = cat023::StatusReport::from_record(record);
            let _ = cat034::ServiceMessage::from_record(record);
            let _ = cat048::TargetReport::from_record(record);
            let _ = cat062::SystemTrack::from_record(record);
            let _ = cat063::SensorStatus::from_record(record);
            let _ = cat065::ServiceStatus::from_record(record);
            let _ = cat247::VersionReport::from_record(record);
        }
        assert_eq!(covered, usize::from(block.length));
    }
});
