// Fuzz du decodeur ASTERIX : en-tetes de data block, FSPEC extensibles,
// items fixes, extensibles, repetitifs, composes et explicites, sur trois
// UAP. Ni panic ni boucle infinie ; quand le decodage reussit, les data
// blocks pavent exactement l'entree, chaque record porte au moins un item
// et chaque item pointe dans le buffer d'origine.
#![no_main]

use libfuzzer_sys::fuzz_target;
use packet_parser::parse::application::protocols::asterix::{
    AsterixPacket, cat021, cat034, cat048,
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
            covered += record.fspec.len();
            for item in &record.items {
                assert!(!item.data.is_empty());
                assert!(data.as_ptr_range().contains(&item.data.as_ptr()));
                covered += item.data.len();
            }
            let _ = cat048::TargetReport::from_record(record);
            let _ = cat034::ServiceMessage::from_record(record);
            let _ = cat021::TargetReport::from_record(record);
        }
        assert_eq!(covered, usize::from(block.length));
    }
});
