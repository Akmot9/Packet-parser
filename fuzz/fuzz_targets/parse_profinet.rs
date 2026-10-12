// Fuzz du decodeur PROFINET : classement du Frame ID de toute trame RT, puis
// decodage DCP des seuls Frame ID DCP. Ni panic ni boucle infinie ; quand le
// decodage reussit, le message est DCP, ses blocs et son NameOfStation
// pointent dans le buffer d'origine, et la validation de trame rend le meme
// Frame ID.
#![no_main]

use libfuzzer_sys::fuzz_target;
use packet_parser::parse::internet::protocols::profinet::{
    ProfinetPacket, validate_frame,
};

fuzz_target!(|data: &[u8]| {
    let frame = validate_frame(data);
    match ProfinetPacket::try_from(data) {
        Ok(packet) => {
            assert!(packet.frame_id.is_dcp());
            assert_eq!(frame.ok(), Some(packet.frame_id.clone()));
            let body_end = 12 + usize::from(packet.dcp_data_length);
            assert!(body_end <= data.len());
            let body = data[12..body_end].as_ptr_range();
            for block in &packet.blocks {
                assert!(block.data.is_empty() || body.contains(&block.data.as_ptr()));
                assert!(usize::from(block.block_length) >= block.data.len());
            }
            assert!(
                packet.name_of_station.is_empty()
                    || body.contains(&packet.name_of_station.as_ptr())
            );
        }
        Err(_) => {
            if let Ok(frame_id) = frame {
                assert!(!frame_id.is_dcp());
            }
        }
    }
});
