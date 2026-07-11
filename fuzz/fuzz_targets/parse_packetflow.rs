// Fuzz du point d'entrée principal : aucun octet hostile ne doit provoquer
// de panic, seulement Ok(_) ou Err(_).
#![no_main]

use libfuzzer_sys::fuzz_target;
use packet_parser::PacketFlow;

fuzz_target!(|data: &[u8]| {
    if let Ok(flow) = PacketFlow::try_from(data) {
        // Exerce aussi les chemins de conversion et d'aplatissement.
        let _ = flow.to_owned();
        let _ = flow.flatten();
    }
});
