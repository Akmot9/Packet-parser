// Fuzz du dispatcher L7 : tous les parseurs applicatifs sondés à l'aveugle
// doivent rejeter proprement les octets hostiles.
#![no_main]

use libfuzzer_sys::fuzz_target;
use packet_parser::Application;

fuzz_target!(|data: &[u8]| {
    let _ = Application::try_from(data);
});
