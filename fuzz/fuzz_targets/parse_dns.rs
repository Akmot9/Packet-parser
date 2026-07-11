// Fuzz du parseur DNS (compression de noms incluse) : les pointeurs
// malveillants ne doivent créer ni boucle infinie ni panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use packet_parser::parse::application::protocols::dns::DnsPacket;

fuzz_target!(|data: &[u8]| {
    let _ = DnsPacket::try_from(data);
});
