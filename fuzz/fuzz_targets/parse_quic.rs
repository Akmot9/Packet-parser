// Fuzz du parseur QUIC Long Header : varints RFC 9000, Connection IDs et
// champ Length ne doivent jamais paniquer ni lire hors bornes sur des
// octets hostiles.
#![no_main]

use libfuzzer_sys::fuzz_target;
use packet_parser::parse::application::protocols::quic::QuicPacket;

fuzz_target!(|data: &[u8]| {
    let _ = QuicPacket::try_from(data);
});
