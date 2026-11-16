// Fuzz du decodeur UMAS (Schneider, fonction Modbus 0x5A) : MBAP, session,
// fonction UMAS, donnees. Ni panic ni boucle ; quand le decodage reussit,
// le code de fonction Modbus est 0x5A, session et fonction sont les deux
// premiers octets du PDU, les donnees en sont la suite, et le MBAP se
// decode aussi seul.
#![no_main]

#[path = "../oracles/seeds.rs"]
mod seeds;

use libfuzzer_sys::fuzz_target;
use packet_parser::parse::application::protocols::{
    modbus_tcp::MBAP,
    umas::{UmasFunction, UmasPacket},
};
use seeds::{inside, replay_mutated};

// umas.pcap, trame 4 : requete UMAS.
const REQUEST: &[u8] = &[0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x5a, 0x00, 0x02];

// umas.pcap, trame 8 : reponse UMAS (fonction 0xFE).
const REPLY: &[u8] = &[
    0x00, 0x01, 0x00, 0x00, 0x00, 0x11, 0x00, 0x5a, 0x00, 0xfe, 0xfd, 0x00, 0x01, 0x04, 0x00, 0x00,
    0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

fn exercise(data: &[u8]) {
    let Ok(packet) = UmasPacket::try_from(data) else {
        return;
    };
    assert!(MBAP::try_from(data).is_ok());
    let pdu = packet.mbap.pdu.pdu_data;
    assert_eq!(packet.mbap.pdu.function_code, 0x5a);
    assert_eq!([packet.session_id, packet.function.code()], pdu[0..2]);
    assert_eq!(packet.data, &pdu[2..]);
    assert!(inside(data, packet.data));
    assert_eq!(
        packet.function == UmasFunction::Reply,
        packet.function.code() == 0xfe
    );
}

fuzz_target!(|data: &[u8]| {
    exercise(data);
    replay_mutated(&[REQUEST, REPLY], data, exercise);
});
