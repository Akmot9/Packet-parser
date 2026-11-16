// Fuzz du decodeur OpenVPN : opcode et key_id, identifiant de session des
// paquets de controle, peer-id de P_DATA_V2, et l'enregistrement TCP prefixe
// par sa longueur. Ni panic ni boucle ; quand le decodage reussit, l'opcode
// et le key_id sont ceux du premier octet, le payload est la fin de
// l'enregistrement apres l'en-tete de son opcode, et `from_tcp_stream` rend
// l'enregistrement declare suivi du reste du flux.
#![no_main]

#[path = "../oracles/seeds.rs"]
mod seeds;

use libfuzzer_sys::fuzz_target;
use packet_parser::parse::application::protocols::openvpn::{OpenVpnOpcode, OpenVpnPacket};
use seeds::{inside, replay_mutated};

// OpenVPN_UDP_tls-auth.pcapng, trame 1 : P_CONTROL_HARD_RESET_CLIENT_V2.
const HARD_RESET_CLIENT: &[u8] = &[
    0x38, 0x81, 0x38, 0x14, 0x62, 0x1d, 0x67, 0x46, 0x2d, 0xde, 0x86, 0x73, 0x4d, 0x2c, 0xbf, 0xf1,
    0x51, 0xb2, 0xb1, 0x23, 0x1b, 0x61, 0xe4, 0x23, 0x08, 0xa2, 0x72, 0x81, 0x8e, 0x00, 0x00, 0x00,
    0x01, 0x50, 0xff, 0x26, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// OpenVPN_UDP_tls-auth.pcapng, trame 3 : P_ACK_V1.
const ACK: &[u8] = &[
    0x28, 0x81, 0x38, 0x14, 0x62, 0x1d, 0x67, 0x46, 0x2d, 0x0e, 0x2e, 0x72, 0x32, 0x0f, 0x65, 0xf7,
    0xcf, 0xec, 0x66, 0x50, 0x27, 0x95, 0xce, 0xf7, 0x31, 0x6d, 0xf0, 0x17, 0x34, 0x00, 0x00, 0x00,
    0x02, 0x50, 0xff, 0x26, 0x2c, 0x01, 0x00, 0x00, 0x00, 0x00, 0x57, 0x37, 0x14, 0xa9, 0x17, 0xf3,
    0x60, 0x48,
];

// OpenVPN_TCP_tls-auth.pcapng, trame 4 : le meme hard reset, prefixe par sa
// longueur sur TCP.
const TCP_HARD_RESET_CLIENT: &[u8] = &[
    0x00, 0x2a, 0x38, 0x28, 0xe1, 0x32, 0x8a, 0x71, 0x85, 0xe6, 0xca, 0x77, 0x9c, 0xda, 0x2d, 0x22,
    0x30, 0xe4, 0x75, 0x50, 0x40, 0xa7, 0x8d, 0xf9, 0x56, 0xf0, 0x26, 0x8c, 0x51, 0xfb, 0x71, 0x00,
    0x00, 0x00, 0x01, 0x50, 0xff, 0x20, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00,
];

fn check(record: &[u8], packet: &OpenVpnPacket<'_>) {
    assert_eq!(
        OpenVpnOpcode::from_wire(record[0] >> 3),
        Some(packet.opcode)
    );
    assert_eq!(packet.key_id, record[0] & 0x07);
    let header = match (packet.session_id, packet.peer_id) {
        (Some(_), None) => 1 + 8,
        (None, Some(_)) => 1 + 3,
        (None, None) => 1,
        (Some(_), Some(_)) => panic!("session et peer-id ensemble"),
    };
    assert_eq!(header + packet.payload.len(), record.len());
    assert!(record.ends_with(packet.payload) && inside(record, packet.payload));
    assert_eq!(packet.session_id.is_none(), packet.opcode.is_data());
    assert_eq!(
        packet.peer_id.is_some(),
        packet.opcode == OpenVpnOpcode::DataV2
    );
    assert!(!packet.opcode.is_hard_reset() || packet.opcode.is_reset());
    assert!(!(packet.opcode.is_reset() && packet.opcode.is_data()));
}

fn exercise(data: &[u8]) {
    if let Ok(packet) = OpenVpnPacket::try_from(data) {
        check(data, &packet);
    }
    if let Ok((packet, rest)) = OpenVpnPacket::from_tcp_stream(data) {
        let declared = usize::from(u16::from_be_bytes([data[0], data[1]]));
        assert_eq!(2 + declared + rest.len(), data.len());
        assert!(data.ends_with(rest) && inside(data, rest));
        check(&data[2..2 + declared], &packet);
    }
}

fuzz_target!(|data: &[u8]| {
    exercise(data);
    replay_mutated(
        &[HARD_RESET_CLIENT, ACK, TCP_HARD_RESET_CLIENT],
        data,
        exercise,
    );
});
