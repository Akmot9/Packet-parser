// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests OpenVPN sur trames reellement capturees (issue #5).
//!
//! Les fixtures viennent des deux samples publics de la wiki Wireshark
//! versionnes dans `pcaps_exemple/protocols/openvpn/` (voir `SOURCE.md`) :
//! une session `tls-auth` sur UDP 1194 et la meme sur TCP 1194. Les valeurs
//! attendues (opcode, key id, session id, longueurs) ont ete relevees dans le
//! decodage `openvpn` de tshark 4.6.6.
//!
//! Le module n'etant pas encore cable dans le dispatch L7 (garde de port
//! 1194, session principale), les tests parsent le payload transport extrait
//! de la trame complete — embarquee ici en hex depuis l'en-tete Ethernet,
//! comme le veut la convention du depot.

use packet_parser::parse::application::protocols::openvpn::{OpenVpnOpcode, OpenVpnPacket};

/// Trame 1 de `OpenVPN_UDP_tls-auth.pcapng` : P_CONTROL_HARD_RESET_CLIENT_V2,
/// 192.168.56.103:33198 -> 192.168.56.102:1194. tshark : key id 0, session id
/// 9311214641221158445, HMAC SHA-1, replay packet-id 1, ack array vide,
/// message packet-id 0.
const UDP_HARD_RESET_CLIENT_V2_FRAME_HEX: &str = concat!(
    "0800274abe45080027bb22840800450000460000400040114889c0a83867c0a8",
    "386681ae04aa003253b438813814621d67462dde86734d2cbff151b2b1231b61",
    "e42308a272818e0000000150ff262c0000000000"
);

/// Trame 2 du meme fichier : P_CONTROL_HARD_RESET_SERVER_V2,
/// 192.168.56.102:1194 -> 192.168.56.103:33198. tshark : key id 0, session id
/// 6284514521502670920, ack array de longueur 1 acquittant le packet-id 0,
/// remote session id 9311214641221158445.
const UDP_HARD_RESET_SERVER_V2_FRAME_HEX: &str = concat!(
    "080027bb22840800274abe45080045000052000040004011487dc0a83866c0a8",
    "386704aa81ae003e342740573714a917f36048885887cdb6dd77785d00d15edb",
    "be9aa6203a45570000000150ff262b0100000000813814621d67462d00000000"
);

/// Trame 365 du meme fichier : premier P_DATA_V1 de la session, key id 0,
/// 52 octets de charge chiffree (tshark : « Data (52 bytes) »).
const UDP_DATA_V1_FRAME_HEX: &str = concat!(
    "0800274abe45080027bb2284080045000051000040004011487ec0a83867c0a8",
    "386681ae04aa003d135d30d7b233d32203d9b4f27ce4a943ded9b8d51b867e5c",
    "40f65b26e5457c521cca59e863878d46b0f482dd061f968f5d62d8179bbba6"
);

/// Trame 4 de `OpenVPN_TCP_tls-auth.pcapng` : le meme hard reset client v2
/// sur TCP 1194 (51089 -> 1194), prefixe de longueur 0x002a (42). tshark :
/// session id 2945691201468491466.
const TCP_HARD_RESET_CLIENT_V2_FRAME_HEX: &str = concat!(
    "0800274abe45080027bb2284080045000060cd4a400040067b2fc0a83867c0a8",
    "3866c79104aa8e58ccc0ee2edbc380181c84104300000101080a000302f40004",
    "f24f002a3828e1328a7185e6ca779cda2d2230e4755040a78df956f0268c51fb",
    "710000000150ff20fd0000000000"
);

/// Offset du payload UDP : Ethernet (14) + IPv4 sans options (20) + UDP (8).
const UDP_PAYLOAD_OFFSET: usize = 42;

/// Offset du payload TCP de la trame 4 : Ethernet (14) + IPv4 (20) + TCP avec
/// options timestamp (data offset 8 -> 32 octets).
const TCP_PAYLOAD_OFFSET: usize = 66;

fn frame(hex_fixture: &str, expected_len: usize) -> Vec<u8> {
    let bytes = hex::decode(hex_fixture).expect("invalid test hex fixture");
    assert_eq!(
        bytes.len(),
        expected_len,
        "the fixture must match the frame length reported by tshark"
    );
    bytes
}

#[test]
fn captured_hard_reset_client_v2_parses() {
    let bytes = frame(UDP_HARD_RESET_CLIENT_V2_FRAME_HEX, 84);
    let payload = &bytes[UDP_PAYLOAD_OFFSET..];

    let packet = OpenVpnPacket::try_from(payload).expect("captured hard reset client parses");

    assert_eq!(packet.opcode, OpenVpnOpcode::ControlHardResetClientV2);
    assert_eq!(packet.key_id, 0);
    // tshark : Session ID 9311214641221158445 (0x813814621d67462d).
    assert_eq!(packet.session_id, Some(9_311_214_641_221_158_445));
    assert_eq!(packet.peer_id, None);
    // HMAC tls-auth (20) + replay packet-id (4) + net-time (4) +
    // ack array length (1) + message packet-id (4).
    assert_eq!(packet.payload.len(), 33);
    // Le HMAC releve par tshark ouvre le payload...
    assert_eq!(
        &packet.payload[..4],
        hex::decode("de86734d").expect("hmac prefix").as_slice()
    );
    // ... et le message packet-id 0 le clot, ack array vide juste avant.
    assert_eq!(&packet.payload[28..], &[0x00, 0x00, 0x00, 0x00, 0x00]);
}

#[test]
fn captured_hard_reset_server_v2_parses() {
    let bytes = frame(UDP_HARD_RESET_SERVER_V2_FRAME_HEX, 96);
    let payload = &bytes[UDP_PAYLOAD_OFFSET..];

    let packet = OpenVpnPacket::try_from(payload).expect("captured hard reset server parses");

    assert_eq!(packet.opcode, OpenVpnOpcode::ControlHardResetServerV2);
    assert_eq!(packet.key_id, 0);
    // tshark : Session ID 6284514521502670920 (0x573714a917f36048).
    assert_eq!(packet.session_id, Some(6_284_514_521_502_670_920));
    // HMAC (20) + replay packet-id (4) + net-time (4) + ack array length (1)
    // + un packet-id acquitte (4) + remote session id (8) + message
    // packet-id (4).
    assert_eq!(packet.payload.len(), 45);
    // tshark : ack array de longueur 1, acquittant le packet-id 0.
    assert_eq!(packet.payload[28], 0x01);
    assert_eq!(&packet.payload[29..33], &[0x00, 0x00, 0x00, 0x00]);
    // tshark : Remote Session ID 9311214641221158445 — la session id du
    // client de la trame 1.
    assert_eq!(
        &packet.payload[33..41],
        &9_311_214_641_221_158_445_u64.to_be_bytes()
    );
}

#[test]
fn captured_data_v1_parses() {
    let bytes = frame(UDP_DATA_V1_FRAME_HEX, 95);
    let payload = &bytes[UDP_PAYLOAD_OFFSET..];

    let packet = OpenVpnPacket::try_from(payload).expect("captured data packet parses");

    assert_eq!(packet.opcode, OpenVpnOpcode::DataV1);
    assert_eq!(packet.key_id, 0);
    assert_eq!(packet.session_id, None);
    assert_eq!(packet.peer_id, None);
    // tshark : Data (52 bytes), d7b2...bba6.
    assert_eq!(packet.payload.len(), 52);
    assert_eq!(packet.payload, &payload[1..]);
    assert_eq!(
        &packet.payload[..4],
        hex::decode("d7b233d3").expect("data prefix").as_slice()
    );
}

#[test]
fn captured_tcp_record_parses_with_its_length_prefix() {
    let bytes = frame(TCP_HARD_RESET_CLIENT_V2_FRAME_HEX, 110);
    let payload = &bytes[TCP_PAYLOAD_OFFSET..];

    let (packet, rest) =
        OpenVpnPacket::from_tcp_stream(payload).expect("captured TCP record parses");

    assert_eq!(packet.opcode, OpenVpnOpcode::ControlHardResetClientV2);
    assert_eq!(packet.key_id, 0);
    // tshark : Packet Length 42, Session ID 2945691201468491466.
    assert_eq!(packet.session_id, Some(2_945_691_201_468_491_466));
    assert_eq!(packet.payload.len(), 33);
    assert!(rest.is_empty(), "the segment carries a single record");
}

/// Oracle negatif : les payloads voisins du corpus ne doivent pas passer pour
/// de l'OpenVPN. Vecteurs synthetiques verrouillant les confusions les plus
/// plausibles avant le cablage derriere le port 1194.
#[test]
fn lookalike_payloads_are_rejected() {
    // Un record TLS Handshake (0x16 -> opcode 2, key id 6 en apparence) :
    // un hard reset porte toujours le key id 0, un ClientHello complet est
    // donc rejete quelle que soit sa taille.
    let mut tls_client_hello = vec![0x16, 0x03, 0x01, 0x02, 0x00, 0x01];
    tls_client_hello.extend_from_slice(&[0u8; 512]);
    assert!(
        OpenVpnPacket::try_from(tls_client_hello.as_slice()).is_err(),
        "a TLS handshake record must not parse as OpenVPN"
    );

    // Un pseudo hard reset de 2 Ko : la borne des resets doit trancher.
    let mut oversized = vec![0x38];
    oversized.extend_from_slice(&[0u8; 2048]);
    assert!(OpenVpnPacket::try_from(oversized.as_slice()).is_err());

    // Opcode inconnu (0xB8 -> 23).
    let mut unknown = vec![0xb8];
    unknown.extend_from_slice(&[0u8; 32]);
    assert!(OpenVpnPacket::try_from(unknown.as_slice()).is_err());

    // Datagramme vide.
    assert!(OpenVpnPacket::try_from(&[][..]).is_err());
}
