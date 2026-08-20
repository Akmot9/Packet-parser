// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests NetBIOS (issue #8) sur trames reelles de
//! `pcaps_exemple/The-Ultimate-PCAP.pcapng` (numeros de trame notes sur
//! chaque fixture ; corpus : 36 trames `nbns`, 302 trames `nbss`).
//!
//! Les trames NBNS sont Ethernet + IPv4 + UDP 137 -> 137, avec un trailer
//! Ethernet de 4 octets que la couche IPv4 doit ecarter. Les trames NBSS
//! sont Ethernet + 802.1Q + IPv6 + TCP 445 (SMB direct hosting : le corpus
//! ne contient aucun echange sur TCP 139, tous les session services y sont
//! des session messages type 0x00).
//!
//! La detection n'etant pas encore cablee dans la chaine applicative, chaque
//! test remonte au payload transport via `PacketFlow` puis appelle le
//! `TryFrom` du parseur NetBIOS sur ce payload.

use packet_parser::parse::application::protocols::netbios::{
    NbnsPacket, NbnsRecordType, NbssMessageType, NbssPacket,
};
use packet_parser::{LinkType, parse};

/// Trame 38172 : registration broadcast de JOHANNES-DELL<00> par
/// 169.254.140.132, question NB + enregistrement additional dont le nom est
/// un pointeur de compression c00c.
const NBNS_REGISTRATION_FRAME_HEX: &str = concat!(
    "ffffffffffff00e04c6866c1080045000060fe65000080115ba6a9fe8c84a9fe",
    "ffff00890089004c8877d9302910000100000000000120454b45504549454245",
    "4f454f45464644434e45454546454d454d4341434141410000200001c00c0020",
    "0001000493e000066000a9fe8c842acebc26"
);

/// Trame 38229 : name query broadcast de WEBERLAB<1b> (domain master
/// browser) par 10.0.1.97, question seule.
const NBNS_QUERY_FRAME_HEX: &str = concat!(
    "ffffffffffff00e04c6866c108004500004ea6cf000080117c700a0001610a00",
    "01ff00890089003aa951d93f0110000100000000000020464845464543454646",
    "43454d454245434341434143414341434143414341424c00002000012fee3b42"
);

/// Trame 39979 : session message NBSS portant un Negotiate Protocol Request
/// SMB1 (client 49958 -> serveur 445, longueur annoncee 69).
const NBSS_SMB1_NEGOTIATE_FRAME_HEX: &str = concat!(
    "3cfa30031230000c29c37feb8100005186dd600b0725005d06402a006020ad0b",
    "8381fd70e2f9f0319dc42a006020ad0b83800000000000000010c32601bd7977",
    "37d8f1717bb750180405ad42000000000045ff534d4272000000001853c80000",
    "00000000000000000000fffffffe00000000002200024e54204c4d20302e3132",
    "0002534d4220322e3030320002534d4220322e3f3f3f00"
);

/// Trame 40012 : session message NBSS portant un Session Setup Response
/// SMB2 (serveur 445 -> client 49960, longueur annoncee 101).
const NBSS_SMB2_SESSION_SETUP_FRAME_HEX: &str = concat!(
    "3cfa30031230000c29a9e4e38100005086dd6000eaa7007d06402a006020ad0b",
    "838000000000000000102a006020ad0b8381fd70e2f9f0319dc401bdc3283d0c",
    "2110db9f3724501820003b8b000000000065fe534d4240000100000000000100",
    "210011000000000000000200000000000000fffe000000000000250000500020",
    "0000000000000000000000000000000000000900000048001d00a11b3019a003",
    "0a0100a312041001000000ca1d85ba1649942500000000"
);

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
fn nbns_registration_parses_from_the_captured_udp_payload() {
    let bytes = frame(NBNS_REGISTRATION_FRAME_HEX, 114);
    let flow = parse(LinkType::ETHERNET, bytes.as_slice()).expect("captured frame decodes");

    let transport = flow.transport.expect("UDP at the transport slot");
    assert_eq!(transport.source_port, Some(137));
    assert_eq!(transport.destination_port, Some(137));

    let payload = transport.payload.expect("UDP payload is exposed");
    // 76 octets UDP - 8 d'en-tete : le trailer Ethernet de 4 octets ne fuit
    // pas dans le payload.
    assert_eq!(payload.len(), 68);

    let packet = NbnsPacket::try_from(payload).expect("captured NBNS payload parses");
    assert_eq!(packet.transaction_id, 0xd930);
    assert!(!packet.flags.response);
    // Opcode 0x5 : name registration, diffusee (bit B).
    assert_eq!(packet.flags.opcode, 0x5);
    assert!(packet.flags.broadcast);
    assert_eq!(
        [
            packet.question_count,
            packet.answer_count,
            packet.authority_count,
            packet.additional_count
        ],
        [1, 0, 0, 1]
    );

    let question = &packet.questions[0];
    assert_eq!(question.name.as_str(), Some("JOHANNES-DELL"));
    assert_eq!(question.name.suffix, 0x00);
    assert!(question.scope.is_empty());
    assert_eq!(question.question_type, NbnsRecordType::NetBios);

    // L'additional reprend le nom de la question via le pointeur c00c.
    let record = &packet.resource_records[0];
    assert_eq!(record.name, question.name);
    assert_eq!(record.record_type, NbnsRecordType::NetBios);
    assert_eq!(record.ttl, 300_000);
    // RDATA NB : flags (ONT=H, 0x6000) + adresse 169.254.140.132.
    assert_eq!(record.rdata, [0x60, 0x00, 0xa9, 0xfe, 0x8c, 0x84]);
}

#[test]
fn nbns_name_query_parses_from_the_captured_udp_payload() {
    let bytes = frame(NBNS_QUERY_FRAME_HEX, 96);
    let flow = parse(LinkType::ETHERNET, bytes.as_slice()).expect("captured frame decodes");

    let transport = flow.transport.expect("UDP at the transport slot");
    assert_eq!(transport.source_port, Some(137));
    assert_eq!(transport.destination_port, Some(137));

    let payload = transport.payload.expect("UDP payload is exposed");
    assert_eq!(payload.len(), 50);

    let packet = NbnsPacket::try_from(payload).expect("captured NBNS payload parses");
    assert_eq!(packet.transaction_id, 0xd93f);
    // Opcode 0x0 : name query, diffusee (bit B).
    assert_eq!(packet.flags.opcode, 0x0);
    assert!(packet.flags.broadcast);
    assert!(packet.flags.recursion_desired);
    assert_eq!(packet.question_count, 1);
    assert!(packet.resource_records.is_empty());

    let question = &packet.questions[0];
    assert_eq!(question.name.as_str(), Some("WEBERLAB"));
    // Suffixe 0x1b : domain master browser.
    assert_eq!(question.name.suffix, 0x1b);
    assert_eq!(question.question_type, NbnsRecordType::NetBios);
}

#[test]
fn nbss_smb1_negotiate_parses_from_the_captured_tcp_payload() {
    let bytes = frame(NBSS_SMB1_NEGOTIATE_FRAME_HEX, 151);
    let flow = parse(LinkType::ETHERNET, bytes.as_slice()).expect("captured frame decodes");

    let transport = flow.transport.expect("TCP at the transport slot");
    assert_eq!(transport.destination_port, Some(445));

    let payload = transport.payload.expect("TCP payload is exposed");
    assert_eq!(payload.len(), 73);

    let packet = NbssPacket::try_from(payload).expect("captured NBSS payload parses");
    assert_eq!(packet.header.message_type, NbssMessageType::SessionMessage);
    assert_eq!(packet.header.length, 69);
    assert_eq!(packet.payload.len(), 69);
    // Le payload borne commence a la signature SMB1.
    assert_eq!(&packet.payload[..4], b"\xffSMB");
}

#[test]
fn nbss_smb2_session_setup_parses_from_the_captured_tcp_payload() {
    let bytes = frame(NBSS_SMB2_SESSION_SETUP_FRAME_HEX, 183);
    let flow = parse(LinkType::ETHERNET, bytes.as_slice()).expect("captured frame decodes");

    let transport = flow.transport.expect("TCP at the transport slot");
    assert_eq!(transport.source_port, Some(445));

    let payload = transport.payload.expect("TCP payload is exposed");
    assert_eq!(payload.len(), 105);

    let packet = NbssPacket::try_from(payload).expect("captured NBSS payload parses");
    assert_eq!(packet.header.message_type, NbssMessageType::SessionMessage);
    assert_eq!(packet.header.length, 101);
    // Le payload borne commence a la signature SMB2.
    assert_eq!(&packet.payload[..4], b"\xfeSMB");
}
