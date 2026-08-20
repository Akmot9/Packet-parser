// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests GIOP sur trames reelles (issue #58).
//!
//! Capture : `pcaps_exemple/protocols/giop/corba.pcap` (corpus de tests
//! nDPI, voir le `SOURCE.md` du dossier). Les numeros de trame et toutes les
//! valeurs attendues (magic, version, flags, message type, message size,
//! request id, operation, target, service contexts) ont ete verifies avec
//! tshark 4.6.6 (`-Y giop -V`).
//!
//! Ces trames ont revele deux ecarts du parseur a la realite du wire,
//! corriges avec elles :
//! - `message_size` suit l'endianness annoncee par les flags (bit 0), il
//!   n'est pas toujours big-endian (trame 19, little-endian) ;
//! - le body Request est du CDR : discriminant de TargetAddress sur un
//!   short (2 octets) et primitives alignees sur leur taille naturelle
//!   (paddings), sans quoi aucun Request 1.2 reel ne se decode.

use packet_parser::parse::application::protocols::giop::{
    GiopMessage, GiopMessageType, GiopPacket, TargetAddress,
};
use packet_parser::{LinkType, parse};

/// Trame 4 : Request GIOP 1.2 big-endian sur TCP loopback (42717 -> 56899),
/// op "echo", request id 0, un ServiceContext INVOCATION_POLICIES (0x07).
/// tshark : "GIOP 1.2 Request, s=216 id=0: op=echo".
const GIOP12_REQUEST_ECHO_FRAME_HEX: &str = concat!(
    "000000000000000000000000080045000118a41d4000400695c07f0001017f00",
    "0101a6ddde43905fd45390db7ac980180101010d00000101080a0013705a0013",
    "704947494f5001020000000000d80000000003000000000000000000003c0000",
    "000000000001000000104d795f436f6d70726573735f506f6100000000000000",
    "011f5a056dca000000100000011f5a056dca00000000000000000000000565",
    "63686f0000000000000001000000070000002800000000000000010000001c00",
    "000018000000000000000001ddf68a6dc5c42000000000000000000000004100",
    "0202060402010503010205030707060102070705030105030703030103060602",
    "0206040102020201010407050207070306040605020202020205020205040100",
    "00000000000000"
);

/// Trame 6 : Reply GIOP 1.2 big-endian "No Exception" (56899 -> 42717),
/// request id 0. tshark : "GIOP 1.2 Reply, s=81 id=0: No Exception".
const GIOP12_REPLY_FRAME_HEX: &str = concat!(
    "0000000000000000000000000800450000910a81400040062fe47f0001017f00",
    "0101de43a6dd90db7ac9905fd53780180109008600000101080a001370620013",
    "705a47494f500102000100000051000000000000000000000000000000410002",
    "0206040201050301020503070706010207070503010503070303010306060202",
    "06040102020201010407050207070306040605020202020205020205040100"
);

/// Trame 19 : datagramme UDP MIOP (Unreliable Multicast IOP) vers
/// 10.95.28.46:15984 encapsulant un Request GIOP 1.2 **little-endian**
/// (flags 0x01), op "receiveReliableData", request id 0, target ProfileAddr
/// (TaggedProfile TAG_UIPMC = 3). tshark : "GIOP 1.2 Request, s=216 id=0:
/// op=receiveReliableData".
const MIOP_GIOP12_REQUEST_LE_FRAME_HEX: &str = concat!(
    "000000000000000000000000080045000120000040004011ecb30a5f1c2e0a5f",
    "1c2e86ad3e70010c4e374d494f501003e40000000000010000000c0000000000",
    "0000000000000000000047494f5001020100d800000000000000000000000100",
    "00000300000048000000010100000c00000031302e39352e32382e343600703e",
    "00000100000027000000240000000101000009000000436f6e73756d65720000",
    "000000000000010000000000000000000000140000007265636569766552656c",
    "6961626c654461746100000000000000000031320000c80000000000000058e1",
    "8f49a86e01004000000041414141414141414141414141414141414141414141",
    "4141414141414141414141414141414141414141414141414141414141414141",
    "4141414141414141414100000000"
);

/// En-tetes L2-L4 de la trame 4/6 : Ethernet (14) + IPv4 (20) + TCP avec
/// options timestamp (32) = 66 octets avant le message GIOP.
const TCP_GIOP_OFFSET: usize = 66;

/// En-tetes de la trame 19 : Ethernet (14) + IPv4 (20) + UDP (8) + header
/// MIOP PacketHeader_1_0 (32) = 74 octets avant le message GIOP.
const MIOP_GIOP_OFFSET: usize = 74;

fn frame(hex_fixture: &str, expected_len: usize) -> Vec<u8> {
    let bytes = hex::decode(hex_fixture).expect("invalid test hex fixture");
    assert_eq!(
        bytes.len(),
        expected_len,
        "fixture length must match capture"
    );
    bytes
}

#[test]
fn packet_flow_labels_giop_request_over_tcp() {
    let bytes = frame(GIOP12_REQUEST_ECHO_FRAME_HEX, 294);
    let flow = parse(LinkType::ETHERNET, bytes.as_slice()).expect("captured frame decodes");

    assert_eq!(
        flow.application
            .expect("an application layer is detected")
            .application_protocol,
        "GIOP"
    );
}

#[test]
fn packet_flow_labels_giop_reply_over_tcp() {
    let bytes = frame(GIOP12_REPLY_FRAME_HEX, 159);
    let flow = parse(LinkType::ETHERNET, bytes.as_slice()).expect("captured frame decodes");

    assert_eq!(
        flow.application
            .expect("an application layer is detected")
            .application_protocol,
        "GIOP"
    );
}

#[test]
fn giop_1_2_request_big_endian_decodes_against_tshark() {
    let bytes = frame(GIOP12_REQUEST_ECHO_FRAME_HEX, 294);
    let packet =
        GiopPacket::try_from(&bytes[TCP_GIOP_OFFSET..]).expect("captured GIOP message decodes");

    // Header, champ a champ contre tshark.
    assert_eq!(&packet.header.magic, b"GIOP");
    assert_eq!(packet.header.major_version, 1);
    assert_eq!(packet.header.minor_version, 2);
    assert_eq!(packet.header.flags, 0x00, "big-endian, pas de fragment");
    assert!(matches!(
        packet.header.message_type,
        GiopMessageType::Request
    ));
    assert_eq!(packet.header.message_length, 216);

    let GiopMessage::Request(request) = packet.payload else {
        panic!("a Request body is dispatched and decoded");
    };
    assert_eq!(request.request_id, 0);
    // Response flags 3 : SyncScope WITH_TARGET.
    assert_eq!(request.response_flags, 3);
    let TargetAddress::KeyAddr(key) = request.target else {
        panic!("tshark reports TargetAddress: KeyAddr (0)");
    };
    assert_eq!(key.len(), 60, "tshark: Key Address Length: 60");
    let poa = b"My_Compress_Poa";
    assert!(
        key.windows(poa.len()).any(|w| w == poa),
        "the object key names the POA"
    );
    assert_eq!(request.operation, "echo");
    assert_eq!(request.service_contexts.len(), 1);
    // 0x07 : INVOCATION_POLICIES, 40 octets de contexte.
    assert_eq!(request.service_contexts[0].context_id, 7);
    assert_eq!(request.service_contexts[0].context_data.len(), 40);
    // Stub data : 76 octets d'arguments CDR, comme le champ tshark
    // "Stub data" (commence a 00 00 00 41).
    assert_eq!(request.stub_data.len(), 76);
    assert_eq!(&request.stub_data[..4], &[0x00, 0x00, 0x00, 0x41]);
}

#[test]
fn giop_1_2_reply_header_decodes_against_tshark() {
    let bytes = frame(GIOP12_REPLY_FRAME_HEX, 159);
    let packet =
        GiopPacket::try_from(&bytes[TCP_GIOP_OFFSET..]).expect("captured GIOP message decodes");

    assert_eq!(&packet.header.magic, b"GIOP");
    assert_eq!(packet.header.major_version, 1);
    assert_eq!(packet.header.minor_version, 2);
    assert_eq!(packet.header.flags, 0x00);
    assert!(matches!(packet.header.message_type, GiopMessageType::Reply));
    assert_eq!(packet.header.message_length, 81);
    // Le body Reply n'est pas encore decode (epic #76) : la variante Reply
    // atteste seulement du dispatch.
    assert!(matches!(packet.payload, GiopMessage::Reply(_)));
}

#[test]
fn giop_1_2_little_endian_request_over_miop_decodes_against_tshark() {
    let bytes = frame(MIOP_GIOP12_REQUEST_LE_FRAME_HEX, 302);
    // MIOP est de l'UDP multicast : le dispatch applicatif ne sonde GIOP que
    // sur TCP, le message est donc atteste ici au niveau GiopPacket, sur la
    // portion GIOP du datagramme.
    let packet =
        GiopPacket::try_from(&bytes[MIOP_GIOP_OFFSET..]).expect("captured GIOP message decodes");

    assert_eq!(&packet.header.magic, b"GIOP");
    assert_eq!(packet.header.major_version, 1);
    assert_eq!(packet.header.minor_version, 2);
    // Flags 0x01 : message little-endian. Le message_size sur le wire est
    // d8 00 00 00 : une lecture big-endian annoncerait ~3,6 Go et rejetterait
    // la trame en TruncatedBody.
    assert_eq!(packet.header.flags, 0x01);
    assert!(matches!(
        packet.header.message_type,
        GiopMessageType::Request
    ));
    assert_eq!(packet.header.message_length, 216);

    let GiopMessage::Request(request) = packet.payload else {
        panic!("a Request body is dispatched and decoded");
    };
    assert_eq!(request.request_id, 0);
    assert_eq!(request.response_flags, 0, "SyncScope NONE : multicast");
    // tshark : TargetAddress ProfileAddr (1), TaggedProfile TAG_UIPMC (3),
    // profile_data de 72 octets qui porte le groupe multicast.
    let TargetAddress::ProfileAddr(profile) = request.target else {
        panic!("tshark reports TargetAddress: ProfileAddr (1)");
    };
    assert_eq!(profile.len(), 72);
    let group = b"10.95.28.46";
    assert!(
        profile.windows(group.len()).any(|w| w == group),
        "the UIPMC profile carries the multicast group address"
    );
    assert_eq!(request.operation, "receiveReliableData");
    assert!(request.service_contexts.is_empty());
    // Le reste du body (96 octets) est le stub data CDR, padding d'alignement
    // sur 8 compris.
    assert_eq!(request.stub_data.len(), 96);
}
