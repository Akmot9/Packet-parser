// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests Spanning Tree sur trames reelles.
//!
//! Captures :
//! - `pcaps_exemple/The-Ultimate-PCAP.pcapng` (`tshark -Y stp` : 2612
//!   trames, dont 407 en LLC 42-42-03 — toutes des RST BPDU version 2 ;
//!   les 2205 autres sont du PVST+ en SNAP). Numeros de trame notes sur
//!   chaque fixture, hex complet extrait via `tshark -T jsonraw`.
//! - `pcaps_exemple/vlan0--packet-capture CAPWAP a partir de ligne 520
//!   (Ap = 192_168.0.104 ) + radius _ partir de la ligne 33003 .cap` pour
//!   le Configuration BPDU STP classique (version 0, type 0x00), absent en
//!   LLC du corpus Ultimate.
//!
//! Les BPDU circulent en trames 802.3 : champ longueur <= 0x05DC apres les
//! MAC, puis LLC DSAP/SSAP 0x42 controle 0x03. `BpduPacket::try_from` est
//! appele sur les octets APRES l'en-tete LLC, soit l'offset 17 (14 octets
//! Ethernet + 3 octets LLC). Le pipeline `PacketFlow` actuel ne route pas
//! ces trames : un test verrouille ce comportement en attendant le cablage.

use packet_parser::parse::data_link::mac_addres::MacAddress;
use packet_parser::parse::data_link::stp::{
    BpduBody, BpduPacket, BpduType, StpVersion, is_stp_frame, stp_llc_payload,
};
use packet_parser::{LinkType, parse};

/// Offset de la slice BPDU dans une trame Ethernet 802.3 : 14 (Ethernet)
/// + 3 (LLC 42-42-03).
const BPDU_OFFSET: usize = 17;

/// Trame 2173 : RST BPDU vers 01:80:c2:00:00:00, LLC 42-42-03, emis par
/// 00:0a:8a:a1:5a:9a, root 32768/1/00:0a:8a:a1:5a:80, port 0x8042
/// (pcaps_exemple/The-Ultimate-PCAP.pcapng). Longueur 802.3 : 0x0027 = 39
/// = 3 LLC + 36 BPDU, sans bourrage (trame de 53 octets).
const RST_FRAME_2173_HEX: &str = concat!(
    "0180c2000000000a8aa15a9a0027424203000002023c8001000a8aa15a800000",
    "00008001000a8aa15a8080420000140002000f0000"
);

/// Trame 24182 : RST BPDU encapsule dans un mPacket IEEE 802.3br (SMD-E) —
/// preambule 0x55 x7 + 0xd5, trame Ethernet, 7 octets de bourrage, mCRC
/// (pcaps_exemple/The-Ultimate-PCAP.pcapng). Emis par 00:16:47:df:e7:84,
/// root 32768/9/00:16:47:df:e7:80, port 0x8004.
const RST_MPACKET_24182_HEX: &str = concat!(
    "55555555555555d50180c2000000001647dfe7840027424203000002023c8009",
    "001647dfe780000000008009001647dfe78080040000140002000f0000000000",
    "00000000fb9dd0ba"
);

/// Trame 15 : Configuration BPDU STP classique (version 0, type 0x00) emis
/// par fc:fb:fb:f8:cc:01, root 32768/10/fc:fb:fb:f8:cc:00, port 0x8001
/// (pcaps_exemple/vlan0--packet-capture CAPWAP a partir de ligne 520
/// (Ap = 192_168.0.104 ) + radius _ partir de la ligne 33003 .cap).
/// Longueur 802.3 : 0x0026 = 38 = 3 LLC + 35 BPDU, puis 8 octets de
/// bourrage jusqu'au minimum Ethernet de 60 octets.
const CONFIG_FRAME_15_HEX: &str = concat!(
    "0180c2000000fcfbfbf8cc0100264242030000000000800afcfbfbf8cc000000",
    "0000800afcfbfbf8cc0080010000140002000f000000000000000000"
);

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
fn captured_rst_bpdu_decodes_after_the_llc_header() {
    let bytes = frame(RST_FRAME_2173_HEX, 53);

    let bpdu = BpduPacket::try_from(&bytes[BPDU_OFFSET..]).expect("captured RST BPDU decodes");

    assert_eq!(bpdu.protocol_identifier, 0x0000);
    assert_eq!(bpdu.version, StpVersion::Rstp);
    assert_eq!(bpdu.bpdu_type, BpduType::RapidSpanningTree);

    let BpduBody::Configuration(body) = bpdu.body else {
        panic!("RST BPDU exposes a configuration body");
    };
    // Flags 0x3c : forwarding, learning, port designated.
    assert_eq!(body.flags, 0x3c);
    assert_eq!(body.root_identifier.priority(), 32768);
    assert_eq!(body.root_identifier.system_id_extension(), 1);
    assert_eq!(
        body.root_identifier.mac,
        MacAddress([0x00, 0x0a, 0x8a, 0xa1, 0x5a, 0x80])
    );
    assert_eq!(body.root_path_cost, 0);
    assert_eq!(body.bridge_identifier, body.root_identifier);
    assert_eq!(body.port_identifier, 0x8042);
    // Ages et delais en 1/256 s : 20 s, 2 s, 15 s.
    assert_eq!(body.message_age, 0);
    assert_eq!(body.max_age, 20 * 256);
    assert_eq!(body.hello_time, 2 * 256);
    assert_eq!(body.forward_delay, 15 * 256);
    assert_eq!(body.version_1_length, Some(0));
    assert_eq!(body.mst_extension, None);
}

#[test]
fn captured_rst_frame_is_detected_and_delimited() {
    let bytes = frame(RST_FRAME_2173_HEX, 53);

    assert!(is_stp_frame(&bytes));
    // Longueur 802.3 0x0027 : la slice s'arrete a 14 + 39 = 53.
    assert_eq!(stp_llc_payload(&bytes), Some(&bytes[BPDU_OFFSET..53]));
}

#[test]
fn captured_rst_bpdu_inside_a_mpacket_decodes() {
    let bytes = frame(RST_MPACKET_24182_HEX, 72);

    // Enveloppe 802.3br : 8 octets de preambule + SMD avant la trame
    // Ethernet, 4 octets de mCRC en queue. La trame Ethernet interne va
    // donc de 8 a 68, et la slice BPDU commence a 8 + 17 = 25.
    let ethernet_frame = &bytes[8..bytes.len() - 4];

    // La detection retire le bourrage grace au champ longueur 802.3
    // (0x0027 : la slice s'arrete a 17 + 36 = 53 dans la trame interne).
    let payload = stp_llc_payload(ethernet_frame).expect("BPDU detected inside the mPacket");
    assert_eq!(payload, &ethernet_frame[BPDU_OFFSET..BPDU_OFFSET + 36]);

    let bpdu = BpduPacket::try_from(payload).expect("captured RST BPDU decodes");
    assert_eq!(bpdu.version, StpVersion::Rstp);

    let BpduBody::Configuration(body) = bpdu.body else {
        panic!("RST BPDU exposes a configuration body");
    };
    assert_eq!(body.root_identifier.priority(), 32768);
    assert_eq!(body.root_identifier.system_id_extension(), 9);
    assert_eq!(
        body.root_identifier.mac,
        MacAddress([0x00, 0x16, 0x47, 0xdf, 0xe7, 0x80])
    );
    assert_eq!(body.port_identifier, 0x8004);
}

#[test]
fn captured_configuration_bpdu_decodes_with_its_ethernet_padding() {
    let bytes = frame(CONFIG_FRAME_15_HEX, 60);

    // Les octets apres l'en-tete LLC incluent 8 octets de bourrage
    // Ethernet ; le parseur les tolere.
    let bpdu = BpduPacket::try_from(&bytes[BPDU_OFFSET..]).expect("captured config BPDU decodes");

    assert_eq!(bpdu.version, StpVersion::Stp);
    assert_eq!(bpdu.bpdu_type, BpduType::Configuration);

    let BpduBody::Configuration(body) = bpdu.body else {
        panic!("configuration BPDU exposes a configuration body");
    };
    assert_eq!(body.flags, 0x00);
    assert_eq!(body.root_identifier.priority(), 32768);
    assert_eq!(body.root_identifier.system_id_extension(), 10);
    assert_eq!(
        body.root_identifier.mac,
        MacAddress([0xfc, 0xfb, 0xfb, 0xf8, 0xcc, 0x00])
    );
    assert_eq!(body.bridge_identifier, body.root_identifier);
    assert_eq!(body.port_identifier, 0x8001);
    assert_eq!(body.max_age, 20 * 256);
    assert_eq!(body.hello_time, 2 * 256);
    assert_eq!(body.forward_delay, 15 * 256);
    // Configuration BPDU version 0 : pas de version 1 length ni de MST.
    assert_eq!(body.version_1_length, None);
    assert_eq!(body.mst_extension, None);

    // La detection exclut le bourrage : longueur 802.3 0x0026, la slice
    // s'arrete a 14 + 38 = 52.
    assert_eq!(stp_llc_payload(&bytes), Some(&bytes[BPDU_OFFSET..52]));
}

/// Verrouille le constat d'architecture : le pipeline actuel lit le champ
/// longueur 802.3 comme un EtherType inconnu et ne route pas les trames
/// LLC. La trame reste decodable au niveau Ethernet, sans L3/L4 ni couche
/// corrompue, et le cablage STP (issue #4) etiquette desormais le flux.
#[test]
fn packet_flow_labels_llc_bpdu_frames_as_stp() {
    let bytes = frame(RST_FRAME_2173_HEX, 53);

    let flow = parse(LinkType::ETHERNET, bytes.as_slice()).expect("frame decodes as Ethernet");

    let ethernet = flow.data_link.as_ethernet().expect("Ethernet view");
    // Le champ longueur 802.3 (39 octets) est expose comme un EtherType.
    assert_eq!(ethernet.ethertype.0, 0x0027);
    // Le payload Ethernet commence a l'en-tete LLC.
    assert_eq!(ethernet.payload, &bytes[14..]);

    assert!(flow.internet.is_none());
    assert!(flow.transport.is_none());
    assert!(flow.corrupted.is_none());
    assert_eq!(
        flow.application
            .as_ref()
            .map(|application| application.application_protocol),
        Some("STP"),
        "un BPDU en LLC 42-42-03 est etiquete STP"
    );
}
