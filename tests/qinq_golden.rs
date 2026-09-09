// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests QinQ (tags VLAN empiles) sur trames reelles, issue #82.
//!
//! Capture : `pcaps_exemple/vlan/pppoe-over-qinq.pcap` (provenance dans le
//! `SOURCE.md` voisin), 86 trames en double tag 802.1Q — externe 3704,
//! interne 2474 — devant du PPPoE session (0x8864).
//!
//! Avant #82, le parseur ne consommait que le premier tag : `vlan` valait
//! 3704, `ethertype` « VLAN-tagged frame » et la couche 3 etait perdue sans
//! signal. Desormais la pile est consommee entiere, `vlan` retient le tag
//! interne et `ethertype` la vraie charge, ici PPPoE. PPPoE n'est pas
//! decode : `internet` reste `None`, et ce test le fige pour que le jour ou
//! il le sera, l'attendu soit mis a jour sciemment.

use std::path::Path;

use packet_parser::parse::data_link::DataLink;
use packet_parser::parse::data_link::vlan_tag::{TPID_8021Q, VlanTag};
use packet_parser::{LinkType, parse};

mod common;
use common::{FileRead, read_capture};

const CAPTURE: &str = "pcaps_exemple/vlan/pppoe-over-qinq.pcap";

/// Trame 1 (94 octets) : 00:00:00:00:00:00 -> 00:00:00:00:00:01, tag externe
/// 0x8100 VID 3704 (TCI 0x0e78), tag interne 0x8100 VID 2474 (TCI 0x09aa),
/// PPPoE session 0x8864 (version 1, type 1, code 0, session 0x0f07,
/// longueur 66), PPP IPv4 0x0021, TCP 1.1.1.1:1019 -> 2.2.2.2:443 SYN.
const FRAME_1_HEX: &str = concat!(
    "00000000000100000000000081000e78810009aa886411000f07004200214500",
    "0040000040003f0635b301010101020202024faa01bbd7a8415500000000b002",
    "ffffeced0000020405a0010303060101080a012dd88c0000000004020000"
);

/// Offset de la charge utile apres deux tags : 14 + 2 x 4.
const PAYLOAD_OFFSET: usize = 22;

fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex valide"))
        .collect()
}

fn capture_frames() -> Vec<(LinkType, Vec<u8>)> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(CAPTURE);
    let FileRead::Frames {
        frames,
        read_error_after,
    } = read_capture(path.as_path())
    else {
        panic!("{CAPTURE} illisible");
    };
    assert_eq!(read_error_after, None, "lecture complete de {CAPTURE}");
    frames
}

#[test]
fn frame_1_stacked_tags_are_consumed_and_inner_tag_is_kept() {
    let bytes = unhex(FRAME_1_HEX);
    assert_eq!(bytes.len(), 94);
    assert_eq!(u16::from_be_bytes([bytes[12], bytes[13]]), TPID_8021Q);
    assert!(VlanTag::is_tpid(u16::from_be_bytes([bytes[16], bytes[17]])));

    let frame = DataLink::try_from(bytes.as_slice()).expect("trame QinQ decodee");

    let vlan = frame.vlan.expect("tag interne conserve");
    assert_eq!(vlan.id, 2474);
    assert_eq!(vlan.pcp, 0);
    assert!(!vlan.dei);
    assert_eq!(vlan.inner_ethertype.name(), "Pppoe Session Stage");
    assert_eq!(frame.ethertype.name(), "Pppoe Session Stage");
    assert_eq!(frame.payload, &bytes[PAYLOAD_OFFSET..]);
    // Debut PPPoE : version/type 0x11, code 0x00, session 0x0f07.
    assert_eq!(&frame.payload[..4], &[0x11, 0x00, 0x0f, 0x07]);
}

#[test]
fn every_frame_of_the_capture_reports_the_inner_vlan_and_pppoe() {
    let frames = capture_frames();
    assert_eq!(frames.len(), 86, "{CAPTURE} compte 86 trames");

    for (index, (link_type, data)) in frames.iter().enumerate() {
        let number = index + 1;
        assert_eq!(*link_type, LinkType::ETHERNET, "trame {number}");

        let flow =
            parse(*link_type, data).unwrap_or_else(|error| panic!("trame {number} : {error}"));
        let link = serde_json::to_value(&flow.data_link).expect("serialisable");

        assert_eq!(
            link["link_details"]["vlan"],
            serde_json::json!({ "id": 2474, "pcp": 0, "dei": false }),
            "trame {number} : tag interne"
        );
        assert_eq!(
            link["link_details"]["ethertype"], "Pppoe Session Stage",
            "trame {number} : EtherType reel"
        );
        // PPPoE n'est pas decode : pas de couche 3, sans erreur.
        assert!(flow.internet.is_none(), "trame {number} : PPPoE non decode");
    }
}
