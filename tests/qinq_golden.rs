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
//! signal. Desormais la pile est consommee entiere et `vlan` retient le tag
//! interne. Depuis #172, la session PPPoE qui suit est pelee a son tour :
//! `ethertype` est celui du paquet que PPP porte, ici IPv4, `pppoe` garde la
//! session, et la couche internet decode TCP et TLS — sauf sur six trames
//! dont la longueur PPPoE ne couvre pas le paquet IPv4.

use std::path::Path;

use packet_parser::parse::data_link::DataLink;
use packet_parser::parse::data_link::vlan_tag::{TPID_8021Q, VlanTag};
use packet_parser::parse::transport::protocols::TransportProtocol;
use packet_parser::parse::{CorruptedLayer, CorruptedLayerKind};
use packet_parser::{LinkType, parse};

mod common;
use common::{FileRead, read_capture};

const CAPTURE: &str = "pcaps_exemple/vlan/pppoe-over-qinq.pcap";

/// Trame 1 (94 octets) : 00:00:00:00:00:00 -> 00:00:00:00:00:01, tag externe
/// 0x8100 VID 3704 (TCI 0x0e78), tag interne 0x8100 VID 2474 (TCI 0x09aa),
/// PPPoE session 0x8864 (version 1, type 1, code 0, session 0x0f07,
/// longueur 66), PPP IPv4 0x0021, TCP 1.1.1.1:20394 -> 2.2.2.2:443 SYN.
const FRAME_1_HEX: &str = concat!(
    "00000000000100000000000081000e78810009aa886411000f07004200214500",
    "0040000040003f0635b301010101020202024faa01bbd7a8415500000000b002",
    "ffffeced0000020405a0010303060101080a012dd88c0000000004020000"
);

/// Offset de la charge utile apres deux tags (14 + 2 x 4), l'en-tete PPPoE
/// (6) et le protocole PPP (2).
const PAYLOAD_OFFSET: usize = 30;

/// Six acquittements TCP de 76 octets dont la longueur PPPoE (42) ne couvre
/// pas le paquet IPv4 : 46 octets jusqu'a la fin de la trame, six octets
/// nuls compris, sur lesquels les sommes de controle IP et TCP sont
/// valides. Comme tshark (« Possible bad payload length 42 !=
/// 48 », « IPv4 total length exceeds packet length (40 bytes) ») et le noyau
/// Linux (`pppoe_rcv` coupe la trame a la longueur PPPoE), la crate borne le
/// paquet par la longueur PPPoE, et la couche internet le signale corrompu.
const PPPOE_LENGTH_SHORTER_THAN_IPV4: &[usize] = &[19, 33, 41, 47, 63, 81];

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
    // La session PPPoE (#172) : 0x0f07, 66 octets, PPP IPv4.
    let session = frame.pppoe.expect("session PPPoE pelee");
    assert_eq!(
        (session.session_id, session.length, session.ppp_protocol),
        (0x0f07, 66, 0x0021)
    );
    assert_eq!(frame.ethertype.name(), "IPv4");
    // Le paquet IPv4 : 66 - 2 octets, jusqu'a la fin de la trame.
    assert_eq!(frame.payload, &bytes[PAYLOAD_OFFSET..]);
    assert_eq!(frame.payload.len(), 64);
    assert_eq!(frame.payload[0], 0x45);

    // Pile complete (#82), du tag externe au tag interne. tshark :
    // vlan.id 3704,2474 — vlan.etype 0x8100,0x8864.
    assert_eq!(frame.vlan_stack.len(), 2);
    let stack: Vec<VlanTag> = frame.vlan_stack.iter().collect();
    assert_eq!(stack[0].id, 3704, "tag externe (S-VLAN)");
    assert_eq!(
        stack[0].inner_ethertype.0, TPID_8021Q,
        "annonce un second tag"
    );
    assert_eq!(stack[1].id, 2474, "tag interne (C-VLAN)");
    assert_eq!(stack[1].inner_ethertype.0, 0x8864);
    assert_eq!(frame.vlan_stack.outer().map(|tag| tag.id), Some(3704));
    assert_eq!(frame.vlan_stack.inner(), Some(vlan));
    // Zero copie : la pile est une vue sur les octets de tags de la trame.
    assert_eq!(
        std::mem::size_of_val(&frame.vlan_stack),
        2 * std::mem::size_of::<usize>()
    );
}

#[test]
fn every_frame_of_the_capture_reports_the_inner_vlan_and_the_pppoe_session() {
    let frames = capture_frames();
    assert_eq!(frames.len(), 86, "{CAPTURE} compte 86 trames");

    let mut truncated = 0;
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
            link["link_details"]["ethertype"], "IPv4",
            "trame {number} : EtherType du paquet que PPP porte"
        );
        // La pile complete est serialisee (deux tags), externe d'abord, et le
        // modele owned rend exactement le meme JSON.
        let stack = serde_json::json!([
            { "id": 3704, "pcp": 0, "dei": false },
            { "id": 2474, "pcp": 0, "dei": false },
        ]);
        assert_eq!(link["link_details"]["vlan_stack"], stack, "trame {number}");
        let owned = serde_json::to_value(&flow.to_owned_flow().data_link).expect("serialisable");
        assert_eq!(owned["link_details"]["vlan_stack"], stack, "trame {number}");
        // PPPoE est pele (#172) : IPv4 puis TCP, sans erreur.
        let session = flow
            .data_link
            .as_ethernet()
            .and_then(|ethernet| ethernet.pppoe)
            .unwrap_or_else(|| panic!("trame {number} : session PPPoE"));
        assert_eq!(session.session_id, 0x0f07, "trame {number}");
        if PPPOE_LENGTH_SHORTER_THAN_IPV4.contains(&number) {
            assert_eq!((data.len(), session.length), (76, 42), "trame {number}");
            assert_eq!(
                flow.corrupted,
                Some(CorruptedLayer {
                    layer: CorruptedLayerKind::Internet,
                    error: "IPv4 error: Invalid total length: expected 46 bytes \
                            (header: 20 + data: 26), but got 40 bytes"
                        .to_string(),
                }),
                "trame {number}"
            );
            assert!(flow.internet.is_none(), "trame {number}");
            truncated += 1;
            continue;
        }
        assert!(
            flow.corrupted.is_none(),
            "trame {number} : {:?}",
            flow.corrupted
        );
        assert!(flow.internet.is_some(), "trame {number} : IPv4");
        assert!(
            matches!(
                flow.transport.as_ref().map(|transport| transport.protocol),
                Some(TransportProtocol::Tcp)
            ),
            "trame {number} : TCP"
        );
    }
    assert_eq!(truncated, PPPOE_LENGTH_SHORTER_THAN_IPV4.len());
}
