// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden test PPPoE (#172) sur `pcaps_exemple/The-Ultimate-PCAP.pcapng`, lue
//! en place : 6 795 trames passent par cinq sessions PPPoE (0x001e, 0x8f9e,
//! 0xe579, 0x1f3d, 0x8f80) entre quatre paires d'adresses MAC, toutes sous
//! VLAN 7 — RTP et SIP, DHCPv6, IPv4 dans IPv6, LCP, IPCP et IPv6CP.
//!
//! L'oracle est tshark 4.6.6 (`tools/pppoe_oracle.sh`) : pour chaque trame
//! de session, l'identifiant de session, la longueur PPPoE, le protocole
//! PPP, le protocole qui suit le premier en-tete IP et les ports UDP ou TCP,
//! figes dans `tests/data/pppoe_tshark_oracle.tsv` et compares ici trame par
//! trame.

use std::{collections::BTreeMap, fs, path::Path};

use packet_parser::{PacketFlow, parse, parse::transport::protocols::TransportProtocol};

mod common;
use common::{FileRead, read_capture};

const CAPTURE: &str = "pcaps_exemple/The-Ultimate-PCAP.pcapng";
const ORACLE: &str = "tests/data/pppoe_tshark_oracle.tsv";

/// Premiers fragments IPv4 : tshark lit l'en-tete UDP du premier fragment, la
/// crate ne decode pas de transport dans un fragment. Trame 15114 : le
/// premier des deux fragments d'un datagramme SIP de 2 017 octets
/// (UDP 5060).
const IP_FIRST_FRAGMENTS: &[usize] = &[15114];

fn read_oracle(path: &Path) -> BTreeMap<usize, Vec<String>> {
    let oracle = fs::read_to_string(path).expect("oracle lisible");
    oracle
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| {
            let fields: Vec<String> = line.split('\t').map(ToString::to_string).collect();
            assert_eq!(fields.len(), 7, "ligne d'oracle malformee : {line}");
            (
                fields[0].parse().expect("numero de trame"),
                fields[1..].to_vec(),
            )
        })
        .collect()
}

/// Le protocole qui suit le premier en-tete IP, comme le nomme tshark, et
/// les ports du premier transport UDP ou TCP de la trame.
fn after_ip(flow: &PacketFlow<'_>) -> (String, String, String) {
    let dash = || "-".to_string();
    let ports = |transport: &packet_parser::parse::transport::Transport<'_>| {
        (
            transport.source_port.map_or_else(dash, |p| p.to_string()),
            transport
                .destination_port
                .map_or_else(dash, |p| p.to_string()),
        )
    };
    let Some(transport) = flow.transport.as_ref() else {
        let next = if flow.internet.is_some() { "data" } else { "-" };
        return (next.to_string(), dash(), dash());
    };
    match transport.protocol {
        TransportProtocol::Udp => {
            let (source, destination) = ports(transport);
            ("udp".to_string(), source, destination)
        }
        TransportProtocol::Tcp => {
            let (source, destination) = ports(transport);
            ("tcp".to_string(), source, destination)
        }
        TransportProtocol::Icmp => ("icmp".to_string(), dash(), dash()),
        TransportProtocol::Ipv6Icmp => ("icmpv6".to_string(), dash(), dash()),
        // IPv4 dans IPv6 : les ports sont ceux du paquet interne.
        TransportProtocol::Ipv4 => {
            let (source, destination) = flow
                .inner
                .as_deref()
                .and_then(|inner| inner.transport.as_ref())
                .map_or_else(|| (dash(), dash()), ports);
            ("ip".to_string(), source, destination)
        }
        _ => ("data".to_string(), dash(), dash()),
    }
}

/// Parite avec tshark : la couche liaison pele la session PPPoE exactement
/// sur les trames que tshark decode en `pppoes`, avec la meme session, la
/// meme longueur et le meme protocole PPP, et la couche internet decode ce
/// que PPP porte jusqu'au transport.
#[test]
fn every_pppoe_session_frame_matches_the_tshark_oracle() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let oracle = read_oracle(&base.join(ORACLE));
    assert_eq!(oracle.len(), 6_795);
    let FileRead::Frames { frames, .. } = read_capture(&base.join(CAPTURE)) else {
        panic!("capture illisible");
    };

    let mut sessions = 0;
    let mut fragments = 0;
    let mut by_ppp_protocol: BTreeMap<u16, usize> = BTreeMap::new();
    let mut by_next: BTreeMap<String, usize> = BTreeMap::new();
    for (index, (link_type, data)) in frames.iter().enumerate() {
        let number = index + 1;
        let Ok(flow) = parse(*link_type, data) else {
            assert!(!oracle.contains_key(&number), "trame {number} : illisible");
            continue;
        };
        let pppoe = flow
            .data_link
            .as_ethernet()
            .and_then(|ethernet| ethernet.pppoe);
        let Some(row) = oracle.get(&number) else {
            assert!(
                pppoe.is_none(),
                "trame {number} : PPPoE pour la crate seule"
            );
            continue;
        };
        let session = pppoe.unwrap_or_else(|| panic!("trame {number} : session PPPoE non pelee"));
        assert!(
            flow.corrupted.is_none(),
            "trame {number} : {:?}",
            flow.corrupted
        );
        let (mut next, mut source, mut destination) = after_ip(&flow);
        if IP_FIRST_FRAGMENTS.contains(&number) {
            assert_eq!(next, "data", "trame {number} : fragment");
            (next, source, destination) = (row[3].clone(), row[4].clone(), row[5].clone());
            fragments += 1;
        }
        assert_eq!(
            [
                format!("{:#06x}", session.session_id),
                session.length.to_string(),
                format!("{:#06x}", session.ppp_protocol),
                next.clone(),
                source,
                destination,
            ]
            .as_slice(),
            row.as_slice(),
            "trame {number} : ecart avec tshark"
        );
        *by_ppp_protocol.entry(session.ppp_protocol).or_default() += 1;
        *by_next.entry(next).or_default() += 1;
        sessions += 1;
    }

    assert_eq!(sessions, 6_795);
    assert_eq!(fragments, IP_FIRST_FRAGMENTS.len());
    // IPv4, IPv6, LCP, IPCP, IPv6CP.
    assert_eq!(
        by_ppp_protocol,
        BTreeMap::from([
            (0x0021, 6_486),
            (0x0057, 274),
            (0x8021, 5),
            (0x8057, 4),
            (0xc021, 26)
        ])
    );
    assert_eq!(
        by_next,
        BTreeMap::from([
            ("-".to_string(), 35),
            ("data".to_string(), 1),
            ("icmp".to_string(), 2),
            ("ip".to_string(), 78),
            ("udp".to_string(), 6_679),
        ])
    );
}
