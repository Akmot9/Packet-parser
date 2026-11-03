// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden test Valmet DNA sur trames reelles.
//!
//! Capture : `pcaps_exemple/protocols/valmet_dna/valmet-dna-multicast-anon.pcap`
//! (voir son `SOURCE.md`) — douze secondes du reseau de process d'un systeme
//! Metso/Valmet DNA, 720 datagrammes multicast : 319 telegrammes d'etat de
//! 17 noeuds, 400 messages a etiquette et une balise, anonymises (MAC, IP,
//! etiquettes et horloges reecrites, le reste octet pour octet).
//!
//! tshark n'a pas de dissecteur pour ce protocole proprietaire : pas
//! d'oracle TSV. La structure est verifiee contre ce que la capture porte
//! par ailleurs — l'adresse du noeud dans la charge est la source IP, le
//! groupe la destination IP, le numero du noeud l'octet bas de son
//! identifiant, l'horloge croit de 640 ms d'un telegramme au suivant pour
//! chaque noeud, le compteur « precedent » est le compteur courant du
//! telegramme d'avant — et les comptes (familles, noeuds, classes,
//! longueurs d'etiquette) sont figes.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr},
    path::Path,
};

use packet_parser::{
    DecodeAsProtocol, LinkType, PacketFlow, ParseConfig, parse,
    parse::application::protocols::valmet_dna::{
        MessageKind, TimeBeacon, ValmetDnaMessage, ValmetDnaPacket,
    },
    parse::transport::protocols::TransportProtocol,
    parse_with,
};

mod common;
use common::{FileRead, read_capture};

const CAPTURE: &str = "pcaps_exemple/protocols/valmet_dna/valmet-dna-multicast-anon.pcap";

/// Les 17 noeuds de la capture, par identifiant.
const NODES: [u16; 17] = [
    0x8008, 0x800A, 0x800B, 0x800C, 0x800D, 0x8015, 0x8016, 0x8017, 0x801B, 0x801C, 0x801D, 0x8028,
    0x8029, 0x802A, 0x802B, 0x802C, 0x802D,
];

fn label(flow: &PacketFlow<'_>) -> Option<&'static str> {
    flow.application
        .as_ref()
        .map(|application| application.application_protocol)
}

fn frames() -> Vec<(LinkType, Vec<u8>)> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(CAPTURE);
    let FileRead::Frames {
        frames,
        read_error_after,
    } = read_capture(&path)
    else {
        panic!("{CAPTURE} : capture illisible");
    };
    assert_eq!(read_error_after, None);
    assert_eq!(frames.len(), 720);
    frames
}

fn ipv4(address: Option<IpAddr>) -> Ipv4Addr {
    match address {
        Some(IpAddr::V4(address)) => address,
        other => panic!("adresse IPv4 attendue, {other:?}"),
    }
}

/// Chaque datagramme est etiquete Valmet DNA, se decode, et ses champs
/// recoupent l'en-tete IP et les telegrammes voisins.
#[test]
fn every_datagram_is_valmet_dna_and_consistent_with_its_ip_header() {
    let group = Ipv4Addr::new(239, 0, 171, 1);
    let mut status_count = 0;
    let mut tag_count = 0;
    let mut beacon_count = 0;
    let mut telegrams_per_node: BTreeMap<u16, usize> = BTreeMap::new();
    let mut node_ips: BTreeMap<u16, Ipv4Addr> = BTreeMap::new();
    let mut last_clock: BTreeMap<u16, u64> = BTreeMap::new();
    let mut last_tick: BTreeMap<u16, u32> = BTreeMap::new();
    let mut classes: BTreeMap<String, usize> = BTreeMap::new();
    let mut tag_lengths: BTreeSet<u16> = BTreeSet::new();
    let mut tag_nodes: BTreeSet<u16> = BTreeSet::new();
    let mut binary_tags = 0;

    for (index, (link_type, data)) in frames().iter().enumerate() {
        let number = index + 1;
        let flow =
            parse(*link_type, data).unwrap_or_else(|error| panic!("trame {number} : {error:?}"));
        assert_eq!(label(&flow), Some("Valmet DNA"), "trame {number}");
        let internet = flow.internet.as_ref().expect("couche IP");
        let source = ipv4(internet.source);
        assert_eq!(ipv4(internet.destination), group, "trame {number}");
        let transport = flow.transport.as_ref().expect("couche UDP");
        assert!(matches!(transport.protocol, TransportProtocol::Udp));
        let payload = transport.payload.expect("charge UDP");

        match (transport.source_port, transport.destination_port) {
            (Some(2517), Some(2517)) => {
                let packet = ValmetDnaPacket::try_from(payload)
                    .unwrap_or_else(|error| panic!("trame {number} : {error}"));
                assert_eq!(usize::from(packet.length) + 2, payload.len());
                assert_eq!(packet.source_node >> 8, 0x80, "trame {number}");
                assert_eq!(packet.destination, 0x00FF, "trame {number}");
                assert_eq!(packet.body.len(), payload.len() - 12);
                match packet.message {
                    ValmetDnaMessage::Status(status) => {
                        status_count += 1;
                        assert_eq!(packet.kind, Some(MessageKind::Status));
                        assert_eq!(payload.len(), 126);
                        assert_eq!(status.node_ip, source, "trame {number}");
                        assert_eq!(status.multicast_group, group, "trame {number}");
                        assert_eq!(status.node_number, packet.node_number(), "trame {number}");
                        let known = node_ips.insert(packet.source_node, source);
                        assert!(known.is_none_or(|ip| ip == source), "trame {number}");
                        *telegrams_per_node.entry(packet.source_node).or_default() += 1;

                        let clock = status
                            .clock
                            .unwrap_or_else(|| panic!("trame {number} : horloge invalide"));
                        assert_eq!(
                            (clock.year, clock.month, clock.day, clock.weekday),
                            (2020, 1, 1, 3),
                            "trame {number}"
                        );
                        assert_eq!((clock.hour, clock.minute), (0, 0), "trame {number}");
                        assert!(clock.second <= 11, "trame {number}");
                        let now = clock.microseconds_of_day();
                        if let Some(before) = last_clock.insert(packet.source_node, now) {
                            let elapsed = now.checked_sub(before).unwrap_or_else(|| {
                                panic!("trame {number} : horloge en retour ({before} -> {now})")
                            });
                            assert!(
                                (630_000..=650_000).contains(&elapsed),
                                "trame {number} : {elapsed} us entre deux telegrammes"
                            );
                        }
                        let step = status.tick.wrapping_sub(status.previous_tick);
                        assert!(
                            (630_000..=650_000).contains(&step),
                            "trame {number} : pas de {step} entre les compteurs"
                        );
                        if let Some(tick) = last_tick.insert(packet.source_node, status.tick) {
                            assert_eq!(
                                status.previous_tick, tick,
                                "trame {number} : le compteur precedent n'est pas le dernier"
                            );
                        }
                    }
                    ValmetDnaMessage::Tag(tag) => {
                        tag_count += 1;
                        assert_eq!(packet.kind, Some(MessageKind::Tag));
                        assert_eq!(72 + tag.tag.len(), payload.len(), "trame {number}");
                        assert_eq!(usize::from(tag.tag_length), tag.tag.len());
                        assert!(tag.tag.starts_with(b":e:"), "trame {number}");
                        tag_lengths.insert(tag.tag_length);
                        tag_nodes.insert(packet.source_node);
                        match tag.class() {
                            Some(class) => {
                                *classes.entry(class.to_string()).or_default() += 1;
                                assert!(
                                    tag.path().is_some_and(|path| !path.is_empty()),
                                    "trame {number}"
                                );
                            }
                            None => {
                                binary_tags += 1;
                                assert_eq!(tag.tag_length, 10, "trame {number}");
                                assert_eq!(tag.tag_text(), None, "trame {number}");
                            }
                        }
                    }
                    other => panic!("trame {number} : {other:?}"),
                }
            }
            (Some(4516), Some(4517)) => {
                beacon_count += 1;
                let beacon = TimeBeacon::try_from(payload)
                    .unwrap_or_else(|error| panic!("trame {number} : {error}"));
                assert_eq!(beacon.node_ip, source, "trame {number}");
                assert_eq!((beacon.code, beacon.counter), (6, 0x2380_0000));
                let clock = beacon.clock.expect("horloge de la balise");
                assert_eq!(
                    (clock.year, clock.month, clock.day, clock.weekday),
                    (2020, 1, 1, 3)
                );
                assert_eq!(
                    (clock.hour, clock.minute, clock.second, clock.fraction),
                    (0, 0, 9, 9586)
                );
                // La balise vient d'un noeud qui emet aussi des telegrammes
                // d'etat (0x802C, dont les dix-neuf telegrammes commencent
                // avant elle).
                assert_eq!(node_ips.get(&0x802C), Some(&source), "trame {number}");
            }
            ports => panic!("trame {number} : ports {ports:?}"),
        }
    }

    assert_eq!((status_count, tag_count, beacon_count), (319, 400, 1));
    assert_eq!(
        telegrams_per_node.keys().copied().collect::<Vec<_>>(),
        NODES
    );
    assert!(
        telegrams_per_node
            .values()
            .all(|count| (18..=19).contains(count)),
        "{telegrams_per_node:?}"
    );
    assert_eq!(
        node_ips.values().collect::<BTreeSet<_>>().len(),
        17,
        "une adresse par noeud"
    );
    assert_eq!(
        classes,
        [("di", 286), ("hw", 6), ("li", 2), ("pr", 57), ("sn", 9)]
            .into_iter()
            .map(|(class, count)| (class.to_string(), count))
            .collect()
    );
    assert_eq!(binary_tags, 40);
    assert_eq!(
        (tag_lengths.first(), tag_lengths.last()),
        (Some(&10), Some(&44))
    );
    assert_eq!(tag_nodes.len(), 14);
}

/// Hors de ses ports, un message de famille connue reste reconnu a
/// l'aveugle ; la balise ne l'est que par Decode As. Les ports UDP d'une
/// trame Ethernet/IPv4 sans option sont aux offsets 34 et 36.
#[test]
fn off_its_ports_the_messages_are_blind_matched_and_the_beacon_needs_decode_as() {
    let frames = frames();
    let moved = |data: &[u8]| {
        let mut frame = data.to_vec();
        frame[34..36].copy_from_slice(&40000_u16.to_be_bytes());
        frame[36..38].copy_from_slice(&40001_u16.to_be_bytes());
        frame
    };
    // Trame 1 : telegramme d'etat ; trame 9 : message a etiquette.
    for number in [1, 9] {
        let (link_type, data) = &frames[number - 1];
        let frame = moved(data);
        let flow = parse(*link_type, &frame).expect("trame lisible");
        assert_eq!(label(&flow), Some("Valmet DNA"), "trame {number} deplacee");
    }
    // Trame 591 : la balise.
    let (link_type, data) = &frames[590];
    let frame = moved(data);
    let flow = parse(*link_type, &frame).expect("trame lisible");
    assert_eq!(label(&flow), Some("Unknown"));
    let config = ParseConfig::new().decode_as(40001, DecodeAsProtocol::ValmetDna);
    let flow = parse_with(*link_type, &frame, &config).expect("trame lisible");
    assert_eq!(label(&flow), Some("Valmet DNA"));
}
