// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden test Modbus/TCP sur segments reels (#167).
//!
//! Captures : `pcaps_exemple/protocols/modbus/` et `pcaps_exemple/protocols/umas/`
//! (voir leurs `SOURCE.md`) et, lue en place,
//! `pcaps_exemple/The-Ultimate-PCAP.pcapng` — dont les 57 segments LDAP
//! d'Active Directory (TCP 389, longueur BER sur quatre octets
//! `30 84 00 00 ..`) que la sonde aveugle prenait pour du Modbus.
//!
//! L'oracle est tshark 4.6.6 (`tools/modbus_oracle.sh`) : pour chaque
//! segment, ports et, en-tete MBAP par en-tete MBAP, identifiant de
//! transaction, longueur, unite, code fonction et code d'exception, figes
//! dans `tests/data/modbus_tshark_oracle.tsv` et compares ici segment par
//! segment.

use std::{collections::BTreeMap, fs, path::Path};

use packet_parser::{
    PacketFlow, parse,
    parse::{
        application::protocols::modbus_tcp::ModbusTcpPacket,
        transport::protocols::TransportProtocol,
    },
};

mod common;
use common::{FileRead, read_capture};

const CORPUS: &str = "pcaps_exemple/protocols";
const ORACLE: &str = "tests/data/modbus_tshark_oracle.tsv";

/// Segments TCP 389 a payload de l'Ultimate PCAP.
const LDAP_SEGMENTS: usize = 400;

fn read_oracle(path: &Path) -> BTreeMap<String, BTreeMap<usize, String>> {
    let oracle = fs::read_to_string(path).expect("oracle lisible");
    let mut expected: BTreeMap<String, BTreeMap<usize, String>> = BTreeMap::new();
    for line in oracle.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<&str> = line.splitn(3, '\t').collect();
        assert_eq!(fields.len(), 3, "ligne d'oracle malformee : {line}");
        expected.entry(fields[0].to_string()).or_default().insert(
            fields[1].parse().expect("numero de trame"),
            fields[2].to_string(),
        );
    }
    expected
}

fn frames_of(path: &Path) -> Vec<(packet_parser::LinkType, Vec<u8>)> {
    let FileRead::Frames { frames, .. } = read_capture(path) else {
        panic!("{} : capture illisible", path.display());
    };
    frames
}

/// Le niveau de la trame etiquete Modbus/TCP ou UMAS (porte par Modbus/TCP).
fn modbus_level<'f, 'a>(flow: &'f PacketFlow<'a>) -> Option<&'f PacketFlow<'a>> {
    flow.flatten().into_iter().find(|level| {
        level.application.as_ref().is_some_and(|application| {
            matches!(application.application_protocol, "ModbusTCP" | "UMAS")
        })
    })
}

fn join<T: ToString>(values: impl Iterator<Item = T>) -> String {
    let joined = values.map(|v| v.to_string()).collect::<Vec<_>>().join(",");
    if joined.is_empty() {
        "-".to_string()
    } else {
        joined
    }
}

/// Les colonnes de l'oracle a partir du port source.
fn oracle_columns(source_port: u16, destination_port: u16, payload: &[u8]) -> String {
    let packet = ModbusTcpPacket::try_from(payload).expect("un segment etiquete se decode");
    let mbaps = &packet.mbaps;
    [
        source_port.to_string(),
        destination_port.to_string(),
        join(mbaps.iter().map(|m| m.transaction_identifier)),
        join(mbaps.iter().map(|m| m.length)),
        join(mbaps.iter().map(|m| m.unit_identifier)),
        join(mbaps.iter().map(|m| m.pdu.function_code & 0x7f)),
        join(
            mbaps
                .iter()
                .filter(|m| m.pdu.function_code & 0x80 != 0)
                .filter_map(|m| m.pdu.pdu_data.first()),
        ),
    ]
    .join("\t")
}

/// Parite avec tshark : la crate etiquette Modbus/TCP ou UMAS exactement
/// les segments que tshark decode en Modbus/TCP, et en decode les memes
/// en-tetes ; aucun autre segment — les LDAP de l'Ultimate PCAP compris —
/// ne sort Modbus.
#[test]
fn every_segment_matches_the_tshark_oracle() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let oracle = read_oracle(&base.join(ORACLE));
    let mut segments = 0;
    let mut by_label: BTreeMap<&str, usize> = BTreeMap::new();
    let mut by_function: BTreeMap<u8, usize> = BTreeMap::new();
    let mut missed = Vec::new();
    for (name, rows) in &oracle {
        for (index, (link_type, data)) in
            frames_of(&base.join(CORPUS).join(name)).iter().enumerate()
        {
            let number = index + 1;
            let flow = parse(*link_type, data).expect("trame decodable");
            let level = modbus_level(&flow);
            let Some(row) = rows.get(&number) else {
                assert!(
                    level.is_none(),
                    "{name}:{number} : Modbus pour la crate seule"
                );
                continue;
            };
            let Some(level) = level else {
                missed.push(format!("{name}:{number}"));
                continue;
            };
            let transport = level.transport.as_ref().expect("Modbus est sur TCP");
            let payload = transport.payload.expect("un segment a un payload");
            assert_eq!(
                &oracle_columns(
                    transport.source_port.unwrap(),
                    transport.destination_port.unwrap(),
                    payload
                ),
                row,
                "{name}:{number} : ecart avec tshark"
            );
            *by_label
                .entry(level.application.as_ref().unwrap().application_protocol)
                .or_default() += 1;
            *by_function.entry(payload[7]).or_default() += 1;
            segments += 1;
        }
    }
    assert_eq!(missed, Vec::<String>::new());
    assert_eq!(segments, 601);
    assert_eq!(
        by_label,
        BTreeMap::from([("ModbusTCP", 420), ("UMAS", 181)])
    );
    // Le scanner de MODBUS-TestDataPart2.pcap essaie presque tous les codes
    // fonction : 250 distincts, requetes et reponses d'exception comprises.
    assert_eq!(by_function.len(), 250);
}

/// Les 57 segments LDAP de l'Ultimate PCAP (TCP 389, longueur BER sur
/// quatre octets) : le decodeur tolerant du port 502 les accepte, la sonde
/// aveugle non (#167).
#[test]
fn ldap_segments_are_not_modbus() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut ldap = 0;
    let mut mbap_shaped = 0;
    for (link_type, data) in frames_of(&base.join(CORPUS).join("../The-Ultimate-PCAP.pcapng")) {
        let flow = parse(link_type, &data).expect("trame decodable");
        let Some(transport) = flow.transport.as_ref() else {
            continue;
        };
        let (Some(payload), true) = (
            transport.payload,
            matches!(transport.protocol, TransportProtocol::Tcp)
                && (transport.source_port == Some(389) || transport.destination_port == Some(389)),
        ) else {
            continue;
        };
        if payload.is_empty() {
            continue;
        }
        assert!(modbus_level(&flow).is_none(), "LDAP etiquete Modbus");
        ldap += 1;
        if ModbusTcpPacket::try_from(payload).is_ok() {
            mbap_shaped += 1;
        }
    }
    // Le LDAP en clair et le TLS d'apres StartTLS ; 57 segments ont la
    // forme d'une enveloppe MBAP.
    assert_eq!(ldap, LDAP_SEGMENTS);
    assert_eq!(mbap_shaped, 57);
}

/// Les 601 segments Modbus/TCP reels, deplaces hors du port 502 (TCP 40000
/// -> 40001) : la sonde aveugle reconnait tous ceux dont le code fonction
/// est d'usage courant ; les autres sont les sondes d'un scanner qui essaie
/// les 128 codes de requete, 0x00 a 0x7F (`MODBUS-TestDataPart2.pcap`), et
/// leurs reponses d'exception, que seul le port 502 fait reconnaitre.
#[test]
fn real_segments_off_port() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let oracle = read_oracle(&base.join(ORACLE));
    let mut recognised = 0;
    let mut refused: BTreeMap<String, usize> = BTreeMap::new();
    for (name, rows) in &oracle {
        let frames = frames_of(&base.join(CORPUS).join(name));
        for number in rows.keys() {
            let (link_type, data) = &frames[number - 1];
            let flow = parse(*link_type, data).expect("trame decodable");
            let payload = modbus_level(&flow)
                .and_then(|level| level.transport.as_ref())
                .and_then(|transport| transport.payload)
                .expect("segment Modbus");
            let start = payload.as_ptr() as usize - data.as_ptr() as usize;
            let mut moved = data.clone();
            // L'en-tete TCP precede le payload : ses ports sont ses quatre
            // premiers octets ; il fait au moins vingt octets.
            let tcp = start - tcp_header_length(&flow);
            moved[tcp..tcp + 4].copy_from_slice(&[0x9c, 0x40, 0x9c, 0x41]);
            let moved_flow = parse(*link_type, &moved).expect("trame deplacee");
            if modbus_level(&moved_flow).is_some() {
                recognised += 1;
            } else {
                *refused.entry(name.clone()).or_default() += 1;
            }
        }
    }
    assert_eq!(recognised, 358);
    assert_eq!(
        refused,
        BTreeMap::from([("modbus/MODBUS-TestDataPart2.pcap".to_string(), 243)])
    );
}

/// La longueur de l'en-tete TCP de la trame, options comprises.
fn tcp_header_length(flow: &PacketFlow<'_>) -> usize {
    let level = modbus_level(flow).expect("segment Modbus");
    let transport = level.transport.as_ref().expect("TCP");
    match transport.details.as_ref() {
        Some(packet_parser::parse::transport::TransportDetails::Tcp(tcp)) => {
            usize::from(tcp.header.data_offset) * 4
        }
        _ => panic!("en-tete TCP attendu"),
    }
}
