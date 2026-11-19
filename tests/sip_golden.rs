// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests SIP (#342) sur des captures reelles.
//!
//! Captures : les quatre de `pcaps_exemple/protocols/sip/` (voir son
//! `SOURCE.md`) et `pcaps_exemple/The-Ultimate-PCAP.pcapng`. Toutes portent
//! du SIP sur UDP 5060 ; `ndpi_http_on_sip_port.pcap` est un negatif, du HTTP
//! sur TCP 5060.
//!
//! L'oracle est tshark 4.6.9 (`tools/sip_oracle.sh`), reassemblage IP et TCP
//! coupe : pour chaque trame SIP, la methode ou le code de statut, le CSeq et
//! le Content-Length, figes dans `tests/data/sip_tshark_oracle.tsv`. Il ne
//! contient ni Call-ID ni numero de telephone ; ce test n'en recopie pas non
//! plus. tshark etiquette aussi SIP le premier fragment IPv4 d'un INVITE de
//! 2 017 octets (trame 15114 de The-Ultimate-PCAP) : la crate ne lit pas le
//! transport d'un datagramme fragmente (#105), l'oracle l'exclut et
//! `the_fragmented_invite_has_no_application_layer` le verifie.

use std::{collections::BTreeMap, fs, path::Path};

use packet_parser::{
    PacketFlow, parse,
    parse::application::protocols::sip::{SipMessage, SipStartLine},
};

mod common;
use common::{FileRead, read_capture};

const ORACLE: &str = "tests/data/sip_tshark_oracle.tsv";
const CAPTURES: [&str; 5] = [
    "pcaps_exemple/protocols/sip/ndpi_http_on_sip_port.pcap",
    "pcaps_exemple/protocols/sip/ndpi_sip_hello.pcapng",
    "pcaps_exemple/protocols/sip/wireshark_FAX-Call-t38-CA-TDM-SIP-FB-1.pcap",
    "pcaps_exemple/protocols/sip/wireshark_aaa.pcap",
    "pcaps_exemple/The-Ultimate-PCAP.pcapng",
];

/// Une ligne de l'oracle.
struct Row {
    /// La methode d'une requete, ou le code de statut d'une reponse.
    start: String,
    sequence: u32,
    cseq_method: String,
    content_length: Option<u32>,
}

fn read_oracle(path: &Path) -> BTreeMap<(String, usize), Row> {
    let oracle = fs::read_to_string(path).expect("oracle lisible");
    let mut rows = BTreeMap::new();
    for line in oracle.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 6, "ligne d'oracle malformee : {line}");
        rows.insert(
            (
                fields[0].to_string(),
                fields[1].parse().expect("numero de trame"),
            ),
            Row {
                start: fields[2].to_string(),
                sequence: fields[3].parse().expect("numero CSeq"),
                cseq_method: fields[4].to_string(),
                content_length: (fields[5] != "-")
                    .then(|| fields[5].parse().expect("Content-Length")),
            },
        );
    }
    rows
}

fn label(flow: &PacketFlow<'_>) -> Option<&'static str> {
    flow.application
        .as_ref()
        .map(|application| application.protocol.label())
}

fn frames(capture: &str) -> Vec<(packet_parser::LinkType, Vec<u8>)> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(capture);
    let FileRead::Frames {
        frames,
        read_error_after: None,
    } = read_capture(&path)
    else {
        panic!("{capture} illisible");
    };
    frames
}

fn file_name(capture: &str) -> String {
    Path::new(capture)
        .file_name()
        .and_then(|name| name.to_str())
        .expect("nom de fichier")
        .to_string()
}

#[test]
fn every_sip_frame_matches_the_tshark_oracle() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let rows = read_oracle(&base.join(ORACLE));
    assert_eq!(rows.len(), 201);

    let mut per_capture: BTreeMap<String, usize> = BTreeMap::new();
    for capture in CAPTURES {
        let name = file_name(capture);
        for (index, (link_type, data)) in frames(capture).iter().enumerate() {
            let number = index + 1;
            let flow = parse(*link_type, data).unwrap_or_else(|_| panic!("{name} trame {number}"));
            let Some(row) = rows.get(&(name.clone(), number)) else {
                assert_ne!(
                    label(&flow),
                    Some("SIP"),
                    "{name} trame {number} : SIP pour la crate, pas pour tshark"
                );
                continue;
            };
            *per_capture.entry(name.clone()).or_default() += 1;
            assert_eq!(label(&flow), Some("SIP"), "{name} trame {number}");

            let payload = flow
                .transport
                .as_ref()
                .and_then(|transport| transport.payload)
                .expect("charge UDP");
            let message = SipMessage::try_from(payload)
                .unwrap_or_else(|error| panic!("{name} trame {number} : {error}"));
            match message.start_line {
                SipStartLine::Request { method, .. } => assert_eq!(method, row.start),
                SipStartLine::Response { status_code, .. } => {
                    assert_eq!(status_code.to_string(), row.start)
                }
                _ => panic!("ligne de depart inconnue"),
            }
            assert_eq!(message.cseq.sequence, row.sequence, "{name} trame {number}");
            assert_eq!(
                message.cseq.method, row.cseq_method,
                "{name} trame {number}"
            );
            assert_eq!(
                message.content_length, row.content_length,
                "{name} trame {number}"
            );
            // Un datagramme porte le message entier : le corps a la longueur
            // annoncee.
            if let Some(length) = message.content_length {
                assert_eq!(message.body.len(), length as usize, "{name} trame {number}");
            }
            // Ces captures sont sur UDP, et le Via du haut le dit.
            assert!(
                message.via.to_ascii_uppercase().starts_with("SIP/2.0/UDP"),
                "{name} trame {number} : {}",
                message.via
            );
            assert!(!message.call_id.is_empty() && !message.from.is_empty());
        }
    }
    assert_eq!(
        per_capture,
        BTreeMap::from([
            ("The-Ultimate-PCAP.pcapng".to_string(), 20),
            ("ndpi_sip_hello.pcapng".to_string(), 8),
            (
                "wireshark_FAX-Call-t38-CA-TDM-SIP-FB-1.pcap".to_string(),
                92
            ),
            ("wireshark_aaa.pcap".to_string(), 81),
        ])
    );
}

/// Le negatif de nDPI : une requete HTTP sur TCP 5060 et sa reponse restent
/// HTTP, et rien n'y est SIP.
#[test]
fn http_on_the_sip_port_stays_http() {
    let labels: Vec<Option<&str>> = frames(CAPTURES[0])
        .iter()
        .map(|(link_type, data)| label(&parse(*link_type, data).expect("trame lisible")))
        .collect();
    assert_eq!(labels, [None, None, Some("HTTP"), Some("HTTP")]);
}

/// La limite que l'oracle exclut : le premier fragment IPv4 d'un INVITE de
/// 2 017 octets n'a pas de couche applicative pour la crate.
#[test]
fn the_fragmented_invite_has_no_application_layer() {
    let frames = frames(CAPTURES[4]);
    let (link_type, data) = &frames[15114 - 1];
    let flow = parse(*link_type, data).expect("trame lisible");
    assert_eq!(label(&flow), None);
}
