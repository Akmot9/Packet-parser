// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests Skinny (SCCP Cisco, #370) sur les six captures reelles de
//! `pcaps_exemple/protocols/skinny/` : des postes Cisco et leur serveur
//! d'appel sur TCP 2000, de 2010 a 2019, en versions d'en-tete 0 et 17 a 22
//! (voir leur `SOURCE.md`).
//!
//! L'oracle est tshark 4.6.9 (`tools/skinny_oracle.sh`), rendu sans etat
//! comme la crate : reassemblage TCP et Skinny coupes, analyse des numeros
//! de sequence coupee pour que les retransmissions soient dissequees. Pour
//! chaque segment, la longueur, la version d'en-tete et l'identifiant de
//! chaque message sont figes dans `tests/data/skinny_tshark_oracle.tsv`.
//!
//! Oracle negatif : les onze segments de suite de TCP 2000
//! ([`CONTINUATIONS`]), que tshark ne dissèque pas non plus, sortent
//! `Unknown`, et aucune autre trame de ces captures ne sort `Skinny`.
//! L'histogramme fige de `tests/golden_pcaps.rs` n'a d'entree `Skinny` que
//! pour ce dossier.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use packet_parser::{
    PacketFlow, parse,
    parse::application::protocols::skinny::{SKINNY_HEADER_LENGTH, SkinnyMessage},
};

mod common;
use common::{FileRead, read_capture};

const ORACLE: &str = "tests/data/skinny_tshark_oracle.tsv";
const DIRECTORY: &str = "pcaps_exemple/protocols/skinny";

/// Les captures, et le nombre de trames apres lequel la lecture echoue :
/// `wireshark_8805_packets.cap` finit au milieu d'un enregistrement, six
/// octets apres sa trame 759.
const CAPTURES: [(&str, Option<usize>); 6] = [
    ("ndpi_sccp_hw_conf_register.pcapng", None),
    ("ndpi_skinny.pcap", None),
    (
        "wireshark_10262_7911_CUCM_registration_RFC2833.pcapng",
        None,
    ),
    ("wireshark_6041_cm7_type_b_more.pcap", None),
    ("wireshark_8616_100030.pcap", None),
    ("wireshark_8805_packets.cap", Some(759)),
];

/// Segments de TCP 2000 qui portent la suite d'un message coupe : ni tshark
/// ni la crate ne les nomment. Les trames 43 et 106 de
/// `wireshark_8616_100030.pcap` finissent un message puis en portent un
/// entier (RegisterReq) : il faut l'etat du flux pour en trouver le debut, ce
/// que tshark fait quand son analyse des numeros de sequence est active.
const CONTINUATIONS: [(&str, usize); 11] = [
    ("wireshark_10262_7911_CUCM_registration_RFC2833.pcapng", 125),
    ("wireshark_10262_7911_CUCM_registration_RFC2833.pcapng", 128),
    ("wireshark_10262_7911_CUCM_registration_RFC2833.pcapng", 184),
    ("wireshark_8616_100030.pcap", 41),
    ("wireshark_8616_100030.pcap", 43),
    ("wireshark_8616_100030.pcap", 104),
    ("wireshark_8616_100030.pcap", 106),
    ("wireshark_8616_100030.pcap", 172),
    ("wireshark_8616_100030.pcap", 173),
    ("wireshark_8616_100030.pcap", 175),
    ("wireshark_8616_100030.pcap", 176),
];

/// Un message d'une ligne de l'oracle : longueur, version, identifiant.
type Header = (u32, u32, u32);

/// Une ligne de l'oracle.
struct Row {
    tcp_length: usize,
    messages: Vec<Header>,
}

fn numbers(field: &str) -> Vec<u32> {
    field
        .split(',')
        .map(|value| value.parse().expect("entier de l'oracle"))
        .collect()
}

fn read_oracle(path: &Path) -> BTreeMap<(String, usize), Row> {
    let oracle = fs::read_to_string(path).expect("oracle lisible");
    let mut rows = BTreeMap::new();
    for line in oracle.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 6, "ligne d'oracle malformee : {line}");
        let (lengths, versions, identifiers) =
            (numbers(fields[3]), numbers(fields[4]), numbers(fields[5]));
        assert_eq!(lengths.len(), versions.len(), "{line}");
        assert_eq!(lengths.len(), identifiers.len(), "{line}");
        rows.insert(
            (
                fields[0].to_string(),
                fields[1].parse().expect("numero de trame"),
            ),
            Row {
                tcp_length: fields[2].parse().expect("longueur TCP"),
                messages: lengths
                    .into_iter()
                    .zip(versions)
                    .zip(identifiers)
                    .map(|((length, version), identifier)| (length, version, identifier))
                    .collect(),
            },
        );
    }
    rows
}

/// L'etiquette, les ports et la charge de la couche transport.
fn summary<'a>(flow: &'a PacketFlow<'a>) -> (Option<&'static str>, bool, Option<&'a [u8]>) {
    let label = flow
        .application
        .as_ref()
        .map(|application| application.protocol.label());
    let transport = flow.transport.as_ref();
    let on_port = transport.is_some_and(|transport| {
        transport.source_port == Some(2000) || transport.destination_port == Some(2000)
    });
    (
        label,
        on_port,
        transport.and_then(|transport| transport.payload),
    )
}

fn frames(name: &str, cut_after: Option<usize>) -> Vec<(packet_parser::LinkType, Vec<u8>)> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(DIRECTORY)
        .join(name);
    let FileRead::Frames {
        frames,
        read_error_after,
    } = read_capture(&path)
    else {
        panic!("{name} illisible");
    };
    assert_eq!(read_error_after, cut_after, "{name}");
    frames
}

#[test]
fn every_skinny_segment_matches_the_tshark_oracle() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let rows = read_oracle(&base.join(ORACLE));
    assert_eq!(rows.len(), 656);

    let mut per_capture: BTreeMap<&str, usize> = BTreeMap::new();
    let mut continuations = Vec::new();
    let (mut messages, mut several, mut truncated) = (0, 0, 0);
    let mut versions = BTreeSet::new();
    let mut identifiers = BTreeSet::new();
    for (name, cut_after) in CAPTURES {
        for (index, (link_type, data)) in frames(name, cut_after).iter().enumerate() {
            let number = index + 1;
            let flow = parse(*link_type, data).unwrap_or_else(|_| panic!("{name} trame {number}"));
            let (label, on_port, payload) = summary(&flow);
            let Some(row) = rows.get(&(name.to_string(), number)) else {
                assert_ne!(
                    label,
                    Some("Skinny"),
                    "{name} trame {number} : Skinny pour la crate, pas pour tshark"
                );
                // Une charge sur TCP 2000 que tshark ne dissèque pas.
                if on_port && label.is_some() {
                    assert_eq!(label, Some("Unknown"), "{name} trame {number}");
                    continuations.push((name, number));
                }
                continue;
            };
            *per_capture.entry(name).or_default() += 1;
            assert_eq!(label, Some("Skinny"), "{name} trame {number}");
            let payload = payload.expect("charge TCP");
            assert_eq!(payload.len(), row.tcp_length, "{name} trame {number}");

            let decoded: Vec<SkinnyMessage<'_>> = SkinnyMessage::messages(payload)
                .collect::<Result<_, _>>()
                .unwrap_or_else(|error| panic!("{name} trame {number} : {error}"));
            let headers: Vec<Header> = decoded
                .iter()
                .map(|message| {
                    (
                        message.data_length,
                        message.header_version,
                        message.message_id,
                    )
                })
                .collect();
            assert_eq!(headers, row.messages, "{name} trame {number}");

            // Les en-tetes et les corps pavent le segment, et seul le
            // dernier message peut etre coupe.
            let paved: usize = decoded
                .iter()
                .map(|message| SKINNY_HEADER_LENGTH + message.body.len())
                .sum();
            assert_eq!(paved, payload.len(), "{name} trame {number}");
            let (last, others) = decoded.split_last().expect("au moins un message");
            assert!(others.iter().all(|message| !message.is_truncated()));
            assert!(last.rest().is_empty(), "{name} trame {number}");
            for message in &decoded {
                assert_eq!(
                    message.is_truncated(),
                    message.body.len() + 4 < message.data_length as usize,
                    "{name} trame {number}"
                );
                versions.insert(message.header_version);
                identifiers.insert(message.message_id);
            }
            messages += decoded.len();
            several += usize::from(decoded.len() > 1);
            truncated += usize::from(last.is_truncated());
        }
    }
    assert_eq!(
        per_capture,
        BTreeMap::from([
            ("ndpi_sccp_hw_conf_register.pcapng", 8),
            ("ndpi_skinny.pcap", 40),
            ("wireshark_10262_7911_CUCM_registration_RFC2833.pcapng", 41),
            ("wireshark_6041_cm7_type_b_more.pcap", 85),
            ("wireshark_8616_100030.pcap", 67),
            ("wireshark_8805_packets.cap", 415),
        ])
    );
    assert_eq!(messages, 933);
    assert_eq!(several, 64, "segments de plusieurs messages");
    assert_eq!(truncated, 5, "messages coupes par leur segment");
    assert_eq!(
        versions.into_iter().collect::<Vec<_>>(),
        [0, 17, 18, 19, 20, 21, 22]
    );
    assert_eq!(identifiers.len(), 70, "identifiants de message distincts");
    assert_eq!(continuations, CONTINUATIONS, "segments de suite");
}
