// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests syslog (#374) sur des trames reelles :
//! `pcaps_exemple/The-Ultimate-PCAP.pcapng` (UDP 514, TCP 514 et 601, sous
//! les deux cadrages de la RFC 6587) et les deux captures de
//! `pcaps_exemple/protocols/syslog/` (voir leur `SOURCE.md`).
//!
//! L'oracle est tshark 4.6.9 (`tools/syslog_oracle.sh`), rendu sans etat
//! comme la crate, avec TCP declare en syslog par Decode As : tshark prend
//! TCP 514 pour du RSH. Pour chaque charge, la facilite, la gravite, la
//! version et l'en-tete de la RFC 5424 sont figes dans
//! `tests/data/syslog_tshark_oracle.tsv`.
//!
//! Ecart voulu : d'un segment de messages termines par LF, tshark ne lit que
//! le premier ; la crate les separe (RFC 6587 §3.4.2). L'oracle porte alors
//! sur le premier message, et le nombre de trames est fige ici.
//!
//! Oracle negatif : les segments de suite ([`CONTINUATIONS`]) sortent
//! `Unknown`, aucune autre trame ne sort `Syslog`, et le message de
//! `ndpi_syslog.pcap` sur TCP 52173 ne sort `Syslog` qu'une fois le port
//! declare par Decode As.

use std::{collections::BTreeMap, fs, path::Path};

use packet_parser::{
    DecodeAsProtocol, PacketFlow, ParseConfig,
    parse::application::protocols::syslog::{SyslogFrame, SyslogMessage},
    parse_with,
};

mod common;
use common::{FileRead, read_capture};

const ORACLE: &str = "tests/data/syslog_tshark_oracle.tsv";

/// Les captures et les ports qu'il faut declarer pour y lire syslog.
const CAPTURES: [(&str, &[u16]); 3] = [
    ("pcaps_exemple/The-Ultimate-PCAP.pcapng", &[]),
    (
        "pcaps_exemple/protocols/syslog/ndpi_rsh-syslog-false-positive.pcap",
        &[],
    ),
    ("pcaps_exemple/protocols/syslog/ndpi_syslog.pcap", &[52173]),
];

/// Segments d'un port syslog qui portent la suite d'un message coupe : la
/// crate ne les nomme pas. tshark, declare en syslog, y met son nom sans y
/// lire de priorite.
const CONTINUATIONS: [(&str, usize); 1] = [("ndpi_rsh-syslog-false-positive.pcap", 8)];

/// Trames que la capture a coupees (1 010 octets gardes) : l'en-tete IPv4
/// annonce plus d'octets qu'il n'en reste, la crate s'arrete a la couche
/// reseau. tshark lit ce qui reste.
const CUT_BY_CAPTURE: [(&str, usize); 2] = [
    ("ndpi_rsh-syslog-false-positive.pcap", 6),
    ("ndpi_rsh-syslog-false-positive.pcap", 7),
];

/// Une ligne de l'oracle.
struct Row {
    is_udp: bool,
    length: usize,
    octet_counts: Vec<u32>,
    facilities: Vec<u8>,
    severities: Vec<u8>,
    version: Option<u8>,
    header: [String; 4],
}

fn numbers<T: std::str::FromStr>(field: &str) -> Vec<T> {
    if field == "-" {
        return Vec::new();
    }
    field
        .split(',')
        .map(|value| value.parse().ok().expect("entier de l'oracle"))
        .collect()
}

fn read_oracle(path: &Path) -> BTreeMap<(String, usize), Row> {
    let oracle = fs::read_to_string(path).expect("oracle lisible");
    let mut rows = BTreeMap::new();
    for line in oracle.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 12, "ligne d'oracle malformee : {line}");
        rows.insert(
            (
                fields[0].to_string(),
                fields[1].parse().expect("numero de trame"),
            ),
            Row {
                is_udp: fields[2] == "udp",
                length: fields[3].parse().expect("longueur"),
                octet_counts: numbers(fields[4]),
                facilities: numbers(fields[5]),
                severities: numbers(fields[6]),
                version: numbers(fields[7]).first().copied(),
                header: [fields[8], fields[9], fields[10], fields[11]].map(str::to_string),
            },
        );
    }
    rows
}

/// L'etiquette, si la trame est sur un port syslog, et la charge, lues sur
/// le flux le plus interne : des trames de The-Ultimate-PCAP.pcapng portent
/// syslog dans un tunnel.
fn summary<'a>(
    flow: &'a PacketFlow<'a>,
    declared: &[u16],
) -> (Option<&'static str>, bool, Option<&'a [u8]>) {
    let flow = *flow.flatten().last().expect("au moins un flux");
    let label = flow
        .application
        .as_ref()
        .map(|application| application.protocol.label());
    let transport = flow.transport.as_ref();
    let on_port = transport.is_some_and(|transport| {
        [transport.source_port, transport.destination_port]
            .into_iter()
            .flatten()
            .any(|port| matches!(port, 514 | 601) || declared.contains(&port))
    });
    (
        label,
        on_port,
        transport.and_then(|transport| transport.payload),
    )
}

fn frames(path: &str) -> Vec<(packet_parser::LinkType, Vec<u8>)> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
    let FileRead::Frames {
        frames,
        read_error_after: None,
    } = read_capture(&path)
    else {
        panic!("{} illisible", path.display());
    };
    frames
}

/// Les quatre champs d'en-tete que tshark nomme, `-` pour une valeur
/// absente.
fn header_fields(message: &SyslogMessage<'_>) -> [String; 4] {
    let header = message.header();
    let field = |value: Option<&str>| value.unwrap_or("-").to_string();
    match header {
        Some(header) => [
            field(header.hostname),
            field(header.app_name),
            field(header.procid),
            field(header.msgid),
        ],
        None => ["-", "-", "-", "-"].map(str::to_string),
    }
}

/// Ce que le corpus porte, fige.
#[derive(Debug, Default, PartialEq, Eq)]
struct Totals {
    datagrams: usize,
    segments: usize,
    counted_frames: usize,
    line_frames: usize,
    several_frames: usize,
    cut_frames: usize,
    rfc5424: usize,
    priorities: BTreeMap<u8, usize>,
}

#[test]
fn every_syslog_payload_matches_the_tshark_oracle() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let rows = read_oracle(&base.join(ORACLE));
    assert_eq!(rows.len(), 341);

    let mut per_capture: BTreeMap<&str, usize> = BTreeMap::new();
    let mut continuations = Vec::new();
    let mut cut_by_capture = Vec::new();
    let mut totals = Totals::default();
    for (path, declared) in CAPTURES {
        let name = path.rsplit('/').next().expect("nom de capture");
        let config = declared.iter().fold(ParseConfig::new(), |config, port| {
            config.decode_as(*port, DecodeAsProtocol::Syslog)
        });
        for (index, (link_type, data)) in frames(path).iter().enumerate() {
            let number = index + 1;
            let flow = parse_with(*link_type, data, &config)
                .unwrap_or_else(|_| panic!("{name} trame {number}"));
            let (label, on_port, payload) = summary(&flow, declared);
            let Some(row) = rows.get(&(name.to_string(), number)) else {
                assert_ne!(
                    label,
                    Some("Syslog"),
                    "{name} trame {number} : Syslog pour la crate, pas pour tshark"
                );
                // Une charge sur un port syslog ou tshark ne lit pas de
                // priorite.
                if on_port && label.is_some() {
                    assert_eq!(label, Some("Unknown"), "{name} trame {number}");
                    continuations.push((name, number));
                }
                continue;
            };
            if flow.corrupted.is_some() {
                assert_eq!(label, None, "{name} trame {number}");
                cut_by_capture.push((name, number));
                continue;
            }
            *per_capture.entry(name).or_default() += 1;
            assert_eq!(label, Some("Syslog"), "{name} trame {number}");
            let payload = payload.expect("charge");
            assert_eq!(payload.len(), row.length, "{name} trame {number}");

            if row.is_udp {
                let message = SyslogMessage::try_from(payload)
                    .unwrap_or_else(|error| panic!("{name} trame {number} : {error}"));
                assert_eq!(vec![message.facility()], row.facilities, "{name} {number}");
                assert_eq!(vec![message.severity()], row.severities, "{name} {number}");
                assert_eq!(message.version, row.version, "{name} trame {number}");
                assert_eq!(header_fields(&message), row.header, "{name} {number}");
                totals.datagrams += 1;
                totals.rfc5424 += usize::from(message.version.is_some());
                *totals.priorities.entry(message.priority).or_default() += 1;
                continue;
            }

            let decoded: Vec<SyslogFrame<'_>> = SyslogFrame::frames(payload)
                .collect::<Result<_, _>>()
                .unwrap_or_else(|error| panic!("{name} trame {number} : {error}"));
            let (last, others) = decoded.split_last().expect("au moins une trame");
            // Les trames pavent le segment, et seule la derniere peut etre
            // coupee.
            assert!(others.iter().all(|frame| !frame.is_truncated()));
            assert!(last.rest().is_empty(), "{name} trame {number}");
            let mut rest = payload;
            for frame in &decoded {
                assert_eq!(SyslogFrame::try_from(rest).as_ref(), Ok(frame));
                rest = frame.rest();
            }

            let counts: Vec<u32> = decoded
                .iter()
                .filter_map(|frame| frame.octet_count)
                .collect();
            assert_eq!(counts, row.octet_counts, "{name} trame {number}");
            // tshark separe les trames comptees ; d'un segment de lignes, il
            // ne lit que la premiere.
            let compared = if counts.is_empty() { 1 } else { decoded.len() };
            assert!(counts.is_empty() || counts.len() == decoded.len());
            let facilities: Vec<u8> = decoded[..compared]
                .iter()
                .map(|frame| frame.message.facility())
                .collect();
            let severities: Vec<u8> = decoded[..compared]
                .iter()
                .map(|frame| frame.message.severity())
                .collect();
            assert_eq!(facilities, row.facilities, "{name} trame {number}");
            assert_eq!(severities, row.severities, "{name} trame {number}");
            assert_eq!(decoded[0].message.version, row.version, "{name} {number}");
            assert_eq!(header_fields(&decoded[0].message), row.header);

            totals.segments += 1;
            totals.several_frames += usize::from(decoded.len() > 1);
            totals.cut_frames += usize::from(last.is_truncated());
            for frame in &decoded {
                match frame.octet_count {
                    Some(count) => {
                        totals.counted_frames += 1;
                        let visible = frame.message.content.len();
                        assert!(visible < count as usize, "{name} trame {number}");
                    }
                    None => totals.line_frames += 1,
                }
                totals.rfc5424 += usize::from(frame.message.version.is_some());
                *totals.priorities.entry(frame.message.priority).or_default() += 1;
            }
        }
    }
    assert_eq!(
        per_capture,
        BTreeMap::from([
            ("The-Ultimate-PCAP.pcapng", 250),
            ("ndpi_rsh-syslog-false-positive.pcap", 5),
            ("ndpi_syslog.pcap", 84),
        ])
    );
    assert_eq!(continuations, CONTINUATIONS, "segments de suite");
    assert_eq!(
        cut_by_capture, CUT_BY_CAPTURE,
        "trames coupees par la capture"
    );
    assert_eq!(
        totals,
        Totals {
            datagrams: 95,
            segments: 244,
            counted_frames: 128,
            line_frames: 132,
            several_frames: 8,
            // Les deux seules trames coupees du corpus le sont aussi par la
            // capture ([`CUT_BY_CAPTURE`]).
            cut_frames: 0,
            rfc5424: 5,
            priorities: BTreeMap::from([
                (6, 4),
                (11, 2),
                (13, 3),
                (14, 71),
                (22, 1),
                (26, 2),
                (27, 1),
                (28, 2),
                (29, 2),
                (30, 52),
                (45, 10),
                (46, 2),
                (133, 12),
                (134, 16),
                (147, 2),
                (167, 12),
                (187, 4),
                (188, 1),
                (189, 120),
                (190, 36),
            ]),
        }
    );
}

/// Sans Decode As, le message de `ndpi_syslog.pcap` sur TCP 52173 (trame
/// 81, RFC 5424) reste `Unknown` : la garde de port.
#[test]
fn other_ports_need_decode_as() {
    let rows = read_oracle(&Path::new(env!("CARGO_MANIFEST_DIR")).join(ORACLE));
    let config = ParseConfig::new();
    let mut unknown = Vec::new();
    for (index, (link_type, data)) in frames(CAPTURES[2].0).iter().enumerate() {
        let number = index + 1;
        let flow = parse_with(*link_type, data, &config).expect("trame lisible");
        let (label, _, _) = summary(&flow, &[]);
        let in_oracle = rows.contains_key(&("ndpi_syslog.pcap".to_string(), number));
        match label {
            Some("Syslog") => assert!(in_oracle, "trame {number}"),
            Some("Unknown") if in_oracle => unknown.push(number),
            _ => assert!(!in_oracle, "trame {number} : {label:?}"),
        }
    }
    assert_eq!(unknown, [81]);
}
