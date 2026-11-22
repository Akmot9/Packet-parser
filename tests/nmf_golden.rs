// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests .NET Message Framing (#352) sur des trames de terrain
//! censurees : `pcaps_exemple/protocols/nmf/terrain_nmf_censure.pcap`
//! (voir son `SOURCE.md` pour ce que la censure a reecrit).
//!
//! L'oracle est tshark 4.6.9 (`tools/nmf_oracle.sh`), les ports des deux
//! services declares : pour chaque segment a charge, les types
//! d'enregistrement, la taille de l'enveloppe, le mode, l'encodage connu et
//! la longueur de Via, figes dans `tests/data/nmf_tshark_oracle.tsv`.
//!
//! tshark ne reassemble pas : il lit les quinze segments de suite comme des
//! enregistrements. La crate les laisse `Unknown`, a l'aveugle comme sur un
//! port declare.

use std::{collections::BTreeMap, fs, path::Path};

use packet_parser::{
    DecodeAsProtocol, PacketFlow, ParseConfig, parse,
    parse::application::protocols::nmf::{NmfMode, NmfRecord, NmfSegment},
    parse_with,
};

mod common;
use common::{FileRead, read_capture};

const ORACLE: &str = "tests/data/nmf_tshark_oracle.tsv";
const CAPTURE: &str = "pcaps_exemple/protocols/nmf/terrain_nmf_censure.pcap";
/// Ports des deux services, apres censure.
const SERVICE_PORTS: [u16; 2] = [50001, 50002];

/// Segments qui commencent un enregistrement, d'apres les numeros de
/// sequence TCP : une session complete (trames 4 a 10) et la premiere
/// enveloppe d'un message de 50 253 octets (trame 23). Les autres segments
/// a charge sont des segments de suite.
const RECORD_SEGMENTS: [usize; 8] = [4, 5, 6, 7, 8, 9, 10, 23];

/// Une ligne de l'oracle.
struct Row {
    tcp_length: usize,
    records: usize,
    types: Option<Vec<u8>>,
    envelope_size: Option<u32>,
    mode: Option<u8>,
    known_encoding: Option<u8>,
    via_length: Option<usize>,
}

fn read_oracle(path: &Path) -> BTreeMap<usize, Row> {
    let oracle = fs::read_to_string(path).expect("oracle lisible");
    let mut rows = BTreeMap::new();
    for line in oracle.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 9, "ligne d'oracle malformee : {line}");
        let number = |field: &str| (field != "-").then(|| field.parse::<u32>().expect("entier"));
        rows.insert(
            fields[1].parse().expect("numero de trame"),
            Row {
                tcp_length: fields[2].parse().expect("longueur TCP"),
                records: fields[3].parse().expect("nombre d'enregistrements"),
                types: (fields[4] != "-").then(|| {
                    fields[4]
                        .split(',')
                        .map(|kind| kind.parse().expect("type"))
                        .collect()
                }),
                envelope_size: number(fields[5]),
                mode: number(fields[6]).map(|mode| mode as u8),
                known_encoding: number(fields[7]).map(|encoding| encoding as u8),
                via_length: number(fields[8]).map(|length| length as usize),
            },
        );
    }
    rows
}

/// L'etiquette et la charge du flux le plus interne.
fn innermost<'a>(flow: &'a PacketFlow<'a>) -> (Option<&'static str>, Option<&'a [u8]>) {
    let flows = flow.flatten();
    let inner = flows.last().expect("flatten n'est jamais vide");
    (
        inner
            .application
            .as_ref()
            .map(|application| application.protocol.label()),
        inner
            .transport
            .as_ref()
            .and_then(|transport| transport.payload),
    )
}

fn frames() -> Vec<(packet_parser::LinkType, Vec<u8>)> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(CAPTURE);
    let FileRead::Frames {
        frames,
        read_error_after: None,
    } = read_capture(&path)
    else {
        panic!("{CAPTURE} illisible");
    };
    frames
}

fn mode_number(mode: NmfMode) -> u8 {
    match mode {
        NmfMode::SingletonUnsized => 1,
        NmfMode::Duplex => 2,
        NmfMode::Simplex => 3,
        NmfMode::SingletonSized => 4,
        _ => panic!("mode inconnu du test : {mode:?}"),
    }
}

#[test]
fn every_record_segment_matches_the_tshark_oracle() {
    let rows = read_oracle(&Path::new(env!("CARGO_MANIFEST_DIR")).join(ORACLE));
    assert_eq!(rows.len(), 23);

    let mut compared = 0;
    for (index, (link_type, data)) in frames().iter().enumerate() {
        let number = index + 1;
        let flow = parse(*link_type, data).expect("trame lisible");
        let (label, payload) = innermost(&flow);
        let Some(row) = rows.get(&number) else {
            assert_eq!(label, None, "trame {number} : segment sans charge");
            continue;
        };
        let payload = payload.expect("charge TCP");
        assert_eq!(payload.len(), row.tcp_length, "trame {number}");

        if !RECORD_SEGMENTS.contains(&number) {
            // Segment de suite : ni la sonde ni le decodeur n'en veulent.
            assert_eq!(label, Some("Unknown"), "trame {number}");
            assert!(NmfSegment::try_from(payload).is_err(), "trame {number}");
            continue;
        }

        let segment = NmfSegment::try_from(payload)
            .unwrap_or_else(|error| panic!("trame {number} : {error}"));
        let records: Vec<_> = segment.records().collect();
        assert_eq!(records.len(), row.records, "trame {number}");
        let types: Vec<u8> = records.iter().map(NmfRecord::record_type).collect();
        assert_eq!(Some(&types), row.types.as_ref(), "trame {number}");

        let mut envelope_size = None;
        let mut mode = None;
        let mut known_encoding = None;
        let mut via_length = None;
        let mut consumed = 0;
        for record in &records {
            match *record {
                NmfRecord::SizedEnvelope {
                    declared_length,
                    payload: content,
                } => {
                    envelope_size = Some(declared_length);
                    // L'en-tete : le type et la taille sur deux ou trois octets.
                    let header = payload.len() - content.len();
                    assert!((3..=4).contains(&header), "trame {number}");
                    assert_eq!(
                        record.is_truncated(),
                        (declared_length as usize) > content.len(),
                        "trame {number}"
                    );
                    consumed += header + content.len();
                }
                NmfRecord::Mode(value) => {
                    mode = Some(mode_number(value));
                    consumed += 2;
                }
                NmfRecord::KnownEncoding(value) => {
                    known_encoding = Some(value);
                    consumed += 2;
                }
                NmfRecord::Via(via) => {
                    via_length = Some(via.len());
                    assert!(via.starts_with("net.tcp://"), "trame {number}");
                    consumed += 2 + via.len();
                }
                NmfRecord::Version { major, minor } => {
                    assert_eq!((major, minor), (1, 0), "trame {number}");
                    consumed += 3;
                }
                NmfRecord::End | NmfRecord::PreambleAck | NmfRecord::PreambleEnd => consumed += 1,
                other => panic!("trame {number} : enregistrement inattendu {other:?}"),
            }
        }
        assert_eq!(consumed, payload.len(), "trame {number}");
        assert_eq!(envelope_size, row.envelope_size, "trame {number}");
        assert_eq!(mode, row.mode, "trame {number}");
        assert_eq!(known_encoding, row.known_encoding, "trame {number}");
        assert_eq!(via_length, row.via_length, "trame {number}");

        // A l'aveugle : le preambule et les enveloppes, pas les
        // enregistrements d'un octet.
        let expected = if matches!(types[0], 0x00 | 0x06) {
            "NMF"
        } else {
            "Unknown"
        };
        assert_eq!(label, Some(expected), "trame {number}");
        compared += 1;
    }
    assert_eq!(compared, RECORD_SEGMENTS.len());
}

#[test]
fn declared_ports_name_the_one_byte_records_too() {
    let mut config = ParseConfig::default();
    for port in SERVICE_PORTS {
        config = config.decode_as(port, DecodeAsProtocol::Nmf);
    }
    let mut named = Vec::new();
    for (index, (link_type, data)) in frames().iter().enumerate() {
        let flow = parse_with(*link_type, data, &config).expect("trame lisible");
        if innermost(&flow).0 == Some("NMF") {
            named.push(index + 1);
        }
    }
    assert_eq!(named, RECORD_SEGMENTS);
}

#[test]
fn the_long_envelope_is_cut_by_its_segment() {
    let (link_type, data) = &frames()[22];
    let flow = parse(*link_type, data).expect("trame lisible");
    let payload = innermost(&flow).1.expect("charge TCP");
    let segment = NmfSegment::try_from(payload).expect("enveloppe");
    let mut records = segment.records();
    let record = records.next().expect("un enregistrement");
    assert!(record.is_truncated());
    assert!(matches!(
        record,
        NmfRecord::SizedEnvelope { declared_length: 50_253, payload } if payload.len() == 1456
    ));
    assert_eq!(records.next(), None);
}
