// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests HTTP/1.x sur trames reelles (#176) : requetes et reponses,
//! telles qu'elles tiennent dans un segment TCP.
//!
//! Captures : tout `pcaps_exemple/protocols/` et `The-Ultimate-PCAP.pcapng`.
//! L'oracle est tshark 4.6.6 sans reassemblage TCP (`tools/http_oracle.sh`),
//! hors retransmissions, que tshark ne dissèque pas, et hors HTTP dechiffre
//! dans TLS (`tls12-dsb.pcapng`, cle dans le fichier : la crate voit du
//! TLS). Pour chaque trame HTTP : genre, version, methode et URI, ou code et
//! phrase, figes dans `tests/data/http_tshark_oracle.tsv` et compares ici
//! trame par trame. Toute trame que la crate etiquette HTTP doit etre dans
//! l'oracle, et reciproquement — sauf les retransmissions TCP, que l'oracle
//! liste sans les dissequer : la crate, sans etat, les etiquette comme les
//! segments d'origine, et elles sont ecartees de la comparaison. Sur
//! `http-on-port-5432.pcap`, tshark a besoin d'un « Decode As » que la sonde
//! aveugle de la crate n'a pas.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use packet_parser::{
    PacketFlow, parse,
    parse::application::protocols::http::{HttpRequest, HttpResponse},
};

mod common;
use common::{FileRead, collect_capture_files, read_capture};

const CORPUS: &str = "pcaps_exemple/protocols";
const ULTIMATE: &str = "pcaps_exemple/The-Ultimate-PCAP.pcapng";
const ORACLE: &str = "tests/data/http_tshark_oracle.tsv";

/// Une ligne de l'oracle : genre, version, methode ou code, URI ou phrase.
#[derive(Debug, PartialEq, Eq)]
struct OracleRow {
    kind: String,
    version: String,
    what: String,
    detail: String,
}

fn read_oracle(path: &Path) -> BTreeMap<String, BTreeMap<usize, OracleRow>> {
    let oracle = fs::read_to_string(path).expect("oracle lisible");
    let mut expected: BTreeMap<String, BTreeMap<usize, OracleRow>> = BTreeMap::new();
    for line in oracle.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 6, "ligne d'oracle malformee : {line}");
        let frame: usize = fields[1].parse().expect("numero de trame");
        let row = OracleRow {
            kind: fields[2].to_string(),
            version: fields[3].to_string(),
            what: fields[4].to_string(),
            detail: fields[5].to_string(),
        };
        let previous = expected
            .entry(fields[0].to_string())
            .or_default()
            .insert(frame, row);
        assert!(previous.is_none(), "trame {frame} en double dans l'oracle");
    }
    expected
}

fn dash_if_empty(value: &str) -> String {
    if value.is_empty() {
        "-".to_string()
    } else {
        value.to_string()
    }
}

/// La ligne d'oracle que la crate produit pour un flux etiquete HTTP, par le
/// premier message du segment : une requete, sinon une reponse.
fn http_row(flow: &PacketFlow<'_>) -> Option<OracleRow> {
    for flattened in flow.flatten() {
        let Some(application) = flattened.application.as_ref() else {
            continue;
        };
        if application.application_protocol != "HTTP" {
            continue;
        }
        let payload = flattened
            .transport
            .as_ref()
            .and_then(|transport| transport.payload)
            .expect("une trame etiquetee HTTP a un payload");
        if let Ok(request) = HttpRequest::try_from(payload) {
            return Some(OracleRow {
                kind: "request".to_string(),
                version: request.version.to_string(),
                what: request.method.to_string(),
                detail: dash_if_empty(request.uri),
            });
        }
        let response = HttpResponse::try_from(payload).expect("une trame etiquetee HTTP se decode");
        return Some(OracleRow {
            kind: "response".to_string(),
            version: response.version.to_string(),
            what: response.status_code.to_string(),
            detail: dash_if_empty(response.reason),
        });
    }
    None
}

/// Parite avec tshark : chaque trame de l'oracle est etiquetee HTTP et
/// decodee a l'identique (genre, version, methode et URI ou code et phrase),
/// et aucune autre trame du corpus ne l'est.
#[test]
fn every_frame_matches_the_tshark_oracle() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let expected = read_oracle(&base.join(ORACLE));
    let oracle_rows: usize = expected.values().map(BTreeMap::len).sum();
    let mut captures: Vec<PathBuf> = Vec::new();
    collect_capture_files(&base.join(CORPUS), &mut captures);
    captures.push(base.join(ULTIMATE));
    captures.sort();

    let mut checked = 0;
    let mut retransmissions = 0;
    let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
    let mut missing = Vec::new();
    let mut extra = Vec::new();
    for path in &captures {
        let file = path.file_name().unwrap().to_string_lossy().to_string();
        let FileRead::Frames { frames, .. } = read_capture(path) else {
            continue;
        };
        let empty = BTreeMap::new();
        let oracle_frames = expected.get(&file).unwrap_or(&empty);
        for (index, (link_type, data)) in frames.iter().enumerate() {
            let number = index + 1;
            let Ok(flow) = parse(*link_type, data) else {
                continue;
            };
            match (oracle_frames.get(&number), http_row(&flow)) {
                (Some(expected), actual) if expected.kind == "retransmission" => {
                    retransmissions += usize::from(actual.is_some());
                }
                (Some(expected), Some(actual)) => {
                    assert_eq!(&actual, expected, "{file}:{number}");
                    *by_kind.entry(actual.kind.clone()).or_default() += 1;
                    checked += 1;
                }
                (Some(expected), None) => missing.push(format!("{file}:{number} {expected:?}")),
                (None, Some(actual)) => extra.push(format!("{file}:{number} {actual:?}")),
                (None, None) => {}
            }
        }
    }
    assert!(
        missing.is_empty(),
        "trames HTTP de l'oracle que la crate n'etiquette pas :\n{}",
        missing.join("\n")
    );
    assert!(
        extra.is_empty(),
        "trames etiquetees HTTP par la crate, absentes de l'oracle :\n{}",
        extra.join("\n")
    );
    let retransmission_rows: usize = expected
        .values()
        .flat_map(BTreeMap::values)
        .filter(|row| row.kind == "retransmission")
        .count();
    assert_eq!(
        checked + retransmission_rows,
        oracle_rows,
        "toutes les lignes de l'oracle verifiees"
    );
    assert_eq!(by_kind.get("request"), Some(&144));
    assert_eq!(by_kind.get("response"), Some(&152));
    // Six retransmissions d'un segment HTTP, que tshark ne dissèque pas :
    // trois du GET vers le proxy 3128 de l'Ultimate PCAP et trois reponses
    // (Ultimate PCAP, dns_isp_hijack, tcp_ports).
    assert_eq!(retransmissions, 6);
}
