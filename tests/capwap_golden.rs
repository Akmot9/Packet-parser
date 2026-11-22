// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests CAPWAP (#355) sur des captures reelles, toutes deja
//! versionnees : le canal de controle en clair et sous DTLS, les keep-alive
//! du canal de donnees et les trames 802.11 que le tunnel ne decapsule pas.
//!
//! L'oracle est tshark 4.6.9 (`tools/capwap_oracle.sh`) : pour chaque
//! datagramme CAPWAP sur UDP 5246 ou 5247, le type de preambule, HLEN, le
//! WBID et les drapeaux, figes dans `tests/data/capwap_tshark_oracle.tsv`.
//!
//! La crate et tshark nomment CAPWAP les memes datagrammes. Un flux interne
//! n'existe que pour les trames 802.11 de donnees que le tunnel sait peler :
//! ces captures n'en portent pas, les tests du tunnel les couvrent.

use std::{collections::BTreeMap, fs, path::Path};

use packet_parser::parse;

mod common;
use common::{FileRead, read_capture};

const ORACLE: &str = "tests/data/capwap_tshark_oracle.tsv";
const CAPTURES: [&str; 4] = [
    "pcaps_exemple/capwap-only.pcap",
    "pcaps_exemple/capwap-association-valid.pcapng",
    "pcaps_exemple/The-Ultimate-PCAP.pcapng",
    "pcaps_exemple/vlan0--packet-capture CAPWAP a partir de ligne 520  (Ap = 192_168.0.104 ) + radius _ partir de la ligne 33003 .cap",
];

/// Une ligne de l'oracle.
struct Row {
    port: u16,
    preamble_type: u8,
    header_words: Option<u8>,
    wbid: Option<u8>,
    flags: Option<u32>,
}

fn read_oracle(path: &Path) -> BTreeMap<(String, usize), Row> {
    let oracle = fs::read_to_string(path).expect("oracle lisible");
    let mut rows = BTreeMap::new();
    for line in oracle.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 8, "ligne d'oracle malformee : {line}");
        let optional = |field: &str| (field != "-").then(|| field.parse::<u8>().expect("entier"));
        rows.insert(
            (
                fields[0].to_string(),
                fields[1].parse().expect("numero de trame"),
            ),
            Row {
                port: fields[2].parse().expect("port"),
                preamble_type: fields[3].parse().expect("type de preambule"),
                header_words: optional(fields[4]),
                wbid: optional(fields[5]),
                flags: (fields[6] != "-").then(|| {
                    u32::from_str_radix(fields[6].trim_start_matches("0x"), 16).expect("drapeaux")
                }),
            },
        );
    }
    rows
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
fn every_capwap_datagram_matches_the_tshark_oracle() {
    let rows = read_oracle(&Path::new(env!("CARGO_MANIFEST_DIR")).join(ORACLE));
    assert_eq!(rows.len(), 341);

    // (controle en clair, DTLS, donnees sans flux interne, donnees pelees)
    let mut shapes = [0usize; 4];
    for capture in CAPTURES {
        let name = file_name(capture);
        for (index, (link_type, data)) in frames(capture).iter().enumerate() {
            let number = index + 1;
            let key = (name.clone(), number);
            let Ok(flow) = parse(*link_type, data) else {
                assert!(!rows.contains_key(&key), "{name} trame {number}");
                continue;
            };
            let label = flow
                .application
                .as_ref()
                .map(|application| application.protocol.label());
            let Some(row) = rows.get(&key) else {
                assert_ne!(label, Some("CAPWAP"), "{name} trame {number}");
                continue;
            };
            assert_eq!(label, Some("CAPWAP"), "{name} trame {number}");

            let transport = flow.transport.as_ref().expect("UDP");
            let ports = [transport.source_port, transport.destination_port];
            assert!(ports.contains(&Some(row.port)), "{name} trame {number}");
            let payload = transport.payload.expect("charge UDP");
            assert_eq!(payload[0] >> 4, 0, "{name} trame {number} : version");
            assert_eq!(
                payload[0] & 0x0f,
                row.preamble_type,
                "{name} trame {number}"
            );

            if row.preamble_type == 1 {
                // Preambule DTLS : rien d'autre n'est lu, aucun flux interne.
                assert!(flow.inner.is_none(), "{name} trame {number}");
                shapes[1] += 1;
                continue;
            }
            assert_eq!(
                Some(payload[1] >> 3),
                row.header_words,
                "{name} trame {number}"
            );
            assert_eq!(
                Some((payload[2] >> 1) & 0x1f),
                row.wbid,
                "{name} trame {number}"
            );
            // T, F, L, W, M, K puis trois bits reserves : les neuf derniers
            // bits des octets 2 et 3.
            let flags = u32::from(u16::from_be_bytes([payload[2], payload[3]]) & 0x01ff);
            assert_eq!(Some(flags), row.flags, "{name} trame {number}");

            match (row.port, flow.inner.is_some()) {
                (5246, false) => shapes[0] += 1,
                (5247, false) => shapes[2] += 1,
                (5247, true) => shapes[3] += 1,
                other => panic!("{name} trame {number} : forme inattendue {other:?}"),
            }
        }
    }
    // Aucune de ces trames 802.11 n'est une trame de donnees que le tunnel
    // pele : 12 keep-alive et 11 trames de gestion restent sans flux interne.
    assert_eq!(shapes, [34, 284, 23, 0]);
}
