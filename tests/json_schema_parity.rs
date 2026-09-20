// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Un seul schema JSON pour les deux modeles (issue #22, epic #76).
//!
//! `PacketFlow` (borrowed) et `PacketFlowOwned` decrivaient la meme trame
//! avec deux jeux de cles L3/L4 sans une seule cle commune, et une casse
//! differente pour le protocole de transport. Les tests d'egalite existants
//! ne comparaient que `data_link` : personne ne l'avait vu.
//!
//! Ce test compare le JSON du **flux complet**, sur chaque trame de chaque
//! capture du depot.

use std::{collections::BTreeMap, path::Path};

use packet_parser::parse;

mod common;
use common::{FileRead, collect_capture_files, read_capture};

#[test]
fn borrowed_and_owned_flows_serialize_to_the_same_json_on_the_whole_corpus() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("pcaps_exemple");
    let mut captures = Vec::new();
    collect_capture_files(&root, &mut captures);
    captures.sort();

    let mut compared = 0;
    let mut divergences = Vec::new();
    // Ce que le corpus exerce, pour qu'un test vert prouve quelque chose.
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();

    for capture in &captures {
        let FileRead::Frames { frames, .. } = read_capture(capture) else {
            continue;
        };
        for (index, (link_type, data)) in frames.iter().enumerate() {
            let Ok(flow) = parse(*link_type, data) else {
                continue;
            };
            let borrowed = serde_json::to_value(&flow).expect("flux borrowed serialisable");
            let owned =
                serde_json::to_value(flow.to_owned_flow()).expect("flux owned serialisable");
            compared += 1;

            for (key, label) in [
                ("protocol_transport", "transport"),
                ("source_ip", "internet"),
                ("application_protocol", "application"),
                ("corrupted", "corrupted"),
                ("inner", "tunnel"),
            ] {
                if borrowed.get(key).is_some() {
                    *seen.entry(label).or_default() += 1;
                }
            }
            if borrowed["data_link"]["link_details"].get("vlan").is_some() {
                *seen.entry("vlan").or_default() += 1;
            }
            match borrowed.get("protocol_transport").and_then(|p| p.as_str()) {
                Some("TCP") => *seen.entry("TCP").or_default() += 1,
                Some("UDP") => *seen.entry("UDP").or_default() += 1,
                _ => {}
            }

            if borrowed != owned && divergences.len() < 10 {
                divergences.push(format!(
                    "{} trame {}\n  borrowed {borrowed}\n  owned    {owned}",
                    capture.display(),
                    index + 1
                ));
            }
        }
    }

    assert!(
        divergences.is_empty(),
        "les deux modeles divergent :\n{}",
        divergences.join("\n")
    );
    assert!(compared > 4_000, "trames comparees : {compared}");
    for label in [
        "internet",
        "transport",
        "application",
        "corrupted",
        "tunnel",
        "vlan",
        "TCP",
        "UDP",
    ] {
        assert!(
            seen.get(label).copied().unwrap_or(0) > 0,
            "le corpus n'exerce pas `{label}` : {seen:?}"
        );
    }
}
