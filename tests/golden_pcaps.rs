// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Snapshot de classification applicative sur le corpus reel (audit 8.1.0
//! §5.3, prerequis a toute refonte du dispatch L7) : l'histogramme
//! {etiquette -> nombre de flux} sur `pcaps_exemple/protocols/` (hors
//! `s7comm/`, couvert par sa propre regression, selection < 2 Mo) est fige.
//!
//! Une regression de classification — un protocole qui cesse d'etre reconnu,
//! un faux positif qui apparait — casse ce test avec un diff lisible. Toute
//! evolution volontaire du dispatch doit mettre a jour l'attendu **dans le
//! meme commit**, avec sa justification.

use std::collections::BTreeMap;
use std::path::Path;

use packet_parser::parse;

mod common;
use common::{FileRead, collect_capture_files, read_capture};

/// Etiquette d'un flux : son protocole applicatif, ou un marqueur explicite.
const NO_APPLICATION: &str = "(sans application)";
const LINK_ERROR: &str = "(erreur L2)";

fn classification_histogram() -> BTreeMap<String, usize> {
    let protocol_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("pcaps_exemple")
        .join("protocols");
    let mut captures = Vec::new();
    collect_capture_files(protocol_dir.as_path(), &mut captures);
    captures.sort();
    assert!(!captures.is_empty(), "corpus introuvable");

    let mut histogram: BTreeMap<String, usize> = BTreeMap::new();
    for path in &captures {
        let FileRead::Frames { frames, .. } = read_capture(path) else {
            continue;
        };
        for (link_type, data) in &frames {
            let Ok(flow) = parse(*link_type, data) else {
                *histogram.entry(LINK_ERROR.to_string()).or_default() += 1;
                continue;
            };
            for flattened in flow.flatten() {
                let label = flattened
                    .application
                    .as_ref()
                    .map_or(NO_APPLICATION, |application| {
                        application.application_protocol
                    });
                *histogram.entry(label.to_string()).or_default() += 1;
            }
        }
    }
    histogram
}

#[test]
fn application_classification_histogram_is_frozen() {
    let actual = classification_histogram();

    // Fige le 2026-08-19 sur 58 captures (2 893 trames), avant la refonte du
    // dispatch L7 en table declarative. Les 42 « erreur L2 » sont les trames
    // de mqtt_packets_MosquittoLinux.pcap et consorts au LINKTYPE non
    // supporte, deja comptees par la regression s7comm.
    let expected: BTreeMap<String, usize> = [
        (LINK_ERROR, 42_usize),
        (NO_APPLICATION, 1233),
        ("DHCP", 6),
        ("DHCPv6", 4),
        ("DNS", 102),
        ("HTTP", 62),
        ("MQTT", 38),
        ("ModbusTCP", 383),
        ("NNTP", 6),
        ("NTP", 4),
        ("SMTP", 6),
        ("TLS", 584),
        ("Unknown", 419),
        ("mDNS", 4),
    ]
    .into_iter()
    .map(|(label, count)| (label.to_string(), count))
    .collect();

    assert_eq!(
        actual, expected,
        "\nhistogramme observe (a figer dans `expected` si le changement est voulu) :\n{:#?}\n",
        actual
    );
}
