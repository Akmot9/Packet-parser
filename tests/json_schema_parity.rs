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
//! capture du depot : la valeur et le texte (#193). L'egalite de deux
//! `Value` ignore l'ordre des membres — sans la feature `preserve_order` de
//! serde_json, un objet est une `BTreeMap` triee par cle ; avec elle,
//! l'egalite d'`IndexMap` l'ignore aussi. C'est ainsi que
//! `protocol_transport` et `ethertype`, a deux places differentes dans les
//! deux modeles, sont passes inapercus. La comparaison des valeurs reste :
//! elle separe un ecart de valeur d'un ecart d'ordre.

use std::{collections::BTreeMap, path::Path};

use packet_parser::{LinkType, parse};

mod common;
use common::{FileRead, collect_capture_files, read_capture};

#[test]
fn borrowed_and_owned_flows_serialize_to_the_same_json_on_the_whole_corpus() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("pcaps_exemple");
    let mut captures = Vec::new();
    collect_capture_files(&root, &mut captures);
    captures.sort();

    let mut compared = 0;
    let mut value_divergences = 0;
    let mut order_divergences = 0;
    let mut examples = Vec::new();
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
            let owned_flow = flow.to_owned_flow();
            let borrowed = serde_json::to_value(&flow).expect("flux borrowed serialisable");
            let owned = serde_json::to_value(&owned_flow).expect("flux owned serialisable");
            let borrowed_text = serde_json::to_string(&flow).expect("flux borrowed serialisable");
            let owned_text = serde_json::to_string(&owned_flow).expect("flux owned serialisable");
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
            for key in ["vlan", "vlan_stack"] {
                if borrowed["data_link"]["link_details"].get(key).is_some() {
                    *seen.entry(key).or_default() += 1;
                }
            }
            // La session PPPoE n'est pas serialisee : seul le modele borrowed
            // la porte, et la serialiser d'un seul cote ferait diverger ces
            // trames.
            if flow
                .data_link
                .as_ethernet()
                .is_some_and(|ethernet| ethernet.pppoe.is_some())
            {
                *seen.entry("pppoe").or_default() += 1;
            }
            match borrowed.get("protocol_transport").and_then(|p| p.as_str()) {
                Some("TCP") => *seen.entry("TCP").or_default() += 1,
                Some("UDP") => *seen.entry("UDP").or_default() += 1,
                _ => {}
            }

            let divergence = if borrowed != owned {
                value_divergences += 1;
                "valeurs differentes"
            } else if borrowed_text != owned_text {
                order_divergences += 1;
                "memes valeurs, ordre des cles different"
            } else {
                continue;
            };
            if examples.len() < 10 {
                examples.push(format!(
                    "{} trame {} ({divergence})\n  borrowed {borrowed_text}\n  owned    {owned_text}",
                    capture.display(),
                    index + 1
                ));
            }
        }
    }

    assert!(
        examples.is_empty(),
        "les deux modeles divergent sur {} trames sur {compared} : {value_divergences} par \
         les valeurs, {order_divergences} par le seul texte (ordre des cles)\n{}",
        value_divergences + order_divergences,
        examples.join("\n")
    );
    assert!(compared > 4_000, "trames comparees : {compared}");
    for label in [
        "internet",
        "transport",
        "application",
        "corrupted",
        "tunnel",
        "vlan",
        "vlan_stack",
        "pppoe",
        "TCP",
        "UDP",
    ] {
        assert!(
            seen.get(label).copied().unwrap_or(0) > 0,
            "le corpus n'exerce pas `{label}` : {seen:?}"
        );
    }
}

/// Trame de #193 : Ethernet, 802.1Q VID 104, IPv4 192.168.1.10 -> 8.8.8.8,
/// TCP SYN 12345 -> 80, 58 octets. tshark 4.6.6 la lit
/// `eth:ethertype:vlan:ethertype:ip:tcp`, VLAN 104, sommes de controle IPv4
/// et TCP « Good ».
const VLAN_TCP_SYN_HEX: &str = concat!(
    "020000000002020000000001810000680800", // Ethernet, 802.1Q VID 104
    "45000028000100004006a90dc0a8010a08080808", // IPv4
    "3039005000000001000000005002ffffad960000", // TCP SYN
);

/// Le JSON du modele owned, celui qui fait foi (CHANGELOG 11.0.0) et que lit
/// Sonar. Fige ici, son ordre ne peut pas changer sans que ce test le dise :
/// la comparaison des deux modeles laisserait passer un reordonnancement
/// des deux a la fois.
const VLAN_TCP_SYN_JSON: &str = concat!(
    r#"{"data_link":{"link_type":1,"network_protocol":{"kind":"ipv4"},"#,
    r#""link_kind":"ethernet","link_details":{"destination_mac":"02:00:00:00:00:02","#,
    r#""source_mac":"02:00:00:00:00:01","ethertype":"IPv4","#,
    r#""vlan":{"id":104,"pcp":0,"dei":false}}},"#,
    r#""source_ip":"192.168.1.10","ip_source_type":"Private","#,
    r#""destination_ip":"8.8.8.8","ip_destination_type":"Public","#,
    r#""protocol_internet":"IPv4","#,
    r#""source_port":12345,"destination_port":80,"protocol_transport":"TCP"}"#,
);

/// #193 : les memes valeurs ne suffisent pas. Avant le correctif, le modele
/// borrowed ecrivait `vlan` avant `ethertype` et `protocol_transport` avant
/// les ports ; un fichier golden, l'empreinte d'une ligne JSONL ou un `diff`
/// entre les deux exports voyaient deux flux differents pour la meme trame.
#[test]
fn borrowed_and_owned_flows_serialize_to_the_same_text_on_a_vlan_tcp_syn() {
    let bytes = hex::decode(VLAN_TCP_SYN_HEX).expect("hex valide");
    assert_eq!(bytes.len(), 58);
    let flow = parse(LinkType::ETHERNET, &bytes).expect("trame lisible");
    assert!(flow.corrupted.is_none(), "{:?}", flow.corrupted);
    let owned = flow.to_owned_flow();

    assert_eq!(
        serde_json::to_value(&flow).expect("flux borrowed serialisable"),
        serde_json::to_value(&owned).expect("flux owned serialisable")
    );
    assert_eq!(
        serde_json::to_string(&owned).expect("flux owned serialisable"),
        VLAN_TCP_SYN_JSON,
        "modele owned"
    );
    assert_eq!(
        serde_json::to_string(&flow).expect("flux borrowed serialisable"),
        VLAN_TCP_SYN_JSON,
        "modele borrowed"
    );
}
