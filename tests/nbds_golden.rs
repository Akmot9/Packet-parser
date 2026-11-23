// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests du service de datagrammes NetBIOS (NBDS, #377) sur toutes
//! les captures de `pcaps_exemple/protocols/` : les 165 datagrammes de
//! `netbios/smb-browser-elections.pcapng` (voir son `SOURCE.md`) et les 14
//! epars dans quatre autres dossiers, tous des annonces et des elections du
//! service Browser.
//!
//! L'oracle est tshark 4.6.9 (`tools/nbds_oracle.sh`) : type, drapeaux,
//! identifiant, adresse et port source, longueur annoncee, decalage et les
//! deux noms de chaque datagramme, figes dans
//! `tests/data/nbds_tshark_oracle.tsv`.
//!
//! Oracle negatif : aucune autre trame de ces captures ne sort `NBDS`, et
//! aucune charge d'UDP 138 n'echappe a l'oracle.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use packet_parser::{
    parse,
    parse::application::protocols::netbios::{NbdsBody, NbdsMessageType, NbdsPacket, NetbiosName},
};

mod common;
use common::{FileRead, collect_capture_files, read_capture};

const ORACLE: &str = "tests/data/nbds_tshark_oracle.tsv";
const CORPUS: &str = "pcaps_exemple/protocols";

/// Le nom comme tshark l'ecrit : quinze octets sans les espaces de fin, un
/// octet non imprimable en `<xx>`, puis le suffixe en `<xx>`.
fn tshark_name(name: &NetbiosName) -> String {
    let mut text = String::new();
    for byte in name.name {
        if (0x20..=0x7e).contains(&byte) {
            text.push(char::from(byte));
        } else {
            text.push_str(&format!("<{byte:02x}>"));
        }
    }
    format!("{}<{:02x}>", text.trim_end_matches(' '), name.suffix)
}

#[test]
fn every_nbds_datagram_matches_the_tshark_oracle() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let oracle = fs::read_to_string(base.join(ORACLE)).expect("oracle lisible");
    let mut rows: BTreeMap<(String, usize), Vec<String>> = BTreeMap::new();
    for line in oracle.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<String> = line.split('\t').map(str::to_string).collect();
        assert_eq!(fields.len(), 12, "ligne d'oracle malformee : {line}");
        let frame = fields[1].parse().expect("numero de trame");
        rows.insert((fields[0].clone(), frame), fields);
    }
    assert_eq!(rows.len(), 179);

    let corpus = base.join(CORPUS);
    let mut captures = Vec::new();
    collect_capture_files(&corpus, &mut captures);
    captures.sort();

    let mut per_capture: BTreeMap<String, usize> = BTreeMap::new();
    let mut flags = BTreeMap::new();
    let mut names = BTreeSet::new();
    let mut user_data = 0usize;
    for path in &captures {
        let name = path
            .strip_prefix(&corpus)
            .expect("capture du corpus")
            .to_string_lossy()
            .replace('\\', "/");
        let FileRead::Frames { frames, .. } = read_capture(path) else {
            continue;
        };
        for (index, (link_type, data)) in frames.iter().enumerate() {
            let number = index + 1;
            let Ok(flow) = parse(*link_type, data) else {
                assert!(
                    !rows.contains_key(&(name.clone(), number)),
                    "{name} {number}"
                );
                continue;
            };
            let flow = *flow.flatten().last().expect("au moins un flux");
            let label = flow
                .application
                .as_ref()
                .map(|application| application.protocol.label());
            let transport = flow.transport.as_ref();
            let on_port = transport.is_some_and(|transport| {
                transport.protocol == packet_parser::TransportProtocol::Udp
                    && (transport.source_port == Some(138)
                        || transport.destination_port == Some(138))
            });
            let Some(row) = rows.get(&(name.clone(), number)) else {
                assert_ne!(label, Some("NBDS"), "{name} trame {number}");
                assert!(!on_port, "{name} trame {number} : UDP 138 hors de l'oracle");
                continue;
            };
            *per_capture.entry(name.clone()).or_default() += 1;
            assert_eq!(label, Some("NBDS"), "{name} trame {number}");
            let payload = transport
                .and_then(|transport| transport.payload)
                .expect("charge UDP");
            let packet = NbdsPacket::try_from(payload)
                .unwrap_or_else(|error| panic!("{name} trame {number} : {error}"));
            let NbdsBody::Datagram(datagram) = packet.body else {
                panic!("{name} trame {number} : pas un datagramme");
            };
            let raw_flags = (packet.flags.node_type << 2)
                | (u8::from(packet.flags.first) << 1)
                | u8::from(packet.flags.more);
            let decoded = [
                name.clone(),
                number.to_string(),
                payload.len().to_string(),
                packet.message_type.code().to_string(),
                raw_flags.to_string(),
                packet.datagram_id.to_string(),
                packet.source_ip.to_string(),
                packet.source_port.to_string(),
                datagram.length.to_string(),
                datagram.packet_offset.to_string(),
                tshark_name(&datagram.source_name),
                tshark_name(&datagram.destination_name),
            ];
            assert_eq!(decoded.as_slice(), row.as_slice());

            // Les noms et les donnees pavent ce que la longueur annonce.
            assert_eq!(packet.message_type, NbdsMessageType::DirectGroup);
            assert!(datagram.source_scope.is_empty() && datagram.destination_scope.is_empty());
            assert_eq!(usize::from(datagram.length), 68 + datagram.user_data.len());
            assert_eq!(payload.len(), 14 + usize::from(datagram.length));
            // Les donnees sont du SMB sur mailslot.
            assert!(
                datagram.user_data.starts_with(b"\xffSMB"),
                "{name} {number}"
            );
            *flags.entry(raw_flags).or_insert(0usize) += 1;
            names.insert(tshark_name(&datagram.destination_name));
            user_data += datagram.user_data.len();
        }
    }
    assert_eq!(
        per_capture,
        BTreeMap::from([
            ("iec104/iti_090813_diverse.pcap".to_string(), 1),
            ("netbios/smb-browser-elections.pcapng".to_string(), 165),
            (
                "profinet/cisagov_profinet_io_cm_mixed_1.pcap".to_string(),
                2
            ),
            ("sip/wireshark_aaa.pcap".to_string(), 8),
            (
                "skinny/wireshark_10262_7911_CUCM_registration_RFC2833.pcapng".to_string(),
                3
            ),
        ])
    );
    // Noeuds B (drapeaux 0x02) et noeuds de type 3 (0x0e), premier et seul
    // fragment.
    assert_eq!(flags, BTreeMap::from([(0x02, 173), (0x0e, 6)]));
    assert_eq!(
        names.into_iter().collect::<Vec<_>>(),
        [
            "<01><02>__MSBROWSE__<02><01>",
            "ARBETSGRUPP<1e>",
            "ECI_DOMAIN<1d>",
            "SYNERITY<1d>",
            "SYNERITY<1e>",
            "WORKGROUP<1d>",
        ],
        "noms destinataires"
    );
    assert_eq!(user_data, 19_794, "octets de donnees utilisateur");
}
