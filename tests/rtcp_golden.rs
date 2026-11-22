// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests RTCP (#354) sur des trames reelles : un SR + SDES + BYE
//! d'un appel SIP (`protocols/sip/wireshark_aaa.pcap`), onze messages de
//! retour seuls d'un appel LINE (`protocols/ntp/ndpi_line.pcap`, RTCP de
//! taille reduite) et quarante datagrammes de terrain censures
//! (`protocols/rtcp/terrain_rtcp_censure.pcap`, voir son `SOURCE.md`) : SR
//! + SDES et RR + SDES.
//!
//! L'oracle est tshark 4.6.9 (`tools/rtcp_oracle.sh`) : pour chaque
//! datagramme, les types et les longueurs des paquets, le SSRC des
//! emetteurs et les informations d'emetteur d'un SR, figes dans
//! `tests/data/rtcp_tshark_oracle.tsv`.
//!
//! La crate et tshark nomment RTCP les memes datagrammes de ces captures.

use std::{collections::BTreeMap, fs, path::Path};

use packet_parser::{
    PacketFlow, parse,
    parse::application::protocols::rtcp::{RTCP_HEADER_LENGTH, RtcpCompound},
};

mod common;
use common::{FileRead, read_capture};

const ORACLE: &str = "tests/data/rtcp_tshark_oracle.tsv";
const CAPTURES: [&str; 3] = [
    "pcaps_exemple/protocols/sip/wireshark_aaa.pcap",
    "pcaps_exemple/protocols/ntp/ndpi_line.pcap",
    "pcaps_exemple/protocols/rtcp/terrain_rtcp_censure.pcap",
];

/// Une ligne de l'oracle.
struct Row {
    /// Longueur UDP, en-tete de huit octets compris.
    udp_length: usize,
    types: Vec<u8>,
    /// Longueurs en mots de quatre octets, moins un.
    lengths: Vec<usize>,
    sender_ssrcs: Vec<u32>,
    /// NTP (poids fort, poids faible), horodatage RTP, paquets, octets.
    sender_info: Option<(u32, u32, u32, u32, u32)>,
}

fn read_oracle(path: &Path) -> BTreeMap<(String, usize), Row> {
    let oracle = fs::read_to_string(path).expect("oracle lisible");
    let mut rows = BTreeMap::new();
    for line in oracle.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 11, "ligne d'oracle malformee : {line}");
        fn list(field: &str) -> Vec<&str> {
            if field == "-" {
                Vec::new()
            } else {
                field.split(',').collect()
            }
        }
        let number = |field: &str| field.parse::<u32>().expect("entier");
        rows.insert(
            (
                fields[0].to_string(),
                fields[1].parse().expect("numero de trame"),
            ),
            Row {
                udp_length: fields[2].parse().expect("longueur UDP"),
                types: list(fields[3])
                    .iter()
                    .map(|kind| kind.parse().expect("type"))
                    .collect(),
                lengths: list(fields[4])
                    .iter()
                    .map(|length| length.parse().expect("longueur"))
                    .collect(),
                sender_ssrcs: list(fields[5])
                    .iter()
                    .map(|ssrc| {
                        u32::from_str_radix(ssrc.trim_start_matches("0x"), 16).expect("SSRC")
                    })
                    .collect(),
                sender_info: (fields[6] != "-").then(|| {
                    (
                        number(fields[6]),
                        number(fields[7]),
                        number(fields[8]),
                        number(fields[9]),
                        number(fields[10]),
                    )
                }),
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

#[test]
fn every_rtcp_datagram_matches_the_tshark_oracle() {
    let rows = read_oracle(&Path::new(env!("CARGO_MANIFEST_DIR")).join(ORACLE));
    assert_eq!(rows.len(), 52);

    let mut per_capture: BTreeMap<String, usize> = BTreeMap::new();
    for capture in CAPTURES {
        let name = Path::new(capture)
            .file_name()
            .and_then(|name| name.to_str())
            .expect("nom de fichier")
            .to_string();
        for (index, (link_type, data)) in frames(capture).iter().enumerate() {
            let number = index + 1;
            let key = (name.clone(), number);
            let Ok(flow) = parse(*link_type, data) else {
                assert!(!rows.contains_key(&key), "{name} trame {number}");
                continue;
            };
            let (label, payload) = innermost(&flow);
            let Some(row) = rows.get(&key) else {
                assert_ne!(label, Some("RTCP"), "{name} trame {number}");
                continue;
            };
            *per_capture.entry(name.clone()).or_default() += 1;
            assert_eq!(label, Some("RTCP"), "{name} trame {number}");

            let payload = payload.expect("charge UDP");
            assert_eq!(payload.len() + 8, row.udp_length, "{name} trame {number}");
            let compound = RtcpCompound::try_from(payload)
                .unwrap_or_else(|error| panic!("{name} trame {number} : {error}"));
            assert_eq!(compound.as_bytes(), payload);
            let packets: Vec<_> = compound.packets().collect();
            let types: Vec<u8> = packets
                .iter()
                .map(|packet| packet.packet_type.as_u8())
                .collect();
            assert_eq!(types, row.types, "{name} trame {number}");
            let lengths: Vec<usize> = packets.iter().map(|packet| packet.body.len() / 4).collect();
            assert_eq!(lengths, row.lengths, "{name} trame {number}");
            // Les paquets pavent le datagramme.
            assert_eq!(
                packets
                    .iter()
                    .map(|packet| RTCP_HEADER_LENGTH + packet.body.len())
                    .sum::<usize>(),
                payload.len(),
                "{name} trame {number}"
            );
            let ssrcs: Vec<u32> = packets
                .iter()
                .filter_map(|packet| packet.sender_ssrc())
                .collect();
            assert_eq!(ssrcs, row.sender_ssrcs, "{name} trame {number}");
            let info = packets.iter().find_map(|packet| packet.sender_info());
            assert_eq!(
                info.map(|info| (
                    (info.ntp_timestamp >> 32) as u32,
                    info.ntp_timestamp as u32,
                    info.rtp_timestamp,
                    info.packet_count,
                    info.octet_count,
                )),
                row.sender_info,
                "{name} trame {number}"
            );
        }
    }
    assert_eq!(
        per_capture,
        BTreeMap::from([
            ("ndpi_line.pcap".to_string(), 11),
            ("terrain_rtcp_censure.pcap".to_string(), 40),
            ("wireshark_aaa.pcap".to_string(), 1),
        ])
    );
}
