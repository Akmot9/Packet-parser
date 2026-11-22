// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests RTP (#353, #364) sur des captures reelles.
//!
//! Captures, toutes deja versionnees : `The-Ultimate-PCAP.pcapng` (appels
//! SIP, video, SRTP), `protocols/ntp/ndpi_line.pcap` (un appel LINE, avec
//! extensions d'en-tete et bourrage) et les deux captures SIP de
//! `protocols/sip/` (G.711 et G.722).
//!
//! L'oracle est tshark 4.6.9 (`tools/rtp_oracle.sh`), son heuristique
//! `rtp_udp` activee et son dissecteur T.38 coupe : pour chaque trame RTP,
//! le type de charge, le marqueur, le numero de sequence, l'horodatage, le
//! SSRC, le nombre de CSRC, l'extension et le bourrage, figes dans
//! `tests/data/rtp_tshark_oracle.tsv`.
//!
//! RTP n'a pas de regle aveugle (#364) : sans Decode As, aucune trame de
//! ces captures ne sort `RTP`. Le port de destination de chaque trame de
//! l'oracle declare, les 15 011 sortent `RTP` et se decodent comme tshark
//! les lit. SRTP garde l'en-tete RTP en clair : ses 457 trames de
//! The-Ultimate-PCAP en font partie.

use std::{collections::BTreeMap, fs, path::Path};

use packet_parser::{
    DecodeAsProtocol, PacketFlow, ParseConfig, parse,
    parse::application::protocols::rtp::{RTP_FIXED_HEADER_LENGTH, RtpPacket},
    parse_with,
};

mod common;
use common::{FileRead, read_capture};

const ORACLE: &str = "tests/data/rtp_tshark_oracle.tsv";
const CAPTURES: [&str; 4] = [
    "pcaps_exemple/The-Ultimate-PCAP.pcapng",
    "pcaps_exemple/protocols/ntp/ndpi_line.pcap",
    "pcaps_exemple/protocols/sip/wireshark_FAX-Call-t38-CA-TDM-SIP-FB-1.pcap",
    "pcaps_exemple/protocols/sip/wireshark_aaa.pcap",
];

/// Captures ou la regle aveugle retiree nommait RTP huit trames a tort :
/// trois datagrammes RDP-UDP de The-Ultimate-PCAP, trois lignes de texte
/// sur UDP 7001 et deux Version Negotiation QUIC hors du port 443.
const FORMER_FALSE_POSITIVE_CAPTURES: [&str; 3] = [
    "pcaps_exemple/The-Ultimate-PCAP.pcapng",
    "pcaps_exemple/protocols/asterix/wireshark_8579_radardata.pcap",
    "pcaps_exemple/protocols/ntp/ndpi_quic_interop_V.pcapng",
];

/// Une ligne de l'oracle.
struct Row {
    payload_type: u8,
    marker: bool,
    sequence_number: u16,
    timestamp: u32,
    ssrc: u32,
    csrc_count: usize,
    /// Longueur de l'extension en mots de quatre octets.
    extension_words: Option<usize>,
    padding: Option<u8>,
    /// Longueur UDP, en-tete de huit octets compris.
    udp_length: usize,
}

fn read_oracle(path: &Path) -> BTreeMap<(String, usize), Row> {
    let oracle = fs::read_to_string(path).expect("oracle lisible");
    let mut rows = BTreeMap::new();
    for line in oracle.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 11, "ligne d'oracle malformee : {line}");
        let optional = |field: &str| (field != "-").then(|| field.parse().expect("entier"));
        rows.insert(
            (
                fields[0].to_string(),
                fields[1].parse().expect("numero de trame"),
            ),
            Row {
                payload_type: fields[2].parse().expect("type de charge"),
                marker: fields[3] == "1",
                sequence_number: fields[4].parse().expect("numero de sequence"),
                timestamp: fields[5].parse().expect("horodatage"),
                ssrc: u32::from_str_radix(fields[6].trim_start_matches("0x"), 16).expect("SSRC"),
                csrc_count: fields[7].parse().expect("nombre de CSRC"),
                extension_words: optional(fields[8]),
                padding: optional(fields[9]).map(|padding: usize| padding as u8),
                udp_length: fields[10].parse().expect("longueur UDP"),
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

fn file_name(capture: &str) -> String {
    Path::new(capture)
        .file_name()
        .and_then(|name| name.to_str())
        .expect("nom de fichier")
        .to_string()
}

#[test]
fn every_rtp_frame_matches_the_tshark_oracle() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let rows = read_oracle(&base.join(ORACLE));
    assert_eq!(rows.len(), 15_011);

    let mut per_capture: BTreeMap<String, usize> = BTreeMap::new();
    for capture in CAPTURES {
        let name = file_name(capture);
        for (index, (link_type, data)) in frames(capture).iter().enumerate() {
            let number = index + 1;
            let Ok(flow) = parse(*link_type, data) else {
                assert!(!rows.contains_key(&(name.clone(), number)));
                continue;
            };
            // Sans Decode As, rien ne sort RTP.
            let (label, _) = innermost(&flow);
            assert_ne!(label, Some("RTP"), "{name} trame {number}");
            let Some(row) = rows.get(&(name.clone(), number)) else {
                continue;
            };
            *per_capture.entry(name.clone()).or_default() += 1;

            // Le port de destination declare : la trame sort RTP.
            let port = flow
                .flatten()
                .last()
                .and_then(|inner| inner.transport.as_ref())
                .and_then(|transport| transport.destination_port)
                .expect("port UDP");
            let config = ParseConfig::new().decode_as(port, DecodeAsProtocol::Rtp);
            let declared = parse_with(*link_type, data, &config).expect("trame lisible");
            let (label, payload) = innermost(&declared);
            assert_eq!(label, Some("RTP"), "{name} trame {number}");

            let payload = payload.expect("charge UDP");
            let packet = RtpPacket::try_from(payload)
                .unwrap_or_else(|error| panic!("{name} trame {number} : {error}"));
            assert_eq!(packet.version, 2);
            assert_eq!(
                packet.payload_type, row.payload_type,
                "{name} trame {number}"
            );
            assert_eq!(packet.marker, row.marker, "{name} trame {number}");
            assert_eq!(
                packet.sequence_number, row.sequence_number,
                "{name} trame {number}"
            );
            assert_eq!(packet.timestamp, row.timestamp, "{name} trame {number}");
            assert_eq!(packet.ssrc, row.ssrc, "{name} trame {number}");
            assert_eq!(packet.csrc.len(), row.csrc_count, "{name} trame {number}");
            assert_eq!(
                packet.extension.map(|extension| extension.data.len() / 4),
                row.extension_words,
                "{name} trame {number}"
            );
            assert_eq!(
                (packet.padding_length != 0).then_some(packet.padding_length),
                row.padding,
                "{name} trame {number}"
            );
            // L'en-tete, la liste CSRC, l'extension, la charge et le
            // bourrage pavent le datagramme.
            let extension = packet
                .extension
                .map_or(0, |extension| 4 + extension.data.len());
            assert_eq!(
                RTP_FIXED_HEADER_LENGTH
                    + packet.csrc.as_bytes().len()
                    + extension
                    + packet.payload.len()
                    + usize::from(packet.padding_length),
                payload.len(),
                "{name} trame {number}"
            );
            assert_eq!(payload.len() + 8, row.udp_length, "{name} trame {number}");
        }
    }
    assert_eq!(
        per_capture,
        BTreeMap::from([
            ("The-Ultimate-PCAP.pcapng".to_string(), 7907),
            ("ndpi_line.pcap".to_string(), 100),
            (
                "wireshark_FAX-Call-t38-CA-TDM-SIP-FB-1.pcap".to_string(),
                6995
            ),
            ("wireshark_aaa.pcap".to_string(), 9),
        ])
    );
}

/// Les captures ou la regle aveugle se trompait : sans Decode As, plus une
/// seule trame n'y sort RTP.
#[test]
fn nothing_is_named_rtp_without_decode_as() {
    for capture in FORMER_FALSE_POSITIVE_CAPTURES {
        let labelled = frames(capture)
            .iter()
            .filter(|(link_type, data)| {
                parse(*link_type, data).is_ok_and(|flow| innermost(&flow).0 == Some("RTP"))
            })
            .count();
        assert_eq!(labelled, 0, "{capture}");
    }
}

/// Un paquet reel hors de tout port declare ne sort pas RTP, ni sur UDP ni
/// sur TCP (RFC 4571 prefixe chaque paquet de sa longueur, ce que la crate
/// ne lit pas).
#[test]
fn rtp_bytes_on_an_undeclared_port_are_not_rtp() {
    use packet_parser::{TransportProtocol, parse::classify_payload};

    // Trame 624 de wireshark_aaa.pcap : un paquet G.711 PCMA.
    let frames = frames(CAPTURES[3]);
    let (link_type, data) = &frames[624 - 1];
    let flow = parse(*link_type, data).expect("trame lisible");
    let (label, payload) = innermost(&flow);
    assert_eq!(label, Some("Unknown"));
    let payload = payload.expect("charge UDP");
    assert!(RtpPacket::try_from(payload).is_ok());
    for transport in [TransportProtocol::Udp, TransportProtocol::Tcp] {
        assert_ne!(
            classify_payload(transport, None, None, payload)
                .map(|application| application.protocol.label()),
            Some("RTP")
        );
    }
}
