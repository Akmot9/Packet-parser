// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests RTP (#353) sur des captures reelles.
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
//! La crate et tshark nomment RTP les memes trames, a trois pres
//! ([`KNOWN_FALSE_POSITIVES`]). SRTP garde l'en-tete RTP en clair : ses 457
//! trames de The-Ultimate-PCAP sortent RTP, pour la crate comme dans
//! l'oracle.

use std::{collections::BTreeMap, fs, path::Path};

use packet_parser::{
    PacketFlow, parse,
    parse::application::protocols::rtp::{RTP_FIXED_HEADER_LENGTH, RtpPacket},
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

/// Trames que la sonde aveugle nomme RTP a tort : deux bits de version ne
/// font pas une signature. Trois datagrammes RDP-UDP (MS-RDPEUDP, UDP 3389)
/// de The-Ultimate-PCAP, dont le premier octet vaut `0x80` ou `0xA0`.
const KNOWN_FALSE_POSITIVES: [(&str, usize); 3] = [
    ("The-Ultimate-PCAP.pcapng", 44454),
    ("The-Ultimate-PCAP.pcapng", 44608),
    ("The-Ultimate-PCAP.pcapng", 45308),
];

/// Les memes, hors des captures de l'oracle : trois lignes de texte d'un
/// journal sur UDP 7001 (`80 3C` puis « built-in function ») et deux
/// Version Negotiation QUIC hors du port 443.
const KNOWN_FALSE_POSITIVES_ELSEWHERE: [(&str, &[usize]); 2] = [
    (
        "pcaps_exemple/protocols/asterix/wireshark_8579_radardata.pcap",
        &[10914, 27819, 44641],
    ),
    (
        "pcaps_exemple/protocols/ntp/ndpi_quic_interop_V.pcapng",
        &[57, 73],
    ),
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
    let mut false_positives = Vec::new();
    for capture in CAPTURES {
        let name = file_name(capture);
        for (index, (link_type, data)) in frames(capture).iter().enumerate() {
            let number = index + 1;
            let Ok(flow) = parse(*link_type, data) else {
                assert!(!rows.contains_key(&(name.clone(), number)));
                continue;
            };
            let (label, payload) = innermost(&flow);
            let Some(row) = rows.get(&(name.clone(), number)) else {
                if label == Some("RTP") {
                    false_positives.push((name.as_str().to_string(), number));
                }
                continue;
            };
            *per_capture.entry(name.clone()).or_default() += 1;
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
    let known: Vec<(String, usize)> = KNOWN_FALSE_POSITIVES
        .iter()
        .map(|(name, number)| (name.to_string(), *number))
        .collect();
    assert_eq!(false_positives, known);
}

/// Hors des captures de l'oracle, la sonde ne nomme RTP que cinq trames
/// connues : la liste est figee, pour qu'un faux positif de plus se voie.
#[test]
fn known_false_positives_elsewhere_are_frozen() {
    for (capture, expected) in KNOWN_FALSE_POSITIVES_ELSEWHERE {
        let labelled: Vec<usize> = frames(capture)
            .iter()
            .enumerate()
            .filter(|(_, (link_type, data))| {
                parse(*link_type, data).is_ok_and(|flow| innermost(&flow).0 == Some("RTP"))
            })
            .map(|(index, _)| index + 1)
            .collect();
        assert_eq!(labelled, expected, "{capture}");
    }
}

/// La meme charge sur TCP n'est pas du RTP : la regle est gardee par UDP
/// (RFC 4571 prefixe chaque paquet de sa longueur, ce que la crate ne lit
/// pas).
#[test]
fn rtp_bytes_over_tcp_are_not_rtp() {
    use packet_parser::{TransportProtocol, parse::classify_payload};

    // Trame 624 de wireshark_aaa.pcap : un paquet G.711 PCMA.
    let frames = frames(CAPTURES[3]);
    let (link_type, data) = &frames[624 - 1];
    let flow = parse(*link_type, data).expect("trame lisible");
    let (label, payload) = innermost(&flow);
    assert_eq!(label, Some("RTP"));
    let payload = payload.expect("charge UDP");
    assert_eq!(
        classify_payload(TransportProtocol::Udp, None, None, payload)
            .map(|application| application.protocol.label()),
        Some("RTP")
    );
    assert_ne!(
        classify_payload(TransportProtocol::Tcp, None, None, payload)
            .map(|application| application.protocol.label()),
        Some("RTP")
    );
}
