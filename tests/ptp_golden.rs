// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests PTP (IEEE 1588) sur trames reelles (#121).
//!
//! Captures : `pcaps_exemple/protocols/ptp/` (voir son `SOURCE.md`), huit
//! equipements ou profils, en UDP 319/320 (IPv4 et IPv6) comme en couche 2
//! (EtherType `0x88F7`, dont une trame taguee VLAN), PTPv2 et PTPv1.
//!
//! L'oracle est tshark 4.6.6 : pour chaque message PTP, version, type,
//! longueur, domaine, sequenceId, identite de la source et types des TLV,
//! figes dans `tests/data/ptp_tshark_oracle.tsv` et compares ici trame par
//! trame. Les deux ICMP de la NodeB qui citent un datagramme PTP en sont
//! exclus : la crate les classe ICMP.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use packet_parser::{
    DecodeAsProtocol, PacketFlow, ParseConfig,
    errors::application::ptp::PtpPacketParseError,
    parse,
    parse::application::protocols::ptp::{PortIdentity, PtpPacket, PtpTimestamp, PtpV2Body},
    parse::internet::InternetDetails,
    parse_with,
};

mod common;
use common::{FileRead, collect_capture_files, read_capture};

const CORPUS: &str = "pcaps_exemple/protocols/ptp";
const ORACLE: &str = "tests/data/ptp_tshark_oracle.tsv";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Le message PTP d'un flux et son transport, tels que la crate les voit :
/// la couche internet en couche 2, le payload UDP sous l'etiquette "PTP".
fn ptp_message<'a>(flow: &'a PacketFlow<'a>) -> Option<(&'static str, PtpPacket<'a>)> {
    let internet = flow.internet.as_ref()?;
    if let Some(InternetDetails::Ptp(packet)) = &internet.details {
        assert_eq!(internet.protocol_name, "PTP");
        return Some(("l2", packet.clone()));
    }
    let application = flow.application.as_ref()?;
    if application.application_protocol != "PTP" {
        return None;
    }
    let payload = flow.transport.as_ref()?.payload?;
    let packet = PtpPacket::try_from_udp(payload).expect("une trame etiquetee PTP se decode");
    Some(("udp", packet))
}

/// Les colonnes de l'oracle a partir de la trame 3 : transport, version,
/// type, longueur, domaine, sequence, source, tlvs. Un TLV tronque est rendu
/// par son type, comme tshark le fait, et compte dans `truncated_tlvs`.
fn oracle_row(transport: &str, packet: &PtpPacket<'_>, truncated_tlvs: &mut usize) -> String {
    let columns = match packet {
        PtpPacket::V2(message) => {
            let header = &message.header;
            let tlvs: Vec<String> = message
                .tlvs
                .iter()
                .map(|tlv| match tlv {
                    Ok(tlv) => format!("{:04x}", tlv.tlv_type),
                    Err(PtpPacketParseError::TruncatedTlv {
                        tlv_type: Some(tlv_type),
                        ..
                    }) => {
                        *truncated_tlvs += 1;
                        format!("{tlv_type:04x}")
                    }
                    Err(error) => panic!("TLV illisible : {error}"),
                })
                .collect();
            [
                "2".to_string(),
                format!("{:x}", header.message_type),
                header.message_length.to_string(),
                header.domain_number.to_string(),
                header.sequence_id.to_string(),
                format!(
                    "{}:{}",
                    hex(&header.source_port_identity.clock_identity),
                    header.source_port_identity.port_number
                ),
                if tlvs.is_empty() {
                    "-".to_string()
                } else {
                    tlvs.join(",")
                },
            ]
        }
        PtpPacket::V1(message) => {
            let header = &message.header;
            let subdomain_end = header
                .subdomain
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(header.subdomain.len());
            [
                "1".to_string(),
                header.control.to_string(),
                "-".to_string(),
                String::from_utf8_lossy(&header.subdomain[..subdomain_end]).into_owned(),
                header.sequence_id.to_string(),
                format!("{}:{}", hex(&header.source_uuid), header.source_port_id),
                "-".to_string(),
            ]
        }
        _ => panic!("version PTP inattendue"),
    };
    format!("{transport}\t{}", columns.join("\t"))
}

fn read_frames(path: &Path) -> Vec<(packet_parser::LinkType, Vec<u8>)> {
    let FileRead::Frames {
        frames,
        read_error_after: None,
    } = read_capture(path)
    else {
        panic!("{} : capture illisible", path.display());
    };
    frames
}

/// Parite exacte avec tshark sur les 3 328 messages PTP du dossier : la
/// crate reconnait exactement les trames que tshark voit, ni plus ni moins,
/// et en decode les memes champs.
#[test]
fn every_ptp_message_matches_the_tshark_oracle() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let oracle = fs::read_to_string(base.join(ORACLE)).expect("oracle lisible");
    let mut expected: BTreeMap<String, BTreeMap<usize, String>> = BTreeMap::new();
    for line in oracle.lines().filter(|line| !line.starts_with('#')) {
        let (file, rest) = line.split_once('\t').expect("ligne d'oracle");
        let (number, row) = rest.split_once('\t').expect("ligne d'oracle");
        expected
            .entry(file.to_string())
            .or_default()
            .insert(number.parse().expect("numero de trame"), row.to_string());
    }

    let mut captures = Vec::new();
    collect_capture_files(&base.join(CORPUS), &mut captures);
    let names: Vec<String> = captures
        .iter()
        .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(
        expected.keys().cloned().collect::<Vec<_>>(),
        sorted,
        "l'oracle couvre chaque capture du dossier"
    );

    let mut by_transport: BTreeMap<String, usize> = BTreeMap::new();
    let mut truncated_tlvs = 0;
    for (path, name) in captures.iter().zip(&names) {
        let mut actual = BTreeMap::new();
        for (index, (link_type, data)) in read_frames(path).iter().enumerate() {
            let flow = parse(*link_type, data).expect("trame du corpus decodable");
            if let Some((transport, packet)) = ptp_message(&flow) {
                actual.insert(
                    index + 1,
                    oracle_row(transport, &packet, &mut truncated_tlvs),
                );
                *by_transport
                    .entry(format!("{transport} v{}", packet.version()))
                    .or_default() += 1;
            }
        }
        assert_eq!(&actual, &expected[name], "{name} : ecart avec tshark");
    }

    // Un seul TLV tronque dans le corpus : le Signaling de la trame 7 de
    // wireshark_4761_802_1as.pcap, 802.1AS d'avant la norme, que tshark
    // declare aussi malforme (lengthField 12, 10 octets avant messageLength).
    assert_eq!(truncated_tlvs, 1);
    assert_eq!(
        by_transport,
        BTreeMap::from([
            ("l2 v2".to_string(), 107),
            ("udp v1".to_string(), 4),
            ("udp v2".to_string(), 3217),
        ])
    );
}

/// Oracle negatif : aucune trame des autres dossiers du corpus n'est prise
/// pour du PTP, ni en couche 2 ni sur UDP, tunnels compris.
#[test]
fn no_other_capture_is_labelled_ptp() {
    let protocols = Path::new(env!("CARGO_MANIFEST_DIR")).join("pcaps_exemple/protocols");
    let ptp_dir = protocols.join("ptp");
    let mut captures: Vec<PathBuf> = Vec::new();
    collect_capture_files(&protocols, &mut captures);
    captures.retain(|path| !path.starts_with(&ptp_dir));
    assert!(captures.len() > 100, "corpus negatif trop maigre");

    let mut frames_checked = 0;
    for path in &captures {
        let FileRead::Frames { frames, .. } = read_capture(path) else {
            continue;
        };
        for (index, (link_type, data)) in frames.iter().enumerate() {
            let Ok(flow) = parse(*link_type, data) else {
                continue;
            };
            for layer in flow.flatten() {
                assert!(
                    ptp_message(layer).is_none(),
                    "{} trame {} : faux positif PTP",
                    path.display(),
                    index + 1
                );
            }
            frames_checked += 1;
        }
    }
    assert!(frames_checked > 50_000, "{frames_checked} trames seulement");
}

fn frame(hex_fixture: &str, expected_len: usize) -> Vec<u8> {
    let bytes = hex::decode(hex_fixture).expect("invalid test hex fixture");
    assert_eq!(
        bytes.len(),
        expected_len,
        "fixture length must match capture"
    );
    bytes
}

/// `wireshark_7694_c37_238.pcap` trame 1 : un Announce du profil electrique
/// IEEE C37.238 (SEL), en couche 2 dans un tag VLAN 42. tshark : sequenceId
/// 5790, source 0x00000030a7f00263 port 401, flags 0x003c,
/// originCurrentUTCOffset 35, priority1 128, clockClass 6, clockAccuracy
/// 0x23, variance 19876, priority2 128, stepsRemoved 2, timeSource GPS
/// (0x20). Le TLV C37.238 suit messageLength (64) au lieu d'y etre compte :
/// tshark l'ignore, la crate le laisse dans `trailing`.
const C37_238_ANNOUNCE_FRAME_1_HEX: &str = concat!(
    "011b190000000030a7f002638100d02a88f70b0200400000003c0000000000000000000000000000",
    "0030a7f002630191169e0000000000000000000000000023008006234da48000000030a7f0026300",
    "0220000300121c129d00000100d6000001590000000000000009002400ffff9d9000000000000000",
    "00000014506163696669632e202020200000000000000000"
);

#[test]
fn c37_238_announce_decodes_through_the_vlan_tag() {
    let bytes = frame(C37_238_ANNOUNCE_FRAME_1_HEX, 144);
    let flow = parse(packet_parser::LinkType::ETHERNET, &bytes).expect("trame decodable");
    assert_eq!(
        flow.data_link
            .as_ethernet()
            .and_then(|frame| frame.vlan.as_ref())
            .map(|tag| tag.id),
        Some(42)
    );
    assert!(flow.transport.is_none() && flow.application.is_none());
    let Some(("l2", PtpPacket::V2(message))) = ptp_message(&flow) else {
        panic!("PTPv2 en couche 2 attendu");
    };
    assert_eq!(message.header.sequence_id, 5790);
    assert_eq!(message.header.flags, 0x003c);
    assert_eq!(message.header.source_port_identity.port_number, 401);
    let PtpV2Body::Announce(announce) = message.body else {
        panic!("Announce attendu");
    };
    assert_eq!(announce.current_utc_offset, 35);
    assert_eq!(announce.grandmaster_priority1, 128);
    assert_eq!(announce.grandmaster_clock_quality.clock_class, 6);
    assert_eq!(announce.grandmaster_clock_quality.clock_accuracy, 0x23);
    assert_eq!(
        announce
            .grandmaster_clock_quality
            .offset_scaled_log_variance,
        19876
    );
    assert_eq!(announce.grandmaster_priority2, 128);
    assert_eq!(
        announce.grandmaster_identity,
        [0x00, 0x00, 0x00, 0x30, 0xa7, 0xf0, 0x02, 0x63]
    );
    assert_eq!(announce.steps_removed, 2);
    assert_eq!(announce.time_source, 0x20);
    assert_eq!(message.tlvs.iter().count(), 0);
    // Organization extension (0x0003) de 18 octets, hors messageLength.
    assert_eq!(&message.trailing[..4], [0x00, 0x03, 0x00, 0x12]);
}

/// `wireshark_6126_nodeb_startup.pcap` trame 114 (UDP 320 -> 320) : un
/// Delay_Resp. tshark : source 0x143e60fffe548546 port 1, sequenceId 1,
/// receiveTimestamp 87921 s 512977550 ns, requestingPortIdentity
/// 0x1880f5ffff31353d port 1.
const NODEB_DELAY_RESP_FRAME_114_HEX: &str = concat!(
    "1880f531353d8c90d39044e7080045c00052333340003f1110a20adedede0a47030301400140003e",
    "00000902003600000420000000000000000000000000143e60fffe54854600010001037f00000001",
    "57711e936a8e1880f5ffff31353d0001"
);

#[test]
fn nodeb_delay_resp_decodes_its_body() {
    let bytes = frame(NODEB_DELAY_RESP_FRAME_114_HEX, 96);
    let flow = parse(packet_parser::LinkType::ETHERNET, &bytes).expect("trame decodable");
    let Some(("udp", PtpPacket::V2(message))) = ptp_message(&flow) else {
        panic!("PTPv2 sur UDP attendu");
    };
    assert_eq!(message.header.sequence_id, 1);
    assert_eq!(
        message.body,
        PtpV2Body::DelayResp {
            receive_timestamp: PtpTimestamp {
                seconds: 87_921,
                nanoseconds: 512_977_550,
            },
            requesting_port_identity: PortIdentity {
                clock_identity: [0x18, 0x80, 0xf5, 0xff, 0xff, 0x31, 0x35, 0x3d],
                port_number: 1,
            },
        }
    );
}

/// Trame 114 de la NodeB avec ses deux ports UDP deplaces de 320 a 5320
/// (seule mutation). Sans declaration, hors 319/320, elle reste "Unknown" ;
/// declaree par Decode As, elle redevient PTP.
#[test]
fn decode_as_routes_ptp_on_a_non_standard_port() {
    let mut bytes = frame(NODEB_DELAY_RESP_FRAME_114_HEX, 96);
    // En-tete UDP a l'offset 34 (Ethernet 14 + IPv4 20) : ports source et
    // destination.
    bytes[34..38].copy_from_slice(&[0x14, 0xc8, 0x14, 0xc8]);
    let label = |flow: &PacketFlow<'_>| {
        flow.application
            .as_ref()
            .map(|application| application.application_protocol)
    };

    let flow = parse(packet_parser::LinkType::ETHERNET, &bytes).expect("trame decodable");
    assert_eq!(label(&flow), Some("Unknown"));

    let config = ParseConfig::new().decode_as(5320, DecodeAsProtocol::Ptp);
    let flow =
        parse_with(packet_parser::LinkType::ETHERNET, &bytes, &config).expect("trame decodable");
    assert_eq!(label(&flow), Some("PTP"));
}
