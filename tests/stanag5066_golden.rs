// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests STANAG 5066 SIS sur trames reelles (#122).
//!
//! Captures : `pcaps_exemple/protocols/stanag5066/` (voir son `SOURCE.md`),
//! le banc HF Chat de l'agence C3 de l'OTAN, des donnees expediees et un
//! transport ACP 142 en boucle locale.
//!
//! L'oracle est tshark 4.6.6 sans reassemblage TCP
//! (`tools/stanag5066_oracle.sh`) : pour chaque segment ou tshark voit du
//! SIS, les types de S_PDU, les tailles de primitive, les adresses de noeud,
//! les SAP, les tailles d'U_PDU, les modes, TTL, rangs, MTU et motifs, figes
//! dans `tests/data/stanag5066_tshark_oracle.tsv` et compares ici segment
//! par segment. Les segments de continuation, sans preambule, n'en font pas
//! partie : la crate les laisse `Unknown`, tshark aussi.

use std::{collections::BTreeMap, fs, path::Path};

use packet_parser::{
    DecodeAsProtocol, PacketFlow, ParseConfig, parse,
    parse::application::protocols::stanag5066::{PduType, SisPdu, SisPrimitive},
    parse_with,
};

mod common;
use common::{FileRead, collect_capture_files, read_capture};

const CORPUS: &str = "pcaps_exemple/protocols/stanag5066";
const ORACLE: &str = "tests/data/stanag5066_tshark_oracle.tsv";

/// Les colonnes 3 a 13 d'une ligne d'oracle, telles quelles.
type OracleRow = [String; 11];

fn read_oracle(path: &Path) -> BTreeMap<String, BTreeMap<usize, OracleRow>> {
    let oracle = fs::read_to_string(path).expect("oracle lisible");
    let mut expected: BTreeMap<String, BTreeMap<usize, OracleRow>> = BTreeMap::new();
    for line in oracle.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 13, "ligne d'oracle malformee : {line}");
        let frame: usize = fields[1].parse().expect("numero de trame");
        let row: OracleRow = fields[2..]
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .try_into()
            .expect("onze colonnes");
        expected
            .entry(fields[0].to_string())
            .or_default()
            .insert(frame, row);
    }
    expected
}

fn join<T: ToString>(values: &[T]) -> String {
    if values.is_empty() {
        "-".to_string()
    } else {
        values
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// Tous les S_PDU d'un segment, par `consumed`.
fn pdus(payload: &[u8]) -> Vec<SisPdu<'_>> {
    let mut out = Vec::new();
    let mut rest = payload;
    while !rest.is_empty() {
        let pdu = SisPdu::try_from(rest).expect("un segment etiquete SIS se decoupe en S_PDU");
        let consumed = pdu.consumed();
        out.push(pdu);
        rest = &rest[consumed..];
    }
    out
}

/// La ligne d'oracle que la crate produit pour un segment, dans le format
/// de tshark : les champs des primitives 20 a 27 sont groupes par type, dans
/// l'ordre des types, puis dans l'ordre du segment.
fn oracle_row(pdus: &[SisPdu<'_>]) -> OracleRow {
    let types: Vec<u8> = pdus.iter().map(|pdu| pdu.header.pdu_type).collect();
    let sizes: Vec<u16> = pdus.iter().map(|pdu| pdu.header.primitive_size).collect();
    let mut addresses = Vec::new();
    for pdu in pdus {
        match pdu.primitive {
            SisPrimitive::HardLink { remote_node, .. } => addresses.push(remote_node.to_string()),
            SisPrimitive::Unidata {
                destination,
                source,
                ..
            } => {
                addresses.push(destination.to_string());
                if let Some(source) = source {
                    addresses.push(source.to_string());
                }
            }
            _ => {}
        }
    }
    let by_type = |types: &[u8], pick: &dyn Fn(&SisPdu<'_>) -> Option<String>| -> String {
        let mut values = Vec::new();
        for wanted in types {
            for pdu in pdus.iter().filter(|pdu| pdu.header.pdu_type == *wanted) {
                values.extend(pick(pdu));
            }
        }
        join(&values)
    };
    let unidata = [20, 21, 22, 23, 24, 25, 26, 27];
    [
        join(&types),
        join(&sizes),
        join(&addresses),
        by_type(&unidata, &|pdu| match pdu.primitive {
            SisPrimitive::Unidata {
                destination_sap_id, ..
            } => Some(destination_sap_id.to_string()),
            _ => None,
        }),
        by_type(&unidata, &|pdu| match pdu.primitive {
            SisPrimitive::Unidata { u_pdu_size, .. } => Some(u_pdu_size.to_string()),
            _ => None,
        }),
        by_type(&[21, 25], &|pdu| match pdu.primitive {
            SisPrimitive::Unidata { source_sap_id, .. } => source_sap_id.map(|s| s.to_string()),
            _ => None,
        }),
        by_type(&[21, 25], &|pdu| match pdu.primitive {
            SisPrimitive::Unidata {
                transmission_mode, ..
            } => transmission_mode.map(|m| format!("{m:#04x}")),
            _ => None,
        }),
        by_type(&[20, 24], &|pdu| match pdu.primitive {
            SisPrimitive::Unidata { time_to_live, .. } => time_to_live.map(|t| t.to_string()),
            _ => None,
        }),
        by_type(&[1], &|pdu| match pdu.primitive {
            SisPrimitive::Bind { sap_id, rank, .. } => Some(format!("{sap_id},{rank}")),
            _ => None,
        }),
        by_type(&[3], &|pdu| match pdu.primitive {
            SisPrimitive::BindAccepted { sap_id, mtu } => Some(format!("{sap_id},{mtu}")),
            _ => None,
        }),
        by_type(&[4, 5, 23, 27], &|pdu| match pdu.primitive {
            SisPrimitive::Rejected { reason } => Some(reason.to_string()),
            SisPrimitive::Unidata {
                reason: Some(reason),
                ..
            } => Some(reason.to_string()),
            _ => None,
        }),
    ]
}

fn label(flow: &PacketFlow<'_>) -> Option<&'static str> {
    flow.application
        .as_ref()
        .map(|application| application.application_protocol)
}

/// Parite avec tshark sur les 34 segments SIS du corpus : chaque segment de
/// l'oracle est etiquete STANAG 5066 et decoupe a l'identique ; tout autre
/// segment a payload du dossier (les cinq continuations) ne l'est pas.
#[test]
fn every_segment_matches_the_tshark_oracle() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let expected = read_oracle(&base.join(ORACLE));
    let mut captures = Vec::new();
    collect_capture_files(&base.join(CORPUS), &mut captures);
    assert_eq!(captures.len(), 4);

    let mut segments_checked = 0;
    let mut continuations = 0;
    let mut truncated_pdus = 0;
    let mut by_type: BTreeMap<String, usize> = BTreeMap::new();
    for path in &captures {
        let file = path.file_name().unwrap().to_string_lossy().to_string();
        let FileRead::Frames { frames, .. } = read_capture(path) else {
            panic!("{file} : capture illisible");
        };
        let oracle_frames = expected
            .get(&file)
            .unwrap_or_else(|| panic!("{file} absente de l'oracle"));
        for (index, (link_type, data)) in frames.iter().enumerate() {
            let number = index + 1;
            let flow =
                parse(*link_type, data).unwrap_or_else(|error| panic!("{file}:{number} : {error}"));
            let payload = flow
                .transport
                .as_ref()
                .and_then(|transport| transport.payload);
            match (oracle_frames.get(&number), label(&flow), payload) {
                (Some(row), Some("STANAG 5066"), Some(payload)) => {
                    let pdus = pdus(payload);
                    assert_eq!(&oracle_row(&pdus), row, "{file}:{number}");
                    for pdu in &pdus {
                        *by_type.entry(format!("{:?}", pdu.pdu_type)).or_default() += 1;
                        truncated_pdus += usize::from(pdu.truncated);
                    }
                    segments_checked += 1;
                }
                (Some(_), other, _) => {
                    panic!("{file}:{number} : tshark voit du SIS, la crate dit {other:?}")
                }
                (None, Some("STANAG 5066"), _) => {
                    panic!("{file}:{number} : la crate voit du SIS, pas tshark")
                }
                (None, _, Some(payload)) if !payload.is_empty() => continuations += 1,
                (None, _, _) => {}
            }
        }
    }
    assert_eq!(segments_checked, 34);
    assert_eq!(continuations, 5, "segments de continuation sans preambule");
    // Les cinq premiers segments de S_PDU coupes : trois de HFChat-1 (une
    // indication, une requete, une confirmation), deux de HFChat-Rejected
    // (une requete, un rejet).
    assert_eq!(truncated_pdus, 5);
    assert_eq!(
        by_type.keys().collect::<Vec<_>>(),
        [
            "BindAccepted",
            "BindRequest",
            "ExpeditedUnidataIndication",
            "ExpeditedUnidataRequest",
            "ExpeditedUnidataRequestConfirm",
            "HardLinkAccept",
            "HardLinkIndication",
            "HardLinkTerminated",
            "UnbindRequest",
            "UnidataIndication",
            "UnidataRequest",
            "UnidataRequestConfirm",
            "UnidataRequestRejected",
        ]
    );
}

/// `wireshark_10827_sis_acp142.pcap` trame 4 : trois S_UNIDATA_REQUEST de
/// 2 065 octets dans un segment de 6 195 — `consumed` enchaine les S_PDU.
/// Et la garde de port : les memes octets hors de TCP 5066 ne sont pas du
/// SIS, sauf port declare par Decode As.
#[test]
fn several_pdus_per_segment_and_port_guard() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let FileRead::Frames { frames, .. } =
        read_capture(&base.join(CORPUS).join("wireshark_10827_sis_acp142.pcap"))
    else {
        panic!("capture illisible");
    };
    let (link_type, data) = &frames[3];
    let flow = parse(*link_type, data).expect("trame 4");
    assert_eq!(label(&flow), Some("STANAG 5066"));
    let payload = flow.transport.as_ref().unwrap().payload.unwrap();
    let pdus = pdus(payload);
    assert_eq!(pdus.len(), 3);
    assert!(
        pdus.iter()
            .all(|pdu| pdu.pdu_type == PduType::UnidataRequest)
    );
    assert!(pdus.iter().all(|pdu| !pdu.truncated));
    assert_eq!(pdus.iter().map(SisPdu::consumed).sum::<usize>(), 6195);

    // Le payload de la trame 4 sur un autre port : Unknown, puis declare.
    let (link_type, data) = &frames[3];
    let mut moved = data.clone();
    // Port destination TCP (Ethernet 14 + IPv4 20 + 2) : 5066 -> 5067.
    moved[36..38].copy_from_slice(&5067u16.to_be_bytes());
    let flow = parse(*link_type, &moved).expect("trame deplacee");
    assert_eq!(label(&flow), Some("Unknown"));
    let config = ParseConfig::new().decode_as(5067, DecodeAsProtocol::Stanag5066);
    let flow = parse_with(*link_type, &moved, &config).expect("trame declaree");
    assert_eq!(label(&flow), Some("STANAG 5066"));
}
