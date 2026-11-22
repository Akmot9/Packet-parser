// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests DCE/RPC oriente connexion (#356) sur une capture reelle
//! deja versionnee : `pcaps_exemple/The-Ultimate-PCAP.pcapng`, des appels
//! MSRPC et DCOM entre postes Windows (Bind, Alter Context, Request,
//! Response, avec et sans authentification).
//!
//! L'oracle est tshark 4.6.9 (`tools/dcerpc_oracle.sh`), reassemblage TCP
//! et DCE/RPC coupes : pour chaque segment, la version mineure, le type de
//! PDU, les drapeaux, la representation des donnees, les longueurs,
//! l'identifiant d'appel et le numero d'operation, figes dans
//! `tests/data/dcerpc_tshark_oracle.tsv`.
//!
//! La crate nomme quatorze segments de plus que tshark
//! ([`RETRANSMISSIONS`]) : des retransmissions TCP, que tshark ne passe pas
//! a son dissecteur et que la crate, sans etat, lit comme les autres.
//!
//! Oracle negatif : aucune autre trame de la capture, dont le DCE/RPC porte
//! par SMB, ne sort `DCE/RPC` ; et l'histogramme fige de
//! `tests/golden_pcaps.rs` n'a aucune entree `DCE/RPC` sur les captures de
//! `pcaps_exemple/protocols/`.

use std::{collections::BTreeMap, fs, path::Path};

use packet_parser::{
    PacketFlow, parse,
    parse::application::protocols::dcerpc::{DCERPC_COMMON_HEADER_LENGTH, DceRpcPdu},
};

mod common;
use common::{FileRead, read_capture};

const ORACLE: &str = "tests/data/dcerpc_tshark_oracle.tsv";
const CAPTURE: &str = "pcaps_exemple/The-Ultimate-PCAP.pcapng";

/// Segments DCE/RPC que tshark marque `tcp.analysis.retransmission` et ne
/// dissèque pas : quatorze Response retransmis a l'identique.
const RETRANSMISSIONS: [usize; 14] = [
    40295, 40364, 40365, 40560, 40579, 40583, 40585, 40812, 40814, 41479, 42667, 42672, 42742,
    42743,
];

/// Une ligne de l'oracle.
struct Row {
    tcp_length: usize,
    version_minor: u8,
    pdu_type: u8,
    flags: u8,
    data_representation: [u8; 4],
    frag_length: u16,
    auth_length: u16,
    call_id: u32,
    opnum: Option<u16>,
}

fn read_oracle(path: &Path) -> BTreeMap<usize, Row> {
    let oracle = fs::read_to_string(path).expect("oracle lisible");
    let mut rows = BTreeMap::new();
    for line in oracle.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 11, "ligne d'oracle malformee : {line}");
        let drep = u32::from_str_radix(fields[6], 16).expect("drep");
        rows.insert(
            fields[1].parse().expect("numero de trame"),
            Row {
                tcp_length: fields[2].parse().expect("longueur TCP"),
                version_minor: fields[3].parse().expect("version mineure"),
                pdu_type: fields[4].parse().expect("type"),
                flags: u8::from_str_radix(fields[5].trim_start_matches("0x"), 16)
                    .expect("drapeaux"),
                data_representation: drep.to_be_bytes(),
                frag_length: fields[7].parse().expect("frag_length"),
                auth_length: fields[8].parse().expect("auth_length"),
                call_id: fields[9].parse().expect("call_id"),
                opnum: (fields[10] != "-").then(|| fields[10].parse().expect("opnum")),
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

#[test]
fn every_dcerpc_segment_matches_the_tshark_oracle() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let rows = read_oracle(&base.join(ORACLE));
    assert_eq!(rows.len(), 385);
    let FileRead::Frames {
        frames,
        read_error_after: None,
    } = read_capture(&base.join(CAPTURE))
    else {
        panic!("{CAPTURE} illisible");
    };

    let mut seen = 0;
    let mut truncated = 0;
    let mut requests = 0;
    let mut elsewhere = Vec::new();
    for (index, (link_type, data)) in frames.iter().enumerate() {
        let number = index + 1;
        let Ok(flow) = parse(*link_type, data) else {
            assert!(!rows.contains_key(&number), "trame {number}");
            continue;
        };
        let (label, payload) = innermost(&flow);
        let Some(row) = rows.get(&number) else {
            if label == Some("DCE/RPC") {
                elsewhere.push(number);
            }
            continue;
        };
        seen += 1;
        assert_eq!(label, Some("DCE/RPC"), "trame {number}");
        let payload = payload.expect("charge TCP");
        assert_eq!(payload.len(), row.tcp_length, "trame {number}");

        let pdu =
            DceRpcPdu::try_from(payload).unwrap_or_else(|error| panic!("trame {number} : {error}"));
        assert_eq!(pdu.version_minor, row.version_minor, "trame {number}");
        assert_eq!(pdu.pdu_type.as_u8(), row.pdu_type, "trame {number}");
        assert_eq!(pdu.flags, row.flags, "trame {number}");
        assert_eq!(pdu.is_first_fragment(), row.flags & 0x01 != 0);
        assert_eq!(pdu.is_last_fragment(), row.flags & 0x02 != 0);
        assert_eq!(
            pdu.data_representation, row.data_representation,
            "trame {number}"
        );
        assert!(pdu.little_endian, "trame {number}");
        assert_eq!(pdu.frag_length, row.frag_length, "trame {number}");
        assert_eq!(pdu.auth_length, row.auth_length, "trame {number}");
        assert_eq!(pdu.call_id, row.call_id, "trame {number}");
        assert_eq!(
            pdu.request().map(|request| request.opnum),
            row.opnum,
            "trame {number}"
        );
        requests += usize::from(pdu.request().is_some());

        // L'en-tete, le corps et la suite pavent le segment.
        assert_eq!(
            DCERPC_COMMON_HEADER_LENGTH + pdu.body.len() + pdu.rest().len(),
            payload.len(),
            "trame {number}"
        );
        assert_eq!(
            pdu.is_truncated(),
            usize::from(row.frag_length) > row.tcp_length,
            "trame {number}"
        );
        truncated += usize::from(pdu.is_truncated());
    }
    assert_eq!(seen, 385);
    assert_eq!(requests, 135);
    assert_eq!(truncated, 16, "fragments coupes par leur segment");
    assert_eq!(elsewhere, RETRANSMISSIONS, "DCE/RPC hors de l'oracle");
}
