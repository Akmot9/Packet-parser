// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests RDP (MS-RDPBCGR) sur trames reelles (#100).
//!
//! Captures : `pcaps_exemple/protocols/rdp/` (voir son `SOURCE.md`), cinq
//! fichiers du corpus de tests de Zeek : connexion avec et sans cookie,
//! bascule vers TLS, chiffrement RDP standard avec toute la session MCS.
//!
//! L'oracle est tshark 4.6.6 sans reassemblage TCP (`tools/rdp_oracle.sh`,
//! la vue d'un parseur sans etat) : pour chaque segment a payload, la
//! couche la plus haute que tshark y voit (rdp, t125, t124, tls, data, tcp)
//! et, pour les Connection Request et Confirm, le jeton X.224 et la
//! negociation ; pour les PDU MCS, le ConnectMCSPDU ou le DomainMCSPDU.
//!
//! Ce qui est etiquete apres la bascule TLS est une decision, pas un effet
//! de bord : **TLS**. Un parseur sans etat voit des records TLS, il les
//! nomme. Les suites de TPKT coupes par la segmentation, sans en-tete,
//! restent inconnues, comme chez tshark (`data`).

use std::{collections::BTreeMap, fs, path::Path};

use packet_parser::{
    DecodeAsProtocol, PacketFlow, ParseConfig, parse,
    parse::application::protocols::{
        copt::CotpPduType,
        rdp::{McsPduType, NegotiationResponse, RdpPacket, RdpPayload},
    },
    parse_with,
};

mod common;
use common::{FileRead, collect_capture_files, read_capture};

const CORPUS: &str = "pcaps_exemple/protocols/rdp";
const ORACLE: &str = "tests/data/rdp_tshark_oracle.tsv";

/// Les colonnes 3 a 15 d'une ligne d'oracle.
type OracleRow = [String; 13];

fn read_oracle(path: &Path) -> BTreeMap<String, BTreeMap<usize, OracleRow>> {
    let oracle = fs::read_to_string(path).expect("oracle lisible");
    let mut expected: BTreeMap<String, BTreeMap<usize, OracleRow>> = BTreeMap::new();
    for line in oracle.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 15, "ligne d'oracle malformee : {line}");
        let row: OracleRow = fields[2..]
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .try_into()
            .expect("treize colonnes");
        expected
            .entry(fields[0].to_string())
            .or_default()
            .insert(fields[1].parse().expect("numero de trame"), row);
    }
    expected
}

fn label(flow: &PacketFlow<'_>) -> Option<&'static str> {
    flow.application
        .as_ref()
        .map(|application| application.application_protocol)
}

/// Le choix PER que tshark affiche pour un DomainMCSPDU.
fn domain_choice(kind: McsPduType) -> Option<u8> {
    Some(match kind {
        McsPduType::ErectDomainRequest => 1,
        McsPduType::DisconnectProviderUltimatum => 8,
        McsPduType::AttachUserRequest => 10,
        McsPduType::AttachUserConfirm => 11,
        McsPduType::ChannelJoinRequest => 14,
        McsPduType::ChannelJoinConfirm => 15,
        McsPduType::SendDataRequest => 25,
        McsPduType::SendDataIndication => 26,
        McsPduType::ConnectInitial | McsPduType::ConnectResponse => return None,
        _ => return None,
    })
}

/// Parite avec tshark sur les 861 segments a payload du corpus.
#[test]
fn every_segment_matches_the_tshark_oracle() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let expected = read_oracle(&base.join(ORACLE));
    let mut captures = Vec::new();
    collect_capture_files(&base.join(CORPUS), &mut captures);
    assert_eq!(captures.len(), 5);

    let mut segments = 0;
    let mut rdp = 0;
    let mut tls = 0;
    let mut tls_continuations = 0;
    let mut unknown = 0;
    let mut retransmissions = 0;
    let mut truncated = 0;
    let mut connection_requests = 0;
    let mut cookies = 0;
    let mut by_mcs: BTreeMap<String, usize> = BTreeMap::new();
    for path in &captures {
        let file = path.file_name().unwrap().to_string_lossy().to_string();
        let FileRead::Frames { frames, .. } = read_capture(path) else {
            panic!("{file} : capture illisible");
        };
        let rows = expected
            .get(&file)
            .unwrap_or_else(|| panic!("{file} absente de l'oracle"));
        for (index, (link_type, data)) in frames.iter().enumerate() {
            let number = index + 1;
            let flow =
                parse(*link_type, data).unwrap_or_else(|error| panic!("{file}:{number} : {error}"));
            let transport = flow.transport.as_ref().expect("transport");
            let Some(payload) = transport.payload.filter(|payload| !payload.is_empty()) else {
                assert!(
                    !rows.contains_key(&number),
                    "{file}:{number} : sans payload"
                );
                continue;
            };
            let row = rows
                .get(&number)
                .unwrap_or_else(|| panic!("{file}:{number} absente de l'oracle"));
            assert_eq!(
                (
                    transport.source_port,
                    transport.destination_port,
                    payload.len()
                ),
                (
                    Some(row[0].parse().unwrap()),
                    Some(row[1].parse().unwrap()),
                    row[2].parse().unwrap()
                ),
                "{file}:{number}"
            );
            segments += 1;
            if row[12] == "1" {
                // tshark ne dissèque pas une retransmission ; le parseur sans
                // etat voit les memes octets que la premiere fois.
                retransmissions += 1;
                continue;
            }
            match row[11].as_str() {
                "tls" | "x509ce" | "x509sat" => {
                    // TLS quand un record commence dans le segment ; la suite
                    // d'un record coupe par la segmentation reste inconnue
                    // pour un parseur sans etat, tshark la rattache au TLS.
                    match label(&flow) {
                        Some("TLS") => tls += 1,
                        Some("Unknown") => tls_continuations += 1,
                        other => panic!("{file}:{number} : {other:?}"),
                    }
                    continue;
                }
                "data" | "tcp" => {
                    assert_ne!(label(&flow), Some("RDP"), "{file}:{number}");
                    unknown += 1;
                    continue;
                }
                "rdp" | "t125" | "t124" => {}
                other => panic!("{file}:{number} : couche tshark inattendue {other}"),
            }
            assert_eq!(label(&flow), Some("RDP"), "{file}:{number}");
            let packet = RdpPacket::try_from(payload)
                .unwrap_or_else(|error| panic!("{file}:{number} : {error}"));
            assert_eq!(
                packet.pdus.len(),
                1,
                "{file}:{number} : un TPKT par segment"
            );
            let pdu = &packet.pdus[0];
            assert_eq!(pdu.tpkt_length.to_string(), row[3], "{file}:{number}");
            if packet.truncated {
                assert!(
                    usize::from(pdu.tpkt_length) > payload.len(),
                    "{file}:{number}"
                );
                truncated += 1;
            }
            let cotp_type = match pdu.cotp.pdu_type {
                CotpPduType::ConnectionRequest => "0x0e",
                CotpPduType::ConnectionConfirm => "0x0d",
                CotpPduType::Data => "0x0f",
                other => panic!("{file}:{number} : TPDU {other:?}"),
            };
            assert_eq!(cotp_type, row[4], "{file}:{number}");
            rdp += 1;
            match &pdu.payload {
                RdpPayload::ConnectionRequest { token, negotiation } => {
                    let token =
                        token.map_or("-".to_string(), |t| String::from_utf8_lossy(t).to_string());
                    // tshark double les antislashs (`FTBCO\\A70`) dans ses champs.
                    assert_eq!(token, row[5].replace("\\\\", "\\"), "{file}:{number}");
                    let (kind, protocols) =
                        negotiation.map_or(("-".to_string(), "-".to_string()), |n| {
                            (
                                "0x01".to_string(),
                                format!("{:#010x}", n.requested_protocols),
                            )
                        });
                    assert_eq!(
                        (kind, protocols),
                        (row[6].clone(), row[7].clone()),
                        "{file}:{number}"
                    );
                    assert_eq!(row[8], "-", "{file}:{number}");
                    connection_requests += 1;
                    cookies += usize::from(pdu.payload.cookie_user().is_some());
                }
                RdpPayload::ConnectionConfirm { negotiation } => {
                    let (kind, selected) = match negotiation {
                        Some(NegotiationResponse::Accepted {
                            selected_protocol, ..
                        }) => ("0x02".to_string(), format!("{selected_protocol:#010x}")),
                        Some(NegotiationResponse::Failure { .. }) => {
                            ("0x03".to_string(), "-".to_string())
                        }
                        None => ("-".to_string(), "-".to_string()),
                        Some(other) => panic!("{file}:{number} : {other:?}"),
                    };
                    assert_eq!(
                        (kind, selected),
                        (row[6].clone(), row[8].clone()),
                        "{file}:{number}"
                    );
                }
                RdpPayload::Mcs(mcs) => {
                    let expected = match mcs.kind {
                        McsPduType::ConnectInitial => ("101".to_string(), "-".to_string()),
                        McsPduType::ConnectResponse => ("102".to_string(), "-".to_string()),
                        kind => ("-".to_string(), domain_choice(kind).unwrap().to_string()),
                    };
                    assert_eq!(
                        expected,
                        (row[9].clone(), row[10].clone()),
                        "{file}:{number}"
                    );
                    *by_mcs.entry(format!("{:?}", mcs.kind)).or_default() += 1;
                    if let Some(send) = mcs.send_data {
                        assert!(
                            send.channel_id >= 1001 || send.channel_id == 0,
                            "{file}:{number}"
                        );
                    }
                }
                other => panic!("{file}:{number} : {other:?}"),
            }
        }
    }
    assert_eq!(
        (
            segments,
            rdp,
            tls,
            tls_continuations,
            unknown,
            retransmissions,
            truncated,
            connection_requests,
            cookies
        ),
        (861, 83, 449, 32, 287, 10, 12, 7, 6)
    );
    assert_eq!(
        by_mcs,
        BTreeMap::from([
            ("ConnectInitial".to_string(), 3),
            ("ConnectResponse".to_string(), 2),
            ("ErectDomainRequest".to_string(), 1),
            ("DisconnectProviderUltimatum".to_string(), 1),
            ("AttachUserRequest".to_string(), 1),
            ("AttachUserConfirm".to_string(), 1),
            ("ChannelJoinRequest".to_string(), 6),
            ("ChannelJoinConfirm".to_string(), 6),
            ("SendDataRequest".to_string(), 27),
            ("SendDataIndication".to_string(), 21),
        ])
    );
}

/// `rdp-x509.pcap` trame 6 : la connexion sur 3389 ; ailleurs, rien sans
/// Decode As. Et `rdp-to-ssl.pcap` : apres le Connection Confirm qui retient
/// TLS, le premier segment du client est etiquete TLS, pas RDP.
#[test]
fn port_guard_decode_as_and_the_tls_switch() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let FileRead::Frames { frames, .. } = read_capture(&base.join(CORPUS).join("rdp-x509.pcap"))
    else {
        panic!("capture illisible");
    };
    let (link_type, data) = &frames[5];
    let flow = parse(*link_type, data).expect("trame 6");
    assert_eq!(label(&flow), Some("RDP"));
    // Ethernet + IPv4 sans options : ports TCP aux octets 34 a 38.
    let mut moved = data.clone();
    moved[36..38].copy_from_slice(&3390u16.to_be_bytes());
    let flow = parse(*link_type, &moved).expect("trame deplacee");
    assert_eq!(label(&flow), Some("Unknown"));
    let config = ParseConfig::new().decode_as(3390, DecodeAsProtocol::Rdp);
    let flow = parse_with(*link_type, &moved, &config).expect("trame declaree");
    assert_eq!(label(&flow), Some("RDP"));

    let FileRead::Frames { frames, .. } = read_capture(&base.join(CORPUS).join("rdp-to-ssl.pcap"))
    else {
        panic!("capture illisible");
    };
    let confirm = parse(frames[5].0, &frames[5].1).expect("trame 6");
    assert_eq!(label(&confirm), Some("RDP"));
    let packet = RdpPacket::try_from(confirm.transport.as_ref().unwrap().payload.unwrap()).unwrap();
    assert_eq!(
        packet.pdus[0].payload,
        RdpPayload::ConnectionConfirm {
            negotiation: Some(NegotiationResponse::Accepted {
                flags: 1,
                selected_protocol: 2
            })
        }
    );
    let client_hello = parse(frames[7].0, &frames[7].1).expect("trame 8");
    assert_eq!(label(&client_hello), Some("TLS"));
}
