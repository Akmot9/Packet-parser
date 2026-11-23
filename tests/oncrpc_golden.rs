// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests ONC RPC (#381) sur des trames reelles : les quatre captures
//! de `pcaps_exemple/protocols/oncrpc/` (voir leur `SOURCE.md`) et trois
//! appels au portmapper de
//! `protocols/goose/iti_Sample_File_MMS_and_GOOSE.pcap`.
//!
//! L'oracle est tshark 4.6.9 (`tools/oncrpc_oracle.sh`), rendu sans etat
//! comme la crate : reassemblage coupe, chaque segment lu seul. Pour chaque
//! message sont figes dans `tests/data/oncrpc_tshark_oracle.tsv` la marque
//! de fragment de TCP, l'identifiant de transaction et le type ; pour un
//! appel, le programme, sa version, la procedure, la saveur et la longueur
//! de l'authentifiant et du verifieur ; pour une reponse, son etat, son
//! verifieur et l'etat d'acceptation.
//!
//! Les ports 111 et 2049 sortent `ONC RPC`. Les messages des autres ports,
//! ceux de `mountd` que le portmapper annonce, sortent `Unknown` par defaut
//! et `ONC RPC` une fois leur port declare par Decode As ; le decodeur les
//! lit tous.
//!
//! Oracle negatif : aucune autre trame de ces captures ne sort `ONC RPC`,
//! et les autres charges des ports 111 et 2049, des segments de suite,
//! sortent `Unknown`.

use std::{collections::BTreeMap, fs, path::Path};

use packet_parser::{
    DecodeAsProtocol, ParseConfig, TransportProtocol, classify_payload_with, parse,
    parse::application::protocols::oncrpc::{
        OncRpcAuth, OncRpcBody, OncRpcMessage, OncRpcRecord, OncRpcReply,
    },
};

mod common;
use common::{FileRead, collect_capture_files, read_capture};

const ORACLE: &str = "tests/data/oncrpc_tshark_oracle.tsv";
const ROOT: &str = "pcaps_exemple";
/// Colonnes de l'oracle ; les treize dernieres decrivent le message.
const COLUMNS: usize = 22;
const ABSENT: &str = "-";

fn is_oncrpc_port(port: Option<u16>) -> bool {
    matches!(port, Some(111 | 2049))
}

/// La saveur et la longueur d'un `opaque_auth`, comme l'oracle les ecrit.
fn auth(auth: Option<OncRpcAuth<'_>>) -> [String; 2] {
    auth.map_or_else(
        || [ABSENT.to_string(), ABSENT.to_string()],
        |auth| [auth.flavor.to_string(), auth.body.len().to_string()],
    )
}

/// Les treize colonnes d'un message : xid, type, programme, version,
/// procedure, authentifiant, verifieur, puis les quatre etats d'une reponse.
fn columns(message: &OncRpcMessage<'_>) -> Vec<String> {
    let absent = || ABSENT.to_string();
    let mut columns = vec![message.xid.to_string()];
    match message.body {
        OncRpcBody::Call(call) => {
            columns.push("0".to_string());
            columns.extend([call.program, call.version, call.procedure].map(|n| n.to_string()));
            columns.extend(auth(Some(call.credentials)));
            columns.extend(auth(Some(call.verifier)));
            columns.extend([absent(), absent(), absent(), absent()]);
        }
        OncRpcBody::Reply(reply) => {
            columns.push("1".to_string());
            columns.extend([absent(), absent(), absent(), absent(), absent()]);
            match reply {
                OncRpcReply::Accepted(accepted) => {
                    columns.extend(auth(Some(accepted.verifier)));
                    columns.extend([
                        "0".to_string(),
                        accepted.status.code().to_string(),
                        absent(),
                        absent(),
                    ]);
                }
                OncRpcReply::RpcMismatch { .. } => {
                    columns.extend(auth(None));
                    columns.extend(["1".to_string(), absent(), "0".to_string(), absent()]);
                }
                OncRpcReply::AuthError { status, .. } => {
                    columns.extend(auth(None));
                    columns.extend([
                        "1".to_string(),
                        absent(),
                        "1".to_string(),
                        status.to_string(),
                    ]);
                }
                reply => panic!("reponse inattendue : {reply:?}"),
            }
        }
        body => panic!("corps inattendu : {body:?}"),
    }
    columns
}

#[test]
fn every_oncrpc_message_matches_the_tshark_oracle() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let oracle = fs::read_to_string(base.join(ORACLE)).expect("oracle lisible");
    // Par trame, ses messages dans l'ordre.
    let mut rows: BTreeMap<(String, usize), Vec<Vec<String>>> = BTreeMap::new();
    let mut total = 0usize;
    for line in oracle.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<String> = line.split('\t').map(str::to_string).collect();
        assert_eq!(fields.len(), COLUMNS, "ligne d'oracle malformee : {line}");
        let frame = fields[1].parse().expect("numero de trame");
        let messages = rows.entry((fields[0].clone(), frame)).or_default();
        assert_eq!(fields[2], messages.len().to_string(), "rang : {line}");
        messages.push(fields);
        total += 1;
    }
    assert_eq!(total, 409);

    let root = base.join(ROOT);
    let mut captures = vec![root.join("The-Ultimate-PCAP.pcapng")];
    collect_capture_files(&root.join("protocols"), &mut captures);

    let mut per_capture: BTreeMap<String, usize> = BTreeMap::new();
    let mut kinds: BTreeMap<(String, bool), usize> = BTreeMap::new();
    let mut programs: BTreeMap<(u32, u32), usize> = BTreeMap::new();
    let mut flavors: BTreeMap<u32, usize> = BTreeMap::new();
    let mut truncated = 0usize;
    let mut off_port = 0usize;
    let mut continuations: BTreeMap<String, usize> = BTreeMap::new();
    for path in &captures {
        let capture = path
            .strip_prefix(&root)
            .expect("capture du corpus")
            .to_string_lossy()
            .replace('\\', "/");
        let FileRead::Frames { frames, .. } = read_capture(path) else {
            continue;
        };
        for (index, (link_type, data)) in frames.iter().enumerate() {
            let number = index + 1;
            let key = (capture.clone(), number);
            let Ok(flow) = parse(*link_type, data) else {
                assert!(!rows.contains_key(&key), "{capture} trame {number}");
                continue;
            };
            let flow = *flow.flatten().last().expect("au moins un flux");
            let label = flow
                .application
                .as_ref()
                .map(|application| application.protocol.label());
            let transport = flow.transport.as_ref();
            let payload = transport.and_then(|transport| transport.payload);
            let on_port = transport.is_some_and(|transport| {
                is_oncrpc_port(transport.source_port) || is_oncrpc_port(transport.destination_port)
            });
            let Some(messages) = rows.get(&key) else {
                assert_ne!(label, Some("ONC RPC"), "{capture} trame {number}");
                // Le reste des ports 111 et 2049 : des segments de suite.
                if on_port && payload.is_some_and(|payload| !payload.is_empty()) {
                    assert_eq!(label, Some("Unknown"), "{capture} trame {number}");
                    assert_eq!(
                        transport.map(|transport| transport.protocol),
                        Some(TransportProtocol::Tcp),
                        "{capture} trame {number}"
                    );
                    *continuations.entry(capture.clone()).or_default() += 1;
                }
                continue;
            };
            let transport = transport.expect("couche transport");
            let payload = payload.expect("charge");
            let is_udp = transport.protocol == TransportProtocol::Udp;
            let transport_name = if is_udp { "udp" } else { "tcp" };

            if on_port {
                assert_eq!(label, Some("ONC RPC"), "{capture} trame {number}");
            } else {
                // Un port que le portmapper a annonce : la table ne le
                // connait pas, Decode As le declare.
                assert_eq!(label, Some("Unknown"), "{capture} trame {number}");
                let is_call = messages[0][10] == "0";
                let server = if is_call {
                    transport.destination_port
                } else {
                    transport.source_port
                };
                let config = ParseConfig::new()
                    .decode_as(server.expect("port du serveur"), DecodeAsProtocol::OncRpc);
                let declared = classify_payload_with(
                    transport.protocol,
                    transport.source_port,
                    transport.destination_port,
                    payload,
                    &config,
                );
                assert_eq!(
                    declared.map(|application| application.protocol.label()),
                    Some("ONC RPC"),
                    "{capture} trame {number}"
                );
                off_port += 1;
            }

            // Un datagramme porte un message ; un segment, des
            // enregistrements qui le pavent.
            let decoded: Vec<([String; 2], OncRpcMessage<'_>)> = if is_udp {
                let message = OncRpcMessage::try_from(payload)
                    .unwrap_or_else(|error| panic!("{capture} trame {number} : {error}"));
                vec![([ABSENT.to_string(), ABSENT.to_string()], message)]
            } else {
                let mut consumed = 0usize;
                let records: Vec<_> = OncRpcRecord::records(payload)
                    .map(|record| {
                        let record = record
                            .unwrap_or_else(|error| panic!("{capture} trame {number} : {error}"));
                        // Aucun enregistrement du corpus n'a plus d'un
                        // fragment : la marque annonce tout le message, que
                        // le segment coupe quand il est plus court.
                        assert!(record.is_last_fragment, "{capture} trame {number}");
                        assert!(record.continuation().is_empty());
                        consumed += 4 + record.length as usize;
                        assert_eq!(
                            record.is_truncated(),
                            payload.len() < consumed,
                            "{capture} trame {number}"
                        );
                        truncated += usize::from(record.is_truncated());
                        (
                            [
                                record.length.to_string(),
                                u8::from(record.is_last_fragment).to_string(),
                            ],
                            record.message,
                        )
                    })
                    .collect();
                assert!(consumed >= payload.len(), "{capture} trame {number}");
                records
            };
            assert_eq!(decoded.len(), messages.len(), "{capture} trame {number}");

            for (rank, ((mark, message), row)) in decoded.iter().zip(messages).enumerate() {
                let mut line = vec![
                    capture.clone(),
                    number.to_string(),
                    rank.to_string(),
                    transport_name.to_string(),
                    transport.source_port.expect("port source").to_string(),
                    transport
                        .destination_port
                        .expect("port de destination")
                        .to_string(),
                    payload.len().to_string(),
                ];
                line.extend(mark.clone());
                line.extend(columns(message));
                assert_eq!(&line, row, "{capture} trame {number}");

                *per_capture.entry(capture.clone()).or_default() += 1;
                let is_call = matches!(message.body, OncRpcBody::Call(_));
                *kinds
                    .entry((transport_name.to_string(), is_call))
                    .or_default() += 1;
                if let OncRpcBody::Call(call) = message.body {
                    *programs.entry((call.program, call.version)).or_default() += 1;
                    *flavors.entry(call.credentials.flavor).or_default() += 1;
                }
            }
        }
    }
    assert_eq!(per_capture.values().sum::<usize>(), 409);
    let counts = |entries: &[(&str, usize)]| -> BTreeMap<String, usize> {
        entries
            .iter()
            .map(|(capture, count)| (capture.to_string(), *count))
            .collect()
    };
    assert_eq!(
        per_capture,
        counts(&[
            ("protocols/goose/iti_Sample_File_MMS_and_GOOSE.pcap", 3),
            ("protocols/oncrpc/ndpi_nfsv2.pcap", 156),
            ("protocols/oncrpc/ndpi_nfsv3.pcap", 128),
            ("protocols/oncrpc/wireshark_getsetacl.cap", 56),
            ("protocols/oncrpc/wireshark_nfsv4.1_pnfs.cap", 66),
        ]),
        "messages par capture"
    );
    // Autant d'appels que de reponses sur TCP ; sur UDP, trois appels au
    // portmapper d'un hote qui n'en a pas (capture GOOSE) restent sans
    // reponse.
    let kinds: Vec<(&str, bool, usize)> = kinds
        .iter()
        .map(|((transport, is_call), count)| (transport.as_str(), *is_call, *count))
        .collect();
    assert_eq!(
        kinds,
        [
            ("tcp", false, 61),
            ("tcp", true, 61),
            ("udp", false, 142),
            ("udp", true, 145),
        ],
        "reponses et appels par transport"
    );
    // Le portmapper (100000, versions 2 et 3), NFS (100003, versions 2, 3
    // et 4), mountd (100005), NFS_ACL (100227) et le programme de rappel
    // de NFSv4.1 (0x40000000, le premier numero de la plage transitoire).
    assert_eq!(
        programs.into_iter().collect::<Vec<_>>(),
        [
            ((100_000, 2), 3),
            ((100_000, 3), 6),
            ((100_003, 2), 73),
            ((100_003, 3), 80),
            ((100_003, 4), 32),
            ((100_005, 1), 3),
            ((100_005, 3), 2),
            ((100_227, 3), 6),
            ((0x4000_0000, 1), 1),
        ],
        "appels par programme et version"
    );
    // AUTH_NONE (0) et AUTH_SYS (1) ; aucun appel du corpus ne porte une
    // autre saveur.
    assert_eq!(
        flavors.into_iter().collect::<Vec<_>>(),
        [(0, 13), (1, 193)],
        "saveur de l'authentifiant des appels"
    );
    // Dix messages de mountd, sur un port que le portmapper a annonce.
    assert_eq!(off_port, 10, "messages hors des ports 111 et 2049");
    // Quatre reponses de NFS depassent leur segment ; les huit segments
    // qui portent leur suite ne sont pas nommes.
    assert_eq!(truncated, 4, "enregistrements coupes");
    assert_eq!(
        continuations,
        counts(&[("protocols/oncrpc/wireshark_getsetacl.cap", 8)]),
        "segments de suite"
    );
}
