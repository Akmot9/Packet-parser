// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Regression differentielle GIOP contre tshark, message par message.
//!
//! `tests/data/giop_tshark_oracle.tsv` est produit par `tools/giop_oracle.sh`
//! (tshark 4.6.6, reassemblage TCP desactive : la vue d'un parseur
//! stateless). Ce test rejoue chaque capture de
//! `pcaps_exemple/protocols/giop/` dans le parseur, rend les memes colonnes,
//! et exige l'egalite ligne a ligne : type de message, version, flags,
//! taille, request id, statut de Reply et de LocateReply, operation,
//! exception, hote et port IIOP d'un LOCATION_FORWARD.
//!
//! Les ecarts assumes sont nommes dans `tshark_only_columns`, pas masques.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use packet_parser::{
    parse,
    parse::application::protocols::giop::{
        GiopLocateStatus, GiopMessage, GiopMessageType, GiopPacket, GiopReplyDetail,
        GiopReplyStatus, TargetAddress, find_giop_message, giop_messages,
    },
};

mod common;
use common::{FileRead, read_capture};

const ORACLE: &str = include_str!("data/giop_tshark_oracle.tsv");

fn message_type_code(message_type: GiopMessageType) -> u8 {
    match message_type {
        GiopMessageType::Request => 0,
        GiopMessageType::Reply => 1,
        GiopMessageType::CancelRequest => 2,
        GiopMessageType::LocateRequest => 3,
        GiopMessageType::LocateReply => 4,
        GiopMessageType::CloseConnection => 5,
        GiopMessageType::MessageError => 6,
        GiopMessageType::Fragment => 7,
        other => panic!("type de message GIOP sans code d'oracle : {other:?}"),
    }
}

fn reply_status_code(status: GiopReplyStatus) -> u32 {
    match status {
        GiopReplyStatus::NoException => 0,
        GiopReplyStatus::UserException => 1,
        GiopReplyStatus::SystemException => 2,
        GiopReplyStatus::LocationForward => 3,
        GiopReplyStatus::LocationForwardPerm => 4,
        GiopReplyStatus::NeedsAddressingMode => 5,
        other => panic!("statut de Reply sans code d'oracle : {other:?}"),
    }
}

fn locate_status_code(status: GiopLocateStatus) -> u32 {
    match status {
        GiopLocateStatus::UnknownObject => 0,
        GiopLocateStatus::ObjectHere => 1,
        GiopLocateStatus::ObjectForward => 2,
        GiopLocateStatus::ObjectForwardPerm => 3,
        GiopLocateStatus::LocSystemException => 4,
        GiopLocateStatus::LocNeedsAddressingMode => 5,
        other => panic!("statut de LocateReply sans code d'oracle : {other:?}"),
    }
}

/// Rend un message decode dans les colonnes de l'oracle (sans capture ni
/// numero de trame).
///
/// `decoded_by_tshark` : tshark ne rend pas de `stub data` pour ce message
/// parce qu'il en decode lui-meme les arguments (voir [`observed`]).
fn render(packet: &GiopPacket<'_>, decoded_by_tshark: bool) -> String {
    let header = &packet.header;
    // tshark n'a pas de champ `giop.flags` en GIOP 1.0 : l'octet y est le
    // booleen `byte_order`.
    let flags = if header.minor_version == 0 {
        String::new()
    } else {
        format!("0x{:02x}", header.flags)
    };

    let mut request_id = String::new();
    let mut reply_status = String::new();
    let mut locate_status = String::new();
    let mut operation = String::new();
    let mut exception_id = String::new();
    let mut iiop_host = String::new();
    let mut iiop_port = String::new();
    let mut object_key_len = 0;
    let mut stub_data_len = 0;
    let mut minor_code = String::new();
    let mut completion_status = String::new();

    let key_len = |target: &TargetAddress<'_>| match target {
        TargetAddress::KeyAddr(key) => key.len(),
        _ => 0,
    };

    match &packet.payload {
        GiopMessage::Request(request) => {
            request_id = request.request_id.to_string();
            operation = request.operation.to_string();
            object_key_len = key_len(&request.target);
            stub_data_len = request.stub_data.len();
        }
        GiopMessage::Reply(reply) => {
            request_id = reply.request_id.to_string();
            reply_status = reply_status_code(reply.reply_status).to_string();
            // tshark ne rend un `stub data` que pour les resultats d'une
            // operation ; le body d'une exception ou d'un forward est
            // decode, pas rendu brut.
            if reply.detail == GiopReplyDetail::Results {
                stub_data_len = reply.body.len();
            }
            match &reply.detail {
                GiopReplyDetail::UserException {
                    exception_id: id,
                    members,
                } => {
                    exception_id = (*id).to_string();
                    // tshark rend bruts les membres d'une exception
                    // utilisateur, sauf celles des services OMG (CosNaming,
                    // ...) pour lesquelles il embarque un sous-dissecteur.
                    if !id.starts_with("IDL:omg.org/") {
                        stub_data_len = members.len();
                    }
                }
                GiopReplyDetail::SystemException(exception) => {
                    exception_id = exception.exception_id.to_string();
                    minor_code = exception.minor_code.to_string();
                    completion_status = exception.completion_status.to_string();
                }
                GiopReplyDetail::LocationForward(ior) => {
                    if let Some(iiop) = ior.iiop() {
                        iiop_host = iiop.host.to_string();
                        iiop_port = iiop.port.to_string();
                    }
                }
                _ => {}
            }
        }
        GiopMessage::CancelRequest(cancel) => request_id = cancel.request_id.to_string(),
        GiopMessage::LocateRequest(locate) => {
            request_id = locate.request_id.to_string();
            object_key_len = key_len(&locate.target);
        }
        GiopMessage::LocateReply(locate) => {
            request_id = locate.request_id.to_string();
            locate_status = locate_status_code(locate.locate_status).to_string();
        }
        GiopMessage::Fragment(fragment) => {
            request_id = fragment
                .request_id
                .map(|id| id.to_string())
                .unwrap_or_default();
        }
        GiopMessage::CloseConnection | GiopMessage::MessageError => {}
        // Body non decode : rendu tel quel, il ressort comme une divergence
        // nommee par sa trame plutot que comme une panique anonyme.
        other => operation = format!("<{other:?}>"),
    }

    // Premier fragment coupe par la segmentation TCP : tshark attend le
    // reassemblage pour rendre le stub data (trame 41 de la capture #11616).
    // Un premier fragment entier dans son segment est rendu tout de suite.
    if decoded_by_tshark || (header.has_more_fragments() && packet.truncated) {
        stub_data_len = 0;
    }

    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        message_type_code(header.message_type),
        header.minor_version,
        flags,
        header.message_length,
        request_id,
        reply_status,
        locate_status,
        operation,
        exception_id,
        iiop_host,
        iiop_port,
        object_key_len,
        stub_data_len,
        minor_code,
        completion_status
    )
}

/// Colonnes que tshark remplit grace a son etat et qu'un parseur stateless ne
/// peut pas connaitre : elles sont videes de l'oracle avant comparaison.
///
/// - Fragment : tshark reassemble les fragments et rapporte sur le dernier
///   l'operation, l'object key et le stub data du Request d'origine (trame
///   57 de `wireshark_11616_locate_fragment.pcap` : `op=push`).
///   Apres reassemblage d'un Reply fragmente, il y rapporte aussi son statut
///   (trame 24 de `lab_giop12_basic.pcap`).
/// - Fragment GIOP 1.1 : tshark y lit un request id, alors que le Fragment
///   1.1 n'a pas d'en-tete (CORBA 2.3 §15.4.8 ; le request id n'arrive
///   qu'avec GIOP 1.2). Sur les trames 19 et 23 de `lab_giop11_basic.pcap`
///   il rapporte 2021161080 = 0x78787878, soit les quatre premiers `x` de
///   la chaine envoyee par le client : ce sont des donnees, pas un
///   identifiant. Bug connu de Wireshark (issue 1934).
fn tshark_only_columns(columns: &mut [String]) {
    const TYPE: usize = 0;
    const MINOR: usize = 1;
    const REQUEST_ID: usize = 4;
    const REPLY_STATUS: usize = 5;
    const OPERATION: usize = 7;
    const OBJECT_KEY_LEN: usize = 11;
    const STUB_DATA_LEN: usize = 12;
    if columns[TYPE] == "7" {
        if columns[MINOR] == "1" {
            columns[REQUEST_ID].clear();
        }
        columns[REPLY_STATUS].clear();
        columns[OPERATION].clear();
        columns[OBJECT_KEY_LEN] = "0".to_string();
        columns[STUB_DATA_LEN] = "0".to_string();
    }
}

/// Un flux, identifie par ses deux extremites (adresse, port), dans un sens
/// canonique.
type FlowKey = (String, String);

fn flow_key(flow: &packet_parser::PacketFlow<'_>) -> Option<FlowKey> {
    let internet = flow.internet.as_ref()?;
    let transport = flow.transport.as_ref()?;
    let a = format!("{:?}:{:?}", internet.source, transport.source_port);
    let b = format!(
        "{:?}:{:?}",
        internet.destination, transport.destination_port
    );
    Some(if a <= b { (a, b) } else { (b, a) })
}

/// Position du message GIOP dans un payload, pour un appelant qui suit les
/// flux comme le fait tshark :
/// - au debut du payload pour IIOP (TCP) ;
/// - apres le PacketHeader pour MIOP (UDP multicast, magic `MIOP`) ;
/// - au milieu d'un segment de continuation, **seulement** si ce flux a
///   deja porte du GIOP (resynchronisation, voir `find_giop_message`).
fn giop_offset(payload: &[u8], flow_is_known_giop: bool) -> Option<usize> {
    if payload.starts_with(b"GIOP") {
        return Some(0);
    }
    if payload.starts_with(b"MIOP") || flow_is_known_giop {
        return find_giop_message(payload);
    }
    None
}

/// Messages GIOP de chaque trame d'une capture, rendus comme l'oracle.
/// tshark n'emet qu'une ligne par trame (`occurrence=f`) : le premier message.
fn observed(path: &Path) -> BTreeMap<usize, String> {
    let FileRead::Frames { frames, .. } = read_capture(path) else {
        panic!("{}: capture illisible", path.display());
    };
    let mut lines = BTreeMap::new();
    let mut giop_flows: BTreeSet<FlowKey> = BTreeSet::new();
    // Pseudo-operations de CORBA::Object (`_is_a`, `_non_existent`, ...) :
    // tshark en connait la signature et decode leurs arguments au lieu de
    // rendre un `stub data`, pour le Request comme pour son Reply — qu'il
    // apparie par (flux, request id). Le harnais tient ce meme etat.
    let mut pseudo_operations: BTreeSet<(Option<FlowKey>, u32)> = BTreeSet::new();
    for (index, (link_type, data)) in frames.iter().enumerate() {
        let Ok(flow) = parse(*link_type, data) else {
            continue;
        };
        let Some(payload) = flow.transport.as_ref().and_then(|t| t.payload) else {
            continue;
        };
        let key = flow_key(&flow);
        let known = key.as_ref().is_some_and(|key| giop_flows.contains(key));
        let Some(offset) = giop_offset(payload, known) else {
            continue;
        };
        if let Some(packet) = giop_messages(&payload[offset..]).next() {
            let decoded_by_tshark = match &packet.payload {
                GiopMessage::Request(request) if request.operation.starts_with('_') => {
                    pseudo_operations.insert((key.clone(), request.request_id));
                    true
                }
                GiopMessage::Reply(reply) => {
                    pseudo_operations.remove(&(key.clone(), reply.request_id))
                }
                _ => false,
            };
            lines.insert(index + 1, render(&packet, decoded_by_tshark));
            if let Some(key) = key {
                giop_flows.insert(key);
            }
        }
    }
    lines
}

/// Seul message du corpus qui ne sorte pas d'un ORB : le Request tronque que
/// `tools/giop_lab/garbage.py` envoie pour provoquer le MessageError du
/// serveur (trame 6 de la meme capture, elle bien reelle). Son en-tete
/// Request est illisible par construction : il sort en `Other`.
const HAND_MADE_FRAMES: [(&str, usize); 1] = [("lab_message_error.pcap", 4)];

/// Compare une capture a son oracle et rend le nombre de messages compares
/// et la liste des divergences, dans les deux sens.
fn compare(base: &Path, oracle_text: &str) -> (usize, Vec<String>) {
    let mut expected: BTreeMap<&str, BTreeMap<usize, String>> = BTreeMap::new();
    for line in oracle_text.lines().filter(|line| !line.is_empty()) {
        let mut columns = line.split('|');
        let capture = columns.next().expect("colonne capture");
        let frame: usize = columns
            .next()
            .and_then(|frame| frame.parse().ok())
            .expect("colonne trame");
        if HAND_MADE_FRAMES.contains(&(capture, frame)) {
            continue;
        }
        let mut rest: Vec<String> = columns.map(str::to_string).collect();
        tshark_only_columns(&mut rest);
        expected
            .entry(capture)
            .or_default()
            .insert(frame, rest.join("|"));
    }

    let mut messages = 0;
    let mut divergences = Vec::new();
    for (capture, oracle) in &expected {
        let observed = observed(&base.join(capture));
        for (frame, line) in oracle {
            messages += 1;
            if observed.get(frame) != Some(line) {
                divergences.push(format!(
                    "{capture} trame {frame} : tshark `{line}` / parseur `{}`",
                    observed.get(frame).map_or("<rien>", String::as_str)
                ));
            }
        }
        // Dans l'autre sens : aucun message GIOP vu par le parseur que
        // tshark ne voit pas.
        for (frame, line) in &observed {
            if !oracle.contains_key(frame) && !HAND_MADE_FRAMES.contains(&(*capture, *frame)) {
                divergences.push(format!(
                    "{capture} trame {frame} : parseur `{line}` / tshark <rien>"
                ));
            }
        }
    }
    (messages, divergences)
}

#[test]
fn every_real_giop_message_decodes_like_tshark() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("pcaps_exemple/protocols/giop");
    let (messages, divergences) = compare(&base, ORACLE);
    assert!(
        divergences.is_empty(),
        "le parseur diverge de tshark :\n{}",
        divergences.join("\n")
    );
    assert_eq!(messages, 134, "volumetrie de l'oracle");
}

/// Meme comparaison sur un corpus local trop volumineux pour le depot (voir
/// `pcaps_exemple/protocols/giop/SOURCE.md`), oracle genere a la volee :
///
/// ```sh
/// GIOP_EXTRA_CORPUS=/chemin/vers/captures \
///     cargo test --test giop_tshark_regression -- --ignored --nocapture
/// ```
#[test]
#[ignore = "exige tshark et un corpus local (GIOP_EXTRA_CORPUS)"]
fn extra_corpus_decodes_like_tshark() {
    let corpus = std::env::var("GIOP_EXTRA_CORPUS").expect("GIOP_EXTRA_CORPUS");
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tools/giop_oracle.sh");
    let output = std::process::Command::new(script)
        .arg(&corpus)
        .output()
        .expect("tools/giop_oracle.sh s'execute");
    assert!(output.status.success(), "tshark a echoue");
    let oracle = String::from_utf8(output.stdout).expect("oracle UTF-8");

    let (messages, divergences) = compare(Path::new(&corpus), &oracle);
    println!(
        "{messages} messages compares, {} divergences",
        divergences.len()
    );
    for divergence in &divergences {
        println!("{divergence}");
    }
    assert!(divergences.is_empty());
}

/// Toute trame TCP que tshark dissèque comme GIOP sort etiquetee `GIOP` du
/// pipeline complet — y compris le premier segment d'un message qui deborde
/// (trames 8 et 12 de corba.pcap, 41 et 48 de la capture #11616).
#[test]
fn every_real_giop_frame_over_tcp_is_labelled_by_the_pipeline() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("pcaps_exemple/protocols/giop");
    let mut checked = 0;
    let mut stateless_gaps = Vec::new();
    let mut captures: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for line in ORACLE.lines().filter(|line| !line.is_empty()) {
        let mut columns = line.split('|');
        let capture = columns.next().expect("colonne capture");
        let frame = columns
            .next()
            .and_then(|frame| frame.parse().ok())
            .expect("colonne trame");
        captures.entry(capture).or_default().push(frame);
    }

    for (capture, oracle_frames) in captures {
        let FileRead::Frames { frames, .. } = read_capture(&base.join(capture)) else {
            panic!("{capture}: capture illisible");
        };
        for frame in oracle_frames {
            let (link_type, data) = &frames[frame - 1];
            let flow = parse(*link_type, data).expect("trame reelle decodee");
            let over_tcp = flow
                .transport
                .as_ref()
                .and_then(|t| t.payload)
                .is_some_and(|payload| payload.starts_with(b"GIOP"));
            if !over_tcp {
                // Ecarts figes, pas masques : le payload ne commence pas par
                // le magic GIOP.
                // - MIOP (UDP multicast) : hors du dispatch GIOP, voir
                //   giop_golden.rs ;
                // - segment de continuation TCP dont le header GIOP demarre
                //   au milieu du payload, que tshark retrouve par son suivi
                //   de flux (capture #11616, trames 48 et 57).
                stateless_gaps.push((capture, frame));
                continue;
            }
            assert_eq!(
                flow.application.map(|a| a.application_protocol),
                Some("GIOP"),
                "{capture} trame {frame}"
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 123, "trames GIOP sur TCP de l'oracle");
    let continuation_gaps: Vec<_> = stateless_gaps
        .iter()
        .filter(|(capture, _)| *capture != "corba.pcap")
        .collect();
    assert_eq!(
        continuation_gaps,
        [
            &("wireshark_11616_locate_fragment.pcap", 48),
            &("wireshark_11616_locate_fragment.pcap", 57)
        ],
        "seuls ecarts d'etiquetage hors MIOP"
    );
    assert_eq!(
        stateless_gaps.len(),
        12,
        "10 datagrammes MIOP + 2 continuations"
    );
}

/// Payloads GIOP (a partir du magic) de toutes les trames du corpus du depot.
fn real_giop_payloads() -> Vec<Vec<u8>> {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("pcaps_exemple/protocols/giop");
    let mut captures: BTreeSet<&str> = BTreeSet::new();
    for line in ORACLE.lines().filter(|line| !line.is_empty()) {
        captures.insert(line.split('|').next().expect("colonne capture"));
    }

    let mut payloads = Vec::new();
    for capture in captures {
        let FileRead::Frames { frames, .. } = read_capture(&base.join(capture)) else {
            panic!("{capture}: capture illisible");
        };
        for (link_type, data) in &frames {
            let Ok(flow) = parse(*link_type, data) else {
                continue;
            };
            let Some(payload) = flow.transport.as_ref().and_then(|t| t.payload) else {
                continue;
            };
            if let Some(offset) = find_giop_message(payload) {
                payloads.push(payload[offset..].to_vec());
            }
        }
    }
    payloads
}

/// Fige ce que le corpus reel exerce : si une capture disparait ou si un
/// decodage regresse en `Other`, la couverture annoncee tombe avec ce test.
#[test]
fn real_corpus_covers_the_protocol() {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for payload in real_giop_payloads() {
        for packet in giop_messages(&payload) {
            let header = &packet.header;
            let endianness = if header.is_little_endian() {
                "LE"
            } else {
                "BE"
            };
            seen.insert(format!("1.{} {endianness}", header.minor_version));
            if packet.truncated {
                seen.insert("truncated".to_string());
            }
            if header.has_more_fragments() {
                seen.insert(format!("more-fragments 1.{}", header.minor_version));
            }
            seen.insert(match &packet.payload {
                GiopMessage::Request(request) => {
                    match (&request.target, request.requesting_principal) {
                        (TargetAddress::ProfileAddr(_), _) => "Request ProfileAddr".to_string(),
                        (_, Some(_)) => "Request with principal".to_string(),
                        _ => "Request KeyAddr".to_string(),
                    }
                }
                GiopMessage::Reply(reply) => format!("Reply {:?}", reply.reply_status),
                GiopMessage::LocateRequest(_) => "LocateRequest".to_string(),
                GiopMessage::LocateReply(reply) => format!("LocateReply {:?}", reply.locate_status),
                GiopMessage::Fragment(fragment) => match fragment.request_id {
                    Some(_) => "Fragment with request id".to_string(),
                    None => "Fragment without request id".to_string(),
                },
                GiopMessage::CloseConnection => "CloseConnection".to_string(),
                GiopMessage::MessageError => "MessageError".to_string(),
                GiopMessage::CancelRequest(_) => "CancelRequest".to_string(),
                // Le seul `Other` du corpus est le stimulus fait main.
                other => format!("{other:?}"),
            });
            if let GiopMessage::Reply(reply) = &packet.payload {
                if let GiopReplyDetail::LocationForward(ior) = &reply.detail {
                    assert!(ior.iiop().is_some(), "le forward reel porte un profil IIOP");
                    seen.insert("LocationForward IIOP profile".to_string());
                }
                assert_ne!(reply.detail, GiopReplyDetail::Undecoded, "{reply:?}");
            }
        }
    }

    let expected = [
        "1.0 LE",
        "1.1 LE",
        "1.2 BE",
        "1.2 LE",
        "CloseConnection",
        "Fragment with request id",
        "Fragment without request id",
        "LocateReply ObjectHere",
        "LocateReply UnknownObject",
        "LocateRequest",
        "LocationForward IIOP profile",
        "MessageError",
        "Other",
        "Reply LocationForward",
        "Reply NoException",
        "Reply SystemException",
        "Reply UserException",
        "Request KeyAddr",
        "Request ProfileAddr",
        "Request with principal",
        "more-fragments 1.1",
        "more-fragments 1.2",
        "truncated",
    ];
    let seen: Vec<&str> = seen.iter().map(String::as_str).collect();
    // Absents du corpus, faute d'ORB qui les emette (voir SOURCE.md) :
    // CancelRequest, LocateReply OBJECT_FORWARD et au-dela, Reply
    // LOCATION_FORWARD_PERM et NEEDS_ADDRESSING_MODE, TargetAddress
    // ReferenceAddr, GIOP 1.0/1.1 big-endian (l'endianness est portee par le
    // curseur CDR, independamment de la version, et le big-endian est couvert
    // en 1.2). Ils sont couverts par les tests unitaires du module.
    assert_eq!(seen, expected);
}

/// Aucune entree derivee d'un message reel ne fait paniquer le decodeur :
/// chaque message est rejoue tronque a toutes ses longueurs, puis avec
/// chacun de ses 256 premiers octets inverse.
#[test]
fn truncated_and_mutated_real_messages_never_panic() {
    let payloads = real_giop_payloads();
    assert!(payloads.len() >= 130);

    let exercise = |bytes: &[u8]| {
        for packet in giop_messages(bytes) {
            if let GiopMessage::Reply(reply) = &packet.payload
                && let GiopReplyDetail::LocationForward(ior) = &reply.detail
            {
                let _ = ior.iiop();
            }
            assert!(packet.wire_len() >= 12 && packet.wire_len() <= bytes.len());
        }
        let _ = find_giop_message(bytes);
    };

    for payload in &payloads {
        let window = payload.len().min(2048);
        for len in 0..=window {
            exercise(&payload[..len]);
        }
        let mut mutated = payload[..window].to_vec();
        for index in 0..window.min(256) {
            mutated[index] ^= 0xFF;
            exercise(&mutated);
            mutated[index] ^= 0xFF;
        }
    }
}
