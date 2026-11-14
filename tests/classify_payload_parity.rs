// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! `classify_payload` rend l'etiquette de `parse` (#219).
//!
//! `Application::try_from(&[u8])` classait un payload sans transport ni
//! port : sur le corpus, 9 307 flux sur 254 107 n'y recevaient pas
//! l'etiquette de `parse`. `classify_payload` prend le transport et les
//! ports, et promet la meme reponse que `parse`. Ce fichier tient la
//! promesse sur tout `pcaps_exemple/`, flux par flux, tunnels compris, puis
//! fige sur des octets reels les cas que l'ancienne entree ratait.

use std::path::{Path, PathBuf};

use packet_parser::{
    Application, CorruptedLayerKind, DecodeAsProtocol, LinkType, ParseConfig, TransportProtocol,
    classify_payload, classify_payload_with, parse, parse_with,
};

mod common;
use common::{FileRead, read_capture};

/// pcaps_exemple/protocols/goose/iti_Sample_File_MMS_and_GOOSE.pcap, trame
/// 126, TCP 102 -> 1345 : un MMS confirmed-ErrorPDU sous TPKT et COTP
/// (tshark : `tpkt:cotp:ses:pres:mms`). `Application::try_from` y lisait un
/// RADIUS Access-Reject : `03 00 00 22` est aussi un code 3 de 34 octets, et
/// le BER qui suit pave deux attributs.
const MMS_OVER_COTP: &str = "0300002202f0800100010061153013020103a00ea20c800304a273a205a003870102";

/// pcaps_exemple/capture_sll2.pcap, trame 722, UDP 47715 -> 53 : une requete
/// AAAA avec EDNS, 48 octets (tshark : `dns`). Hors du port 53 elle a la
/// forme d'un paquet NTP, et `Application::try_from` l'appelait NTP.
const DNS_QUERY_WITH_EDNS: &str = concat!(
    "0d060100000100000000000108756e6167692d657506616d617a6f6e03636f6d",
    "00001c000100002905ac000000000000",
);

fn bytes(hex_dump: &str) -> Vec<u8> {
    hex::decode(hex_dump).expect("hex")
}

fn label(application: Option<Application>) -> Option<&'static str> {
    application.map(|application| application.application_protocol)
}

/// Toutes les captures du corpus, `s7comm/` compris : `collect_capture_files`
/// de `common` l'ecarte, l'histogramme golden ayant sa propre regression
/// pour lui.
fn every_capture(path: &Path, captures: &mut Vec<PathBuf>) {
    if path.is_dir() {
        let mut entries: Vec<_> = std::fs::read_dir(path)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
            .map(|entry| entry.expect("readable directory entry").path())
            .collect();
        entries.sort();
        for entry in entries {
            every_capture(entry.as_path(), captures);
        }
    } else if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "pcap" | "pcapng" | "cap"
            )
        })
    {
        captures.push(path.to_path_buf());
    }
}

#[derive(Default)]
struct Tally {
    /// Flux a transport TCP ou UDP porteur d'un payload, meme vide.
    compared: usize,
    /// Parmi eux, ceux que `parse` etiquette du nom d'un tunnel.
    tunnels: usize,
    /// Segments TCP anormaux, ecartes.
    anomalous: usize,
    /// Flux `Unknown` par defaut que la configuration etiquette SSDP.
    relabelled_ssdp: usize,
}

/// Compare, pour chaque flux de chaque capture (le flux externe et ceux des
/// tunnels), ce que `parse` a mis dans `application` a ce que rend la
/// fonction pour le meme transport, les memes ports et le meme payload.
/// Avec une configuration, ce sont `parse_with` et `classify_payload_with`.
fn compare(captures: &[PathBuf], config: Option<&ParseConfig>) -> Tally {
    let mut tally = Tally::default();
    for path in captures {
        let FileRead::Frames { frames, .. } = read_capture(path) else {
            continue;
        };
        for (index, (link_type, data)) in frames.iter().enumerate() {
            let parsed = match config {
                Some(config) => parse_with(*link_type, data, config),
                None => parse(*link_type, data),
            };
            let Ok(flow) = parsed else { continue };
            for (depth, flow) in flow.flatten().into_iter().enumerate() {
                let Some(transport) = flow.transport.as_ref() else {
                    continue;
                };
                // Seuls TCP et UDP exposent un payload : `parse` ne sonde
                // rien d'autre.
                let Some(payload) = transport.payload else {
                    continue;
                };
                // Segment TCP anormal (#24) : `parse` ne le sonde pas, et la
                // fonction, sans en-tete, ne peut pas le savoir. Difference
                // documentee, figee par
                // `anomalous_tcp_is_the_documented_difference`.
                if flow
                    .corrupted
                    .as_ref()
                    .is_some_and(|corrupted| corrupted.layer == CorruptedLayerKind::Transport)
                {
                    tally.anomalous += 1;
                    continue;
                }

                let by_default = classify_payload(
                    transport.protocol,
                    transport.source_port,
                    transport.destination_port,
                    payload,
                );
                let classified = match config {
                    Some(config) => classify_payload_with(
                        transport.protocol,
                        transport.source_port,
                        transport.destination_port,
                        payload,
                        config,
                    ),
                    None => by_default.clone(),
                };
                assert_eq!(
                    classified,
                    flow.application,
                    "{} trame {} profondeur {depth} : {} {:?} -> {:?}, {} octets",
                    path.display(),
                    index + 1,
                    transport.protocol,
                    transport.source_port,
                    transport.destination_port,
                    payload.len(),
                );

                tally.compared += 1;
                if matches!(
                    label(classified.clone()),
                    Some("VXLAN" | "Geneve" | "GTP-U")
                ) {
                    tally.tunnels += 1;
                }
                if label(classified) == Some("SSDP") && label(by_default) == Some("Unknown") {
                    tally.relabelled_ssdp += 1;
                }
            }
        }
    }
    tally
}

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("pcaps_exemple")
}

/// Le critere d'acceptation de #219 : la fonction reproduit `parse`
/// etiquette pour etiquette sur le corpus.
#[test]
fn classify_payload_answers_like_parse_on_the_whole_corpus() {
    let mut captures = Vec::new();
    every_capture(corpus().as_path(), &mut captures);

    let tally = compare(&captures, None);

    // Le test n'est pas vide. Mesure du 2026-11-14 : 358 247 flux, dont
    // 104 140 a payload vide et 93 de tunnel (GTP-U 34, Geneve 30, VXLAN
    // 29), aucun segment TCP anormal. Les tunnels comptent : la table seule
    // les rendrait `Unknown`, `parse` les nomme avant elle.
    assert!(
        tally.compared >= 350_000,
        "{} flux compares seulement",
        tally.compared
    );
    assert!(
        tally.tunnels >= 93,
        "{} flux de tunnel seulement",
        tally.tunnels
    );
}

/// « Decode As » (#65) : avec la meme configuration, `classify_payload_with`
/// rend l'etiquette de `parse_with`. The-Ultimate-PCAP.pcapng porte cinq
/// reponses SSDP envoyees en unicast depuis le port 3911 (trames 8308, 8422,
/// 8430, 8450 et 8463), hors du port 1900 de la table : `Unknown` par
/// defaut, SSDP une fois le port declare.
#[test]
fn classify_payload_with_answers_like_parse_with_on_a_declared_port() {
    let config = ParseConfig::new().decode_as(3911, DecodeAsProtocol::Ssdp);

    let tally = compare(&[corpus().join("The-Ultimate-PCAP.pcapng")], Some(&config));

    // Mesure du 2026-11-14 : 36 200 flux dans cette capture.
    assert!(
        tally.compared >= 36_000,
        "{} flux compares seulement",
        tally.compared
    );
    assert_eq!(tally.relabelled_ssdp, 5);
}

/// Le port confirme une signature faible : TPKT et COTP sur TCP 102.
#[test]
fn mms_on_iso_tsap_is_cotp() {
    let payload = bytes(MMS_OVER_COTP);

    let application = classify_payload(TransportProtocol::Tcp, Some(102), Some(1345), &payload);

    assert_eq!(label(application), Some("COTP"));
}

/// Sans port, la regle COTP ne s'applique pas ; mais la garde de transport
/// reste, et RADIUS, qui ne circule que sur UDP, ne recupere pas ce segment
/// TCP comme le faisait la cascade sans garde.
#[test]
fn mms_without_ports_is_unknown_not_radius() {
    let payload = bytes(MMS_OVER_COTP);

    let application = classify_payload(TransportProtocol::Tcp, None, None, &payload);

    assert_eq!(label(application), Some("Unknown"));
}

/// La regle de port DNS passe avant la sonde NTP sans port.
#[test]
fn dns_query_on_port_53_is_dns() {
    let payload = bytes(DNS_QUERY_WITH_EDNS);

    let application = classify_payload(TransportProtocol::Udp, Some(47715), Some(53), &payload);

    assert_eq!(label(application), Some("DNS"));
}

/// `parse` ne sonde que ce que TCP et UDP transportent : au-dessus d'ICMP,
/// d'ESP ou d'un protocole sans decodeur, `Transport::payload` reste `None`
/// et la couche application vide. La fonction ne rouvre pas cette porte,
/// quels que soient les octets et les ports qu'on lui tend.
#[test]
fn other_transports_are_never_probed() {
    for protocol in [
        TransportProtocol::Sctp,
        TransportProtocol::Icmp,
        TransportProtocol::Ipv6Icmp,
        TransportProtocol::Esp,
        TransportProtocol::Gre,
    ] {
        for (source_port, destination_port, payload) in [
            (Some(102), Some(1345), bytes(MMS_OVER_COTP)),
            (Some(47715), Some(53), bytes(DNS_QUERY_WITH_EDNS)),
            (None, None, bytes(DNS_QUERY_WITH_EDNS)),
        ] {
            assert_eq!(
                classify_payload(protocol, source_port, destination_port, &payload),
                None,
                "{protocol} {source_port:?} -> {destination_port:?}"
            );
        }
    }
}

/// Un payload vide n'a pas de couche application, comme le segment ACK nu
/// que `parse` laisse sans etiquette.
#[test]
fn empty_payload_has_no_application() {
    assert_eq!(
        classify_payload(TransportProtocol::Tcp, Some(102), Some(1345), &[]),
        None
    );
    assert_eq!(
        classify_payload(TransportProtocol::Udp, Some(47715), Some(53), &[]),
        None
    );
}

/// Le port 5353 est reserve a mDNS (RFC 6762) : un contenu qui n'en est pas
/// reste sans etiquette, au lieu de retomber dans les sondes sans port. Le
/// payload est reel, la situation ne l'est pas : c'est le segment MMS,
/// presente comme un datagramme sur ce port.
#[test]
fn reserved_mdns_port_with_other_content_is_none() {
    let payload = bytes(MMS_OVER_COTP);

    let application = classify_payload(TransportProtocol::Udp, Some(5353), Some(5353), &payload);

    assert_eq!(application, None);
}

/// La seule difference avec `parse`. Un segment SYN+FIN garde sa couche
/// transport, l'anomalie est signalee, et sa couche application n'est pas
/// sondee (#24). `classify_payload` ne recoit pas l'en-tete TCP : elle ne
/// voit pas les drapeaux, et classe.
///
/// Trame synthetique : en-tetes Ethernet, IPv4 et TCP ecrits a la main,
/// drapeaux SYN|FIN, autour du segment MMS reel.
#[test]
fn anomalous_tcp_is_the_documented_difference() {
    let payload = bytes(MMS_OVER_COTP);
    let mut frame = vec![
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // MAC destination
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // MAC source
        0x08, 0x00, // EtherType IPv4
        0x45, 0x00, 0x00, 0x4a, // longueur totale 74 = 20 IP + 20 TCP + 34
        0x12, 0x34, 0x40, 0x00, // identification, DF
        64, 6, 0x00, 0x00, // TTL, protocole TCP, checksum
        192, 0, 2, 1, // TEST-NET-1
        198, 51, 100, 2, // TEST-NET-2
        0x00, 0x66, 0x05, 0x41, // ports 102 -> 1345
        0x00, 0x00, 0x00, 0x01, // sequence
        0x00, 0x00, 0x00, 0x00, // acquittement
        0x50, 0x03, // data offset 5, drapeaux SYN|FIN
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, // fenetre, checksum, urgent
    ];
    frame.extend_from_slice(&payload);

    let flow = parse(LinkType::ETHERNET, &frame).expect("la trame se decode");
    let transport = flow.transport.as_ref().expect("couche transport conservee");
    assert_eq!(transport.payload, Some(payload.as_slice()));
    assert_eq!(
        flow.corrupted.as_ref().map(|corrupted| corrupted.layer),
        Some(CorruptedLayerKind::Transport)
    );
    assert_eq!(flow.application, None, "`parse` ne sonde pas ce segment");

    let application = classify_payload(
        transport.protocol,
        transport.source_port,
        transport.destination_port,
        &payload,
    );
    assert_eq!(label(application), Some("COTP"));
}
