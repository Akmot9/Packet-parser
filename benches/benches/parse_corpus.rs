// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Bench de `parse` sur le corpus versionne (#214).
//!
//! Deux groupes :
//! - `frame/*` : une trame representative par famille, pour voir quelle
//!   couche bouge quand une mesure bouge ;
//! - `corpus/*` : un sous-ensemble fige de captures, parcouru en entier.
//!
//! Les trames sont lues dans `pcaps_exemple/` et choisies par un predicat
//! sur le resultat de `parse` (« la premiere trame etiquetee TLS »), pas par
//! un numero : le choix reste lisible et survit a une capture completee. Une
//! capture ou une trame introuvable fait echouer le bench au demarrage, au
//! lieu de mesurer autre chose en silence.
//!
//! Les noms des benches sont stables : CodSpeed suit chacun d'eux dans le
//! temps. En renommer un coupe son historique.

use std::hint::black_box;
use std::path::Path;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use packet_parser::parse::PacketFlow;
use packet_parser::parse::transport::protocols::TransportProtocol;
use packet_parser::{LinkType, parse};

#[path = "../../tests/common/mod.rs"]
mod common;
use common::{FileRead, read_capture};

type Frame = (LinkType, Vec<u8>);

/// Toutes les trames d'une capture de `pcaps_exemple/`.
fn frames(capture: &str) -> Vec<Frame> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../pcaps_exemple")
        .join(capture);
    match read_capture(&path) {
        FileRead::Frames {
            frames,
            read_error_after: None,
        } if !frames.is_empty() => frames,
        _ => panic!("capture illisible ou vide : {capture}"),
    }
}

/// La premiere trame de `capture` dont le flux decode satisfait `wanted`.
fn first_frame(capture: &str, wanted: impl Fn(&PacketFlow<'_>) -> bool) -> Frame {
    frames(capture)
        .into_iter()
        .find(|(link_type, data)| parse(*link_type, data).is_ok_and(|flow| wanted(&flow)))
        .unwrap_or_else(|| panic!("aucune trame attendue dans {capture}"))
}

fn has_label(flow: &PacketFlow<'_>, label: &str) -> bool {
    flow.application
        .as_ref()
        .is_some_and(|application| application.application_protocol == label)
}

/// Le paquet de reference de `tools/verbench` : IPv6, TCP, payload chiffre
/// qu'aucune sonde ne reconnait, donc toute la cascade est parcourue. Le
/// garder ici relie ces mesures a celles de `perf_by_version.json`.
const REFERENCE_HEX: &str = include_str!("reference_packet.hex");

/// Trame synthetique : Ethernet, IPv4, TCP et 60 000 octets pseudo-aleatoires
/// qu'aucune sonde ne reconnait. C'est la taille d'un segment agrege par GRO,
/// et la borne du cout des sondes qui lisent le payload entier (#185). Le
/// corpus n'en contient pas d'aussi grand ; la trame ne sert qu'a mesurer.
fn tcp_segment_60k() -> Vec<u8> {
    const PAYLOAD_LEN: usize = 60_000;
    let total_len = u16::try_from(20 + 20 + PAYLOAD_LEN).expect("tient dans un datagramme IPv4");
    let mut frame = Vec::with_capacity(14 + usize::from(total_len));
    // Ethernet II, EtherType IPv4.
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01, 0x02, 0, 0, 0, 0, 0x02, 0x08, 0x00]);
    // IPv4 : IHL 5, DF, TTL 64, TCP, 192.0.2.1 -> 192.0.2.2.
    frame.extend_from_slice(&[0x45, 0x00]);
    frame.extend_from_slice(&total_len.to_be_bytes());
    frame.extend_from_slice(&[0, 1, 0x40, 0x00, 64, 6, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2]);
    // TCP : 40000 -> 40001, data offset 5, ACK+PSH.
    frame.extend_from_slice(&40_000u16.to_be_bytes());
    frame.extend_from_slice(&40_001u16.to_be_bytes());
    frame.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
    // Payload : xorshift a graine fixe, octets de poids fort.
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    frame.extend((0..PAYLOAD_LEN).map(|_| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state.to_be_bytes()[0]
    }));
    frame
}

fn bench_frames(c: &mut Criterion) {
    let reference = hex::decode(REFERENCE_HEX.trim()).expect("paquet de reference en hexadecimal");
    let segment_60k = tcp_segment_60k();
    assert!(
        parse(LinkType::ETHERNET, &segment_60k).is_ok_and(|flow| {
            flow.transport
                .as_ref()
                .is_some_and(|transport| transport.payload.is_some_and(|p| p.len() == 60_000))
                && has_label(&flow, "Unknown")
        }),
        "le segment synthetique doit etre un TCP de 60 000 octets non reconnu"
    );

    let cases: [(&str, Frame); 7] = [
        (
            "tcp_pure_ack",
            first_frame("protocols/tcp/tcp_handshake.pcapng", |flow| {
                flow.application.is_none()
                    && flow.transport.as_ref().is_some_and(|transport| {
                        transport.protocol == TransportProtocol::Tcp
                            && transport.payload.is_none_or(<[u8]>::is_empty)
                    })
            }),
        ),
        (
            "tls",
            first_frame("protocols/tls/tls12-dsb.pcapng", |flow| {
                has_label(flow, "TLS")
            }),
        ),
        (
            "dns",
            first_frame("protocols/dns/dns.pcap", |flow| has_label(flow, "DNS")),
        ),
        (
            "vxlan_tunnel",
            first_frame("tunnels/vxlan/vxlan_ping.pcapng", |flow| {
                flow.inner.is_some()
            }),
        ),
        (
            "asterix_multiblock",
            frames("protocols/asterix/cat_034_048.pcap")
                .into_iter()
                .filter(|(link_type, data)| {
                    parse(*link_type, data).is_ok_and(|flow| has_label(&flow, "ASTERIX"))
                })
                .max_by_key(|(_, data)| data.len())
                .expect("une trame ASTERIX dans cat_034_048.pcap"),
        ),
        ("unknown_l7_reference", (LinkType::ETHERNET, reference)),
        ("tcp_60k_unknown", (LinkType::ETHERNET, segment_60k)),
    ];

    let mut group = c.benchmark_group("frame");
    for (name, (link_type, data)) in &cases {
        group.bench_function(*name, |b| {
            b.iter(|| parse(black_box(*link_type), black_box(data)));
        });
    }
    group.finish();
}

/// Sous-ensemble fige du corpus : petit, pour tourner en quelques secondes,
/// et varie (IT, industriel, defense, tunnels). En ajouter une capture
/// deplace la mesure : le faire dans un commit a part.
const CORPUS_SUBSET: [&str; 12] = [
    "ftp.pcap",
    "protocols/tcp/tcp_handshake.pcapng",
    "protocols/dns/dns.pcap",
    "protocols/tls/tls12-dsb.pcapng",
    "protocols/modbus/Modbus.pcap",
    "protocols/dnp3/dnp3.pcap",
    "protocols/s7comm/s7comm_downloading_block_db1.pcap",
    "protocols/iec104/wireshark_iec104.pcap",
    "protocols/profinet/miguelob_pn.pcapng",
    "protocols/mqtt/mqtt_packets.pcapng",
    "protocols/asterix/cat_034_048.pcap",
    "tunnels/vxlan/vxlan_ping.pcapng",
];

fn bench_corpus(c: &mut Criterion) {
    let corpus: Vec<Frame> = CORPUS_SUBSET
        .iter()
        .flat_map(|capture| frames(capture))
        .collect();

    let mut group = c.benchmark_group("corpus");
    group.throughput(Throughput::Elements(corpus.len() as u64));
    group.bench_function("subset", |b| {
        b.iter(|| {
            for (link_type, data) in &corpus {
                let _ = black_box(parse(black_box(*link_type), black_box(data)));
            }
        });
    });
    group.finish();
}

criterion_group!(benches, bench_frames, bench_corpus);
criterion_main!(benches);
