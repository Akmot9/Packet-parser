// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! `packet_parser`, `etherparse` et `pnet_packet` sur les memes trames, de
//! la couche 2 a la couche 4 (#375).
//!
//!   cargo bench --manifest-path tools/compare/Cargo.toml
//!   python3 tools/compare/report.py
//!
//! Groupes :
//! - `<corpus>` : toutes les trames gardees d'un corpus ;
//! - `<corpus>_no_payload` : celles sans octet apres la couche 4 (SYN, ACK
//!   nus, FIN). `packet_parser::parse` n'y lit pas de couche 7 : c'est la
//!   comparaison a perimetre egal ;
//! - `frame_<cas>` : une trame par famille.
//!
//! Fonctions : `slice_*` localise les en-tetes, `full_*` lit tous leurs
//! champs. Voir `src/lib.rs` pour ce que fait chacune, et
//! `docs/benchmark-l2-l4.md` pour ce que la comparaison vaut.

use std::hint::black_box;
use std::time::Duration;

use criterion::measurement::WallTime;
use criterion::{BenchmarkGroup, Criterion, Throughput, criterion_group, criterion_main};
use packet_parser::parse::PacketFlow;
use packet_parser::{LinkType, ParseError, parse};
use packet_parser_compare::corpus::{Corpus, Readings, load_all};
use packet_parser_compare::{Key, L4, ep, pn};

/// `parse` sans enrobage : son `Result` n'est pas converti.
#[inline]
fn parse_ethernet(frame: &[u8]) -> Result<PacketFlow<'_>, ParseError> {
    parse(LinkType::ETHERNET, frame)
}

fn bench_frames(group: &mut BenchmarkGroup<'_, WallTime>, frames: &[&[u8]]) {
    group.throughput(Throughput::Elements(frames.len() as u64));
    macro_rules! case {
        ($name:literal, $function:path) => {
            group.bench_function($name, |b| {
                b.iter(|| {
                    for frame in frames {
                        // Par reference : la valeur rendue n'est pas
                        // deplacee. Celle d'etherparse pese 9,5 ko.
                        let decoded = $function(black_box(frame));
                        black_box(&decoded);
                    }
                });
            });
        };
    }
    case!("slice_etherparse", etherparse::SlicedPacket::from_ethernet);
    case!("slice_pnet", pn::slice);
    case!(
        "full_etherparse",
        etherparse::PacketHeaders::from_ethernet_slice
    );
    case!("full_etherparse_slices", ep::full_from_slices);
    case!("full_pnet", pn::full);
    case!("full_packet_parser", parse_ethernet);
}

fn key(frame: &[u8]) -> Key {
    Readings::of(frame)
        .agreed()
        .expect("le corpus ne garde que des trames lues de la meme facon")
}

fn bench_corpora(c: &mut Criterion, corpora: &[Corpus]) {
    for corpus in corpora {
        let all: Vec<&[u8]> = corpus.frames.iter().map(Vec::as_slice).collect();
        let mut group = c.benchmark_group(corpus.name);
        bench_frames(&mut group, &all);
        group.finish();

        let no_payload: Vec<&[u8]> = all
            .iter()
            .copied()
            .filter(|frame| {
                let key = key(frame);
                key.l4 == L4::Tcp && key.payload_len == 0
            })
            .collect();
        assert!(
            no_payload.len() >= 100,
            "{} : trop peu de trames sans charge utile",
            corpus.name
        );
        let mut group = c.benchmark_group(format!("{}_no_payload", corpus.name));
        bench_frames(&mut group, &no_payload);
        group.finish();
    }
}

/// Une trame par famille : la premiere du corpus que le predicat retient.
/// Une famille introuvable fait echouer le bench, au lieu de mesurer autre
/// chose en silence.
fn bench_single(c: &mut Criterion, corpora: &[Corpus]) {
    let vlan = |frame: &[u8]| frame[12..14] == [0x81, 0x00];
    type Wanted<'a> = &'a dyn Fn(&[u8], &Key) -> bool;
    let cases: [(&str, Wanted<'_>); 6] = [
        ("tcp_ack", &|f, k| {
            k.l4 == L4::Tcp && k.payload_len == 0 && k.source.is_ipv4() && !vlan(f)
        }),
        ("tcp_data", &|f, k| {
            k.l4 == L4::Tcp && k.payload_len >= 1000 && k.source.is_ipv4() && !vlan(f)
        }),
        ("udp_dns", &|f, k| {
            k.l4 == L4::Udp && k.destination_port == 53 && k.source.is_ipv4() && !vlan(f)
        }),
        ("tcp_ipv6", &|_, k| k.l4 == L4::Tcp && k.source.is_ipv6()),
        ("icmp", &|f, k| k.l4 == L4::Icmp && !vlan(f)),
        ("vlan_udp", &|f, k| k.l4 == L4::Udp && vlan(f)),
    ];
    for (name, wanted) in cases {
        let frame = corpora
            .iter()
            .flat_map(|corpus| &corpus.frames)
            .find(|frame| wanted(frame, &key(frame)))
            .unwrap_or_else(|| panic!("aucune trame pour le cas {name}"));
        let mut group = c.benchmark_group(format!("frame_{name}"));
        bench_frames(&mut group, &[frame.as_slice()]);
        group.finish();
    }
}

fn benches(c: &mut Criterion) {
    let corpora = load_all();
    bench_corpora(c, &corpora);
    bench_single(c, &corpora);
}

criterion_group! {
    name = l2l4;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(2))
        .measurement_time(Duration::from_secs(5))
        .sample_size(100);
    targets = benches
}
criterion_main!(l2l4);
