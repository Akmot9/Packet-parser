// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Regression tshark generalisee (epic #70) : le pattern de
//! `s7comm_regression` — comptes et digests FNV-1a des numeros de trame,
//! generes independamment avec tshark — applique aux corpus Modbus TCP
//! (#71), DNS (#72) et TLS (#73).
//!
//! Les oracles ci-dessous ont ete generes avec tshark 4.6.6 (filtres
//! `mbtcp`, `dns`, `tls`) sur les numeros de trame ordonnes. Quand le
//! parseur stateless ne peut pas atteindre le compte tshark (reassemblage
//! TCP), l'ecart est documente trame par trame dans le commentaire de
//! l'oracle : c'est l'ecart qui est fige, pas une approximation silencieuse.

use std::path::Path;

use packet_parser::parse;

mod common;
use common::{FileRead, read_capture};

/// Compte + digest FNV-1a des numeros de trame (1-based), comme
/// `s7comm_regression` : un compte separe verifie la volumetrie, le digest
/// detecte une trame remplacee ou reordonnee a compte constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FrameOracle {
    count: usize,
    frame_digest: u64,
}

const FNV_OFFSET: u64 = 14_695_981_039_346_656_037;

fn update_frame_digest(digest: &mut u64, frame_number: usize) {
    for byte in (frame_number as u64).to_le_bytes() {
        *digest ^= u64::from(byte);
        *digest = digest.wrapping_mul(1_099_511_628_211);
    }
}

/// Oracle observe : trames dont le flux le plus profond porte une des
/// etiquettes attendues.
fn observed(path: &Path, labels: &[&str]) -> FrameOracle {
    let FileRead::Frames { frames, .. } = read_capture(path) else {
        panic!("{}: capture illisible", path.display());
    };
    let mut count = 0;
    let mut frame_digest = FNV_OFFSET;
    for (index, (link_type, data)) in frames.iter().enumerate() {
        let frame_number = index + 1;
        let Ok(flow) = parse(*link_type, data) else {
            continue;
        };
        let innermost_label = flow
            .flatten()
            .into_iter()
            .next_back()
            .and_then(|flow| flow.application.as_ref())
            .map(|application| application.application_protocol);
        if innermost_label.is_some_and(|label| labels.contains(&label)) {
            count += 1;
            update_frame_digest(&mut frame_digest, frame_number);
        }
    }
    FrameOracle {
        count,
        frame_digest,
    }
}

fn check_corpus(directory: &str, labels: &[&str], expected: &[(&str, FrameOracle)]) {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("pcaps_exemple")
        .join("protocols")
        .join(directory);
    for (file, oracle) in expected {
        let path = base.join(file);
        let actual = observed(&path, labels);
        assert_eq!(
            actual, *oracle,
            "{directory}/{file} : oracle {oracle:?}, observe {actual:?}"
        );
    }
}

#[test]
fn modbus_corpus_matches_tshark() {
    // Parite exacte avec `tshark -Y mbtcp` sur les deux captures.
    check_corpus(
        "modbus",
        &["ModbusTCP"],
        &[
            (
                "MODBUS-TestDataPart2.pcap",
                FrameOracle {
                    count: 281,
                    frame_digest: 13_421_435_158_736_108_547,
                },
            ),
            (
                "Modbus.pcap",
                FrameOracle {
                    count: 102,
                    frame_digest: 6_764_856_668_703_751_170,
                },
            ),
        ],
    );
}

#[test]
fn dns_corpus_matches_tshark() {
    // Parite exacte avec `tshark -Y dns`, aux trames a reassemblage pres :
    // - dns_axfr : tshark voit [6 (message reassemble sur 2 segments), 7],
    //   le parseur stateless decode [7] (message DNS/TCP complet dans son
    //   segment) — la trame 6 exige le reassemblage TCP, meme frontiere que
    //   le QUIC Short Header documentee dans src/parse/mod.rs ;
    // - dns_tcp : tshark [1, 2, 6, 10 (reassemble)], nous [1, 2, 6].
    check_corpus(
        "dns",
        &["DNS", "mDNS"],
        &[
            (
                "dns.pcap",
                FrameOracle {
                    count: 7,
                    frame_digest: 9_302_330_386_190_453_893,
                },
            ),
            (
                "dns_axfr.pcapng",
                FrameOracle {
                    count: 1,
                    frame_digest: 5_465_015_992_139_406_178,
                },
            ),
            (
                "dns_isp_hijack.pcapng",
                FrameOracle {
                    count: 4,
                    frame_digest: 5_096_769_273_918_694_852,
                },
            ),
            (
                "dns_lab.pcapng",
                FrameOracle {
                    count: 22,
                    frame_digest: 4_170_901_637_368_250_866,
                },
            ),
            (
                "dns_query_nonexistent.pcapng",
                FrameOracle {
                    count: 2,
                    frame_digest: 8_581_494_755_304_202_342,
                },
            ),
            (
                "dns_query_response.pcapng",
                FrameOracle {
                    count: 2,
                    frame_digest: 8_581_494_755_304_202_342,
                },
            ),
            (
                "dns_recursivequery_client.pcapng",
                FrameOracle {
                    count: 2,
                    frame_digest: 8_581_494_755_304_202_342,
                },
            ),
            (
                "dns_recursivequery_server.pcapng",
                FrameOracle {
                    count: 4,
                    frame_digest: 9_912_279_967_458_543_905,
                },
            ),
            (
                "dns_reverse_lookup.pcapng",
                FrameOracle {
                    count: 2,
                    frame_digest: 8_581_494_755_304_202_342,
                },
            ),
            (
                "dns_tcp.pcapng",
                FrameOracle {
                    count: 3,
                    frame_digest: 4_559_358_014_454_279_264,
                },
            ),
            (
                "udp_dnsrequest.pcapng",
                FrameOracle {
                    count: 1,
                    frame_digest: 9_929_646_806_074_584_996,
                },
            ),
        ],
    );
}

#[test]
fn tls_corpus_matches_tshark() {
    // Parite exacte avec `tshark -Y tls`, a deux frontieres connues pres :
    // - reassemblage TCP : tls1.3-ech perd les trames 20/30/45/67/74 (records
    //   sur 2 a 4 segments, deja documente dans ROADMAP.md), tls12-dsb perd
    //   la trame 3 (2 segments) ;
    // - dump.pcapng perd les trames 964/1069/1084 : Client Hello
    //   **SSLv2-compatible** (record 0x80..., pre-TLS), hors du record layer
    //   TLS que decode la crate.
    check_corpus(
        "tls",
        &["TLS"],
        &[
            (
                "dump.pcapng",
                FrameOracle {
                    count: 508,
                    frame_digest: 1_693_381_745_535_847_733,
                },
            ),
            (
                "tls1.0.pcapng",
                FrameOracle {
                    count: 12,
                    frame_digest: 2_700_793_128_671_641_988,
                },
            ),
            (
                "tls1.1.pcapng",
                FrameOracle {
                    count: 12,
                    frame_digest: 2_700_793_128_671_641_988,
                },
            ),
            (
                "tls1.2.pcapng",
                FrameOracle {
                    count: 7,
                    frame_digest: 7_149_315_856_211_472_246,
                },
            ),
            (
                "tls1.3-ech.pcapng",
                FrameOracle {
                    count: 24,
                    frame_digest: 533_587_393_845_227_764,
                },
            ),
            (
                "tls1.3.pcapng",
                FrameOracle {
                    count: 8,
                    frame_digest: 11_493_578_898_699_981_316,
                },
            ),
            (
                "tls12-dsb.pcapng",
                FrameOracle {
                    count: 16,
                    frame_digest: 7_144_532_833_693_351_175,
                },
            ),
        ],
    );
}

/// Mode calibration : `cargo test --test tshark_regression -- --ignored
/// --nocapture` imprime les oracles observes, a croiser avec tshark avant de
/// les figer ci-dessus.
#[test]
#[ignore = "outil de calibration, pas un test"]
fn print_observed_oracles() {
    for (directory, labels) in [
        ("modbus", &["ModbusTCP"][..]),
        ("dns", &["DNS", "mDNS"][..]),
        ("tls", &["TLS"][..]),
    ] {
        let base = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("pcaps_exemple")
            .join("protocols")
            .join(directory);
        let mut entries: Vec<_> = std::fs::read_dir(&base)
            .expect("corpus directory")
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                matches!(
                    path.extension().and_then(|extension| extension.to_str()),
                    Some("pcap" | "pcapng" | "cap")
                )
            })
            .collect();
        entries.sort();
        for path in entries {
            let oracle = observed(&path, labels);
            println!(
                "{directory}/{}\tcount={}\tdigest={}",
                path.file_name().unwrap().to_str().unwrap(),
                oracle.count,
                oracle.frame_digest
            );
        }
    }
}
