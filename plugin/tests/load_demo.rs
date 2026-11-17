// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Le chemin complet d'un plugin (#319) : `demo_parser` compile en
//! bibliotheque native par un vrai `cargo build`, charge par `load_parser`,
//! enregistre, puis rejoue par `parse_with` et par l'hote `plugin_host` sur
//! une capture ecrite pour le test. Toutes les trames sont synthetiques : le
//! protocole DEMO n'existe pas hors de l'exemple.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use packet_parser::{
    ApplicationParser, ApplicationProtocol, CustomTransports, LinkType, ParseConfig,
    ParserRegistrationError, PayloadContext, TransportProtocol, parse_with,
};
use packet_parser_plugin::{PluginLoadError, load_parser};
use pcap_file::pcap::{PcapPacket, PcapWriter};

/// Les binaires de `demo_parser` et de `plugin_host`, construits une fois.
struct Built {
    library: PathBuf,
    host: PathBuf,
}

/// Construit les deux exemples dans un repertoire cible a part : le
/// `cargo test` en cours garde le sien.
fn built() -> &'static Built {
    static BUILT: OnceLock<Built> = OnceLock::new();
    BUILT.get_or_init(|| {
        let target = Path::new(env!("CARGO_TARGET_TMPDIR")).join("examples-build");
        let output = Command::new(env!("CARGO"))
            .args([
                "build",
                "--example",
                "demo_parser",
                "--example",
                "plugin_host",
            ])
            .args([
                "--message-format",
                "json-render-diagnostics",
                "--manifest-path",
            ])
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .env("CARGO_TARGET_DIR", &target)
            .output()
            .expect("cargo lance");
        assert!(
            output.status.success(),
            "cargo build : {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let (mut library, mut host) = (None, None);
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let Ok(message) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            if message["reason"] != "compiler-artifact" {
                continue;
            }
            match message["target"]["name"].as_str() {
                Some("demo_parser") => {
                    library = message["filenames"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(serde_json::Value::as_str)
                        .map(PathBuf::from)
                        .find(|path| {
                            path.extension().is_some_and(|extension| {
                                ["so", "dylib", "dll"]
                                    .iter()
                                    .any(|known| extension == *known)
                            })
                        });
                }
                Some("plugin_host") => {
                    host = message["executable"].as_str().map(PathBuf::from);
                }
                _ => {}
            }
        }
        Built {
            library: library.expect("bibliotheque de demo_parser"),
            host: host.expect("executable de plugin_host"),
        }
    })
}

fn demo() -> Arc<dyn ApplicationParser> {
    // SAFETY: the library built above from this repository.
    unsafe { load_parser(&built().library) }.expect("plugin valide")
}

/// Un message DEMO : en-tete de 8 octets, puis le corps.
fn demo_message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut message = b"DEMO".to_vec();
    message.extend_from_slice(&[1, kind]);
    message.extend_from_slice(&u16::try_from(body.len()).expect("court").to_be_bytes());
    message.extend_from_slice(body);
    message
}

/// Une trame Ethernet/IPv4/UDP synthetique de 192.0.2.1:40000 vers
/// 192.0.2.2:`destination_port`. Somme IPv4 calculee, somme UDP nulle.
fn udp_frame(destination_port: u16, payload: &[u8]) -> Vec<u8> {
    let udp_length = u16::try_from(8 + payload.len()).expect("charge courte");
    let mut ip = vec![0x45, 0];
    ip.extend_from_slice(&(20 + udp_length).to_be_bytes());
    ip.extend_from_slice(&[0, 1, 0x40, 0, 64, 17, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2]);
    let sum: u32 = ip
        .chunks(2)
        .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
        .sum();
    let folded = (sum & 0xffff) + (sum >> 16);
    let checksum = !u16::try_from((folded & 0xffff) + (folded >> 16)).expect("plie");
    ip[10..12].copy_from_slice(&checksum.to_be_bytes());

    let mut frame = vec![0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1, 0x08, 0x00];
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&40_000_u16.to_be_bytes());
    frame.extend_from_slice(&destination_port.to_be_bytes());
    frame.extend_from_slice(&udp_length.to_be_bytes());
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(payload);
    frame
}

#[test]
fn the_demo_plugin_declares_its_parser() {
    let parser = demo();
    assert_eq!(parser.label(), "DEMO");
    assert_eq!(parser.transports(), CustomTransports::Udp);
    assert_eq!(parser.ports(), [47_000]);

    let context = PayloadContext::new(TransportProtocol::Udp, Some(40_000), Some(47_000));
    let hello = demo_message(1, b"bonjour");
    assert!(parser.matches(&hello, &context));
    assert_eq!(
        parser.fields(&hello, &context),
        [
            ("version".to_string(), "1".to_string()),
            ("kind".to_string(), "hello".to_string()),
            ("body".to_string(), "bonjour".to_string()),
        ]
    );
    // Longueur fausse : refus, et pas de champs.
    let mut truncated = hello.clone();
    truncated.pop();
    assert!(!parser.matches(&truncated, &context));
    assert!(parser.fields(&truncated, &context).is_empty());
}

#[test]
fn parse_with_labels_the_frames_of_the_plugin() {
    let config = ParseConfig::new()
        .with_parser(demo())
        .expect("etiquette valide");
    let data = demo_message(2, b"\x00\x01\x02");

    let frame = udp_frame(47_000, &data);
    let flow = parse_with(LinkType::ETHERNET, &frame, &config).expect("trame valide");
    assert_eq!(
        flow.application
            .as_ref()
            .map(|application| application.protocol),
        Some(ApplicationProtocol::Custom("DEMO"))
    );
    let fields = config.custom_fields(&flow).expect("champs");
    assert_eq!(fields[1], ("kind".to_string(), "data".to_string()));

    // Hors du port declare, le plugin n'est pas appele.
    let other_frame = udp_frame(47_001, &data);
    let other = parse_with(LinkType::ETHERNET, &other_frame, &config).expect("trame valide");
    assert_eq!(
        other
            .application
            .as_ref()
            .map(|application| application.protocol),
        Some(ApplicationProtocol::Unknown)
    );
}

#[test]
fn a_plugin_loaded_twice_is_refused_on_registration() {
    let mut config = ParseConfig::new().with_parser(demo()).expect("premier");
    assert_eq!(
        config.add_parser(demo()).expect_err("doublon"),
        ParserRegistrationError::DuplicateLabel {
            label: "DEMO".to_string()
        }
    );
}

#[test]
fn a_file_that_is_not_a_library_is_refused() {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join("not_a_plugin.so");
    std::fs::write(&path, b"not an ELF, a Mach-O nor a PE file").expect("ecrit");
    // SAFETY: the loader refuses the file before running anything.
    let error = unsafe { load_parser(&path) }.err().expect("refus");
    assert!(matches!(error, PluginLoadError::Open { .. }), "{error}");
}

/// L'hote de l'exemple, sur une capture ecrite ici : deux messages DEMO,
/// un datagramme quelconque sur le meme port.
#[test]
fn the_host_example_counts_the_labels_of_a_capture() {
    let capture = Path::new(env!("CARGO_TARGET_TMPDIR")).join("demo.pcap");
    let frames = [
        udp_frame(47_000, &demo_message(1, b"bonjour")),
        udp_frame(47_000, &demo_message(2, b"donnees")),
        udp_frame(47_000, b"pas un message DEMO"),
    ];
    let mut writer =
        PcapWriter::new(std::fs::File::create(&capture).expect("cree")).expect("en-tete");
    for (second, frame) in (1..).zip(&frames) {
        let length = u32::try_from(frame.len()).expect("court");
        writer
            .write_packet(&PcapPacket::new(Duration::from_secs(second), length, frame))
            .expect("trame ecrite");
    }
    drop(writer);

    let output = Command::new(&built().host)
        .arg("--fields")
        .arg(&capture)
        .arg(&built().library)
        .output()
        .expect("plugin_host lance");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lines: Vec<&str> = stdout.lines().map(str::trim).collect();
    assert!(lines.contains(&"2  DEMO"), "{stdout}");
    assert!(lines.contains(&"1  Unknown"), "{stdout}");
    assert!(lines.contains(&"body = bonjour"), "{stdout}");
}
