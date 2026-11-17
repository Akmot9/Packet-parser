// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Regles TOML (#325), de bout en bout : une trame nommee par une regle, ses
//! champs, son etiquette relue (#323), l'enregistrement tout ou rien, et sur
//! tout le corpus, la propriete qui rend une regle sans risque : elle ne
//! change que des flux que la crate laissait `Unknown`. ACME est invente.
#![cfg(feature = "rules")]

use std::path::Path;
use std::sync::Arc;

use packet_parser::{
    ApplicationParser, ApplicationProtocol, LinkType, ParseConfig, ParserRegistrationError,
    PayloadContext, RuleSet, TransportProtocol, parse, parse_with,
};

mod common;
use common::{FileRead, collect_capture_files, read_capture};

const EXAMPLE: &str = include_str!("../examples/acme_rules.toml");

/// Une trame Ethernet/IPv4/UDP de 192.0.2.1:40000 vers 192.0.2.2.
fn udp_frame(destination_port: u16, payload: &[u8]) -> Vec<u8> {
    let udp_length = u16::try_from(8 + payload.len()).expect("charge courte");
    let ip_length = 20 + udp_length;
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1, 0x08, 0x00]);
    let mut ip = vec![0x45, 0];
    ip.extend_from_slice(&ip_length.to_be_bytes());
    ip.extend_from_slice(&[0, 1, 0x40, 0, 64, 17, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2]);
    let sum = ip
        .chunks(2)
        .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
        .sum::<u32>();
    let folded = (sum & 0xffff) + (sum >> 16);
    let checksum = !u16::try_from((folded & 0xffff) + (folded >> 16)).expect("plie");
    ip[10..12].copy_from_slice(&checksum.to_be_bytes());
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&40_000_u16.to_be_bytes());
    frame.extend_from_slice(&destination_port.to_be_bytes());
    frame.extend_from_slice(&udp_length.to_be_bytes());
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(payload);
    frame
}

#[test]
fn a_rule_names_the_frame_and_its_label_reads_back() {
    let rules = RuleSet::from_toml(EXAMPLE).expect("exemple valide");
    let config = ParseConfig::new()
        .with_rules(&rules)
        .expect("etiquettes libres");
    assert_eq!(config.parser_labels().collect::<Vec<_>>(), ["ACME", "DEMO"]);

    let frame = udp_frame(47_000, b"ACME\x01\x01\x00\x0c\x00\x00\x00\x2a");
    let plain = parse(LinkType::ETHERNET, &frame).expect("trame valide");
    assert_eq!(
        plain.application.as_ref().map(|a| a.protocol),
        Some(ApplicationProtocol::Unknown)
    );
    let flow = parse_with(LinkType::ETHERNET, &frame, &config).expect("trame valide");
    let protocol = flow.application.as_ref().map(|a| a.protocol);
    assert_eq!(protocol, Some(ApplicationProtocol::Custom("ACME")));
    assert_eq!(
        serde_json::to_string(&flow.application).expect("json"),
        r#"{"application_protocol":"ACME"}"#
    );
    assert_eq!(
        config.custom_fields(&flow),
        Some(vec![
            ("version".to_string(), "1".to_string()),
            ("type".to_string(), "request (1)".to_string()),
            ("length".to_string(), "12".to_string()),
            ("id".to_string(), "00 00 00 2A".to_string()),
        ])
    );
    // L'etiquette ecrite se relit avec la configuration (#323).
    assert_eq!(
        config.application_protocol("ACME"),
        Ok(ApplicationProtocol::Custom("ACME"))
    );
    assert!("ACME".parse::<ApplicationProtocol>().is_err());

    // Hors du port declare, la meme charge reste inconnue.
    let elsewhere = udp_frame(47_001, b"ACME\x01\x01\x00\x0c\x00\x00\x00\x2a");
    let flow = parse_with(LinkType::ETHERNET, &elsewhere, &config).expect("trame valide");
    assert_eq!(
        flow.application.as_ref().map(|a| a.protocol),
        Some(ApplicationProtocol::Unknown)
    );
}

/// Un parseur deja enregistre sous ACME.
struct Taken;

impl ApplicationParser for Taken {
    fn label(&self) -> &'static str {
        "acme"
    }
    fn matches(&self, _payload: &[u8], _context: &PayloadContext) -> bool {
        false
    }
}

#[test]
fn registration_is_all_or_nothing() {
    let rules = RuleSet::from_toml(
        "version = 1\n\
         [[rule]]\nlabel = \"FIRST\"\n[[rule.pattern]]\noffset = 0\nbytes = \"46 49\"\n\
         [[rule]]\nlabel = \"ACME\"\n[[rule.pattern]]\noffset = 0\nbytes = \"41 43\"\n",
    )
    .expect("valide");
    let mut config = ParseConfig::new()
        .with_parser(Arc::new(Taken))
        .expect("libre");
    assert_eq!(
        config.add_rules(&rules),
        Err(ParserRegistrationError::DuplicateLabel {
            label: "ACME".to_string()
        })
    );
    // FIRST, accepte avant le refus, n'est pas reste.
    assert_eq!(config.parser_labels().collect::<Vec<_>>(), ["acme"]);

    // Le meme fichier, deux fois : la seconde est refusee.
    let config = ParseConfig::new().with_rules(&rules).expect("libres");
    assert!(config.clone().with_rules(&rules).is_err());
    assert_eq!(
        config.parser_labels().collect::<Vec<_>>(),
        ["FIRST", "ACME"]
    );
}

#[test]
fn rules_follow_the_transport_and_the_crate_keeps_its_payloads() {
    let rules = RuleSet::from_toml(EXAMPLE).expect("exemple valide");
    let config = ParseConfig::new().with_rules(&rules).expect("libres");
    let label = |protocol, port, payload: &[u8]| {
        packet_parser::classify_payload_with(protocol, Some(40_000), Some(port), payload, &config)
            .map(|application| application.protocol)
    };
    assert_eq!(
        label(TransportProtocol::Tcp, 9_000, b"DEMO!\x00\x00"),
        Some(ApplicationProtocol::Custom("DEMO"))
    );
    assert_eq!(
        label(TransportProtocol::Udp, 9_000, b"DEMO!\x00\x00"),
        Some(ApplicationProtocol::Unknown)
    );
    // Une banniere SSH reste SSH, meme si une regle l'accepterait.
    let ssh = RuleSet::from_toml(
        "version = 1\n[[rule]]\nlabel = \"NOT-SSH\"\n[[rule.pattern]]\noffset = 0\nbytes = \"53 53 48 2D\"\n",
    )
    .expect("valide");
    let config = ParseConfig::new().with_rules(&ssh).expect("libre");
    assert_eq!(
        packet_parser::classify_payload_with(
            TransportProtocol::Tcp,
            Some(40_000),
            Some(40_001),
            b"SSH-2.0-OpenSSH_9.6\r\n",
            &config
        )
        .map(|application| application.protocol),
        Some(ApplicationProtocol::Ssh)
    );
}

/// Sur tout le corpus : une regle large (deux octets nuls en tete) ne
/// change que des flux `Unknown`, et en change.
#[test]
fn a_rule_only_changes_unknown_flows_of_the_corpus() {
    let rules = RuleSet::from_toml(
        "version = 1\n[[rule]]\nlabel = \"ZEROES\"\n[[rule.pattern]]\noffset = 0\nbytes = \"00 00\"\n",
    )
    .expect("valide");
    let config = ParseConfig::new().with_rules(&rules).expect("libre");
    let protocol_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("pcaps_exemple")
        .join("protocols");
    let mut captures = Vec::new();
    collect_capture_files(protocol_dir.as_path(), &mut captures);
    captures.sort();
    assert!(!captures.is_empty(), "corpus introuvable");

    let (mut renamed, mut kept) = (0_usize, 0_usize);
    for path in &captures {
        let FileRead::Frames { frames, .. } = read_capture(path) else {
            continue;
        };
        for (index, (link_type, data)) in frames.iter().enumerate() {
            let (Ok(plain), Ok(ruled)) = (
                parse(*link_type, data),
                parse_with(*link_type, data, &config),
            ) else {
                continue;
            };
            let (plain, ruled) = (plain.flatten(), ruled.flatten());
            assert_eq!(
                plain.len(),
                ruled.len(),
                "{} trame {}",
                path.display(),
                index + 1
            );
            for (depth, (before, after)) in plain.iter().zip(&ruled).enumerate() {
                let before_protocol = before.application.as_ref().map(|a| a.protocol);
                let after_protocol = after.application.as_ref().map(|a| a.protocol);
                if after_protocol == Some(ApplicationProtocol::Custom("ZEROES")) {
                    renamed += 1;
                    assert_eq!(
                        before_protocol,
                        Some(ApplicationProtocol::Unknown),
                        "{} trame {} niveau {depth}",
                        path.display(),
                        index + 1
                    );
                    let payload = after.transport.as_ref().and_then(|t| t.payload);
                    assert!(payload.is_some_and(|payload| payload.starts_with(&[0, 0])));
                } else {
                    kept += 1;
                    assert_eq!(
                        after_protocol,
                        before_protocol,
                        "{} trame {} niveau {depth}",
                        path.display(),
                        index + 1
                    );
                }
                assert_eq!(before.transport, after.transport);
                assert_eq!(before.corrupted, after.corrupted);
            }
        }
    }
    assert!(
        renamed > 0 && kept > renamed,
        "{renamed} renommes, {kept} gardes"
    );
}
