// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Parseurs ajoutes par l'appelant (#319) : enregistrement, gardes, ordre, et
//! la propriete qui les rend sans risque pour la crate. Sur tout le corpus,
//! un parseur qui accepte tout ne change que les flux que la table laissait
//! `Unknown`, tunnels compris.

use std::path::Path;
use std::sync::Arc;

use packet_parser::{
    ApplicationParser, ApplicationProtocol, CustomTransports, ParseConfig, ParserRegistrationError,
    PayloadContext, TransportProtocol, classify_payload_with, parse, parse_with,
};

mod common;
use common::{FileRead, collect_capture_files, read_capture};

/// Un parseur de test : une etiquette, des gardes, et un predicat.
struct Probe {
    label: &'static str,
    transports: CustomTransports,
    ports: &'static [u16],
    accepts: fn(&[u8]) -> bool,
}

impl Probe {
    fn new(label: &'static str, accepts: fn(&[u8]) -> bool) -> Self {
        Self {
            label,
            transports: CustomTransports::TcpAndUdp,
            ports: &[],
            accepts,
        }
    }
}

impl ApplicationParser for Probe {
    fn label(&self) -> &'static str {
        self.label
    }
    fn transports(&self) -> CustomTransports {
        self.transports
    }
    fn ports(&self) -> &[u16] {
        self.ports
    }
    fn matches(&self, payload: &[u8], _context: &PayloadContext) -> bool {
        (self.accepts)(payload)
    }
    fn fields(&self, payload: &[u8], context: &PayloadContext) -> Vec<(String, String)> {
        vec![
            ("length".to_string(), payload.len().to_string()),
            (
                "destination port".to_string(),
                format!("{:?}", context.destination_port),
            ),
        ]
    }
}

fn config_with(parsers: Vec<Probe>) -> ParseConfig {
    parsers
        .into_iter()
        .fold(ParseConfig::new(), |config, parser| {
            config
                .with_parser(Arc::new(parser))
                .expect("etiquette valide")
        })
}

/// Charge synthetique, qu'aucune regle de la table ne reconnait.
const SYNTHETIC: &[u8] = b"\x5a\x5a\x00\x01 synthetic payload for #319";

fn label(
    config: &ParseConfig,
    protocol: TransportProtocol,
    ports: (Option<u16>, Option<u16>),
    payload: &[u8],
) -> Option<&'static str> {
    classify_payload_with(protocol, ports.0, ports.1, payload, config)
        .map(|application| application.protocol.label())
}

#[test]
fn an_added_parser_names_what_the_table_left_unknown() {
    let config = config_with(vec![Probe::new("ZZ", |payload| payload.starts_with(b"ZZ"))]);
    let ports = (Some(40_000), Some(40_001));
    assert_eq!(
        label(
            &ParseConfig::new(),
            TransportProtocol::Udp,
            ports,
            SYNTHETIC
        ),
        Some("Unknown")
    );
    assert_eq!(
        label(&config, TransportProtocol::Udp, ports, SYNTHETIC),
        Some("ZZ")
    );
    assert_eq!(
        label(&config, TransportProtocol::Tcp, ports, SYNTHETIC),
        Some("ZZ")
    );
    assert_eq!(
        classify_payload_with(TransportProtocol::Udp, ports.0, ports.1, SYNTHETIC, &config)
            .map(|application| application.protocol),
        Some(ApplicationProtocol::Custom("ZZ"))
    );
    // Rien a sonder : pas d'appel.
    assert_eq!(label(&config, TransportProtocol::Udp, ports, b""), None);
    // Ni TCP ni UDP : pas d'appel non plus.
    assert_eq!(
        label(&config, TransportProtocol::Icmp, ports, SYNTHETIC),
        None
    );
}

#[test]
fn an_added_parser_never_takes_a_payload_from_the_crate() {
    let config = config_with(vec![Probe::new("ANY", |_| true)]);
    // Une banniere SSH reste SSH, sur tout port.
    let banner = b"SSH-2.0-OpenSSH_9.6\r\n";
    assert_eq!(
        label(
            &config,
            TransportProtocol::Tcp,
            (Some(40_000), Some(40_001)),
            banner
        ),
        Some("SSH")
    );
    // Un port mDNS sans contenu mDNS reste sans application : la table
    // tranche, `None` n'est pas `Unknown`.
    assert_eq!(
        label(
            &config,
            TransportProtocol::Udp,
            (Some(5353), Some(5353)),
            SYNTHETIC
        ),
        None
    );
}

#[test]
fn transports_and_ports_guard_the_call() {
    let config = config_with(vec![
        Probe {
            transports: CustomTransports::Udp,
            ports: &[47_000],
            ..Probe::new("UDP-47000", |_| true)
        },
        Probe {
            transports: CustomTransports::Tcp,
            ..Probe::new("TCP-ANY", |_| true)
        },
    ]);
    let udp = TransportProtocol::Udp;
    assert_eq!(
        label(&config, udp, (Some(47_000), Some(1_024)), SYNTHETIC),
        Some("UDP-47000")
    );
    assert_eq!(
        label(&config, udp, (Some(1_024), Some(47_000)), SYNTHETIC),
        Some("UDP-47000")
    );
    // Le port declare manque : la charge reste inconnue.
    assert_eq!(
        label(&config, udp, (Some(1_024), Some(1_025)), SYNTHETIC),
        Some("Unknown")
    );
    assert_eq!(
        label(&config, udp, (None, None), SYNTHETIC),
        Some("Unknown")
    );
    // Le parseur TCP accepte tout port, et aucun.
    let tcp = TransportProtocol::Tcp;
    assert_eq!(
        label(&config, tcp, (Some(47_000), Some(1_024)), SYNTHETIC),
        Some("TCP-ANY")
    );
    assert_eq!(
        label(&config, tcp, (None, None), SYNTHETIC),
        Some("TCP-ANY")
    );
}

#[test]
fn the_first_parser_registered_wins() {
    let config = config_with(vec![
        Probe::new("FIRST", |payload| payload.len() > 4),
        Probe::new("SECOND", |_| true),
    ]);
    let ports = (Some(40_000), Some(40_001));
    assert_eq!(
        label(&config, TransportProtocol::Udp, ports, SYNTHETIC),
        Some("FIRST")
    );
    assert_eq!(
        label(&config, TransportProtocol::Udp, ports, b"\x5a\x5a"),
        Some("SECOND")
    );
    assert_eq!(
        config.parser_labels().collect::<Vec<_>>(),
        ["FIRST", "SECOND"]
    );

    let mut config = config;
    assert!(config.remove_parser("first").is_none(), "etiquette exacte");
    assert!(config.remove_parser("FIRST").is_some());
    assert_eq!(
        label(&config, TransportProtocol::Udp, ports, SYNTHETIC),
        Some("SECOND")
    );
}

#[test]
fn registration_refuses_ambiguous_labels() {
    let refused = |config: &mut ParseConfig, label: &'static str| {
        config
            .add_parser(Arc::new(Probe::new(label, |_| true)))
            .expect_err(label)
    };
    let mut config = ParseConfig::new()
        .with_parser(Arc::new(Probe::new("ACME", |_| true)))
        .expect("valide");
    let invalid = |label: &str| ParserRegistrationError::InvalidLabel {
        label: label.to_string(),
    };
    let long = "L".repeat(65).leak();
    for label in ["", " ACMF", "ACMF ", "ACM\nF", long] {
        assert_eq!(refused(&mut config, label), invalid(label));
    }
    assert!(
        config
            .add_parser(Arc::new(Probe::new(&long[..64], |_| true)))
            .is_ok()
    );
    for label in [
        "DNS", "dns", "Unknown", "unknown", "Java RMI", "CAPWAP", "STP",
    ] {
        assert_eq!(
            refused(&mut config, label),
            ParserRegistrationError::BuiltInLabel {
                label: label.to_string()
            }
        );
    }
    for label in ["ACME", "acme"] {
        assert_eq!(
            refused(&mut config, label),
            ParserRegistrationError::DuplicateLabel {
                label: label.to_string()
            }
        );
    }
    // Un refus laisse la configuration intacte.
    assert_eq!(config.parser_labels().count(), 2);
    assert!(format!("{config:?}").contains("ACME"));
}

/// Une trame Ethernet/IPv4/UDP synthetique de 192.0.2.1:40000 vers
/// 192.0.2.2:`destination_port`, portant `payload`. Somme IPv4 calculee,
/// somme UDP nulle.
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
fn parse_with_labels_the_frame_and_custom_fields_reads_it() {
    let config = config_with(vec![Probe {
        ports: &[47_000],
        ..Probe::new("ZZ", |payload| payload.starts_with(b"ZZ"))
    }]);
    let frame = udp_frame(47_000, SYNTHETIC);
    let link = packet_parser::LinkType::ETHERNET;

    let flow = parse_with(link, &frame, &config).expect("trame valide");
    assert_eq!(
        flow.application
            .as_ref()
            .map(|application| application.protocol),
        Some(ApplicationProtocol::Custom("ZZ"))
    );
    assert_eq!(
        serde_json::to_value(&flow).expect("json")["application_protocol"],
        "ZZ"
    );
    assert_eq!(
        config.custom_fields(&flow),
        Some(vec![
            ("length".to_string(), SYNTHETIC.len().to_string()),
            ("destination port".to_string(), "Some(47000)".to_string()),
        ])
    );

    // Sans le parseur, la meme trame est inconnue, et n'a pas de champs.
    let plain = parse(link, &frame).expect("trame valide");
    assert_eq!(
        plain
            .application
            .as_ref()
            .map(|application| application.protocol),
        Some(ApplicationProtocol::Unknown)
    );
    assert_eq!(config.custom_fields(&plain), None);
    assert_eq!(ParseConfig::new().custom_fields(&flow), None);
}

/// La propriete du dispatch (#319), sur tout le corpus : avec un parseur qui
/// accepte tout, chaque flux garde l'etiquette de la table, sauf ceux qu'elle
/// laissait `Unknown` sur une charge TCP ou UDP non vide, qui prennent celle
/// du parseur. Les flux internes des tunnels suivent la meme regle.
#[test]
fn a_catch_all_parser_only_changes_unknown_flows_of_the_corpus() {
    let config = config_with(vec![Probe::new("ANY", |_| true)]);
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
            let (Ok(plain), Ok(custom)) = (
                parse(*link_type, data),
                parse_with(*link_type, data, &config),
            ) else {
                continue;
            };
            let (plain, custom) = (plain.flatten(), custom.flatten());
            assert_eq!(
                plain.len(),
                custom.len(),
                "{} trame {}",
                path.display(),
                index + 1
            );
            for (depth, (before, after)) in plain.iter().zip(&custom).enumerate() {
                let reads = before.transport.as_ref().is_some_and(|transport| {
                    matches!(
                        transport.protocol,
                        TransportProtocol::Tcp | TransportProtocol::Udp
                    ) && transport.payload.is_some_and(|payload| !payload.is_empty())
                });
                let expected = match before.application.as_ref().map(|a| a.protocol) {
                    Some(ApplicationProtocol::Unknown) if reads => {
                        renamed += 1;
                        Some(ApplicationProtocol::Custom("ANY"))
                    }
                    protocol => {
                        kept += 1;
                        protocol
                    }
                };
                assert_eq!(
                    after.application.as_ref().map(|a| a.protocol),
                    expected,
                    "{} trame {} niveau {depth}",
                    path.display(),
                    index + 1
                );
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

/// Le flux interne d'un tunnel passe par les parseurs ajoutes, et le flux
/// externe garde le nom du tunnel. Le corpus n'a pas de flux interne
/// `Unknown` : la trame est synthetique, VXLAN (RFC 7348, VNI 1) sur UDP
/// 4789 autour de la trame UDP du test precedent.
#[test]
fn the_inner_flow_of_a_tunnel_goes_through_added_parsers() {
    let config = config_with(vec![Probe::new("ZZ", |payload| payload.starts_with(b"ZZ"))]);
    let mut vxlan = vec![0x08, 0, 0, 0, 0, 0, 1, 0];
    vxlan.extend_from_slice(&udp_frame(47_000, SYNTHETIC));
    let frame = udp_frame(4789, &vxlan);

    let flow =
        parse_with(packet_parser::LinkType::ETHERNET, &frame, &config).expect("trame valide");
    let labels: Vec<_> = flow
        .flatten()
        .iter()
        .map(|level| {
            level
                .application
                .as_ref()
                .map(|application| application.protocol.label())
        })
        .collect();
    assert_eq!(labels, [Some("VXLAN"), Some("ZZ")]);
    let inner = flow.inner.as_deref().expect("flux interne");
    assert_eq!(config.custom_fields(&flow), None);
    assert!(config.custom_fields(inner).is_some());
}

/// #323 : une etiquette ecrite se relit avec la configuration qui l'a
/// produite, celles des parseurs ajoutes comprises.
#[test]
fn a_written_label_reads_back_with_its_configuration() {
    let mut config = config_with(vec![
        Probe::new("ZZ", |payload| payload.starts_with(b"ZZ")),
        Probe::new("Acme Bus", |_| false),
    ]);
    let empty = ParseConfig::new();

    // Les protocoles de la crate : la reponse de `FromStr`, avec ou sans
    // parseur ajoute.
    for protocol in ApplicationProtocol::ALL {
        let label = protocol.label();
        assert_eq!(config.application_protocol(label), Ok(*protocol), "{label}");
        assert_eq!(
            empty.application_protocol(label),
            label.parse::<ApplicationProtocol>(),
            "{label}"
        );
    }

    // L'aller-retour d'un flux nomme par un parseur ajoute.
    let written = label(
        &config,
        TransportProtocol::Udp,
        (Some(40_000), Some(40_001)),
        SYNTHETIC,
    )
    .expect("charge non vide");
    assert_eq!(written, "ZZ");
    assert_eq!(
        config.application_protocol(written),
        Ok(ApplicationProtocol::Custom("ZZ"))
    );
    assert_eq!(
        config.application_protocol("Acme Bus"),
        Ok(ApplicationProtocol::Custom("Acme Bus"))
    );

    // Comparaison exacte, et rien hors de la configuration.
    for unknown in ["zz", "ZZ ", "acme bus", "", "Unknown?"] {
        assert_eq!(
            config.application_protocol(unknown).map_err(|e| e.0),
            Err(unknown.to_string()),
            "{unknown:?}"
        );
    }
    assert!(empty.application_protocol("ZZ").is_err());

    // Un parseur retire ne se relit plus.
    assert!(config.remove_parser("ZZ").is_some());
    assert!(config.application_protocol("ZZ").is_err());
    assert_eq!(
        config.application_protocol("Acme Bus"),
        Ok(ApplicationProtocol::Custom("Acme Bus"))
    );
}
