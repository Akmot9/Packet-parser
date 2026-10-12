// Oracles de politique du dispatch applicatif, separes du fuzz anti-panic de
// `parse_packetflow` (issue #108). Une politique de detection est ecrite a
// deux endroits — la table de `src/parse/dispatch.rs` et l'oracle — et leur
// divergence ne se voyait que la nuit, dans une cible qui s'arretait alors de
// chercher les vrais crashs (#107 : quatre nuits perdues sur un oracle
// perime). Ici, un echec n'arrete que cette cible.
//
// Trois filets, du plus rapide au plus profond :
// - les oracles fixes du bloc `init` tournent a chaque PR (job
//   `fuzz-targets-build`, `cargo fuzz run ... -runs=1`) ;
// - `tests/fuzz_policy_parity.rs` confronte les listes de l'oracle a la table
//   a chaque PR, verbe par verbe et port par port ;
// - le fuzz nocturne cherche les octets hostiles qui separent les deux.
#![no_main]

#[path = "../oracles/frames.rs"]
mod frames;
#[path = "../oracles/text_protocols.rs"]
mod text_protocols;

use frames::{
    ARTICLE_COMMAND, COTP_CONNECTION_REQUEST, EHLO_COMMAND, EPHEMERAL_PORT, READ_VAR_REQUEST,
    STOR_COMMAND, ethernet_ipv4_payload, xor_overlay,
};
use libfuzzer_sys::fuzz_target;
use packet_parser::{
    DecodeAsProtocol, LinkType, PacketFlow, ParseConfig,
    parse::{
        application::protocols::{ftp::FtpMessage, nntp::NntpMessage, smtp::SmtpMessage},
        transport::protocols::TransportProtocol,
    },
    parse_with,
};
use text_protocols::{
    PROBE_CAP, TEXT_PROTOCOL_PORTS, expected_off_port_label, is_ftp_only_command,
    is_nntp_only_command, is_smtp_only_command, is_text_protocol_port, on_own_port,
};

/// Port declare par l'appelant pour les oracles Decode As (#65) : hors de
/// toute garde de la table.
const DECLARED_PORT: u16 = 5_000;

/// Le payload sonde par la table : `PROBE_CAP` octets au plus.
fn probed(payload: &[u8]) -> &[u8] {
    &payload[..payload.len().min(PROBE_CAP)]
}

/// Verifie la politique par defaut sur chaque flux (tunnels compris) d'une
/// trame analysable, puis la politique Decode As avec `declared` sur le
/// port `DECLARED_PORT`.
fn check(frame: &[u8], declared: DecodeAsProtocol) {
    if let Ok(flow) = PacketFlow::try_from(frame) {
        for parsed in flow.flatten() {
            check_default_policy(parsed);
        }
    }
    let config = ParseConfig::new().decode_as(DECLARED_PORT, declared);
    if let Ok(flow) = parse_with(LinkType::ETHERNET, frame, &config) {
        for parsed in flow.flatten() {
            check_decode_as_policy(parsed, declared);
        }
    }
}

fn check_default_policy(flow: &PacketFlow<'_>) {
    let label = flow
        .application
        .as_ref()
        .map(|application| application.application_protocol);
    let Some(transport) = flow.transport.as_ref() else {
        assert!(
            !matches!(label, Some("FTP" | "SMTP" | "NNTP" | "S7Comm" | "COTP")),
            "{label:?} exige une couche transport"
        );
        return;
    };
    let ports = [transport.source_port, transport.destination_port];
    let payload = transport.payload.unwrap_or_default();

    match label {
        // Issue #66 : hors de son port, une etiquette texte exige une
        // commande complete dont le verbe n'appartient qu'a ce protocole,
        // jamais sur un port de la famille (le port l'emporte).
        Some(text @ ("FTP" | "SMTP" | "NNTP")) => {
            assert_eq!(
                transport.protocol,
                TransportProtocol::Tcp,
                "{text} ne doit jamais etre detecte hors de TCP"
            );
            if !on_own_port(text, ports) {
                assert!(
                    !ports.iter().any(|port| is_text_protocol_port(*port)),
                    "{text} ne doit jamais etre detecte sur un port d'un autre protocole texte"
                );
                let unambiguous = match text {
                    "FTP" => is_ftp_only_command(payload),
                    "SMTP" => is_smtp_only_command(payload),
                    _ => is_nntp_only_command(payload),
                };
                assert!(
                    unambiguous,
                    "hors de son port, {text} exige une commande complete qui lui est propre"
                );
            }
        }
        Some("S7Comm") => assert_eq!(
            transport.protocol,
            TransportProtocol::Tcp,
            "S7Comm ne doit jamais etre detecte hors de TCP"
        ),
        Some("COTP") => {
            assert_eq!(transport.protocol, TransportProtocol::Tcp);
            assert!(
                ports.contains(&Some(102)),
                "COTP doit rester garde par TCP/102"
            );
        }
        _ => {}
    }

    // L'autre sens (#108) : restreindre la politique sans l'oracle le
    // relachait en silence. Hors des ports de la famille, sur TCP, une
    // commande propre a un protocole texte doit recevoir son etiquette —
    // sauf anomalie semantique du transport (TCP SYN+FIN, bits reserves :
    // `corrupted` est renseigne, la couche est gardee pour ses ports et
    // rien n'est classe au-dessus). Trouve par le fuzz en 359 executions.
    if flow.corrupted.is_none()
        && transport.protocol == TransportProtocol::Tcp
        && !ports.iter().any(|port| is_text_protocol_port(*port))
        && let Some(expected) = expected_off_port_label(payload)
    {
        assert_eq!(
            label,
            Some(expected),
            "commande propre a {expected} hors port : etiquette attendue"
        );
    }
}

/// Issue #65 : un port declare etend les gardes — port ET contenu — sans
/// jamais remplacer la validation de contenu ni la garde de transport.
fn check_decode_as_policy(flow: &PacketFlow<'_>, declared: DecodeAsProtocol) {
    let label = flow
        .application
        .as_ref()
        .map(|application| application.application_protocol);
    let Some(transport) = flow.transport.as_ref() else {
        return;
    };
    let ports = [transport.source_port, transport.destination_port];
    let on_declared_port = ports.contains(&Some(DECLARED_PORT));
    let payload = transport.payload.unwrap_or_default();

    match label {
        Some(text @ ("FTP" | "SMTP" | "NNTP")) => {
            assert_eq!(transport.protocol, TransportProtocol::Tcp, "{text} : TCP");
            let declared_this = matches!(
                (text, declared),
                ("FTP", DecodeAsProtocol::Ftp)
                    | ("SMTP", DecodeAsProtocol::Smtp)
                    | ("NNTP", DecodeAsProtocol::Nntp)
            );
            if !on_own_port(text, ports) {
                let complete = match text {
                    "FTP" => FtpMessage::try_from(probed(payload)).is_ok(),
                    "SMTP" => SmtpMessage::try_from(probed(payload)).is_ok(),
                    _ => NntpMessage::try_from(probed(payload)).is_ok(),
                };
                let by_declaration = declared_this && on_declared_port && complete;
                let by_content = !ports.iter().any(|port| is_text_protocol_port(*port))
                    && match text {
                        "FTP" => is_ftp_only_command(payload),
                        "SMTP" => is_smtp_only_command(payload),
                        _ => is_nntp_only_command(payload),
                    };
                assert!(
                    by_declaration || by_content,
                    "{text} hors port : par declaration (port {DECLARED_PORT}, contenu valide) ou par commande propre"
                );
            }
        }
        Some("COTP") => {
            assert_eq!(transport.protocol, TransportProtocol::Tcp);
            assert!(
                ports.contains(&Some(102))
                    || (declared == DecodeAsProtocol::Cotp && on_declared_port),
                "COTP : TCP/102 ou port declare"
            );
        }
        _ => {}
    }
}

fn label_of(frame: &[u8], config: &ParseConfig) -> Option<&'static str> {
    parse_with(LinkType::ETHERNET, frame, config)
        .expect("la graine Ethernet structuree doit rester analysable")
        .application
        .map(|application| application.application_protocol)
}

fn tcp(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
    ethernet_ipv4_payload(
        TransportProtocol::Tcp,
        source_port,
        destination_port,
        payload,
    )
}

fn udp(destination_port: u16, payload: &[u8]) -> Vec<u8> {
    ethernet_ipv4_payload(
        TransportProtocol::Udp,
        EPHEMERAL_PORT,
        destination_port,
        payload,
    )
}

/// Oracles fixes : ils ne dependent pas de l'entree, `init` les execute une
/// fois au demarrage — donc a chaque PR via `-runs=1`.
fn fixed_policy_checks() {
    let default = ParseConfig::new();

    // COTP n'est annonce que pour une enveloppe TPKT valide sur TCP/102. Les
    // memes octets sur UDP ou hors du port ISO-TSAP sont des oracles negatifs
    // explicites contre les faux positifs.
    let cotp = &COTP_CONNECTION_REQUEST;
    assert_eq!(
        label_of(&tcp(EPHEMERAL_PORT, 102, cotp), &default),
        Some("COTP")
    );
    assert_ne!(
        label_of(&tcp(EPHEMERAL_PORT, 10_102, cotp), &default),
        Some("COTP")
    );
    assert_ne!(label_of(&udp(102, cotp), &default), Some("COTP"));

    // Issue #66 : une commande complete propre a un protocole texte est
    // detectee hors port, jamais sur un port de la famille (destination ou
    // source), jamais sur UDP ; un verbe partage ou une commande incomplete
    // ne le sont pas.
    for (payload, label) in [
        (STOR_COMMAND, "FTP"),
        (EHLO_COMMAND, "SMTP"),
        (ARTICLE_COMMAND, "NNTP"),
    ] {
        assert_eq!(
            label_of(&tcp(EPHEMERAL_PORT, 5_000, payload), &default),
            Some(label),
            "{label} hors port"
        );
        assert_ne!(
            label_of(&udp(5_000, payload), &default),
            Some(label),
            "{label} sur UDP"
        );
        for port in TEXT_PROTOCOL_PORTS {
            if on_own_port(label, [Some(port), None]) {
                continue;
            }
            assert_ne!(
                label_of(&tcp(EPHEMERAL_PORT, port, payload), &default),
                Some(label),
                "{label} vers TCP/{port}"
            );
            assert_ne!(
                label_of(&tcp(port, EPHEMERAL_PORT, payload), &default),
                Some(label),
                "{label} depuis TCP/{port}"
            );
        }
    }
    for payload in [
        &b"LIST\r\n"[..],
        &b"STOR\r\n"[..],
        &b"QUIT\r\n"[..],
        &b"STOR fichier.bin"[..],
        &b"STOR a\nb\r\n"[..],
    ] {
        let label = label_of(&tcp(EPHEMERAL_PORT, 5_000, payload), &default);
        assert!(
            !matches!(label, Some("FTP" | "SMTP" | "NNTP")),
            "{} -> {label:?}",
            payload.escape_ascii()
        );
    }

    // Issue #65 : un port declare etend les gardes, port ET contenu.
    let ftp_on_5000 = ParseConfig::new().decode_as(DECLARED_PORT, DecodeAsProtocol::Ftp);
    let user = &tcp(EPHEMERAL_PORT, DECLARED_PORT, b"USER alice\r\n");
    assert_ne!(label_of(user, &default), Some("FTP"));
    assert_eq!(label_of(user, &ftp_on_5000), Some("FTP"));
    let garbage = &tcp(
        EPHEMERAL_PORT,
        DECLARED_PORT,
        b"\x16\x03\x03\x00\x10aaaaaaaaaaaaaaaa",
    );
    assert_ne!(label_of(garbage, &ftp_on_5000), Some("FTP"));
    let udp_only = ParseConfig::new().decode_as(DECLARED_PORT, DecodeAsProtocol::Mdns);
    assert_ne!(label_of(user, &udp_only), Some("mDNS"));
}

/// Tous les protocoles declarables, dans l'ordre de l'enum : le premier
/// octet de l'entree en choisit un.
const DECODE_AS_PROTOCOLS: [DecodeAsProtocol; 21] = [
    DecodeAsProtocol::Ftp,
    DecodeAsProtocol::Smtp,
    DecodeAsProtocol::Nntp,
    DecodeAsProtocol::Cotp,
    DecodeAsProtocol::Dns,
    DecodeAsProtocol::Mdns,
    DecodeAsProtocol::Llmnr,
    DecodeAsProtocol::Ssdp,
    DecodeAsProtocol::Nbns,
    DecodeAsProtocol::Nbss,
    DecodeAsProtocol::Snmp,
    DecodeAsProtocol::Dhcpv6,
    DecodeAsProtocol::OpcUa,
    DecodeAsProtocol::PostgreSql,
    DecodeAsProtocol::ModbusTcp,
    DecodeAsProtocol::EthernetIp,
    DecodeAsProtocol::Ams,
    DecodeAsProtocol::QuicShortHeader,
    DecodeAsProtocol::OpenVpn,
    DecodeAsProtocol::Ptp,
    DecodeAsProtocol::Stanag5066,
];

fuzz_target!(init: fixed_policy_checks(), |data: &[u8]| {
    let declared = DECODE_AS_PROTOCOLS
        [usize::from(data.first().copied().unwrap_or(0)) % DECODE_AS_PROTOCOLS.len()];
    check(data, declared);

    // Les memes graines que `parse_packetflow`, sur le port declare pour
    // exercer le Decode As : S7Comm et COTP sur leur port et hors port, TCP
    // et UDP ; une commande propre a chaque protocole texte hors port, sur
    // un port de la famille, et sur UDP.
    let seeds: [(TransportProtocol, u16, &[u8]); 12] = [
        (TransportProtocol::Tcp, 102, &READ_VAR_REQUEST),
        (TransportProtocol::Udp, 102, &READ_VAR_REQUEST),
        (TransportProtocol::Tcp, 102, &COTP_CONNECTION_REQUEST),
        (TransportProtocol::Tcp, DECLARED_PORT, &COTP_CONNECTION_REQUEST),
        (TransportProtocol::Udp, 102, &COTP_CONNECTION_REQUEST),
        (TransportProtocol::Tcp, DECLARED_PORT, STOR_COMMAND),
        (TransportProtocol::Tcp, 25, STOR_COMMAND),
        (TransportProtocol::Udp, DECLARED_PORT, STOR_COMMAND),
        (TransportProtocol::Tcp, DECLARED_PORT, EHLO_COMMAND),
        (TransportProtocol::Tcp, 119, EHLO_COMMAND),
        (TransportProtocol::Tcp, DECLARED_PORT, ARTICLE_COMMAND),
        (TransportProtocol::Tcp, DECLARED_PORT, b"USER alice\r\n"),
    ];
    for (protocol, destination_port, payload) in seeds {
        let mut seeded = ethernet_ipv4_payload(protocol, EPHEMERAL_PORT, destination_port, payload);
        xor_overlay(seeded.as_mut_slice(), data);
        check(seeded.as_slice(), declared);
    }
});
