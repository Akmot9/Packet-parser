// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Dispatch applicatif L7 declaratif (audit 8.1.0 §5.3, issues #20, #25, #29).
//!
//! L'ancienne implementation empilait trois mecanismes de priorite — ordre
//! d'une cascade, gardes de port appliquees inegalement, et un override ou le
//! port ecrasait le contenu — repartis sur deux fichiers. Ici, **une seule
//! table ordonnee** porte tout : garde de transport, garde de port
//! optionnelle, sonde. L'ordre du tableau est la priorite, inspectable et
//! testable.
//!
//! Invariants :
//! - une regle a port n'etiquette que si **port et contenu** concordent — le
//!   port seul ne decide jamais (fin de l'override OPC UA, issue #25) ;
//! - chaque sonde s'execute **au plus une fois** par payload : les echecs
//!   sont memoises par [`ProbeId`] (fin du double sondage PostgreSQL et
//!   SNMP, issue #29) ;
//! - le probing ne lit que [`PROBE_CAP`] octets : un payload heberge par un
//!   segment jumbo (GRO 64 Ko) ne coute plus un parse integral par sonde
//!   (issue #20). La borne depasse le plus grand message legitime qu'une
//!   sonde doive voir en entier (un record TLS chiffre : 5 + 16 Ko + tag).

use super::application::Application;
use super::application::protocols::ams::AmsPacket;
use super::application::protocols::bitcoin::BitcoinPacket;
use super::application::protocols::dhcp::DhcpPacket;
use super::application::protocols::dhcpv6::Dhcpv6Packet;
use super::application::protocols::dns::DnsPacket;
use super::application::protocols::ethernet_ip::EtherNetIpPacket;
use super::application::protocols::ftp::FtpMessage;
use super::application::protocols::giop::GiopPacket;
use super::application::protocols::http::HttpRequest;
use super::application::protocols::modbus_tcp::ModbusTcpPacket;
use super::application::protocols::mqtt::MqttPacket;
use super::application::protocols::nntp::NntpMessage;
use super::application::protocols::ntp::NtpPacket;
use super::application::protocols::opcua::OpcuaPacket;
use super::application::protocols::postgresql::is_likely_postgresql_payload;
use super::application::protocols::quic::QuicPacket;
use super::application::protocols::s7comm::S7CommPacket;
use super::application::protocols::smtp::SmtpMessage;
use super::application::protocols::snmp::SnmpPacket;
use super::application::protocols::srvloc::SrvlocPacket;
use super::application::protocols::ssh::SshPacket;
use super::application::protocols::tls::TlsPacket;
use super::cotp_from_tpkt;
use super::transport::Transport;
use super::transport::protocols::TransportProtocol;
use crate::checks::application::quic::is_plausible_short_header;

/// Nombre d'octets soumis aux sondes. Au-dela, seul le prefixe est sonde :
/// la classification est un verdict sur l'en-tete applicatif, pas sur la
/// charge complete, et cette borne supprime le cout pathologique des
/// segments jumbo hostiles mesures par l'audit (x2545).
const PROBE_CAP: usize = 18 * 1024;

/// Transport requis par une regle.
#[derive(Clone, Copy)]
enum Guard {
    Tcp,
    Udp,
    /// Sonde de contenu valable quel que soit le transport.
    Any,
}

impl Guard {
    const fn admits(self, protocol: TransportProtocol) -> bool {
        match self {
            Self::Tcp => matches!(protocol, TransportProtocol::Tcp),
            Self::Udp => matches!(protocol, TransportProtocol::Udp),
            Self::Any => true,
        }
    }
}

/// Identite d'une sonde de contenu. Deux regles peuvent partager la meme
/// sonde (port prioritaire puis repli aveugle) : la memoisation par identite
/// garantit qu'elle ne s'execute qu'une fois par payload.
#[derive(Clone, Copy)]
#[repr(u32)]
enum ProbeId {
    Snmp,
    Dhcpv6,
    S7Comm,
    CotpTpkt,
    Ftp,
    Smtp,
    Nntp,
    Mdns,
    Ams,
    QuicShortHeader,
    Ntp,
    Bitcoin,
    Opcua,
    EthernetIp,
    Postgresql,
    Dns,
    Tls,
    Ssh,
    Http,
    Giop,
    Dhcp,
    Srvloc,
    ModbusTcp,
    QuicLongHeader,
    Mqtt,
}

fn run_probe(probe: ProbeId, payload: &[u8]) -> bool {
    match probe {
        ProbeId::Snmp => SnmpPacket::try_from(payload).is_ok(),
        ProbeId::Dhcpv6 => Dhcpv6Packet::try_from(payload).is_ok(),
        ProbeId::S7Comm => S7CommPacket::try_from(payload).is_ok(),
        ProbeId::CotpTpkt => cotp_from_tpkt(payload).is_some(),
        ProbeId::Ftp => FtpMessage::try_from(payload).is_ok(),
        ProbeId::Smtp => SmtpMessage::try_from(payload).is_ok(),
        ProbeId::Nntp => NntpMessage::try_from(payload).is_ok(),
        ProbeId::Mdns => DnsPacket::try_from_mdns(payload).is_ok(),
        ProbeId::Ams => AmsPacket::try_from(payload).is_ok(),
        ProbeId::QuicShortHeader => is_plausible_short_header(payload),
        ProbeId::Ntp => NtpPacket::try_from(payload).is_ok(),
        ProbeId::Bitcoin => BitcoinPacket::try_from(payload).is_ok(),
        ProbeId::Opcua => OpcuaPacket::try_from(payload).is_ok(),
        ProbeId::EthernetIp => EtherNetIpPacket::try_from(payload).is_ok(),
        ProbeId::Postgresql => is_likely_postgresql_payload(payload),
        ProbeId::Dns => DnsPacket::try_from(payload).is_ok(),
        ProbeId::Tls => TlsPacket::try_from(payload).is_ok(),
        ProbeId::Ssh => SshPacket::try_from(payload).is_ok(),
        ProbeId::Http => HttpRequest::try_from(payload).is_ok(),
        ProbeId::Giop => GiopPacket::try_from(payload).is_ok(),
        ProbeId::Dhcp => DhcpPacket::try_from(payload).is_ok(),
        ProbeId::Srvloc => SrvlocPacket::try_from(payload).is_ok(),
        ProbeId::ModbusTcp => ModbusTcpPacket::try_from(payload).is_ok(),
        ProbeId::QuicLongHeader => QuicPacket::try_from(payload).is_ok(),
        ProbeId::Mqtt => MqttPacket::try_from(payload).is_ok(),
    }
}

/// Une regle du dispatch : `label` est retenu si la garde de transport
/// admet le paquet, que la garde de port (si presente) matche un des deux
/// ports, et que la sonde accepte le contenu.
struct Rule {
    label: &'static str,
    guard: Guard,
    ports: Option<fn(Option<u16>) -> bool>,
    probe: ProbeId,
    /// Regle terminale : si son port matche, le verdict est definitif meme
    /// quand la sonde echoue (mDNS : le port 5353 est reserve, RFC 6762 —
    /// la sonde DNS generique ne doit pas re-etiqueter ces octets).
    terminal_on_port: bool,
}

const fn rule(label: &'static str, guard: Guard, probe: ProbeId) -> Rule {
    Rule {
        label,
        guard,
        ports: None,
        probe,
        terminal_on_port: false,
    }
}

const fn port_rule(
    label: &'static str,
    guard: Guard,
    ports: fn(Option<u16>) -> bool,
    probe: ProbeId,
) -> Rule {
    Rule {
        label,
        guard,
        ports: Some(ports),
        probe,
        terminal_on_port: false,
    }
}

/// La table : l'ordre est la priorite. D'abord les regles a port (signature
/// faible confirmee par le port, ou priorite sur un port standard), puis les
/// sondes aveugles dans l'ordre historique de `Application::try_from` — cet
/// ordre est porteur de semantique (S7Comm avant COTP, DHCP avant SRVLOC,
/// MQTT en dernier) et verrouille par le snapshot `tests/golden_pcaps.rs`.
static RULES: &[Rule] = &[
    port_rule("SNMP", Guard::Udp, is_snmp_udp_port, ProbeId::Snmp),
    port_rule("DHCPv6", Guard::Udp, is_dhcpv6_udp_port, ProbeId::Dhcpv6),
    // Signature assez forte pour le probing aveugle sur TCP, et doit gagner
    // sur l'etiquette COTP generique, y compris sur le port 102.
    rule("S7Comm", Guard::Tcp, ProbeId::S7Comm),
    port_rule("COTP", Guard::Tcp, is_iso_tsap_tcp_port, ProbeId::CotpTpkt),
    // FTP, SMTP et NNTP partagent la meme forme de reponse ("code SP texte
    // CRLF") et plusieurs commandes : strictement gardes par port.
    port_rule("FTP", Guard::Tcp, is_ftp_tcp_port, ProbeId::Ftp),
    port_rule("SMTP", Guard::Tcp, is_smtp_tcp_port, ProbeId::Smtp),
    port_rule("NNTP", Guard::Tcp, is_nntp_tcp_port, ProbeId::Nntp),
    // mDNS reprend le format DNS mais ses reponses omettent souvent la
    // question (RFC 6762 §6) : validateur dedie, et port terminal.
    Rule {
        label: "mDNS",
        guard: Guard::Udp,
        ports: Some(is_mdns_udp_port),
        probe: ProbeId::Mdns,
        terminal_on_port: true,
    },
    port_rule("AMS", Guard::Tcp, is_ams_tcp_port, ProbeId::Ams),
    port_rule("AMS", Guard::Udp, is_ams_udp_port, ProbeId::Ams),
    // QUIC 1-RTT (Short Header) : en-tete volontairement opaque (RFC 9000
    // §17.3), une heuristique gardee par le port est le maximum stateless.
    port_rule(
        "QUIC",
        Guard::Udp,
        is_quic_udp_port,
        ProbeId::QuicShortHeader,
    ),
    // Priorites de port sur sondes par ailleurs aveugles : le port ne suffit
    // jamais, mais il fait passer la sonde avant le reste de la cascade.
    port_rule("OPC UA", Guard::Tcp, is_opcua_tcp_port, ProbeId::Opcua),
    port_rule("DNS", Guard::Any, is_dns_port, ProbeId::Dns),
    // --- cascade aveugle, ordre historique de `Application::try_from` ---
    rule("NTP", Guard::Any, ProbeId::Ntp),
    rule("Bitcoin", Guard::Any, ProbeId::Bitcoin),
    rule("OPC UA", Guard::Any, ProbeId::Opcua),
    rule("EtherNet/IP", Guard::Any, ProbeId::EthernetIp),
    // PostgreSQL ne circule que sur TCP : la garde manquait et la sonde
    // s'executait deux fois (issue #29).
    rule("PostgreSQL", Guard::Tcp, ProbeId::Postgresql),
    rule("DNS", Guard::Any, ProbeId::Dns),
    rule("SNMP", Guard::Any, ProbeId::Snmp),
    rule("TLS", Guard::Any, ProbeId::Tls),
    // SSH avant HTTP : prefixe litteral `SSH-` + version exacte, aucun
    // recouvrement avec les methodes HTTP.
    rule("SSH", Guard::Any, ProbeId::Ssh),
    rule("HTTP", Guard::Any, ProbeId::Http),
    rule("GIOP", Guard::Any, ProbeId::Giop),
    // DHCP avant SRVLOC : un BOOTP mimait un en-tete SLP (issue #3).
    rule("DHCP", Guard::Any, ProbeId::Dhcp),
    rule("SRVLOC", Guard::Any, ProbeId::Srvloc),
    rule("ModbusTCP", Guard::Any, ProbeId::ModbusTcp),
    rule("QUIC", Guard::Any, ProbeId::QuicLongHeader),
    // MQTT en dernier : en-tete fixe peu discriminant.
    rule("MQTT", Guard::Any, ProbeId::Mqtt),
];

/// Classifie le payload d'une couche transport. `None` signifie « rien a
/// sonder » (pas de payload, payload vide, ou port mDNS sans contenu mDNS) ;
/// un payload sonde sans succes reste etiquete `"Unknown"`, comme
/// l'historique `Application::try_from`.
pub(super) fn classify(transport: &Transport<'_>) -> Option<Application> {
    let payload = transport.payload?;
    if payload.is_empty() {
        return None;
    }
    let probed = &payload[..payload.len().min(PROBE_CAP)];

    let mut failed_probes: u32 = 0;
    for rule in RULES {
        if !rule.guard.admits(transport.protocol) {
            continue;
        }
        if let Some(ports) = rule.ports
            && !(ports(transport.source_port) || ports(transport.destination_port))
        {
            continue;
        }

        let bit = 1u32 << rule.probe as u32;
        let matched = failed_probes & bit == 0 && run_probe(rule.probe, probed);
        if matched {
            return Some(Application {
                application_protocol: rule.label,
            });
        }
        failed_probes |= bit;
        if rule.terminal_on_port {
            return None;
        }
    }

    Some(Application {
        application_protocol: "Unknown",
    })
}

fn is_snmp_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(161 | 162))
}

fn is_dhcpv6_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(546 | 547))
}

/// ISO-TSAP (TPKT/COTP, notamment S7comm).
fn is_iso_tsap_tcp_port(port: Option<u16>) -> bool {
    matches!(port, Some(102))
}

/// Beckhoff AMS/ADS sur TCP.
fn is_ams_tcp_port(port: Option<u16>) -> bool {
    matches!(port, Some(48898))
}

/// Beckhoff AMS/ADS discovery sur UDP.
fn is_ams_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(48899))
}

/// QUIC (HTTP/3) : UDP 443.
fn is_quic_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(443))
}

/// FTP control channel : TCP 21.
fn is_ftp_tcp_port(port: Option<u16>) -> bool {
    matches!(port, Some(21))
}

/// SMTP en clair ou avec STARTTLS : TCP 25 (relais) et 587 (soumission).
/// Le port 465 transporte du TLS implicite et ne peut pas contenir
/// directement une commande SMTP dans le payload inspecte ici.
fn is_smtp_tcp_port(port: Option<u16>) -> bool {
    matches!(port, Some(25 | 587))
}

/// NNTP en clair ou avec STARTTLS : TCP 119. Le port 563 transporte du TLS
/// implicite et ne peut pas contenir directement une commande NNTP ici.
fn is_nntp_tcp_port(port: Option<u16>) -> bool {
    matches!(port, Some(119))
}

/// mDNS : UDP 5353 (port reserve, RFC 6762).
fn is_mdns_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(5353))
}

fn is_opcua_tcp_port(port: Option<u16>) -> bool {
    matches!(port, Some(4840 | 12001))
}

/// DNS classique : 53, sur UDP comme sur TCP.
fn is_dns_port(port: Option<u16>) -> bool {
    matches!(port, Some(53))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// La memoisation exige un identifiant de sonde par bit d'un u32.
    #[test]
    fn probe_ids_fit_the_memoization_bitmask() {
        for rule in RULES {
            assert!((rule.probe as u32) < 32);
        }
    }

    /// L'invariant central de la table : une regle a port sans garde de
    /// transport serait un retour de l'override port-seul (issue #25).
    /// Seule DNS/53 est volontairement bi-transport.
    #[test]
    fn port_rules_carry_a_transport_guard() {
        for rule in RULES.iter().filter(|rule| rule.ports.is_some()) {
            assert!(
                !matches!(rule.guard, Guard::Any) || rule.label == "DNS",
                "regle a port sans garde de transport : {}",
                rule.label
            );
        }
    }

    /// La cascade aveugle de la table couvre exactement les protocoles de
    /// `Application::try_from`, dans le meme ordre — le dispatch transport
    /// ne doit pas silencieusement diverger du probing public.
    #[test]
    fn blind_rules_mirror_the_public_cascade_order() {
        let blind: Vec<&str> = RULES
            .iter()
            .filter(|rule| rule.ports.is_none())
            .map(|rule| rule.label)
            .collect();
        assert_eq!(
            blind,
            [
                "S7Comm",
                "NTP",
                "Bitcoin",
                "OPC UA",
                "EtherNet/IP",
                "PostgreSQL",
                "DNS",
                "SNMP",
                "TLS",
                "SSH",
                "HTTP",
                "GIOP",
                "DHCP",
                "SRVLOC",
                "ModbusTCP",
                "QUIC",
                "MQTT",
            ],
            "S7Comm est promu en tete (priorite sur COTP), le reste suit \
             l'ordre historique de Application::try_from"
        );
    }
}
