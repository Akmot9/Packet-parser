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
//! - chaque sonde juge les octets que son decodeur lira : le payload entier,
//!   que les decodeurs exigent souvent pave jusqu'au dernier octet (SNMP,
//!   Modbus/TCP, ASTERIX...) ou couvert par une longueur declaree (NBSS,
//!   DNS sur TCP, TLS...). Seules les sondes des protocoles texte (FTP, SMTP,
//!   NNTP, HTTP), qui valident tout le texte en UTF-8, ne lisent que
//!   [`PROBE_CAP`](probes::PROBE_CAP) octets : la borne de l'issue #20, qui plafonnait jadis
//!   toutes les sondes (#184, #185), et que l'oracle du fuzz recopie.

use super::application::Application;
use super::transport::Transport;
use super::transport::protocols::TransportProtocol;

mod ports;
mod probes;
mod rules;
#[cfg(test)]
mod tests;

use probes::{ProbeId, ProbeMask, run_probe};
use rules::{Guard, RULES, matches_terminal_reserved_port};

/// Protocole que l'appelant peut associer a un port supplementaire via
/// [`crate::ParseConfig`] (« Decode As », issue #65). La regle de la table
/// vaut aussi ici : le port declare ne suffit jamais, la sonde de contenu
/// doit accepter le payload, et la garde de transport du protocole reste
/// appliquee.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecodeAsProtocol {
    Ftp,
    Smtp,
    Nntp,
    Cotp,
    Dns,
    Mdns,
    Llmnr,
    Ssdp,
    Nbns,
    Nbss,
    Snmp,
    Dhcpv6,
    OpcUa,
    PostgreSql,
    ModbusTcp,
    EthernetIp,
    Ams,
    QuicShortHeader,
    OpenVpn,
    Ptp,
    Stanag5066,
    Dis,
    /// IKE nu ou derriere le marqueur non-ESP (UDP).
    Ike,
    /// ESP encapsule dans UDP (RFC 3948), SPI non nul en tete.
    Esp,
    /// RDP : TPKT, COTP X.224 et MCS (TCP).
    Rdp,
    /// IEC 60870-5-104 : APDU `0x68` sur TCP.
    Iec104,
    /// WireGuard sur UDP : la forme du message, octets reserves compris
    /// quel que soit le type.
    WireGuard,
    /// Valmet DNA sur UDP : messages `AB 01` de toute famille, et la balise.
    ValmetDna,
}

impl DecodeAsProtocol {
    /// (etiquette, garde, sonde) de la regle equivalente de la table. DNS
    /// choisit sa forme selon le transport : datagramme sur UDP, prefixe de
    /// longueur sur TCP (RFC 1035 §4.2).
    fn rule(self, protocol: TransportProtocol) -> (&'static str, Guard, ProbeId) {
        match self {
            Self::Ftp => ("FTP", Guard::Tcp, ProbeId::Ftp),
            Self::Smtp => ("SMTP", Guard::Tcp, ProbeId::Smtp),
            Self::Nntp => ("NNTP", Guard::Tcp, ProbeId::Nntp),
            Self::Cotp => ("COTP", Guard::Tcp, ProbeId::CotpTpkt),
            Self::Dns => match protocol {
                TransportProtocol::Tcp => ("DNS", Guard::Tcp, ProbeId::DnsTcp),
                _ => ("DNS", Guard::Udp, ProbeId::Dns),
            },
            Self::Mdns => ("mDNS", Guard::Udp, ProbeId::Mdns),
            Self::Llmnr => ("LLMNR", Guard::Udp, ProbeId::Llmnr),
            Self::Ssdp => ("SSDP", Guard::Udp, ProbeId::Ssdp),
            Self::Nbns => ("NBNS", Guard::Udp, ProbeId::Nbns),
            Self::Nbss => ("NBSS", Guard::Tcp, ProbeId::Nbss),
            Self::Snmp => ("SNMP", Guard::Any, ProbeId::Snmp),
            Self::Dhcpv6 => ("DHCPv6", Guard::Udp, ProbeId::Dhcpv6),
            Self::OpcUa => ("OPC UA", Guard::Tcp, ProbeId::Opcua),
            Self::PostgreSql => ("PostgreSQL", Guard::Tcp, ProbeId::PostgresqlPort),
            Self::ModbusTcp => ("ModbusTCP", Guard::Tcp, ProbeId::ModbusTcp),
            Self::EthernetIp => ("EtherNet/IP", Guard::Any, ProbeId::EthernetIp),
            Self::Ams => ("AMS", Guard::Any, ProbeId::Ams),
            Self::QuicShortHeader => ("QUIC", Guard::Udp, ProbeId::QuicShortHeader),
            Self::OpenVpn => match protocol {
                TransportProtocol::Tcp => ("OpenVPN", Guard::Tcp, ProbeId::OpenVpnTcp),
                _ => ("OpenVPN", Guard::Udp, ProbeId::OpenVpnUdp),
            },
            Self::Ptp => ("PTP", Guard::Udp, ProbeId::Ptp),
            Self::Stanag5066 => ("STANAG 5066", Guard::Tcp, ProbeId::Stanag5066),
            Self::Dis => ("DIS", Guard::Udp, ProbeId::DisLenient),
            Self::Ike => ("IKE", Guard::Udp, ProbeId::Ike),
            Self::Esp => ("ESP", Guard::Udp, ProbeId::EspNatT),
            Self::Rdp => ("RDP", Guard::Tcp, ProbeId::Rdp),
            Self::Iec104 => ("IEC 104", Guard::Tcp, ProbeId::Iec104),
            Self::WireGuard => ("WireGuard", Guard::Udp, ProbeId::WireGuard),
            Self::ValmetDna => ("Valmet DNA", Guard::Udp, ProbeId::ValmetDna),
        }
    }
}

/// Classe un payload sans port ni transport : la cascade de
/// `Application::try_from`, derivee de la table (#216). Ce sont les regles
/// sans garde ni veto de port, dans l'ordre de la table, avec les memes
/// sondes que [`classify`] et la meme memoisation. Faute de transport, leur
/// garde de transport n'est pas appliquee : une signature TCP peut
/// etiqueter un datagramme. Cette API est donc moins sure que `parse`, qui
/// voit les ports et le transport ; elle le restera jusqu'a #209.
pub(crate) fn classify_blind(payload: &[u8]) -> &'static str {
    let mut failed_probes: ProbeMask = 0;
    for rule in RULES {
        if rule.ports.is_some() || rule.ports_veto.is_some() {
            continue;
        }
        let bit = rule.probe.bit();
        if failed_probes & bit == 0 && run_probe(rule.probe, payload) {
            return rule.label;
        }
        failed_probes |= bit;
    }
    "Unknown"
}

/// Classifie le payload d'une couche transport. `None` signifie « rien a
/// sonder » (pas de payload, payload vide, ou port mDNS sans contenu mDNS) ;
/// un payload sonde sans succes reste etiquete `"Unknown"`, comme
/// `Application::try_from`.
pub(super) fn classify(
    transport: &Transport<'_>,
    decode_as: &[(u16, DecodeAsProtocol)],
) -> Option<Application> {
    let payload = transport.payload?;
    if payload.is_empty() {
        return None;
    }
    let mut failed_probes: ProbeMask = 0;

    // Ports declares par l'appelant (« Decode As ») : evalues avant la
    // table, port ET contenu, garde de transport conservee. Un echec est
    // memoise comme ceux de la table. Les ports que la table declare
    // terminaux (mDNS 5353, LLMNR 5355 — reserves par leurs RFC) ne sont
    // jamais contournables : « etendre les gardes sans les remplacer ».
    if !decode_as.is_empty() && !matches_terminal_reserved_port(transport) {
        for (port, protocol) in decode_as {
            if transport.source_port != Some(*port) && transport.destination_port != Some(*port) {
                continue;
            }
            let (label, guard, probe) = protocol.rule(transport.protocol);
            if !guard.admits(transport.protocol) {
                continue;
            }
            let bit = probe.bit();
            if failed_probes & bit == 0 && run_probe(probe, payload) {
                return Some(Application {
                    application_protocol: label,
                });
            }
            failed_probes |= bit;
        }
    }
    for rule in RULES {
        if !rule.guard.admits(transport.protocol) {
            continue;
        }
        if let Some(ports) = rule.ports
            && !(ports(transport.source_port) || ports(transport.destination_port))
        {
            continue;
        }
        if let Some(veto) = rule.ports_veto
            && (veto(transport.source_port) || veto(transport.destination_port))
        {
            continue;
        }

        let bit = rule.probe.bit();
        let matched = failed_probes & bit == 0 && run_probe(rule.probe, payload);
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
