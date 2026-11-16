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
use crate::parse::application::protocol::ApplicationProtocol;

mod ports;
mod probes;
mod rules;
#[cfg(test)]
mod tests;

use probes::{ProbeId, ProbeMask, run_probe};
use rules::{Guard, RULES, matches_terminal_reserved_port};

/// Declare l'enum et `ALL` depuis une seule liste, comme
/// `application_protocols!` : une variante ne peut pas manquer a `ALL`
/// (#274).
macro_rules! decode_as_protocols {
    ($($(#[$doc:meta])* $variant:ident),+ $(,)?) => {
        /// Protocole que l'appelant peut associer a un port supplementaire via
        /// [`crate::ParseConfig`] (« Decode As », issue #65). La regle de la table
        /// vaut aussi ici : le port declare ne suffit jamais, la sonde de contenu
        /// doit accepter le payload, et la garde de transport du protocole reste
        /// appliquee.
        #[non_exhaustive]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum DecodeAsProtocol {
            $(
                $(#[$doc])*
                $variant,
            )+
        }

        impl DecodeAsProtocol {
            /// Toutes les variantes, dans l'ordre de leur declaration : les
            /// protocoles qu'un appelant peut proposer pour un port.
            ///
            /// ```
            /// use packet_parser::DecodeAsProtocol;
            ///
            /// assert_eq!(DecodeAsProtocol::ALL.first(), Some(&DecodeAsProtocol::Ftp));
            /// assert!(DecodeAsProtocol::ALL.contains(&DecodeAsProtocol::ModbusUdp));
            /// ```
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];
        }
    };
}

// Une nouvelle variante s'ajoute en fin de liste : les discriminants ne
// bougent pas, et `ALL` garde son ordre.
decode_as_protocols![
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
    /// Modbus sur UDP : l'enveloppe MBAP, comme sur UDP 502.
    ModbusUdp,
];

impl DecodeAsProtocol {
    /// (etiquette, garde, sonde) de la regle equivalente de la table. DNS
    /// choisit sa forme selon le transport : datagramme sur UDP, prefixe de
    /// longueur sur TCP (RFC 1035 §4.2).
    fn rule(self, protocol: TransportProtocol) -> (ApplicationProtocol, Guard, ProbeId) {
        match self {
            Self::Ftp => (ApplicationProtocol::Ftp, Guard::Tcp, ProbeId::Ftp),
            Self::Smtp => (ApplicationProtocol::Smtp, Guard::Tcp, ProbeId::Smtp),
            Self::Nntp => (ApplicationProtocol::Nntp, Guard::Tcp, ProbeId::Nntp),
            Self::Cotp => (ApplicationProtocol::Cotp, Guard::Tcp, ProbeId::CotpTpkt),
            Self::Dns => match protocol {
                TransportProtocol::Tcp => (ApplicationProtocol::Dns, Guard::Tcp, ProbeId::DnsTcp),
                _ => (ApplicationProtocol::Dns, Guard::Udp, ProbeId::Dns),
            },
            Self::Mdns => (ApplicationProtocol::Mdns, Guard::Udp, ProbeId::Mdns),
            Self::Llmnr => (ApplicationProtocol::Llmnr, Guard::Udp, ProbeId::Llmnr),
            Self::Ssdp => (ApplicationProtocol::Ssdp, Guard::Udp, ProbeId::Ssdp),
            Self::Nbns => (ApplicationProtocol::Nbns, Guard::Udp, ProbeId::Nbns),
            Self::Nbss => (ApplicationProtocol::Nbss, Guard::Tcp, ProbeId::Nbss),
            Self::Snmp => (ApplicationProtocol::Snmp, Guard::Any, ProbeId::Snmp),
            Self::Dhcpv6 => (ApplicationProtocol::Dhcpv6, Guard::Udp, ProbeId::Dhcpv6),
            Self::OpcUa => (ApplicationProtocol::OpcUa, Guard::Tcp, ProbeId::Opcua),
            Self::PostgreSql => (
                ApplicationProtocol::PostgreSql,
                Guard::Tcp,
                ProbeId::PostgresqlPort,
            ),
            Self::ModbusTcp => (
                ApplicationProtocol::ModbusTcp,
                Guard::Tcp,
                ProbeId::ModbusTcp,
            ),
            Self::EthernetIp => (
                ApplicationProtocol::EthernetIp,
                Guard::Any,
                ProbeId::EthernetIp,
            ),
            Self::Ams => (ApplicationProtocol::Ams, Guard::Any, ProbeId::Ams),
            Self::QuicShortHeader => (
                ApplicationProtocol::Quic,
                Guard::Udp,
                ProbeId::QuicShortHeader,
            ),
            Self::OpenVpn => match protocol {
                TransportProtocol::Tcp => (
                    ApplicationProtocol::OpenVpn,
                    Guard::Tcp,
                    ProbeId::OpenVpnTcp,
                ),
                _ => (
                    ApplicationProtocol::OpenVpn,
                    Guard::Udp,
                    ProbeId::OpenVpnUdp,
                ),
            },
            Self::Ptp => (ApplicationProtocol::Ptp, Guard::Udp, ProbeId::Ptp),
            Self::Stanag5066 => (
                ApplicationProtocol::Stanag5066,
                Guard::Tcp,
                ProbeId::Stanag5066,
            ),
            Self::Dis => (ApplicationProtocol::Dis, Guard::Udp, ProbeId::DisLenient),
            Self::Ike => (ApplicationProtocol::Ike, Guard::Udp, ProbeId::Ike),
            Self::Esp => (ApplicationProtocol::Esp, Guard::Udp, ProbeId::EspNatT),
            Self::Rdp => (ApplicationProtocol::Rdp, Guard::Tcp, ProbeId::Rdp),
            Self::Iec104 => (ApplicationProtocol::Iec104, Guard::Tcp, ProbeId::Iec104),
            Self::WireGuard => (
                ApplicationProtocol::WireGuard,
                Guard::Udp,
                ProbeId::WireGuard,
            ),
            Self::ValmetDna => (
                ApplicationProtocol::ValmetDna,
                Guard::Udp,
                ProbeId::ValmetDna,
            ),
            Self::ModbusUdp => (
                ApplicationProtocol::ModbusUdp,
                Guard::Udp,
                ProbeId::ModbusTcp,
            ),
        }
    }
}

/// Classifie le payload d'une couche transport. `None` signifie « rien a
/// sonder » (pas de payload, payload vide, ou port mDNS sans contenu mDNS) ;
/// un payload sonde sans succes reste etiquete `"Unknown"`.
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
                return Some(Application { protocol: label });
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
                protocol: rule.label,
            });
        }
        failed_probes |= bit;
        if rule.terminal_on_port {
            return None;
        }
    }

    Some(Application {
        protocol: ApplicationProtocol::Unknown,
    })
}
