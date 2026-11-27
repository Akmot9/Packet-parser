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
//! - chaque sonde s'execute **au plus une fois** par payload : une sonde
//!   qui echoue retire de la visite les regles suivantes qui la portent (fin
//!   du double sondage PostgreSQL et SNMP, issue #29) ;
//! - chaque sonde juge les octets que son decodeur lira : le payload entier,
//!   que les decodeurs exigent souvent pave jusqu'au dernier octet (SNMP,
//!   Modbus/TCP, ASTERIX...) ou couvert par une longueur declaree (NBSS,
//!   DNS sur TCP, TLS...). Seules les sondes des protocoles texte (FTP, SMTP,
//!   NNTP, HTTP), qui valident tout le texte en UTF-8, ne lisent que
//!   [`PROBE_CAP`](probes::PROBE_CAP) octets : la borne de l'issue #20, qui plafonnait jadis
//!   toutes les sondes (#184, #185), et que l'oracle du fuzz recopie ;
//! - une sonde n'est tentee que si le premier octet du payload peut lui
//!   convenir ([`first_bytes`]) : les regles ecartees auraient echoue, et le
//!   verdict reste celui d'un parcours de toute la table. Trois cas ne sont
//!   pas filtres : une regle terminale, toujours visitee a son rang ; un
//!   port declare par Decode As ; un payload de
//!   [`PROVEN_BELOW`](first_bytes::PROVEN_BELOW) octets ou plus.

use std::num::NonZero;

use super::application::Application;
use super::transport::Transport;
use super::transport::protocols::TransportProtocol;
use crate::parse::application::protocol::ApplicationProtocol;

mod first_bytes;
mod index;
mod ports;
mod probes;
mod rules;
#[cfg(test)]
mod tests;

use probes::{ProbeId, ProbeMask, run_probe};
use rules::Guard;

/// Declare l'enum et `ALL` depuis une seule liste, comme
/// `application_protocols!` : une variante ne peut pas manquer a `ALL`
/// (#274).
macro_rules! decode_as_protocols {
    ($($(#[$doc:meta])* $variant:ident),+ $(,)?) => {
        /// Protocol the caller can bind to an additional port through
        /// [`crate::ParseConfig`] ("Decode As", issue #65). The rule of the
        /// dispatch table applies here too: the declared port is never enough,
        /// the content probe must accept the payload, and the transport guard
        /// of the protocol still applies.
        #[non_exhaustive]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum DecodeAsProtocol {
            $(
                $(#[$doc])*
                $variant,
            )+
        }

        impl DecodeAsProtocol {
            /// Every variant, in declaration order: the protocols a caller
            /// can offer for a port.
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
    /// Bare IKE, or IKE behind the non-ESP marker (UDP).
    Ike,
    /// ESP encapsulated in UDP (RFC 3948), starting with a non-zero SPI.
    Esp,
    /// RDP: TPKT, X.224 COTP and MCS (TCP).
    Rdp,
    /// IEC 60870-5-104: `0x68` APDU over TCP.
    Iec104,
    /// WireGuard over UDP: the shape of the message, reserved bytes
    /// included, whatever the type.
    WireGuard,
    /// Valmet DNA over UDP: `AB 01` messages of any family, and the beacon.
    ValmetDna,
    /// Modbus over UDP: the MBAP envelope, as on UDP 502.
    ModbusUdp,
    /// Java RMI (JRMP) over TCP: any message, for exported objects and JMX
    /// connectors off port 1099. That includes the messages that the blind
    /// rule cannot prove: Ping, PingAck, ProtocolNotSupported, DgcAck and
    /// ProtocolAck.
    JavaRmi,
    /// SIP over TCP or UDP: the same rule as off port, for a port where
    /// another rule would take the message first.
    Sip,
    /// RTP over UDP: any well-formed packet. RTP has two fixed bits and no
    /// blind rule: a declared port is the only way the crate names it.
    Rtp,
    /// .NET Message Framing over TCP: any segment made of framing records,
    /// including the one-byte records and the envelopes that the blind
    /// rule cannot prove.
    Nmf,
    /// RTCP over UDP: any well-formed datagram, where the blind rule asks
    /// for a Sender or Receiver Report first, or a lone feedback message.
    Rtcp,
    /// Skinny (Cisco SCCP) over TCP: the same rule as on TCP 2000, for a
    /// call manager that listens on another port.
    Skinny,
    /// LDAP over TCP or UDP: the same rule as on port 389, for a directory
    /// that listens on another port.
    Ldap,
    /// Syslog: one message per UDP datagram, RFC 6587 frames over TCP, for
    /// a collector that listens on another port than 514.
    Syslog,
    /// NetBIOS Datagram Service over UDP: the same rule as on UDP 138.
    Nbds,
    /// Kerberos V5: one message per UDP datagram, length-prefixed records
    /// over TCP, for a KDC that listens on another port than 88.
    Kerberos,
    /// ONC RPC: one message per UDP datagram, record fragments over TCP,
    /// for a program on a port that the portmapper hands out (`mountd`,
    /// `statd`, `lockd`).
    OncRpc,
];

impl DecodeAsProtocol {
    /// (etiquette, garde, sonde) de la regle equivalente de la table. DNS
    /// choisit sa forme selon le transport : datagramme sur UDP, prefixe de
    /// longueur sur TCP (RFC 1035 §4.2). AMS aussi : en-tete nu hors TCP,
    /// precede de l'en-tete AMS/TCP sur TCP. EtherNet/IP comme ses regles
    /// aveugles : sur TCP, des messages complets qui pavent le segment
    /// (#288) ; ailleurs, un seul message. Syslog de meme : des trames de
    /// la RFC 6587 sur TCP, un message par datagramme ailleurs (#374).
    /// Kerberos aussi : des enregistrements prefixes de leur longueur sur
    /// TCP, un message par datagramme ailleurs (#379). ONC RPC de meme,
    /// avec sa marque de fragment sur TCP (#381).
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
            Self::EthernetIp => match protocol {
                TransportProtocol::Tcp => (
                    ApplicationProtocol::EthernetIp,
                    Guard::Tcp,
                    ProbeId::EthernetIpTcp,
                ),
                _ => (
                    ApplicationProtocol::EthernetIp,
                    Guard::Any,
                    ProbeId::EthernetIp,
                ),
            },
            Self::Ams => match protocol {
                TransportProtocol::Tcp => (ApplicationProtocol::Ams, Guard::Tcp, ProbeId::AmsTcp),
                _ => (ApplicationProtocol::Ams, Guard::Any, ProbeId::Ams),
            },
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
            Self::JavaRmi => (ApplicationProtocol::JavaRmi, Guard::Tcp, ProbeId::JavaRmi),
            Self::Sip => (ApplicationProtocol::Sip, Guard::Any, ProbeId::Sip),
            Self::Rtp => (ApplicationProtocol::Rtp, Guard::Udp, ProbeId::Rtp),
            Self::Nmf => (ApplicationProtocol::Nmf, Guard::Tcp, ProbeId::Nmf),
            Self::Rtcp => (ApplicationProtocol::Rtcp, Guard::Udp, ProbeId::Rtcp),
            Self::Skinny => (ApplicationProtocol::Skinny, Guard::Tcp, ProbeId::Skinny),
            Self::Ldap => (ApplicationProtocol::Ldap, Guard::Any, ProbeId::Ldap),
            Self::Syslog => match protocol {
                TransportProtocol::Tcp => {
                    (ApplicationProtocol::Syslog, Guard::Tcp, ProbeId::SyslogTcp)
                }
                _ => (ApplicationProtocol::Syslog, Guard::Udp, ProbeId::Syslog),
            },
            Self::Nbds => (ApplicationProtocol::Nbds, Guard::Udp, ProbeId::Nbds),
            Self::Kerberos => match protocol {
                TransportProtocol::Tcp => (
                    ApplicationProtocol::Kerberos,
                    Guard::Tcp,
                    ProbeId::KerberosTcp,
                ),
                _ => (ApplicationProtocol::Kerberos, Guard::Udp, ProbeId::Kerberos),
            },
            Self::OncRpc => match protocol {
                TransportProtocol::Tcp => {
                    (ApplicationProtocol::OncRpc, Guard::Tcp, ProbeId::OncRpcTcp)
                }
                _ => (ApplicationProtocol::OncRpc, Guard::Udp, ProbeId::OncRpc),
            },
        }
    }
}

/// Classifie le payload d'une couche transport. `None` signifie « rien a
/// sonder » (pas de payload, payload vide, ou port mDNS sans contenu mDNS) ;
/// un payload sonde sans succes reste etiquete `"Unknown"`.
#[inline]
pub(super) fn classify(
    transport: &Transport<'_>,
    decode_as: &[(u16, DecodeAsProtocol)],
) -> Option<Application> {
    let payload = transport.payload?;
    let first = *payload.first()?;
    classify_payload(transport, payload, first, decode_as)
}

/// L'oracle du prefiltre, en build de debug : chaque regle de la liste que
/// le premier octet ecarte, quels que soient les ports, voit sa sonde
/// rejouee, et elle doit refuser. Les tests, le corpus de reference et les
/// cibles de fuzz verifient ainsi chaque ensemble declare sur chaque payload
/// qu'ils classent.
#[cfg(debug_assertions)]
fn assert_excluded_probes_reject(
    list: &index::RuleList,
    worth_visiting: index::RuleSet,
    payload: &[u8],
    first: u8,
) {
    for (rank, listed) in list.rules().iter().enumerate() {
        if worth_visiting >> rank & 1 == 0 {
            debug_assert!(
                !run_probe(listed.rule.probe, payload),
                "la sonde {} accepte un payload dont elle exclut le premier octet {first:#04x}",
                listed.rule.label,
            );
        }
    }
}

/// La table, sur un payload non vide, dont `first` est le premier octet.
/// Hors de [`classify`] : un segment sans payload (un ACK nu, un quart des
/// trames du corpus) ne paie pas l'entree de la fonction qui parcourt la
/// table, ses registres sauves et son cadre de pile.
#[inline(never)]
fn classify_payload(
    transport: &Transport<'_>,
    payload: &[u8],
    first: u8,
    decode_as: &[(u16, DecodeAsProtocol)],
) -> Option<Application> {
    debug_assert_eq!(payload.first(), Some(&first));
    // Les ports sont lus une fois : l'index donne, pour chacun, les regles
    // de ce transport qu'il ouvre et celles qu'il interdit.
    let list = index::list_for(transport.protocol);
    let source = list.port_effect(transport.source_port);
    let destination = list.port_effect(transport.destination_port);
    let opened = source.opens | destination.opens;
    let vetoed = source.vetoes | destination.vetoes;

    // Les regles a visiter : celles sans garde de port et celles qu'un des
    // deux ports ouvre, moins celles qu'un des deux ports interdit. La garde
    // de transport est deja appliquee, la liste ne porte que les regles de
    // ce transport.
    let mut pending = (list.portless | opened) & !vetoed;

    // Le premier octet ecarte les regles dont la sonde le refuse a coup sur
    // (voir `first_bytes`) : sur un payload que rien ne reconnait, il ne
    // reste que quelques sondes a tenter. Decode As, plus bas, n'est pas
    // filtre.
    if payload.len() < first_bytes::PROVEN_BELOW {
        let worth_visiting = list.worth_visiting(first);
        #[cfg(debug_assertions)]
        assert_excluded_probes_reject(list, worth_visiting, payload, first);
        pending &= worth_visiting;
    }

    // Ports declares par l'appelant (« Decode As ») : evalues avant la
    // table, port ET contenu, garde de transport conservee. Un echec est
    // memoise : la table ne rejoue pas la sonde. Les ports que la table
    // declare terminaux (mDNS 5353, LLMNR 5355 — reserves par leurs RFC) ne
    // sont jamais contournables : « etendre les gardes sans les remplacer ».
    if !decode_as.is_empty() && opened & list.terminal == 0 {
        let mut failed_probes: ProbeMask = 0;
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
        if failed_probes != 0 {
            pending &= !list.already_failed(failed_probes);
        }
    }

    // Du bit le plus faible au plus fort : l'ordre de la table.
    while let Some(set) = NonZero::new(pending) {
        let listed = list.first(set);
        let rule = listed.rule;

        if run_probe(rule.probe, payload) {
            return Some(Application {
                protocol: rule.label,
            });
        }
        if rule.terminal_on_port {
            return None;
        }
        // La sonde a echoue : la regle est visitee, et les regles suivantes
        // qui portent la meme sonde ne la rejouent pas.
        pending &= listed.left;
    }

    Some(Application {
        protocol: ApplicationProtocol::Unknown,
    })
}
