// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! The application protocol of a flow, as an enum (issue #217).

use std::fmt;
use std::str::FromStr;

use serde::{Serialize, Serializer};

/// Declare l'enum, `ALL` et `label` depuis une seule liste : une variante
/// ne peut pas exister sans etiquette, ni manquer a `ALL`.
macro_rules! application_protocols {
    ($(($variant:ident, $label:literal)),+ $(,)?) => {
        /// The application protocol [`fn@crate::parse`] and
        /// [`crate::classify_payload`] name for a flow.
        ///
        /// Each variant has a text label, [`ApplicationProtocol::label`]: the
        /// string the crate has always written in its JSON output, kept byte
        /// for byte. [`fmt::Display`] and [`serde::Serialize`] write that
        /// label, and [`FromStr`] reads it back.
        ///
        /// The enum is `#[non_exhaustive]`: a new protocol is a new variant,
        /// in a minor release. `Unknown` is a payload that was probed and
        /// matched no rule. [`Custom`](Self::Custom) is a protocol that a
        /// parser added by the caller recognized (issue #319).
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum ApplicationProtocol {
            $(
                #[doc = concat!("Label `", $label, "`.")]
                $variant,
            )+
            /// A protocol this crate does not decode, recognized by a parser
            /// registered with [`ParseConfig::with_parser`](crate::ParseConfig::with_parser).
            /// Its label is the one of that parser,
            /// [`ApplicationParser::label`](crate::ApplicationParser::label),
            /// and no built-in protocol has it.
            ///
            /// It is not in [`ALL`](Self::ALL), and [`FromStr`] does not
            /// read it back: only the configuration that registered the
            /// parser knows the label.
            Custom(&'static str),
        }

        impl ApplicationProtocol {
            /// Every built-in variant, in declaration order.
            /// [`Custom`](Self::Custom) is not one of them.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            /// The text label of the protocol, as written in the JSON output.
            pub const fn label(self) -> &'static str {
                match self {
                    $(Self::$variant => $label,)+
                    Self::Custom(label) => label,
                }
            }
        }
    };
}

// Une nouvelle variante s'ajoute en fin de liste : les discriminants ne
// bougent pas.
application_protocols![
    (Ams, "AMS"),
    (Asterix, "ASTERIX"),
    (BacnetIp, "BACnet/IP"),
    (Bitcoin, "Bitcoin"),
    (Capwap, "CAPWAP"),
    (Cotp, "COTP"),
    (Dhcp, "DHCP"),
    (Dhcpv6, "DHCPv6"),
    (Dis, "DIS"),
    (Dnp3, "DNP3"),
    (Dns, "DNS"),
    (Esp, "ESP"),
    (EthernetIp, "EtherNet/IP"),
    (Ftp, "FTP"),
    (Geneve, "Geneve"),
    (Giop, "GIOP"),
    (Gre, "GRE"),
    (GtpU, "GTP-U"),
    (Http, "HTTP"),
    (Iec104, "IEC 104"),
    (Ike, "IKE"),
    (IpInIp, "IP-in-IP"),
    (Llmnr, "LLMNR"),
    (Mdns, "mDNS"),
    (ModbusTcp, "ModbusTCP"),
    (Mqtt, "MQTT"),
    (NatKeepalive, "NAT-keepalive"),
    (Nbns, "NBNS"),
    (Nbss, "NBSS"),
    (Nntp, "NNTP"),
    (Ntp, "NTP"),
    (OpcUa, "OPC UA"),
    (OpenVpn, "OpenVPN"),
    (PostgreSql, "PostgreSQL"),
    (Ptp, "PTP"),
    (Quic, "QUIC"),
    (Radius, "RADIUS"),
    (Rdp, "RDP"),
    (Rtps, "RTPS"),
    (S7Comm, "S7Comm"),
    (Smtp, "SMTP"),
    (Snmp, "SNMP"),
    (Srvloc, "SRVLOC"),
    (Ssdp, "SSDP"),
    (Ssh, "SSH"),
    (Stanag5066, "STANAG 5066"),
    (Stp, "STP"),
    (Tls, "TLS"),
    (Umas, "UMAS"),
    (Unknown, "Unknown"),
    (ValmetDna, "Valmet DNA"),
    (Vxlan, "VXLAN"),
    (WireGuard, "WireGuard"),
    (ModbusUdp, "ModbusUDP"),
    (JavaRmi, "Java RMI"),
];

impl fmt::Display for ApplicationProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

impl Serialize for ApplicationProtocol {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.label())
    }
}

/// A text that is the label of no [`ApplicationProtocol`]. Labels are case
/// sensitive: `"mdns"` is not `"mDNS"`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("etiquette de protocole applicatif inconnue : {0:?}")]
pub struct UnknownApplicationLabel(pub String);

impl FromStr for ApplicationProtocol {
    type Err = UnknownApplicationLabel;

    /// Reads a label back, exactly as [`ApplicationProtocol::label`] writes
    /// it. An unknown text is an error, not [`ApplicationProtocol::Unknown`].
    ///
    /// Only the built-in protocols are read: the label of a parser added by
    /// the caller is an error. [`ParseConfig::application_protocol`](crate::ParseConfig::application_protocol)
    /// reads those too, with the configuration that registered them.
    fn from_str(label: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .iter()
            .copied()
            .find(|protocol| protocol.label() == label)
            .ok_or_else(|| UnknownApplicationLabel(label.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Les etiquettes de la crate, triees : la table de dispatch, les
    /// tunnels, STP et `Unknown`. Une etiquette publiee ne change jamais de
    /// texte ; un protocole nouveau ajoute la sienne (`ModbusUDP` en 12.0.0,
    /// `Java RMI` en 13.0.0).
    const FROZEN_LABELS: [&str; 55] = [
        "AMS",
        "ASTERIX",
        "BACnet/IP",
        "Bitcoin",
        "CAPWAP",
        "COTP",
        "DHCP",
        "DHCPv6",
        "DIS",
        "DNP3",
        "DNS",
        "ESP",
        "EtherNet/IP",
        "FTP",
        "GIOP",
        "GRE",
        "GTP-U",
        "Geneve",
        "HTTP",
        "IEC 104",
        "IKE",
        "IP-in-IP",
        "Java RMI",
        "LLMNR",
        "MQTT",
        "ModbusTCP",
        "ModbusUDP",
        "NAT-keepalive",
        "NBNS",
        "NBSS",
        "NNTP",
        "NTP",
        "OPC UA",
        "OpenVPN",
        "PTP",
        "PostgreSQL",
        "QUIC",
        "RADIUS",
        "RDP",
        "RTPS",
        "S7Comm",
        "SMTP",
        "SNMP",
        "SRVLOC",
        "SSDP",
        "SSH",
        "STANAG 5066",
        "STP",
        "TLS",
        "UMAS",
        "Unknown",
        "VXLAN",
        "Valmet DNA",
        "WireGuard",
        "mDNS",
    ];

    #[test]
    fn every_label_round_trips() {
        for protocol in ApplicationProtocol::ALL {
            assert_eq!(protocol.label().parse(), Ok(*protocol));
            assert_eq!(protocol.to_string(), protocol.label());
        }
    }

    #[test]
    fn labels_are_unique() {
        let labels: HashSet<_> = ApplicationProtocol::ALL.iter().map(|p| p.label()).collect();
        assert_eq!(labels.len(), ApplicationProtocol::ALL.len());
    }

    #[test]
    fn labels_are_frozen() {
        let mut labels: Vec<_> = ApplicationProtocol::ALL.iter().map(|p| p.label()).collect();
        labels.sort_unstable();
        assert_eq!(labels, FROZEN_LABELS);
    }

    /// `ALL` liste chaque variante integree une fois, et pas `Custom` (#319).
    /// La macro le tire de la meme liste que l'enum : l'ordre de declaration
    /// suit. `Custom` porte une donnee, ce qui interdit le cast `as usize`
    /// qui le verifiait avant.
    #[test]
    fn all_lists_every_built_in_variant_once() {
        let discriminants: HashSet<_> = ApplicationProtocol::ALL
            .iter()
            .map(std::mem::discriminant)
            .collect();
        assert_eq!(discriminants.len(), ApplicationProtocol::ALL.len());
        assert!(
            !discriminants.contains(&std::mem::discriminant(&ApplicationProtocol::Custom(
                "ACME"
            )))
        );
        assert_eq!(ApplicationProtocol::ALL.len(), FROZEN_LABELS.len());
    }

    /// Une etiquette ajoutee s'ecrit comme les autres, mais ne se relit pas :
    /// seule la configuration qui a enregistre le parseur la connait.
    #[test]
    fn custom_label_is_written_but_not_read_back() {
        let custom = ApplicationProtocol::Custom("ACME");
        assert_eq!(custom.label(), "ACME");
        assert_eq!(custom.to_string(), "ACME");
        assert_eq!(serde_json::to_string(&custom).unwrap(), r#""ACME""#);
        assert_eq!(
            "ACME".parse::<ApplicationProtocol>(),
            Err(UnknownApplicationLabel("ACME".to_string()))
        );
    }

    #[test]
    fn unknown_label_is_an_error() {
        for text in ["mdns", "Modbus", "", "unknown", " DNS"] {
            assert_eq!(
                text.parse::<ApplicationProtocol>(),
                Err(UnknownApplicationLabel(text.to_string()))
            );
        }
        assert_eq!("Unknown".parse(), Ok(ApplicationProtocol::Unknown));
    }

    #[test]
    fn serializes_as_its_label() {
        assert_eq!(
            serde_json::to_string(&ApplicationProtocol::Iec104).unwrap(),
            r#""IEC 104""#
        );
    }
}
