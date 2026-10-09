// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
// Définition de l'énumération `IpType`
#[derive(Debug, Serialize, Deserialize, Clone, Eq, Hash, PartialEq, Default)]
#[non_exhaustive]
pub enum IpType {
    Private,
    Multicast,
    Loopback,
    Apipa,
    LinkLocal,
    Ula,
    Public,
    Documentation,
    #[default]
    Unknown,
    // En fin d'enum : inseree plus haut, la variante decalait le discriminant
    // de toutes les suivantes (`IpType::Multicast as u8` passait de 1 a 2),
    // rupture silencieuse pour qui stocke ou transmet ces valeurs.
    /// Diffusion limitee IPv4, `255.255.255.255` (RFC 919). La diffusion
    /// dirigee (`192.168.1.255` sur un /24) n'est pas reconnaissable sans le
    /// masque du sous-reseau, hors de portee d'un parseur de paquets : elle
    /// reste classee selon sa plage.
    Broadcast,
}

// Implémentation des méthodes pour `IpType`
impl IpType {
    pub fn from_ip(ip: &str) -> Self {
        match ip.parse::<IpAddr>() {
            Ok(addr) => Self::from_addr(&addr),
            Err(_) => Self::Unknown,
        }
    }

    pub fn from_addr(ip: &IpAddr) -> Self {
        match ip {
            IpAddr::V4(ipv4_addr) => Self::from_ipv4(ipv4_addr),
            // ::ffff:a.b.c.d (RFC 4291 §2.5.5.2) porte une IPv4 entiere : un
            // socket dual-stack logue ses clients IPv4 sous cette forme, et
            // l'adresse se classe comme l'IPv4 qu'elle porte (#136).
            IpAddr::V6(ipv6_addr) => match ipv6_addr.to_ipv4_mapped() {
                Some(ipv4_addr) => Self::from_ipv4(&ipv4_addr),
                None => Self::from_ipv6(ipv6_addr),
            },
        }
    }

    fn from_ipv4(ipv4_addr: &Ipv4Addr) -> Self {
        if ipv4_addr.is_broadcast() {
            Self::Broadcast
        } else if ipv4_addr.is_private() {
            Self::Private
        } else if ipv4_addr.is_loopback() {
            Self::Loopback
        } else if is_apipa_ip(ipv4_addr) {
            Self::Apipa
        } else if ipv4_addr.is_multicast() {
            Self::Multicast
        } else if ipv4_addr.is_documentation() {
            Self::Documentation
        } else if ipv4_addr.is_link_local() {
            Self::LinkLocal
        } else if ipv4_addr.is_unspecified() {
            Self::Unknown
        } else {
            Self::Public
        }
    }

    fn from_ipv6(ipv6_addr: &Ipv6Addr) -> Self {
        if ipv6_addr.is_multicast() {
            Self::Multicast
        } else if ipv6_addr.is_loopback() {
            Self::Loopback
        } else if ipv6_addr.is_unicast_link_local() {
            // fe80::/10 (RFC 4291 §2.5.6), pas seulement fe80::/16 (#136).
            Self::LinkLocal
        } else if ipv6_addr.is_unique_local() {
            Self::Ula
        } else if ipv6_addr.is_unspecified() {
            Self::Unknown
        } else if is_ipv6_documentation(ipv6_addr) {
            Self::Documentation
        } else {
            Self::Public
        }
    }
}

impl fmt::Display for IpType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let display_string = match self {
            IpType::Private => "Privée",
            IpType::Broadcast => "Broadcast",
            IpType::Multicast => "Multicast",
            IpType::Loopback => "Loopback",
            IpType::Apipa => "APIPA",
            IpType::LinkLocal => "Link-Local",
            IpType::Ula => "ULA",
            IpType::Public => "Publique",
            IpType::Unknown => "Inconnue",
            IpType::Documentation => "Documentation",
        };

        write!(f, "{display_string}")
    }
}

// Implémenter Default pour IpType

// Fonctions auxiliaires pour les vérifications spécifiques
fn is_apipa_ip(ip: &Ipv4Addr) -> bool {
    ip.octets()[0] == 169 && ip.octets()[1] == 254
}

/// Prefixes de documentation IPv6 : 2001:db8::/32 (RFC 3849) et 3fff::/20
/// (RFC 9637), pendants de 192.0.2.0/24 et consorts cote IPv4.
/// `Ipv6Addr::is_documentation` n'est pas stable.
fn is_ipv6_documentation(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || (segments[0] == 0x3fff && (segments[1] & 0xf000) == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 255.255.255.255 sortait « Publique » faute de bras dedie (#9).
    /// Les discriminants des variantes historiques sont figes : une nouvelle
    /// variante s'ajoute en fin d'enum.
    #[test]
    fn test_historical_discriminants_are_stable() {
        assert_eq!(IpType::Private as u8, 0);
        assert_eq!(IpType::Multicast as u8, 1);
        assert_eq!(IpType::Loopback as u8, 2);
        assert_eq!(IpType::Apipa as u8, 3);
        assert_eq!(IpType::LinkLocal as u8, 4);
        assert_eq!(IpType::Ula as u8, 5);
        assert_eq!(IpType::Public as u8, 6);
        assert_eq!(IpType::Documentation as u8, 7);
        assert_eq!(IpType::Unknown as u8, 8);
        assert_eq!(IpType::Broadcast as u8, 9);
    }

    #[test]
    fn test_limited_broadcast_ipv4() {
        assert_eq!(IpType::from_ip("255.255.255.255"), IpType::Broadcast);
        assert_eq!(IpType::Broadcast.to_string(), "Broadcast");
        // Diffusion dirigee : indiscernable sans le masque, classee par plage.
        assert_eq!(IpType::from_ip("192.168.1.255"), IpType::Private);
        assert_eq!(IpType::from_ip("255.255.255.254"), IpType::Public);
    }

    #[test]
    fn test_apipa_ipv4() {
        let ip = "169.254.1.1";
        assert_eq!(IpType::from_ip(ip), IpType::Apipa);
    }

    // Reprenons les tests pour les adresses privées, publiques et spéciales,
    // tout en s'assurant qu'ils utilisent la nouvelle logique.
    #[test]
    fn test_private_ipv4() {
        assert_eq!(IpType::from_ip("192.168.1.1"), IpType::Private);
        assert_eq!(IpType::from_ip("10.0.0.1"), IpType::Private);
        assert_eq!(IpType::from_ip("172.16.0.1"), IpType::Private);
    }

    #[test]
    fn test_public_ipv4() {
        assert_eq!(IpType::from_ip("8.8.8.8"), IpType::Public); // Google DNS
        assert_eq!(IpType::from_ip("1.1.1.1"), IpType::Public); // Cloudflare DNS
    }

    #[test]
    fn test_invalid_ipv4() {
        assert_eq!(IpType::from_ip("999.999.999.999"), IpType::Unknown);
        assert_eq!(IpType::from_ip("abcd"), IpType::Unknown);
    }

    #[test]
    fn test_ipv6_multicast() {
        assert_eq!(IpType::from_ip("ff02::1"), IpType::Multicast);
    }

    #[test]
    fn test_ipv6_unicast_link_local() {
        assert_eq!(IpType::from_ip("fe80::1"), IpType::LinkLocal);
        // Tout fe80::/10, pas seulement fe80::/16 (#136).
        assert_eq!(IpType::from_ip("fe81::1"), IpType::LinkLocal);
        assert_eq!(IpType::from_ip("febf::1"), IpType::LinkLocal);
        // fec0::/10, site-local deprecie (RFC 3879), n'en fait pas partie.
        assert_eq!(IpType::from_ip("fec0::1"), IpType::Public);
    }

    /// ::ffff:a.b.c.d se classe comme l'IPv4 qu'elle porte (#136).
    #[test]
    fn test_ipv4_mapped_ipv6_takes_the_ipv4_class() {
        assert_eq!(IpType::from_ip("::ffff:192.168.1.1"), IpType::Private);
        assert_eq!(IpType::from_ip("::ffff:127.0.0.1"), IpType::Loopback);
        assert_eq!(IpType::from_ip("::ffff:224.0.0.251"), IpType::Multicast);
        assert_eq!(IpType::from_ip("::ffff:255.255.255.255"), IpType::Broadcast);
        assert_eq!(IpType::from_ip("::ffff:8.8.8.8"), IpType::Public);
    }

    #[test]
    fn test_ipv6_documentation() {
        assert_eq!(
            IpType::from_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
            IpType::Documentation
        );
        assert_eq!(IpType::from_ip("3fff:fff::1"), IpType::Documentation);
        assert_eq!(IpType::from_ip("2001:db9::1"), IpType::Public);
        assert_eq!(IpType::from_ip("3fff:1000::1"), IpType::Public);
    }

    #[test]
    fn test_ipv6_ula() {
        assert_eq!(IpType::from_ip("fd00::1"), IpType::Ula);
    }

    #[test]
    fn test_ipv6_public() {
        assert_eq!(IpType::from_ip("2606:4700:4700::1111"), IpType::Public); // Cloudflare DNS
    }

    #[test]
    fn test_ipv6_loopback() {
        assert_eq!(IpType::from_ip("::1"), IpType::Loopback);
    }

    #[test]
    fn test_ipv4_multicast() {
        assert_eq!(IpType::from_ip("224.0.0.1"), IpType::Multicast); // Adresse multicast de base
        assert_eq!(IpType::from_ip("239.255.255.255"), IpType::Multicast); // Fin de la plage multicast
    }
}
