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
    /// IPv4 limited broadcast, `255.255.255.255` (RFC 919). A directed
    /// broadcast (`192.168.1.255` on a /24) cannot be recognised without the
    /// subnet mask, which a packet parser does not have: it stays classified
    /// by its range.
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
            IpAddr::V6(ipv6_addr) => Self::from_ipv6(ipv6_addr),
        }
    }

    /// Classe d'une adresse IPv4, en un seul aiguillage sur ses octets. Les
    /// plages sont celles des predicats de `Ipv4Addr` (`is_private`,
    /// `is_loopback`, `is_multicast`, `is_documentation`...), toutes
    /// disjointes : les essayer un par un coutait jusqu'a huit tests a
    /// chaque adresse publique, deux fois par paquet. 169.254.0.0/16 se
    /// classe `Apipa` : aucune adresse IPv4 n'est `LinkLocal`.
    #[inline]
    pub(crate) fn from_ipv4(ipv4_addr: &Ipv4Addr) -> Self {
        match ipv4_addr.octets() {
            [10, ..] | [172, 16..=31, ..] | [192, 168, ..] => Self::Private,
            [127, ..] => Self::Loopback,
            [169, 254, ..] => Self::Apipa,
            [224..=239, ..] => Self::Multicast,
            [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _] => Self::Documentation,
            [255, 255, 255, 255] => Self::Broadcast,
            [0, 0, 0, 0] => Self::Unknown,
            _ => Self::Public,
        }
    }

    /// Classe d'une adresse IPv6, en un seul aiguillage sur ses premiers
    /// octets : memes plages que les predicats de `Ipv6Addr`, essayes un par
    /// un jusque-la (une cinquantaine d'instructions par adresse publique).
    /// Les cas rares vivent tous dans ::/8, traite a part.
    #[inline]
    pub(crate) fn from_ipv6(ipv6_addr: &Ipv6Addr) -> Self {
        match ipv6_addr.octets() {
            [0xff, ..] => Self::Multicast,
            // fe80::/10 (RFC 4291 §2.5.6), pas seulement fe80::/16 (#136).
            [0xfe, 0x80..=0xbf, ..] => Self::LinkLocal,
            [0xfc | 0xfd, ..] => Self::Ula,
            // 2001:db8::/32 (RFC 3849) et 3fff::/20 (RFC 9637), pendants de
            // 192.0.2.0/24 et consorts cote IPv4. `Ipv6Addr::is_documentation`
            // n'est pas stable.
            [0x20, 0x01, 0x0d, 0xb8, ..] | [0x3f, 0xff, 0x00..=0x0f, ..] => Self::Documentation,
            [0x00, ..] => Self::from_ipv6_zero_prefix(ipv6_addr),
            _ => Self::Public,
        }
    }

    /// ::/8 : l'adresse non specifiee, le loopback et les IPv4 mappees.
    #[inline(never)]
    fn from_ipv6_zero_prefix(ipv6_addr: &Ipv6Addr) -> Self {
        // ::ffff:a.b.c.d (RFC 4291 §2.5.5.2) porte une IPv4 entiere : un
        // socket dual-stack logue ses clients IPv4 sous cette forme, et
        // l'adresse se classe comme l'IPv4 qu'elle porte (#136).
        if let Some(ipv4_addr) = ipv6_addr.to_ipv4_mapped() {
            Self::from_ipv4(&ipv4_addr)
        } else if ipv6_addr.is_loopback() {
            Self::Loopback
        } else if ipv6_addr.is_unspecified() {
            Self::Unknown
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

#[cfg(test)]
mod tests {
    use super::*;

    /// La chaine de predicats de `Ipv4Addr` que `from_ipv4` remplace, dans
    /// son ordre d'origine : la reference du test differentiel.
    fn from_ipv4_by_predicates(ipv4_addr: &Ipv4Addr) -> IpType {
        let octets = ipv4_addr.octets();
        if ipv4_addr.is_broadcast() {
            IpType::Broadcast
        } else if ipv4_addr.is_private() {
            IpType::Private
        } else if ipv4_addr.is_loopback() {
            IpType::Loopback
        } else if octets[0] == 169 && octets[1] == 254 {
            IpType::Apipa
        } else if ipv4_addr.is_multicast() {
            IpType::Multicast
        } else if ipv4_addr.is_documentation() {
            IpType::Documentation
        } else if ipv4_addr.is_link_local() {
            IpType::LinkLocal
        } else if ipv4_addr.is_unspecified() {
            IpType::Unknown
        } else {
            IpType::Public
        }
    }

    /// La chaine de predicats de `Ipv6Addr` que `from_ipv6` remplace, IPv4
    /// mappee comprise, dans son ordre d'origine.
    fn from_ipv6_by_predicates(ipv6_addr: &Ipv6Addr) -> IpType {
        let segments = ipv6_addr.segments();
        if let Some(ipv4_addr) = ipv6_addr.to_ipv4_mapped() {
            from_ipv4_by_predicates(&ipv4_addr)
        } else if ipv6_addr.is_multicast() {
            IpType::Multicast
        } else if ipv6_addr.is_loopback() {
            IpType::Loopback
        } else if ipv6_addr.is_unicast_link_local() {
            IpType::LinkLocal
        } else if ipv6_addr.is_unique_local() {
            IpType::Ula
        } else if ipv6_addr.is_unspecified() {
            IpType::Unknown
        } else if (segments[0] == 0x2001 && segments[1] == 0x0db8)
            || (segments[0] == 0x3fff && (segments[1] & 0xf000) == 0)
        {
            IpType::Documentation
        } else {
            IpType::Public
        }
    }

    /// `from_ipv6` rend la classe de la chaine de predicats : les deux
    /// premiers octets sont parcourus en entier, le reste sur les motifs
    /// que les plages distinguent (zero, loopback, IPv4 mappee de chaque
    /// classe, prefixes de documentation et leurs voisins).
    #[test]
    fn test_from_ipv6_agrees_with_the_std_predicates() {
        const TAILS: [[u8; 14]; 16] = [
            [0; 14],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            [0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1],
            [0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1],
            [0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 224, 0, 0, 251],
            [0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 255, 255, 255, 255],
            [0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 8, 8, 8, 8],
            [0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0xff, 192, 168, 1, 1],
            [0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xfe, 192, 168, 1, 1],
            [0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0x0d, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0x0f, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0x10, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0xff; 14],
        ];
        for a in 0..=u8::MAX {
            for b in 0..=u8::MAX {
                for tail in TAILS {
                    let mut octets = [0u8; 16];
                    octets[0] = a;
                    octets[1] = b;
                    octets[2..].copy_from_slice(&tail);
                    let addr = Ipv6Addr::from(octets);
                    let expected = from_ipv6_by_predicates(&addr);
                    assert_eq!(IpType::from_ipv6(&addr), expected, "{addr}");
                    assert_eq!(IpType::from_addr(&IpAddr::V6(addr)), expected, "{addr}");
                }
            }
        }
    }

    /// `from_ipv4` rend la classe de la chaine de predicats pour toute
    /// adresse : les deux premiers octets sont parcourus en entier, les
    /// deux derniers sur toutes les valeurs que les plages distinguent et
    /// sur leurs voisines.
    #[test]
    fn test_from_ipv4_agrees_with_the_std_predicates() {
        const THIRD: [u8; 15] = [
            0, 1, 2, 3, 50, 51, 99, 100, 101, 112, 113, 114, 168, 254, 255,
        ];
        const FOURTH: [u8; 8] = [0, 1, 2, 100, 113, 127, 254, 255];
        for a in 0..=u8::MAX {
            for b in 0..=u8::MAX {
                for c in THIRD {
                    for d in FOURTH {
                        let addr = Ipv4Addr::new(a, b, c, d);
                        assert_eq!(
                            IpType::from_ipv4(&addr),
                            from_ipv4_by_predicates(&addr),
                            "{addr}"
                        );
                    }
                }
            }
        }
    }

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
