// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use super::{DecodedLink, LinkDecoder, RawIpDecoder};
use crate::{LinkLayerError, LinkType, ParseError};

/// Longueur de l'en-tete : la famille d'adresses, sur quatre octets.
const HEADER_LEN: usize = 4;

/// `AF_INET`, identique sur toutes les plateformes.
const AF_INET: u32 = 2;

/// Valeurs d'`AF_INET6` rencontrees : 10 sur Linux, 24 sur NetBSD et
/// OpenBSD, 28 sur FreeBSD, 30 sur macOS. La constante depend du systeme qui
/// a capture, et le format n'en garde aucune trace.
const AF_INET6: [u32; 4] = [10, 24, 28, 30];

/// Decodeur LINKTYPE_NULL : encapsulation loopback BSD.
///
/// L'en-tete est un champ de quatre octets portant la famille d'adresses du
/// paquet qui suit, **dans l'ordre d'octets de la machine qui a capture**.
/// Le format ne dit pas lequel : `02 00 00 00` et `00 00 00 02` designent
/// tous deux `AF_INET`. Le champ est donc lu dans les deux ordres, et seule
/// une interpretation coherente est retenue.
///
/// Cette ambiguite n'a pas de consequence pratique : la famille est
/// redondante avec le quartet de version du paquet IP qui suit. Elle sert
/// ici de controle de coherence, pas de source de verite — un paquet IPv6
/// annonce `AF_INET` est une erreur nommee, pas une devinette, comme pour
/// LINKTYPE_IPV4 et LINKTYPE_IPV6.
///
/// Le jumeau LINKTYPE_LOOP (108, OpenBSD), identique mais en ordre reseau,
/// n'est pas traite : aucune capture du depot ne l'atteste.
pub(super) struct NullLoopbackDecoder;

/// Version IP designee par une famille d'adresses, dans l'un ou l'autre
/// ordre d'octets. `None` si aucune lecture ne donne une famille connue.
fn ip_version_of(family: [u8; HEADER_LEN]) -> Option<u8> {
    let candidates = [u32::from_le_bytes(family), u32::from_be_bytes(family)];
    candidates.into_iter().find_map(|family| match family {
        AF_INET => Some(4),
        family if AF_INET6.contains(&family) => Some(6),
        _ => None,
    })
}

impl LinkDecoder for NullLoopbackDecoder {
    #[inline(always)]
    fn decode<'a>(bytes: &'a [u8]) -> Result<DecodedLink<'a>, ParseError> {
        let family: [u8; HEADER_LEN] = bytes
            .get(..HEADER_LEN)
            .and_then(|header| header.try_into().ok())
            .ok_or(LinkLayerError::Truncated {
                link_type: LinkType::NULL,
                required: HEADER_LEN,
                actual: bytes.len(),
            })?;

        let announced = ip_version_of(family).ok_or(LinkLayerError::InvalidAddressFamily {
            link_type: LinkType::NULL,
            family: u32::from_le_bytes(family),
        })?;

        // Le paquet IP porte lui-meme sa version : RawIpDecoder la lit et
        // rejette ce qui n'est ni v4 ni v6.
        let decoded = RawIpDecoder::decode_as(LinkType::NULL, &bytes[HEADER_LEN..])?;

        // La famille annoncee doit confirmer la version lue, sans quoi le
        // conteneur et son contenu se contredisent.
        let actual = match decoded.layer.network_protocol() {
            crate::NetworkProtocol::Ipv6 => 6,
            _ => 4,
        };
        if announced != actual {
            return Err(LinkLayerError::InvalidAddressFamily {
                link_type: LinkType::NULL,
                family: u32::from_le_bytes(family),
            }
            .into());
        }

        Ok(decoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// En-tete LINKTYPE_NULL suivi d'un debut de paquet IP : octets
    /// construits pour les cas d'erreur et de limite, les trames reelles
    /// vivant dans `tests/opcua_golden.rs`.
    fn frame(family: u32, little_endian: bool, ip: &[u8]) -> Vec<u8> {
        let mut bytes = if little_endian {
            family.to_le_bytes().to_vec()
        } else {
            family.to_be_bytes().to_vec()
        };
        bytes.extend_from_slice(ip);
        bytes
    }

    /// En-tete IPv4 minimal : version 4, IHL 5, longueur totale 20.
    const IPV4_HEADER: [u8; 20] = [
        0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 253, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1,
    ];

    #[test]
    fn af_inet_is_read_in_either_byte_order() {
        // L'ordre d'octets depend de la machine de capture : les deux
        // lectures doivent donner le meme resultat.
        for little_endian in [true, false] {
            let bytes = frame(AF_INET, little_endian, &IPV4_HEADER);
            let decoded = NullLoopbackDecoder::decode(&bytes).expect("AF_INET + IPv4");
            assert_eq!(decoded.layer.link_type(), LinkType::NULL);
        }
    }

    #[test]
    fn every_known_af_inet6_constant_is_accepted() {
        // Un en-tete IPv6 minimal : version 6, puis 39 octets.
        let mut ipv6 = vec![0x60, 0, 0, 0, 0, 0, 59, 64];
        ipv6.extend_from_slice(&[0u8; 32]);
        for family in AF_INET6 {
            let bytes = frame(family, true, &ipv6);
            assert!(
                NullLoopbackDecoder::decode(&bytes).is_ok(),
                "AF_INET6 = {family} refuse"
            );
        }
    }

    #[test]
    fn an_unknown_address_family_is_named_not_guessed() {
        let bytes = frame(0x1234, true, &IPV4_HEADER);
        assert!(matches!(
            NullLoopbackDecoder::decode(&bytes),
            Err(ParseError::InvalidLinkLayer(
                LinkLayerError::InvalidAddressFamily {
                    link_type: LinkType::NULL,
                    family: 0x1234
                }
            ))
        ));
    }

    #[test]
    fn a_family_that_contradicts_the_ip_version_is_rejected() {
        // AF_INET annonce, paquet IPv6 : le conteneur et son contenu se
        // contredisent.
        let mut ipv6 = vec![0x60, 0, 0, 0, 0, 0, 59, 64];
        ipv6.extend_from_slice(&[0u8; 32]);
        assert!(matches!(
            NullLoopbackDecoder::decode(&frame(AF_INET, true, &ipv6)),
            Err(ParseError::InvalidLinkLayer(
                LinkLayerError::InvalidAddressFamily { .. }
            ))
        ));
        // Et l'inverse : AF_INET6 annonce, paquet IPv4.
        assert!(matches!(
            NullLoopbackDecoder::decode(&frame(AF_INET6[0], true, &IPV4_HEADER)),
            Err(ParseError::InvalidLinkLayer(
                LinkLayerError::InvalidAddressFamily { .. }
            ))
        ));
    }

    #[test]
    fn a_header_shorter_than_four_bytes_is_truncated() {
        for len in 0..HEADER_LEN {
            let bytes = vec![0x02; len];
            assert!(matches!(
                NullLoopbackDecoder::decode(&bytes),
                Err(ParseError::InvalidLinkLayer(LinkLayerError::Truncated {
                    link_type: LinkType::NULL,
                    required: HEADER_LEN,
                    actual,
                })) if actual == len
            ));
        }
    }
}
