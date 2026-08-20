// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use super::{DecodedLink, LinkDecoder};
use crate::{LinkLayer, LinkLayerError, LinkType, ParseError};

/// Decoder for the link types whose packet bytes start directly with IPv4/IPv6:
/// LINKTYPE_RAW, LINKTYPE_IPV4 and LINKTYPE_IPV6.
pub(crate) struct RawIpDecoder;

impl RawIpDecoder {
    /// Decodes header-less IP bytes, reporting `link_type` as the capture
    /// declared it rather than normalizing every variant to LINKTYPE_RAW.
    ///
    /// Pour LINKTYPE_IPV4 et LINKTYPE_IPV6, le quartet de version doit
    /// confirmer ce que le conteneur annonce : un paquet v6 sous un lien
    /// declare v4 est une erreur nommee, pas une devinette. Egalement
    /// utilise par le peeling des tunnels IP (GRE, IP-in-IP), qui annonce
    /// la version via le protocole externe.
    #[inline(always)]
    pub(crate) fn decode_as<'a>(
        link_type: LinkType,
        bytes: &'a [u8],
    ) -> Result<DecodedLink<'a>, ParseError> {
        let first = bytes.first().copied().ok_or(LinkLayerError::Truncated {
            link_type,
            required: 1,
            actual: 0,
        })?;

        let claimed = match link_type {
            LinkType::IPV4 => Some(4),
            LinkType::IPV6 => Some(6),
            _ => None,
        };
        let layer = match first >> 4 {
            4 if claimed != Some(6) => LinkLayer::raw_ipv4(link_type, bytes),
            6 if claimed != Some(4) => LinkLayer::raw_ipv6(link_type, bytes),
            version => {
                return Err(LinkLayerError::InvalidIpVersion { link_type, version }.into());
            }
        };

        Ok(DecodedLink::new(layer))
    }
}

impl LinkDecoder for RawIpDecoder {
    #[inline(always)]
    fn decode<'a>(bytes: &'a [u8]) -> Result<DecodedLink<'a>, ParseError> {
        Self::decode_as(LinkType::RAW, bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NetworkProtocol;

    #[test]
    fn version_nibble_selects_ipv4_or_ipv6_without_copying() {
        for (bytes, expected_protocol, expected_version) in [
            ([0x4f, 1], NetworkProtocol::Ipv4, 4),
            ([0x6f, 2], NetworkProtocol::Ipv6, 6),
        ] {
            let decoded = RawIpDecoder::decode(&bytes).expect("recognized RAW IP version");
            let (layer, protocol, payload) = decoded.into_parts();
            let raw = layer.as_raw_ip().expect("RAW view");

            assert_eq!(layer.link_type(), LinkType::RAW);
            assert_eq!(protocol, expected_protocol);
            assert_eq!(payload, bytes.as_slice());
            assert_eq!(payload.as_ptr(), bytes.as_ptr());
            assert_eq!(raw.ip_version, expected_version);
            assert_eq!(raw.payload.as_ptr(), bytes.as_ptr());
            assert!(layer.as_ethernet().is_none());
            assert!(layer.as_ieee80211().is_none());
        }
    }

    #[test]
    fn empty_raw_packet_is_a_link_layer_truncation() {
        assert!(matches!(
            RawIpDecoder::decode(&[]),
            Err(ParseError::InvalidLinkLayer(LinkLayerError::Truncated {
                link_type: LinkType::RAW,
                required: 1,
                actual: 0,
            }))
        ));
    }

    #[test]
    fn every_other_version_nibble_is_malformed() {
        for version in 0..=15 {
            if matches!(version, 4 | 6) {
                continue;
            }

            assert!(matches!(
                RawIpDecoder::decode(&[version << 4]),
                Err(ParseError::InvalidLinkLayer(
                    LinkLayerError::InvalidIpVersion {
                        link_type: LinkType::RAW,
                        version: actual,
                    }
                )) if actual == version
            ));
        }
    }
}
