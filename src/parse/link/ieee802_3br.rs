// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use super::{DecodedLink, LinkDecoder};
use crate::{DataLink, LinkLayer, LinkLayerError, LinkType, ParseError};

/// LINKTYPE_ETHERNET_MPACKET captures the preamble then the SMD. The preamble
/// is at most 7 octets of 0x55, but the standard lets the PHY shorten it: the
/// corpus contains both 7-octet and 6-octet preambles, so the SMD is located
/// as the first non-0x55 octet rather than at a fixed offset.
const MAX_PREAMBLE_LEN: usize = 7;
const PREAMBLE_OCTET: u8 = 0x55;
/// Canonical header length (full preamble + SMD), reported on truncation.
const HEADER_LEN: usize = MAX_PREAMBLE_LEN + 1;
const ETHERNET_HEADER_LEN: usize = 14;
const CRC_LEN: usize = 4;

/// SMD-E: complete express frame, no reassembly (IEEE 802.3br Table 99-1).
const SMD_E: u8 = 0xd5;
/// SMD-S0..S3: first mPacket of a preempted frame.
const SMD_S: [u8; 4] = [0xe6, 0x4c, 0x7f, 0xb3];
/// SMD-C0..C3: continuation mPacket of a preempted frame.
const SMD_C: [u8; 4] = [0x61, 0x52, 0x9e, 0x2a];

/// Decoder for IEEE 802.3br mPackets (Frame Preemption / IET).
///
/// Express mPackets (SMD-E) are complete Ethernet frames wrapped in a
/// preamble, an SMD and a trailing mCRC: decoding removes the wrapping and
/// delegates to the Ethernet decoder. Preemptible fragments (SMD-S/SMD-C)
/// require stateful reassembly — the same boundary as TCP reassembly and the
/// QUIC Short Header, documented in `src/parse/mod.rs` — so they are refused
/// with a named error instead of being guessed at.
pub(super) struct Ieee8023brDecoder;

impl LinkDecoder for Ieee8023brDecoder {
    #[inline(always)]
    fn decode<'a>(bytes: &'a [u8]) -> Result<DecodedLink<'a>, ParseError> {
        // If the first 7 octets are all preamble, the SMD can only sit right
        // after them; an eighth 0x55 then falls out as an unknown SMD value.
        let smd_index = bytes
            .iter()
            .take(MAX_PREAMBLE_LEN)
            .position(|&byte| byte != PREAMBLE_OCTET)
            .unwrap_or(MAX_PREAMBLE_LEN);
        if smd_index == 0 {
            return Err(LinkLayerError::InvalidPreamble {
                link_type: LinkType::IEEE802_3BR,
                value: bytes[0],
            }
            .into());
        }
        if bytes.len() <= smd_index {
            return Err(LinkLayerError::Truncated {
                link_type: LinkType::IEEE802_3BR,
                required: HEADER_LEN,
                actual: bytes.len(),
            }
            .into());
        }

        let smd = bytes[smd_index];
        if SMD_S.contains(&smd) || SMD_C.contains(&smd) {
            return Err(LinkLayerError::PreemptibleFragment {
                link_type: LinkType::IEEE802_3BR,
                smd,
            }
            .into());
        }
        if smd != SMD_E {
            return Err(LinkLayerError::InvalidSmd {
                link_type: LinkType::IEEE802_3BR,
                smd,
            }
            .into());
        }

        // An express mPacket must carry a whole Ethernet header plus its mCRC.
        let header_len = smd_index + 1;
        let min_express_len = header_len + ETHERNET_HEADER_LEN + CRC_LEN;
        if bytes.len() < min_express_len {
            return Err(LinkLayerError::Truncated {
                link_type: LinkType::IEEE802_3BR,
                required: min_express_len,
                actual: bytes.len(),
            }
            .into());
        }

        let frame = DataLink::try_from(&bytes[header_len..bytes.len() - CRC_LEN])?;
        Ok(DecodedLink::new(LinkLayer::ethernet_as(
            LinkType::IEEE802_3BR,
            frame,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NetworkProtocol;

    /// Express mPacket with `preamble_len` octets of 0x55, wrapping a minimal
    /// Ethernet frame carrying `payload`.
    fn express_with_preamble(preamble_len: usize, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![PREAMBLE_OCTET; preamble_len];
        bytes.push(SMD_E);
        bytes.extend_from_slice(&[0, 1, 2, 3, 4, 5]);
        bytes.extend_from_slice(&[6, 7, 8, 9, 10, 11]);
        bytes.extend_from_slice(&0x0800_u16.to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        bytes
    }

    fn express(payload: &[u8]) -> Vec<u8> {
        express_with_preamble(MAX_PREAMBLE_LEN, payload)
    }

    #[test]
    fn express_mpacket_delegates_to_ethernet_without_preamble_and_crc() {
        let bytes = express(&[0x45, 0, 0, 20]);
        let decoded = Ieee8023brDecoder::decode(&bytes).unwrap();
        let (layer, protocol, payload) = decoded.into_parts();
        let frame = layer.as_ethernet().unwrap();

        assert_eq!(layer.link_type(), LinkType::IEEE802_3BR);
        assert_eq!(protocol, NetworkProtocol::Ipv4);
        assert_eq!(payload, &[0x45, 0, 0, 20]);
        // Zero-copy: the payload view points into the original buffer and the
        // trailing mCRC is excluded from it.
        assert_eq!(
            payload.as_ptr(),
            bytes[HEADER_LEN + ETHERNET_HEADER_LEN..].as_ptr()
        );
        assert_eq!(frame.destination_mac.0, [0, 1, 2, 3, 4, 5]);
        assert_eq!(frame.source_mac.0, [6, 7, 8, 9, 10, 11]);
    }

    #[test]
    fn shortened_preambles_still_locate_the_smd() {
        for preamble_len in 1..=MAX_PREAMBLE_LEN {
            let bytes = express_with_preamble(preamble_len, &[0x45, 0, 0, 20]);
            let decoded = Ieee8023brDecoder::decode(&bytes).unwrap();
            let (layer, protocol, payload) = decoded.into_parts();

            assert_eq!(layer.link_type(), LinkType::IEEE802_3BR);
            assert_eq!(protocol, NetworkProtocol::Ipv4);
            assert_eq!(payload, &[0x45, 0, 0, 20]);
        }
    }

    #[test]
    fn every_short_header_is_a_structured_link_truncation() {
        let bytes = express(&[0x45, 0, 0, 20]);
        let min_express_len = HEADER_LEN + ETHERNET_HEADER_LEN + CRC_LEN;

        for len in 0..HEADER_LEN {
            assert!(matches!(
                Ieee8023brDecoder::decode(&bytes[..len]),
                Err(ParseError::InvalidLinkLayer(LinkLayerError::Truncated {
                    link_type: LinkType::IEEE802_3BR,
                    required: HEADER_LEN,
                    actual,
                })) if actual == len
            ));
        }
        for len in HEADER_LEN..min_express_len {
            assert!(matches!(
                Ieee8023brDecoder::decode(&bytes[..len]),
                Err(ParseError::InvalidLinkLayer(LinkLayerError::Truncated {
                    link_type: LinkType::IEEE802_3BR,
                    required,
                    actual,
                })) if required == min_express_len && actual == len
            ));
        }
    }

    #[test]
    fn missing_preamble_names_the_first_byte() {
        let mut bytes = express(&[0x45, 0, 0, 20]);
        bytes[0] = 0xaa;

        assert!(matches!(
            Ieee8023brDecoder::decode(&bytes),
            Err(ParseError::InvalidLinkLayer(
                LinkLayerError::InvalidPreamble {
                    link_type: LinkType::IEEE802_3BR,
                    value: 0xaa,
                }
            ))
        ));
        assert!(matches!(
            Ieee8023brDecoder::decode(&[]),
            Err(ParseError::InvalidLinkLayer(LinkLayerError::Truncated {
                link_type: LinkType::IEEE802_3BR,
                required: HEADER_LEN,
                actual: 0,
            }))
        ));
    }

    #[test]
    fn a_non_preamble_byte_inside_the_preamble_is_read_as_the_smd() {
        // With a variable-length preamble, the first non-0x55 octet is by
        // definition the SMD: a corrupted value is refused as such.
        for offset in 1..MAX_PREAMBLE_LEN {
            let mut bytes = express(&[0x45, 0, 0, 20]);
            bytes[offset] = 0xaa;

            assert!(matches!(
                Ieee8023brDecoder::decode(&bytes),
                Err(ParseError::InvalidLinkLayer(LinkLayerError::InvalidSmd {
                    link_type: LinkType::IEEE802_3BR,
                    smd: 0xaa,
                }))
            ));
        }
    }

    #[test]
    fn an_eighth_preamble_octet_is_an_unknown_smd_not_a_panic() {
        let mut bytes = express(&[0x45, 0, 0, 20]);
        bytes[MAX_PREAMBLE_LEN] = PREAMBLE_OCTET;

        assert!(matches!(
            Ieee8023brDecoder::decode(&bytes),
            Err(ParseError::InvalidLinkLayer(LinkLayerError::InvalidSmd {
                link_type: LinkType::IEEE802_3BR,
                smd: PREAMBLE_OCTET,
            }))
        ));
    }

    #[test]
    fn preemptible_fragments_are_refused_with_a_named_error() {
        for smd in SMD_S.into_iter().chain(SMD_C) {
            let mut bytes = express(&[0x45, 0, 0, 20]);
            bytes[MAX_PREAMBLE_LEN] = smd;

            assert!(matches!(
                Ieee8023brDecoder::decode(&bytes),
                Err(ParseError::InvalidLinkLayer(LinkLayerError::PreemptibleFragment {
                    link_type: LinkType::IEEE802_3BR,
                    smd: reported,
                })) if reported == smd
            ));
        }
    }

    #[test]
    fn unknown_smd_is_refused_without_guessing() {
        let mut bytes = express(&[0x45, 0, 0, 20]);
        bytes[MAX_PREAMBLE_LEN] = 0x00;

        assert!(matches!(
            Ieee8023brDecoder::decode(&bytes),
            Err(ParseError::InvalidLinkLayer(LinkLayerError::InvalidSmd {
                link_type: LinkType::IEEE802_3BR,
                smd: 0x00,
            }))
        ));
    }
}
