// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! RTP, Real-time Transport Protocol (RFC 3550 §5.1, #353) : l'en-tete fixe
//! de douze octets, la liste CSRC, l'extension d'en-tete et le bourrage. La
//! charge est empruntee au datagramme, sans etre decodee : son format
//! depend du type de charge, que seule la signalisation (SDP) attribue aux
//! types dynamiques.
//!
//! RTP n'a ni port ni marqueur : deux bits de version, et rien d'autre de
//! fixe. Aucune sonde sans etat ne peut donc affirmer qu'un datagramme qui
//! commence par `0x80` est du RTP, et la crate ne nomme rien qu'elle ne
//! peut affirmer : il n'y a pas de regle aveugle. RTP se nomme sur un port
//! declare par Decode As (`DecodeAsProtocol::Rtp`), ou tout paquet bien
//! forme est accepte.
//!
//! Une regle aveugle a existe le temps d'une mesure (#353, retiree par
//! #364) : sans CSRC, type de charge hors de 64 a 95, charge non vide, en
//! fin de cascade UDP. Elle nommait a tort trois datagrammes RDP-UDP, trois
//! lignes de texte et deux Version Negotiation QUIC du corpus du depot.
//! Nommer un flux RTP sans declaration demande de l'etat : des numeros de
//! sequence qui se suivent sous un meme SSRC (#364).
//!
//! Limites, sans etat : rien ne relie un paquet a sa session. SRTP garde
//! l'en-tete en clair et se decode donc comme du RTP.

use std::convert::TryFrom;

use crate::errors::application::rtp::RtpError;

/// The RTP version this decoder reads (RFC 3550).
pub const RTP_VERSION: u8 = 2;

/// Length of the fixed RTP header, before the CSRC list.
pub const RTP_FIXED_HEADER_LENGTH: usize = 12;

/// The CSRC list of an [`RtpPacket`]: zero to fifteen contributing source
/// identifiers, borrowed from the packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CsrcList<'a>(&'a [u8]);

impl<'a> CsrcList<'a> {
    /// Number of identifiers, the CC field of the header.
    pub fn len(&self) -> usize {
        self.0.len() / 4
    }

    /// `true` when no mixer contributed: the usual case.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The identifiers, in wire order.
    pub fn iter(&self) -> impl Iterator<Item = u32> + 'a {
        self.0
            .as_chunks::<4>()
            .0
            .iter()
            .map(|csrc| u32::from_be_bytes(*csrc))
    }

    /// The raw bytes of the list.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }
}

/// The header extension of an [`RtpPacket`] (RFC 3550 §5.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RtpHeaderExtension<'a> {
    /// Defined by the profile: `0xBEDE` announces the one-byte elements of
    /// RFC 8285.
    pub profile: u16,
    /// The extension, without its four-byte header: a multiple of four
    /// bytes.
    pub data: &'a [u8],
}

/// An RTP packet: a whole UDP datagram.
///
/// ```mermaid
/// ---
/// title: RtpPacket
/// ---
/// packet-beta
/// 0-1: "V = 2"
/// 2: "P"
/// 3: "X"
/// 4-7: "CC u4"
/// 8: "M"
/// 9-15: "Payload type u7"
/// 16-31: "Sequence number u16"
/// 32-63: "Timestamp u32"
/// 64-95: "SSRC u32"
/// 96-127: "CSRC list (CC x 4 bytes), extension if X, payload, padding if P"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RtpPacket<'a> {
    /// Always [`RTP_VERSION`].
    pub version: u8,
    /// The marker bit: the end of a video frame, the start of a talkspurt,
    /// as the profile defines it.
    pub marker: bool,
    /// Seven bits. 0 to 34 are the static types of RFC 3551, 96 to 127 the
    /// dynamic ones; see [`RtpPacket::static_payload_name`].
    pub payload_type: u8,
    pub sequence_number: u16,
    /// In units of the payload clock: 8000 Hz for G.711, 90 kHz for video.
    pub timestamp: u32,
    /// The synchronization source.
    pub ssrc: u32,
    pub csrc: CsrcList<'a>,
    pub extension: Option<RtpHeaderExtension<'a>>,
    /// The payload, without the padding.
    pub payload: &'a [u8],
    /// Number of padding bytes after the payload, count byte included; 0
    /// without the P bit.
    pub padding_length: u8,
}

impl<'a> RtpPacket<'a> {
    /// The encoding name of a static payload type (RFC 3551 §6, tables 4 and
    /// 5): `PCMU` for 0, `PCMA` for 8, `MP2T` for 33. `None` for a dynamic,
    /// reserved or unassigned type, whose meaning comes from the signalling.
    pub fn static_payload_name(&self) -> Option<&'static str> {
        checks::static_payload_name(self.payload_type)
    }
}

impl<'a> TryFrom<&'a [u8]> for RtpPacket<'a> {
    type Error = RtpError;

    fn try_from(packet: &'a [u8]) -> Result<Self, Self::Error> {
        checks::validate_fixed_header_length(packet)?;
        let version = checks::extract_version(packet[0])?;
        let has_padding = packet[0] & 0x20 != 0;
        let has_extension = packet[0] & 0x10 != 0;
        let csrc_count = packet[0] & 0x0F;
        let marker = packet[1] & 0x80 != 0;
        let payload_type = checks::extract_payload_type(packet[1])?;
        let sequence_number = u16::from_be_bytes([packet[2], packet[3]]);
        let timestamp = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
        let ssrc = u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]);

        let (csrc, rest) =
            checks::extract_csrc_list(&packet[RTP_FIXED_HEADER_LENGTH..], csrc_count)?;
        let (extension, rest) = checks::extract_extension(rest, has_extension)?;
        let (payload, padding_length) = checks::extract_payload(rest, has_padding)?;

        Ok(RtpPacket {
            version,
            marker,
            payload_type,
            sequence_number,
            timestamp,
            ssrc,
            csrc: CsrcList(csrc),
            extension,
            payload,
            padding_length,
        })
    }
}

mod checks {
    use super::{RTP_FIXED_HEADER_LENGTH, RTP_VERSION, RtpHeaderExtension};
    use crate::errors::application::rtp::RtpError;

    /// Longueur de l'en-tete d'une extension : profil et longueur en mots.
    const EXTENSION_HEADER_LENGTH: usize = 4;

    pub(super) fn validate_fixed_header_length(packet: &[u8]) -> Result<(), RtpError> {
        if packet.len() < RTP_FIXED_HEADER_LENGTH {
            return Err(RtpError::TooShort {
                expected: RTP_FIXED_HEADER_LENGTH,
                actual: packet.len(),
            });
        }
        Ok(())
    }

    pub(super) fn extract_version(byte: u8) -> Result<u8, RtpError> {
        let version = byte >> 6;
        if version != RTP_VERSION {
            return Err(RtpError::InvalidVersion(version));
        }
        Ok(version)
    }

    /// Les types 72 a 76 sont reserves : un SR, un RR, un SDES, un BYE ou un
    /// APP de RTCP (200 a 204) aurait ce deuxieme octet (RFC 3551 §6).
    pub(super) fn extract_payload_type(byte: u8) -> Result<u8, RtpError> {
        let payload_type = byte & 0x7F;
        if matches!(payload_type, 72..=76) {
            return Err(RtpError::RtcpPayloadType(payload_type));
        }
        Ok(payload_type)
    }

    pub(super) fn extract_csrc_list(rest: &[u8], count: u8) -> Result<(&[u8], &[u8]), RtpError> {
        let expected = usize::from(count) * 4;
        rest.split_at_checked(expected)
            .ok_or(RtpError::TruncatedCsrcList {
                count,
                expected,
                actual: rest.len(),
            })
    }

    pub(super) fn extract_extension(
        rest: &[u8],
        present: bool,
    ) -> Result<(Option<RtpHeaderExtension<'_>>, &[u8]), RtpError> {
        if !present {
            return Ok((None, rest));
        }
        let Some((header, after)) = rest.split_at_checked(EXTENSION_HEADER_LENGTH) else {
            return Err(RtpError::TruncatedExtension {
                expected: EXTENSION_HEADER_LENGTH,
                actual: rest.len(),
            });
        };
        let profile = u16::from_be_bytes([header[0], header[1]]);
        let length = usize::from(u16::from_be_bytes([header[2], header[3]])) * 4;
        let Some((data, after)) = after.split_at_checked(length) else {
            return Err(RtpError::TruncatedExtension {
                expected: EXTENSION_HEADER_LENGTH + length,
                actual: rest.len(),
            });
        };
        Ok((Some(RtpHeaderExtension { profile, data }), after))
    }

    /// Le dernier octet d'un paquet a bourrage compte les octets a ignorer,
    /// lui compris (RFC 3550 §5.1) : au moins un, au plus ce qui suit
    /// l'en-tete.
    pub(super) fn extract_payload(rest: &[u8], padded: bool) -> Result<(&[u8], u8), RtpError> {
        if !padded {
            return Ok((rest, 0));
        }
        let padding = rest.last().copied().unwrap_or(0);
        if padding == 0 || usize::from(padding) > rest.len() {
            return Err(RtpError::InvalidPadding {
                padding,
                available: rest.len(),
            });
        }
        Ok((&rest[..rest.len() - usize::from(padding)], padding))
    }

    /// RFC 3551 §6, tables 4 et 5.
    pub(super) const fn static_payload_name(payload_type: u8) -> Option<&'static str> {
        Some(match payload_type {
            0 => "PCMU",
            3 => "GSM",
            4 => "G723",
            5 | 6 | 16 | 17 => "DVI4",
            7 => "LPC",
            8 => "PCMA",
            9 => "G722",
            10 | 11 => "L16",
            12 => "QCELP",
            13 => "CN",
            14 => "MPA",
            15 => "G728",
            18 => "G729",
            25 => "CelB",
            26 => "JPEG",
            28 => "nv",
            31 => "H261",
            32 => "MPV",
            33 => "MP2T",
            34 => "H263",
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trame 624 de `pcaps_exemple/protocols/sip/wireshark_aaa.pcap` : G.711
    /// PCMA, 160 octets de son.
    const PCMA_HEX: &str = concat!(
        "80086fae000004d83796cb71",
        "d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5",
        "d5d5d5d5d5d5d5d511041c181812121e1014176a131c18040405060101000705",
        "051913051b1910131905040407030203030000020d0d0d0001030d0c0d000001",
        "0203010606010f0e0e0c030007060003030607010406061b1f1c116960621511",
        "10146a13156069617d74525b59d7475c565255444b42755973785a7c6e68146a",
    );

    /// Trame 47167 de `pcaps_exemple/The-Ultimate-PCAP.pcapng` : type
    /// dynamique 104, extension d'en-tete RFC 8285 de deux mots.
    const EXTENSION_HEX: &str = concat!(
        "90681b67eeda89f312d4a922bede0002225e165f31003500",
        "e72ef39780d6e8c067f756661ab7d69e7dce950051e316bf8263c680d84e12c8",
        "548f2b5b5ed183cdd7f38bc41f70506393bbd7e282",
    );

    /// Trame 10 de `pcaps_exemple/protocols/ntp/ndpi_line.pcap` : un
    /// evenement telephonique (type 101), marqueur leve, extension vide.
    const EMPTY_EXTENSION_HEX: &str =
        "90e5000200002e0309bda67402400000085e5c186365e52a610bb427439e3164a63eff10";

    fn bytes(hex_text: &str) -> Vec<u8> {
        hex::decode(hex_text).expect("hex de test invalide")
    }

    #[test]
    fn a_real_pcma_packet_is_decoded() {
        let data = bytes(PCMA_HEX);
        let packet = RtpPacket::try_from(&data[..]).expect("paquet RTP");
        assert_eq!(packet.version, RTP_VERSION);
        assert!(!packet.marker);
        assert_eq!(packet.payload_type, 8);
        assert_eq!(packet.static_payload_name(), Some("PCMA"));
        assert_eq!(packet.sequence_number, 28590);
        assert_eq!(packet.timestamp, 1240);
        assert_eq!(packet.ssrc, 0x3796_cb71);
        assert!(packet.csrc.is_empty());
        assert_eq!(packet.extension, None);
        assert_eq!(packet.payload.len(), 160);
        assert_eq!(packet.padding_length, 0);
    }

    #[test]
    fn a_real_header_extension_is_split_from_the_payload() {
        let data = bytes(EXTENSION_HEX);
        let packet = RtpPacket::try_from(&data[..]).expect("paquet RTP");
        assert_eq!(packet.payload_type, 104);
        assert_eq!(packet.static_payload_name(), None);
        assert_eq!(packet.sequence_number, 7015);
        let extension = packet.extension.expect("extension");
        assert_eq!(extension.profile, 0xBEDE);
        assert_eq!(extension.data, &data[16..24]);
        assert_eq!(packet.payload, &data[24..]);
    }

    #[test]
    fn a_real_empty_extension_and_marker_are_decoded() {
        let data = bytes(EMPTY_EXTENSION_HEX);
        let packet = RtpPacket::try_from(&data[..]).expect("paquet RTP");
        assert!(packet.marker);
        assert_eq!(packet.payload_type, 101);
        let extension = packet.extension.expect("extension");
        assert_eq!(extension.profile, 0x0240);
        assert!(extension.data.is_empty());
        assert_eq!(packet.payload.len(), data.len() - 16);
    }

    // Les tests qui suivent partent de la trame PCMA reelle et en changent
    // un champ : ce sont des octets synthetiques.

    #[test]
    fn a_short_packet_is_refused() {
        let data = bytes(PCMA_HEX);
        assert_eq!(
            RtpPacket::try_from(&data[..11]),
            Err(RtpError::TooShort {
                expected: 12,
                actual: 11
            })
        );
    }

    #[test]
    fn another_version_is_refused() {
        for (first, version) in [(0x00, 0), (0x40, 1), (0xC0, 3)] {
            let mut data = bytes(PCMA_HEX);
            data[0] = first;
            assert_eq!(
                RtpPacket::try_from(&data[..]),
                Err(RtpError::InvalidVersion(version))
            );
        }
    }

    /// Un Sender Report de RTCP (type 200) a pour deuxieme octet `0xC8` :
    /// lu comme du RTP, marqueur leve et type de charge 72.
    #[test]
    fn rtcp_packet_types_are_refused() {
        for payload_type in 72..=76 {
            let mut data = bytes(PCMA_HEX);
            data[1] = 0x80 | payload_type;
            assert_eq!(
                RtpPacket::try_from(&data[..]),
                Err(RtpError::RtcpPayloadType(payload_type))
            );
        }
    }

    #[test]
    fn a_csrc_list_is_read_and_must_fit() {
        // Deux CSRC : les huit premiers octets de la charge en tiennent lieu.
        let mut data = bytes(PCMA_HEX);
        data[0] = 0x82;
        let packet = RtpPacket::try_from(&data[..]).expect("paquet RTP");
        assert_eq!(packet.csrc.len(), 2);
        assert_eq!(
            packet.csrc.iter().collect::<Vec<_>>(),
            [0xd5d5_d5d5, 0xd5d5_d5d5]
        );
        assert_eq!(packet.payload.len(), 152);

        data[0] = 0x8F;
        assert_eq!(
            RtpPacket::try_from(&data[..20]),
            Err(RtpError::TruncatedCsrcList {
                count: 15,
                expected: 60,
                actual: 8
            })
        );
    }

    #[test]
    fn a_truncated_extension_is_refused() {
        let data = bytes(EXTENSION_HEX);
        assert_eq!(
            RtpPacket::try_from(&data[..14]),
            Err(RtpError::TruncatedExtension {
                expected: 4,
                actual: 2
            })
        );
        assert_eq!(
            RtpPacket::try_from(&data[..20]),
            Err(RtpError::TruncatedExtension {
                expected: 12,
                actual: 8
            })
        );
    }

    #[test]
    fn padding_is_removed_and_must_fit() {
        let mut data = bytes(PCMA_HEX);
        data[0] = 0xA0;
        let last = data.len() - 1;
        data[last] = 4;
        let packet = RtpPacket::try_from(&data[..]).expect("paquet RTP");
        assert_eq!(packet.padding_length, 4);
        assert_eq!(packet.payload.len(), 156);

        data[last] = 0;
        assert_eq!(
            RtpPacket::try_from(&data[..]),
            Err(RtpError::InvalidPadding {
                padding: 0,
                available: 160
            })
        );
        data[last] = 161;
        assert_eq!(
            RtpPacket::try_from(&data[..]),
            Err(RtpError::InvalidPadding {
                padding: 161,
                available: 160
            })
        );
    }
}
