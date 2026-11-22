// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! RTCP, RTP Control Protocol (RFC 3550 §6, #354) : un datagramme porte un
//! ou plusieurs paquets RTCP mis bout a bout, chacun avec un en-tete de
//! quatre octets (version, bourrage, compteur, type, longueur en mots). Le
//! decodeur les enumere sans copie et lit les informations d'emetteur d'un
//! Sender Report ; les blocs de rapport, les items SDES et les messages de
//! retour (RFC 4585) sont empruntes au datagramme, sans etre decodes.
//!
//! Comme RTP, RTCP n'a ni port ni marqueur. La sonde aveugle
//! (`RtcpCompound::is_blind_match`) s'appuie sur ce que RTP n'a pas : des
//! longueurs qui pavent exactement le datagramme, un type de paquet entre
//! 200 et 207 et une taille minimale par type et par compteur. Elle exige
//! en plus que le premier paquet soit un Sender Report ou un Receiver
//! Report (RFC 3550 §6.1), ou un message de retour seul (RTCP de taille
//! reduite, RFC 5506).
//!
//! Sur un port declare par Decode As, tout datagramme bien forme est
//! accepte, quel que soit son premier paquet.
//!
//! Limites, sans etat : SRTCP chiffre le contenu et ajoute un index et une
//! etiquette d'authentification apres le dernier paquet ; les longueurs ne
//! pavent plus le datagramme, qui reste `Unknown`. RTCP multiplexe sur TCP
//! n'est pas lu.

use std::convert::TryFrom;

use crate::errors::application::rtcp::RtcpError;

/// The RTCP version this decoder reads (RFC 3550).
pub const RTCP_VERSION: u8 = 2;

/// Length of the header every RTCP packet starts with.
pub const RTCP_HEADER_LENGTH: usize = 4;

/// Type of an RTCP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RtcpPacketType {
    /// 200, SR (RFC 3550 §6.4.1)
    SenderReport,
    /// 201, RR (RFC 3550 §6.4.2)
    ReceiverReport,
    /// 202, SDES (RFC 3550 §6.5)
    SourceDescription,
    /// 203, BYE (RFC 3550 §6.6)
    Goodbye,
    /// 204, APP (RFC 3550 §6.7)
    ApplicationDefined,
    /// 205, RTPFB (RFC 4585 §6.2)
    TransportFeedback,
    /// 206, PSFB (RFC 4585 §6.3)
    PayloadFeedback,
    /// 207, XR (RFC 3611)
    ExtendedReport,
}

impl RtcpPacketType {
    /// The packet type byte.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::SenderReport => 200,
            Self::ReceiverReport => 201,
            Self::SourceDescription => 202,
            Self::Goodbye => 203,
            Self::ApplicationDefined => 204,
            Self::TransportFeedback => 205,
            Self::PayloadFeedback => 206,
            Self::ExtendedReport => 207,
        }
    }
}

/// The sender information of a Sender Report (RFC 3550 §6.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RtcpSenderInfo {
    /// Wallclock time of the report, as a 64-bit NTP timestamp.
    pub ntp_timestamp: u64,
    /// The same instant in the units of the RTP timestamps of the stream.
    pub rtp_timestamp: u32,
    /// RTP packets sent since the start of the stream.
    pub packet_count: u32,
    /// Payload bytes sent since the start of the stream.
    pub octet_count: u32,
}

/// One RTCP packet of a datagram.
///
/// ```mermaid
/// ---
/// title: RtcpPacket
/// ---
/// packet-beta
/// 0-1: "V = 2"
/// 2: "P"
/// 3-7: "Count u5"
/// 8-15: "Packet type u8"
/// 16-31: "Length u16 (32-bit words, minus one)"
/// 32-63: "Body (Length x 4 bytes)"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RtcpPacket<'a> {
    /// The padding bit: the body ends with padding, whose last byte is its
    /// length.
    pub padding: bool,
    /// The five bits after the padding bit: a report count (SR, RR), a
    /// source count (SDES, BYE), a subtype (APP) or a feedback message type
    /// (RTPFB, PSFB).
    pub count: u8,
    /// The packet type.
    pub packet_type: RtcpPacketType,
    /// What follows the four-byte header, padding included.
    pub body: &'a [u8],
}

impl RtcpPacket<'_> {
    /// The SSRC that opens the body of every packet but SDES and BYE, whose
    /// body is a list of sources.
    pub fn sender_ssrc(&self) -> Option<u32> {
        match self.packet_type {
            RtcpPacketType::SourceDescription | RtcpPacketType::Goodbye => None,
            _ => self
                .body
                .first_chunk::<4>()
                .map(|ssrc| u32::from_be_bytes(*ssrc)),
        }
    }

    /// The sender information of a Sender Report.
    pub fn sender_info(&self) -> Option<RtcpSenderInfo> {
        if self.packet_type != RtcpPacketType::SenderReport {
            return None;
        }
        let info = self.body.get(4..24)?;
        let word = |index: usize| {
            u32::from_be_bytes([
                info[index],
                info[index + 1],
                info[index + 2],
                info[index + 3],
            ])
        };
        Some(RtcpSenderInfo {
            ntp_timestamp: (u64::from(word(0)) << 32) | u64::from(word(4)),
            rtp_timestamp: word(8),
            packet_count: word(12),
            octet_count: word(16),
        })
    }
}

/// The RTCP packets of one UDP datagram: a compound packet (RFC 3550 §6.1)
/// or a single one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RtcpCompound<'a> {
    bytes: &'a [u8],
}

impl<'a> RtcpCompound<'a> {
    /// The packets, in wire order.
    pub fn packets(&self) -> RtcpPackets<'a> {
        RtcpPackets { rest: self.bytes }
    }

    /// The datagram, as received.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Sonde aveugle : un datagramme bien forme qui s'ouvre par un SR ou un
    /// RR, ou un message de retour seul (voir la doc du module).
    pub(crate) fn is_blind_match(payload: &'a [u8]) -> bool {
        let Ok(compound) = RtcpCompound::try_from(payload) else {
            return false;
        };
        let mut packets = compound.packets();
        match packets.next().map(|packet| packet.packet_type) {
            Some(RtcpPacketType::SenderReport | RtcpPacketType::ReceiverReport) => true,
            Some(RtcpPacketType::TransportFeedback | RtcpPacketType::PayloadFeedback) => {
                packets.next().is_none()
            }
            _ => false,
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for RtcpCompound<'a> {
    type Error = RtcpError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let mut rest = bytes;
        loop {
            let (packet, consumed) = checks::packet(rest)?;
            rest = &rest[consumed..];
            if rest.is_empty() {
                return Ok(Self { bytes });
            }
            // Le bourrage n'appartient qu'au dernier paquet (RFC 3550 §6.4.1).
            if packet.padding {
                return Err(RtcpError::InvalidPadding);
            }
        }
    }
}

/// Iterator over the packets of an [`RtcpCompound`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RtcpPackets<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for RtcpPackets<'a> {
    type Item = RtcpPacket<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // Le datagramme a ete valide par `try_from` : chaque paquet se
        // relit sans erreur.
        let (packet, consumed) = checks::packet(self.rest).ok()?;
        self.rest = &self.rest[consumed..];
        Some(packet)
    }
}

mod checks {
    use super::{RTCP_HEADER_LENGTH, RTCP_VERSION, RtcpError, RtcpPacket, RtcpPacketType};

    /// Longueur d'un bloc de rapport de reception (RFC 3550 §6.4.1).
    const REPORT_BLOCK_LENGTH: usize = 24;

    fn packet_type(value: u8) -> Result<RtcpPacketType, RtcpError> {
        Ok(match value {
            200 => RtcpPacketType::SenderReport,
            201 => RtcpPacketType::ReceiverReport,
            202 => RtcpPacketType::SourceDescription,
            203 => RtcpPacketType::Goodbye,
            204 => RtcpPacketType::ApplicationDefined,
            205 => RtcpPacketType::TransportFeedback,
            206 => RtcpPacketType::PayloadFeedback,
            207 => RtcpPacketType::ExtendedReport,
            other => return Err(RtcpError::UnknownPacketType(other)),
        })
    }

    /// Octets que le type et le compteur imposent apres l'en-tete.
    fn minimum_body(packet_type: RtcpPacketType, count: u8) -> usize {
        let count = usize::from(count);
        match packet_type {
            // SSRC, informations d'emetteur, puis `count` blocs.
            RtcpPacketType::SenderReport => 24 + count * REPORT_BLOCK_LENGTH,
            RtcpPacketType::ReceiverReport => 4 + count * REPORT_BLOCK_LENGTH,
            // Un morceau SDES : un SSRC et au moins un item nul, aligne.
            RtcpPacketType::SourceDescription => count * 8,
            RtcpPacketType::Goodbye => count * 4,
            // SSRC et nom de quatre caracteres.
            RtcpPacketType::ApplicationDefined => 8,
            // SSRC de l'emetteur et SSRC de la source du media.
            RtcpPacketType::TransportFeedback | RtcpPacketType::PayloadFeedback => 8,
            RtcpPacketType::ExtendedReport => 4,
        }
    }

    /// Le premier paquet de `bytes` et sa longueur, en-tete compris.
    pub(super) fn packet(bytes: &[u8]) -> Result<(RtcpPacket<'_>, usize), RtcpError> {
        let [first, kind, high, low, ..] = *bytes else {
            return Err(RtcpError::TooShort {
                expected: RTCP_HEADER_LENGTH,
                actual: bytes.len(),
            });
        };
        if first >> 6 != RTCP_VERSION {
            return Err(RtcpError::InvalidVersion(first >> 6));
        }
        let packet_type = packet_type(kind)?;
        let padding = first & 0x20 != 0;
        let count = first & 0x1F;
        let declared = (usize::from(u16::from_be_bytes([high, low])) + 1) * 4;
        let Some(body) = bytes.get(RTCP_HEADER_LENGTH..declared) else {
            return Err(RtcpError::TruncatedPacket {
                declared,
                available: bytes.len(),
            });
        };
        let padding_length = if padding {
            match body.last() {
                Some(&length)
                    if length != 0 && length % 4 == 0 && usize::from(length) <= body.len() =>
                {
                    usize::from(length)
                }
                _ => return Err(RtcpError::InvalidPadding),
            }
        } else {
            0
        };
        let expected = minimum_body(packet_type, count);
        if body.len() - padding_length < expected {
            return Err(RtcpError::PacketTooShortForType {
                packet_type: kind,
                count,
                expected: RTCP_HEADER_LENGTH + expected,
                actual: declared - padding_length,
            });
        }
        Ok((
            RtcpPacket {
                padding,
                count,
                packet_type,
                body,
            },
            declared,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SR + SDES + BYE reel : wireshark_aaa.pcap, trame 633 (104 octets).
    const SR_SDES_BYE: &str = concat!(
        "80c800063796cb7142c907ca5efac603000024c3000000090000060c81ca000b",
        "3796cb71011d31313839343239372d3434333261396638403139322e3136382e",
        "312e3206055349505053000081cb00063796cb711073657373696f6e20736875",
        "74646f776e000000",
    );

    /// Message de retour seul, reel : ndpi_line.pcap, trame 28 (52 octets).
    const FEEDBACK: &str = concat!(
        "8bcd000c00001a9200001a92000001bb000100c909bda67400080002fcbca0b8",
        "2068604009bda6440000000009bda64400000000",
    );

    fn hex(text: &str) -> Vec<u8> {
        hex::decode(text).expect("hexa valide")
    }

    #[test]
    fn compound_lists_its_three_packets() {
        let bytes = hex(SR_SDES_BYE);
        let compound = RtcpCompound::try_from(bytes.as_slice()).expect("RTCP");
        let packets: Vec<_> = compound.packets().collect();
        assert_eq!(
            packets
                .iter()
                .map(|packet| packet.packet_type)
                .collect::<Vec<_>>(),
            [
                RtcpPacketType::SenderReport,
                RtcpPacketType::SourceDescription,
                RtcpPacketType::Goodbye,
            ]
        );
        assert_eq!(packets[0].count, 0);
        assert!(!packets[0].padding);
        assert_eq!(packets[0].sender_ssrc(), Some(0x3796_cb71));
        assert_eq!(
            packets[0].sender_info(),
            Some(RtcpSenderInfo {
                ntp_timestamp: (1_120_470_986 << 32) | 1_593_492_995,
                rtp_timestamp: 9411,
                packet_count: 9,
                octet_count: 1548,
            })
        );
        assert_eq!(packets[1].count, 1);
        assert_eq!(packets[1].sender_ssrc(), None);
        assert_eq!(packets[1].sender_info(), None);
        assert_eq!(packets[2].body.len(), 24);
        assert!(RtcpCompound::is_blind_match(&bytes));
    }

    #[test]
    fn reduced_size_feedback_is_a_blind_match() {
        let bytes = hex(FEEDBACK);
        let compound = RtcpCompound::try_from(bytes.as_slice()).expect("RTCP");
        let packets: Vec<_> = compound.packets().collect();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].packet_type, RtcpPacketType::TransportFeedback);
        assert_eq!(packets[0].count, 11);
        assert_eq!(packets[0].sender_ssrc(), Some(0x1a92));
        assert!(RtcpCompound::is_blind_match(&bytes));
    }

    #[test]
    fn a_compound_that_does_not_open_with_a_report_needs_decode_as() {
        // Le SDES et le BYE de la trame reelle, sans le SR qui les precede :
        // bien formes, mais hors de la sonde aveugle.
        let bytes = hex(SR_SDES_BYE);
        let tail = &bytes[28..];
        assert!(RtcpCompound::try_from(tail).is_ok());
        assert!(!RtcpCompound::is_blind_match(tail));
        // Deux messages de retour a la suite : hors de la sonde aveugle aussi.
        let mut twice = hex(FEEDBACK);
        twice.extend(hex(FEEDBACK));
        assert!(RtcpCompound::try_from(twice.as_slice()).is_ok());
        assert!(!RtcpCompound::is_blind_match(&twice));
    }

    // Les tests qui suivent alterent des octets des trames reelles, ou en
    // ecrivent a la main, pour viser une branche precise.

    #[test]
    fn altered_packets_are_refused() {
        let alter = |index: usize, value: u8| {
            let mut bytes = hex(SR_SDES_BYE);
            bytes[index] = value;
            RtcpCompound::try_from(bytes.as_slice()).map(|_| ())
        };
        assert_eq!(alter(0, 0x40), Err(RtcpError::InvalidVersion(1)));
        assert_eq!(alter(1, 199), Err(RtcpError::UnknownPacketType(199)));
        assert_eq!(alter(1, 208), Err(RtcpError::UnknownPacketType(208)));
        // Longueur du SR portee a 40 mots : au-dela du datagramme.
        assert_eq!(
            alter(3, 39),
            Err(RtcpError::TruncatedPacket {
                declared: 160,
                available: 104
            })
        );
        // Un bloc de rapport annonce dans un SR qui n'a pas la place.
        assert_eq!(
            alter(0, 0x81),
            Err(RtcpError::PacketTooShortForType {
                packet_type: 200,
                count: 1,
                expected: 52,
                actual: 28
            })
        );
        // Bit de bourrage sur le SR : son dernier octet ne fait pas un
        // compteur de bourrage coherent.
        assert!(alter(0, 0xA0).is_err());
        // Longueur du SR raccourcie : la suite ne commence plus par un en-tete.
        assert!(alter(3, 5).is_err());
        assert_eq!(
            RtcpCompound::try_from(&hex(SR_SDES_BYE)[..3]).map(|_| ()),
            Err(RtcpError::TooShort {
                expected: 4,
                actual: 3
            })
        );
        assert_eq!(
            RtcpCompound::try_from(&[][..]).map(|_| ()),
            Err(RtcpError::TooShort {
                expected: 4,
                actual: 0
            })
        );
    }

    #[test]
    fn synthetic_padding_on_the_last_packet() {
        // RR sans bloc, quatre octets de bourrage dont le dernier vaut 4.
        let bytes = hex("a0c900021234567800000004");
        let compound = RtcpCompound::try_from(bytes.as_slice()).unwrap();
        let packet = compound.packets().next().unwrap();
        assert!(packet.padding);
        assert_eq!(packet.packet_type, RtcpPacketType::ReceiverReport);
        assert_eq!(packet.body.len(), 8);
        // Compteur de bourrage nul, non multiple de quatre, ou trop long.
        for last in ["00000000", "00000003", "0000000c"] {
            let bytes = hex(&format!("a0c9000212345678{last}"));
            assert_eq!(
                RtcpCompound::try_from(bytes.as_slice()).map(|_| ()),
                Err(RtcpError::InvalidPadding)
            );
        }
        // Un paquet a bourrage suivi d'un autre : seul le dernier en porte.
        let bytes = hex("a0c90002123456780000000480c9000112345678");
        assert_eq!(
            RtcpCompound::try_from(bytes.as_slice()).map(|_| ()),
            Err(RtcpError::InvalidPadding)
        );
        // Le bourrage ne compte pas dans la taille minimale du type.
        assert!(matches!(
            RtcpCompound::try_from(hex("a0c9000100000004").as_slice()),
            Err(RtcpError::PacketTooShortForType { .. })
        ));
    }

    #[test]
    fn synthetic_every_packet_type_round_trips() {
        // En-tete seul, assez long pour chaque type a compteur nul.
        for (kind, words) in [
            (200u8, 6u8),
            (201, 1),
            (202, 0),
            (203, 0),
            (204, 2),
            (205, 2),
            (206, 2),
            (207, 1),
        ] {
            let mut bytes = vec![0x80, kind, 0, words];
            bytes.resize(4 + usize::from(words) * 4, 0);
            let compound = RtcpCompound::try_from(bytes.as_slice()).unwrap();
            let packet = compound.packets().next().unwrap();
            assert_eq!(packet.packet_type.as_u8(), kind);
            assert_eq!(
                packet.sender_ssrc().is_some(),
                !matches!(kind, 202 | 203),
                "type {kind}"
            );
        }
    }
}
