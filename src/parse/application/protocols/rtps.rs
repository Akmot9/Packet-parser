// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! RTPS, Real-Time Publish-Subscribe (OMG DDSI-RTPS 2.5) : le protocole
//! filaire de DDS, middleware des architectures de combat recentes (NGVA,
//! GVA, systemes navals) et de ROS 2. Successeur de GIOP/MIOP dans ce
//! role.
//!
//! Un message tient dans un datagramme UDP : un en-tete de 20 octets (magic
//! `RTPS`, ou `RTPX` chez RTI, version, vendorId, guidPrefix) puis des
//! sous-messages qui le pavent exactement, chacun introduit par son
//! identifiant, ses flags (dont l'ordre d'octets de ses champs) et
//! `octetsToNextHeader`. Le decodeur decoupe les sous-messages, identifie
//! leur type et expose, en valeurs typees, les identifiants d'entite,
//! numeros de sequence, compteurs et horodatages des types de la
//! specification ; les donnees utilisateur (CDR), les QoS en ligne et les
//! listes de locateurs restent en octets. RTI Connext emet aussi des
//! « pings » de seize octets (`RTPS`, version, vendorId, `NDDSPING`), que
//! tshark compte comme du RTPS : [`RtpsPacket::Ping`].
//!
//! Le magic et le pavage exact donnent une garde a cout constant puis une
//! signature forte : la sonde est aveugle (sans port), ce que les ports
//! unicast aleatoires de Cyclone DDS et Connext Micro imposent.

use std::convert::TryFrom;

use crate::{
    checks::application::rtps::{
        RTPS_FLAG_ENDIANNESS, RTPS_HEADER_LENGTH, RTPS_PING_LENGTH, RTPS_PING_TEXT,
        RTPS_SUBMESSAGE_HEADER_LENGTH, SUBMESSAGE_ACKNACK, SUBMESSAGE_DATA, SUBMESSAGE_DATA_FRAG,
        SUBMESSAGE_GAP, SUBMESSAGE_HEARTBEAT, SUBMESSAGE_HEARTBEAT_FRAG, SUBMESSAGE_INFO_DST,
        SUBMESSAGE_INFO_REPLY, SUBMESSAGE_INFO_REPLY_IP4, SUBMESSAGE_INFO_SRC, SUBMESSAGE_INFO_TS,
        SUBMESSAGE_NACK_FRAG, SUBMESSAGE_PAD, SUBMESSAGE_SEC_BODY, SUBMESSAGE_SEC_POSTFIX,
        SUBMESSAGE_SEC_PREFIX, SUBMESSAGE_SRTPS_POSTFIX, SUBMESSAGE_SRTPS_PREFIX, bitmap_length,
        ensure_len, extract_magic, extract_version, read_sequence_number, read_u16, read_u32,
        submessage_body_length, validate_body_length, validate_submessage_id,
    },
    errors::application::rtps::RtpsParseError,
    parse::application::protocols::bounded_capacity,
};

/// En-tete d'un message RTPS (DDSI-RTPS 2.5, §9.4.4).
///
/// ```mermaid
/// ---
/// title: RtpsHeader
/// ---
/// packet-beta
/// 0-31: "magic 'RTPS'"
/// 32-39: "version major u8"
/// 40-47: "version minor u8"
/// 48-63: "vendorId u16"
/// 64-159: "guidPrefix 12 octets"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct RtpsHeader {
    /// `RTPS`, ou `RTPX` (variante de RTI Connext).
    pub magic: [u8; 4],
    pub version_major: u8,
    pub version_minor: u8,
    /// Deux octets, `0x0101` pour RTI Connext, `0x0110` pour Cyclone DDS...
    pub vendor_id: u16,
    pub guid_prefix: [u8; 12],
}

/// Type d'un sous-message, d'apres son identifiant (§9.4.5.1.1 ; DDS
/// Security 1.1 §7.3.6.2 pour les `Secure*` ; 0x80 a 0xff pour les
/// vendeurs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SubmessageKind {
    Pad,
    AckNack,
    Heartbeat,
    Gap,
    InfoTimestamp,
    InfoSource,
    InfoReplyIp4,
    InfoDestination,
    InfoReply,
    NackFrag,
    HeartbeatFrag,
    Data,
    DataFrag,
    SecureBody,
    SecurePrefix,
    SecurePostfix,
    SecureRtpsPrefix,
    SecureRtpsPostfix,
    VendorSpecific(u8),
}

impl SubmessageKind {
    fn from_id(id: u8) -> Self {
        match id {
            SUBMESSAGE_PAD => Self::Pad,
            SUBMESSAGE_ACKNACK => Self::AckNack,
            SUBMESSAGE_HEARTBEAT => Self::Heartbeat,
            SUBMESSAGE_GAP => Self::Gap,
            SUBMESSAGE_INFO_TS => Self::InfoTimestamp,
            SUBMESSAGE_INFO_SRC => Self::InfoSource,
            SUBMESSAGE_INFO_REPLY_IP4 => Self::InfoReplyIp4,
            SUBMESSAGE_INFO_DST => Self::InfoDestination,
            SUBMESSAGE_INFO_REPLY => Self::InfoReply,
            SUBMESSAGE_NACK_FRAG => Self::NackFrag,
            SUBMESSAGE_HEARTBEAT_FRAG => Self::HeartbeatFrag,
            SUBMESSAGE_DATA => Self::Data,
            SUBMESSAGE_DATA_FRAG => Self::DataFrag,
            SUBMESSAGE_SEC_BODY => Self::SecureBody,
            SUBMESSAGE_SEC_PREFIX => Self::SecurePrefix,
            SUBMESSAGE_SEC_POSTFIX => Self::SecurePostfix,
            SUBMESSAGE_SRTPS_PREFIX => Self::SecureRtpsPrefix,
            SUBMESSAGE_SRTPS_POSTFIX => Self::SecureRtpsPostfix,
            other => Self::VendorSpecific(other),
        }
    }
}

/// Un `Time_t` (§9.3.2) : secondes et fraction de seconde en 2^-32 s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct RtpsTime {
    pub seconds: u32,
    pub fraction: u32,
}

/// Les champs typees d'un sous-message, selon son type (§9.4.5). Les
/// identifiants d'entite sont les quatre octets `EntityId_t` tels quels,
/// `0x000003c2` pour le writer des publications par exemple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SubmessageDetails {
    Data {
        reader_id: u32,
        writer_id: u32,
        writer_sequence_number: i64,
        /// Flag Q : des QoS en ligne precedent les donnees.
        inline_qos: bool,
        /// Flag D : le corps porte des donnees serialisees.
        serialized_payload: bool,
        /// Flag K : le corps porte une cle serialisee.
        serialized_key: bool,
    },
    DataFrag {
        reader_id: u32,
        writer_id: u32,
        writer_sequence_number: i64,
        fragment_starting_number: u32,
        fragments_in_submessage: u16,
        fragment_size: u16,
        sample_size: u32,
    },
    Heartbeat {
        reader_id: u32,
        writer_id: u32,
        first_sequence_number: i64,
        last_sequence_number: i64,
        count: u32,
    },
    AckNack {
        reader_id: u32,
        writer_id: u32,
        /// Base du `SequenceNumberSet` acquitte.
        bitmap_base: i64,
        num_bits: u32,
        count: u32,
        /// Flag F : reponse finale, le reader n'attend rien de plus.
        final_flag: bool,
    },
    Gap {
        reader_id: u32,
        writer_id: u32,
        gap_start: i64,
        gap_list_base: i64,
        num_bits: u32,
    },
    HeartbeatFrag {
        reader_id: u32,
        writer_id: u32,
        writer_sequence_number: i64,
        last_fragment_number: u32,
        count: u32,
    },
    NackFrag {
        reader_id: u32,
        writer_id: u32,
        writer_sequence_number: i64,
        fragment_number_base: u32,
        num_bits: u32,
        count: u32,
    },
    /// `None` quand le flag I invalide l'horodatage.
    InfoTimestamp {
        timestamp: Option<RtpsTime>,
    },
    InfoDestination {
        guid_prefix: [u8; 12],
    },
    InfoSource {
        version_major: u8,
        version_minor: u8,
        vendor_id: u16,
        guid_prefix: [u8; 12],
    },
    /// PAD, INFO_REPLY, INFO_REPLY_IP4, DDS Security et sous-messages
    /// vendeur : corps non interprete.
    Opaque,
}

/// Un sous-message : son en-tete et son corps, zero-copie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RtpsSubmessage<'a> {
    pub kind: SubmessageKind,
    pub id: u8,
    pub flags: u8,
    /// Flag E : les champs du corps sont en petit-boutiste.
    pub little_endian: bool,
    /// `octetsToNextHeader` tel que porte par le wire : la longueur du
    /// corps, ou zero pour un dernier sous-message qui s'etend jusqu'a la
    /// fin du message (et pour un PAD ou un INFO_TS sans corps).
    pub octets_to_next_header: u16,
    /// Le corps, apres les quatre octets d'en-tete.
    pub body: &'a [u8],
    pub details: SubmessageDetails,
}

/// Un message RTPS : l'en-tete et ses sous-messages, dans l'ordre du wire.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RtpsMessage<'a> {
    pub header: RtpsHeader,
    pub submessages: Vec<RtpsSubmessage<'a>>,
}

/// « Ping » RTI Connext : seize octets, magic, version, vendorId et le
/// texte `NDDSPING`, envoyes sur les ports de metatrafic pour sonder un
/// participant. Hors specification, mais present sur tout reseau RTI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct RtpsPing {
    pub magic: [u8; 4],
    pub version_major: u8,
    pub version_minor: u8,
    pub vendor_id: u16,
    /// `NDDSPING`.
    pub text: [u8; 8],
}

/// Un datagramme RTPS : un message, ou un ping RTI.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RtpsPacket<'a> {
    Message(RtpsMessage<'a>),
    Ping(RtpsPing),
}

impl<'a> RtpsPacket<'a> {
    pub fn vendor_id(&self) -> u16 {
        match self {
            Self::Message(message) => message.header.vendor_id,
            Self::Ping(ping) => ping.vendor_id,
        }
    }

    /// `(major, minor)`.
    pub fn version(&self) -> (u8, u8) {
        match self {
            Self::Message(message) => (message.header.version_major, message.header.version_minor),
            Self::Ping(ping) => (ping.version_major, ping.version_minor),
        }
    }

    /// Le message, `None` pour un ping.
    pub fn message(&self) -> Option<&RtpsMessage<'a>> {
        match self {
            Self::Message(message) => Some(message),
            Self::Ping(_) => None,
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for RtpsPacket<'a> {
    type Error = RtpsParseError;

    fn try_from(payload: &'a [u8]) -> Result<Self, Self::Error> {
        if payload.len() == RTPS_PING_LENGTH && payload[8..] == RTPS_PING_TEXT {
            let magic = extract_magic(payload)?;
            let (version_major, version_minor) = extract_version(payload[4], payload[5])?;
            return Ok(RtpsPacket::Ping(RtpsPing {
                magic,
                version_major,
                version_minor,
                vendor_id: u16::from_be_bytes([payload[6], payload[7]]),
                text: RTPS_PING_TEXT,
            }));
        }
        ensure_len(payload, RTPS_HEADER_LENGTH)?;
        let magic = extract_magic(payload)?;
        let (version_major, version_minor) = extract_version(payload[4], payload[5])?;
        let header = RtpsHeader {
            magic,
            version_major,
            version_minor,
            vendor_id: u16::from_be_bytes([payload[6], payload[7]]),
            guid_prefix: payload[8..20].try_into().unwrap_or([0; 12]),
        };

        let mut submessages = Vec::with_capacity(bounded_capacity(
            payload.len() / RTPS_SUBMESSAGE_HEADER_LENGTH,
            payload.len() - RTPS_HEADER_LENGTH,
            RTPS_SUBMESSAGE_HEADER_LENGTH,
        ));
        let mut offset = RTPS_HEADER_LENGTH;
        while offset < payload.len() {
            let (submessage, consumed) = parse_submessage(payload, offset)?;
            submessages.push(submessage);
            offset += consumed;
        }
        if submessages.is_empty() {
            return Err(RtpsParseError::NoSubmessage);
        }
        Ok(RtpsPacket::Message(RtpsMessage {
            header,
            submessages,
        }))
    }
}

/// Decoupe le sous-message qui commence a `offset` ; rend le sous-message
/// et le nombre d'octets consommes, en-tete compris.
fn parse_submessage(
    payload: &[u8],
    offset: usize,
) -> Result<(RtpsSubmessage<'_>, usize), RtpsParseError> {
    let rest = &payload[offset..];
    ensure_len(rest, RTPS_SUBMESSAGE_HEADER_LENGTH).map_err(|_| RtpsParseError::Truncated {
        expected: offset + RTPS_SUBMESSAGE_HEADER_LENGTH,
        actual: payload.len(),
    })?;
    let id = validate_submessage_id(rest[0], offset)?;
    let flags = rest[1];
    let little_endian = flags & RTPS_FLAG_ENDIANNESS != 0;
    let declared = read_u16([rest[2], rest[3]], little_endian);
    let available = rest.len() - RTPS_SUBMESSAGE_HEADER_LENGTH;
    let body_len = submessage_body_length(id, offset, declared, available)?;
    let body = &rest[RTPS_SUBMESSAGE_HEADER_LENGTH..RTPS_SUBMESSAGE_HEADER_LENGTH + body_len];
    let details = submessage_details(id, flags, little_endian, body, offset)?;
    Ok((
        RtpsSubmessage {
            kind: SubmessageKind::from_id(id),
            id,
            flags,
            little_endian,
            octets_to_next_header: declared,
            body,
            details,
        },
        RTPS_SUBMESSAGE_HEADER_LENGTH + body_len,
    ))
}

/// Les champs typees d'un corps, apres verification de sa longueur
/// minimale pour le type (§9.4.5.2 a §9.4.5.17).
fn submessage_details(
    id: u8,
    flags: u8,
    little_endian: bool,
    body: &[u8],
    offset: usize,
) -> Result<SubmessageDetails, RtpsParseError> {
    let at = |start: usize| -> [u8; 4] {
        [
            body[start],
            body[start + 1],
            body[start + 2],
            body[start + 3],
        ]
    };
    let u32_at = |start: usize| read_u32(at(start), little_endian);
    let entity_at = |start: usize| u32::from_be_bytes(at(start));
    let sn_at = |start: usize| {
        read_sequence_number(
            [
                body[start],
                body[start + 1],
                body[start + 2],
                body[start + 3],
                body[start + 4],
                body[start + 5],
                body[start + 6],
                body[start + 7],
            ],
            little_endian,
        )
    };
    let needs = |expected: usize| validate_body_length(id, offset, expected, body.len());

    Ok(match id {
        SUBMESSAGE_DATA => {
            // extraFlags u16, octetsToInlineQos u16, readerId, writerId, writerSN.
            needs(20)?;
            SubmessageDetails::Data {
                reader_id: entity_at(4),
                writer_id: entity_at(8),
                writer_sequence_number: sn_at(12),
                inline_qos: flags & 0x02 != 0,
                serialized_payload: flags & 0x04 != 0,
                serialized_key: flags & 0x08 != 0,
            }
        }
        SUBMESSAGE_DATA_FRAG => {
            // ... puis fragmentStartingNum u32, fragmentsInSubmessage u16,
            // fragmentSize u16, sampleSize u32.
            needs(32)?;
            SubmessageDetails::DataFrag {
                reader_id: entity_at(4),
                writer_id: entity_at(8),
                writer_sequence_number: sn_at(12),
                fragment_starting_number: u32_at(20),
                fragments_in_submessage: read_u16([body[24], body[25]], little_endian),
                fragment_size: read_u16([body[26], body[27]], little_endian),
                sample_size: u32_at(28),
            }
        }
        SUBMESSAGE_HEARTBEAT => {
            needs(28)?;
            SubmessageDetails::Heartbeat {
                reader_id: entity_at(0),
                writer_id: entity_at(4),
                first_sequence_number: sn_at(8),
                last_sequence_number: sn_at(16),
                count: u32_at(24),
            }
        }
        SUBMESSAGE_ACKNACK => {
            // readerId, writerId, SequenceNumberSet (base, numBits, bitmap), count.
            needs(24)?;
            let num_bits = u32_at(16);
            let bitmap = bitmap_length(num_bits);
            needs(24 + bitmap)?;
            SubmessageDetails::AckNack {
                reader_id: entity_at(0),
                writer_id: entity_at(4),
                bitmap_base: sn_at(8),
                num_bits,
                count: u32_at(20 + bitmap),
                final_flag: flags & 0x02 != 0,
            }
        }
        SUBMESSAGE_GAP => {
            // readerId, writerId, gapStart, gapList (base, numBits, bitmap).
            needs(28)?;
            let num_bits = u32_at(24);
            needs(28 + bitmap_length(num_bits))?;
            SubmessageDetails::Gap {
                reader_id: entity_at(0),
                writer_id: entity_at(4),
                gap_start: sn_at(8),
                gap_list_base: sn_at(16),
                num_bits,
            }
        }
        SUBMESSAGE_HEARTBEAT_FRAG => {
            // readerId, writerId, writerSN, lastFragmentNum, count.
            needs(24)?;
            SubmessageDetails::HeartbeatFrag {
                reader_id: entity_at(0),
                writer_id: entity_at(4),
                writer_sequence_number: sn_at(8),
                last_fragment_number: u32_at(16),
                count: u32_at(20),
            }
        }
        SUBMESSAGE_NACK_FRAG => {
            // readerId, writerId, writerSN, FragmentNumberSet (base, numBits,
            // bitmap), count.
            needs(28)?;
            let num_bits = u32_at(20);
            let bitmap = bitmap_length(num_bits);
            needs(28 + bitmap)?;
            SubmessageDetails::NackFrag {
                reader_id: entity_at(0),
                writer_id: entity_at(4),
                writer_sequence_number: sn_at(8),
                fragment_number_base: u32_at(16),
                num_bits,
                count: u32_at(24 + bitmap),
            }
        }
        SUBMESSAGE_INFO_TS => {
            // Flag I : pas d'horodatage.
            if flags & 0x02 != 0 {
                SubmessageDetails::InfoTimestamp { timestamp: None }
            } else {
                needs(8)?;
                SubmessageDetails::InfoTimestamp {
                    timestamp: Some(RtpsTime {
                        seconds: u32_at(0),
                        fraction: u32_at(4),
                    }),
                }
            }
        }
        SUBMESSAGE_INFO_DST => {
            needs(12)?;
            SubmessageDetails::InfoDestination {
                guid_prefix: body[..12].try_into().unwrap_or([0; 12]),
            }
        }
        SUBMESSAGE_INFO_SRC => {
            // unused u32, version, vendorId, guidPrefix.
            needs(20)?;
            SubmessageDetails::InfoSource {
                version_major: body[4],
                version_minor: body[5],
                vendor_id: u16::from_be_bytes([body[6], body[7]]),
                guid_prefix: body[8..20].try_into().unwrap_or([0; 12]),
            }
        }
        SUBMESSAGE_INFO_REPLY_IP4 => {
            // unicastLocator (adresse 4, port 4), multicast optionnel.
            needs(8)?;
            SubmessageDetails::Opaque
        }
        SUBMESSAGE_INFO_REPLY => {
            // LocatorList : au moins son compteur.
            needs(4)?;
            SubmessageDetails::Opaque
        }
        _ => SubmessageDetails::Opaque,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trame 1 de pcaps_exemple/protocols/rtps/wireshark_6449_opendds_messenger.pcap
    /// (OpenDDS vers 239.255.0.1:7401) : INFO_TS puis DATA dont
    /// octetsToNextHeader vaut zero (dernier sous-message, jusqu'a la fin).
    const OPENDDS_FRAME_1: &str = concat!(
        "525450530201010301030000000000000000000109010800ed58934e4ed4d2d4150b000000001000",
        "0000000000000102ffffffff000000007100040000000000010000000001000063000000"
    );

    /// Trame 9 de pcaps_exemple/protocols/rtps/talker-listener-rtps.pcapng
    /// (Cyclone DDS, ROS 2, boucle locale) : INFO_DST, INFO_TS, DATA, HEARTBEAT.
    const CYCLONE_FRAME_9: &str = concat!(
        "525450530201011054a61001319843eca3669a350e010c005ab810011636c7d51895c54e09010800",
        "b7eee960f395406e1505300000001000000200c7000200c200000000010000000001000054a61001",
        "319843eca3669a3500000001010000000000000007011c00000200c7000200c20000000001000000",
        "000000000100000002000000"
    );

    /// Trame 8 de la meme capture : INFO_DST puis trois ACKNACK, le dernier
    /// avec un bitmap d'un mot.
    const CYCLONE_FRAME_8: &str = concat!(
        "52545053020101105ab810011636c7d51895c54e0e010c0054a61001319843eca3669a3506031800",
        "000003c7000003c20000000001000000000000000100000006031800000004c7000004c200000000",
        "01000000000000000100000006031c00000200c7000200c2000000000100000001000000000000800",
        "1000000"
    );

    /// Trame 1 de pcaps_exemple/protocols/rtps/rtps.pcap (nDPI, RTI Connext
    /// en boucle locale 7410) : le ping RTI, seize octets.
    const RTI_PING: &str = "52545053020101014e44445350494e47";

    /// Trame 2 de pcaps_exemple/protocols/rtps/RTPS_Discovery.pcapng : magic
    /// `RTPX`, INFO_TS puis DATA de 876 octets — seul l'en-tete est garde
    /// ici, le DATA est reduit a son minimum (octets synthetiques).
    const RTPX_HEADER: &str = "52545058020101010a4601a700008c3800000002";

    fn message(hex: &str) -> (Vec<u8>, RtpsMessage<'static>) {
        let bytes: &'static [u8] = Box::leak(hex::decode(hex).unwrap().into_boxed_slice());
        match RtpsPacket::try_from(bytes).expect("message RTPS") {
            RtpsPacket::Message(message) => (bytes.to_vec(), message),
            other => panic!("ping inattendu : {other:?}"),
        }
    }

    #[test]
    fn test_decodes_opendds_data_to_the_end_of_the_message() {
        let (bytes, message) = message(OPENDDS_FRAME_1);
        assert_eq!(message.header.magic, *b"RTPS");
        assert_eq!(message.header.version_major, 2);
        assert_eq!(message.header.version_minor, 1);
        assert_eq!(message.header.vendor_id, 0x0103);
        assert_eq!(
            message.header.guid_prefix,
            [0x01, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]
        );
        assert_eq!(message.submessages.len(), 2);
        let info_ts = &message.submessages[0];
        assert_eq!(info_ts.kind, SubmessageKind::InfoTimestamp);
        assert!(info_ts.little_endian);
        assert_eq!(info_ts.octets_to_next_header, 8);
        assert_eq!(
            info_ts.details,
            SubmessageDetails::InfoTimestamp {
                timestamp: Some(RtpsTime {
                    seconds: 0x4e93_58ed, // 2011-10-10 20:43:25 UTC
                    fraction: 0xd4d2_d44e,
                })
            }
        );
        let data = &message.submessages[1];
        assert_eq!(data.kind, SubmessageKind::Data);
        assert_eq!(data.flags, 0x0b);
        assert_eq!(data.octets_to_next_header, 0);
        assert_eq!(data.body.len(), bytes.len() - 20 - 12 - 4);
        assert_eq!(
            data.details,
            SubmessageDetails::Data {
                reader_id: 0,
                writer_id: 0x0000_0102,
                writer_sequence_number: -1 << 32, // 18446744069414584320 chez tshark
                inline_qos: true,
                serialized_payload: false,
                serialized_key: true,
            }
        );
    }

    #[test]
    fn test_decodes_cyclone_discovery_against_tshark() {
        let (_, message) = message(CYCLONE_FRAME_9);
        assert_eq!(message.header.vendor_id, 0x0110);
        let kinds: Vec<SubmessageKind> = message.submessages.iter().map(|s| s.kind).collect();
        assert_eq!(
            kinds,
            [
                SubmessageKind::InfoDestination,
                SubmessageKind::InfoTimestamp,
                SubmessageKind::Data,
                SubmessageKind::Heartbeat,
            ]
        );
        let lengths: Vec<usize> = message.submessages.iter().map(|s| s.body.len()).collect();
        assert_eq!(lengths, [12, 8, 48, 28]);
        assert_eq!(
            message.submessages[0].details,
            SubmessageDetails::InfoDestination {
                guid_prefix: [
                    0x5a, 0xb8, 0x10, 0x01, 0x16, 0x36, 0xc7, 0xd5, 0x18, 0x95, 0xc5, 0x4e
                ]
            }
        );
        assert_eq!(
            message.submessages[2].details,
            SubmessageDetails::Data {
                reader_id: 0x0002_00c7,
                writer_id: 0x0002_00c2,
                writer_sequence_number: 1,
                inline_qos: false,
                serialized_payload: true,
                serialized_key: false,
            }
        );
        assert_eq!(
            message.submessages[3].details,
            SubmessageDetails::Heartbeat {
                reader_id: 0x0002_00c7,
                writer_id: 0x0002_00c2,
                first_sequence_number: 1,
                last_sequence_number: 1,
                count: 2,
            }
        );
    }

    #[test]
    fn test_decodes_acknack_bitmaps() {
        let (_, message) = message(CYCLONE_FRAME_8);
        assert_eq!(message.submessages.len(), 4);
        assert_eq!(
            message.submessages[1].details,
            SubmessageDetails::AckNack {
                reader_id: 0x0000_03c7,
                writer_id: 0x0000_03c2,
                bitmap_base: 1,
                num_bits: 0,
                count: 1,
                final_flag: true,
            }
        );
        assert_eq!(
            message.submessages[3].details,
            SubmessageDetails::AckNack {
                reader_id: 0x0002_00c7,
                writer_id: 0x0002_00c2,
                bitmap_base: 1,
                num_bits: 1,
                count: 1,
                final_flag: true,
            }
        );
        assert_eq!(message.submessages[3].body.len(), 28);
    }

    #[test]
    fn test_decodes_the_rti_ping_and_the_rtpx_magic() {
        let bytes = hex::decode(RTI_PING).unwrap();
        let packet = RtpsPacket::try_from(bytes.as_slice()).expect("ping RTI");
        assert_eq!(
            packet,
            RtpsPacket::Ping(RtpsPing {
                magic: *b"RTPS",
                version_major: 2,
                version_minor: 1,
                vendor_id: 0x0101,
                text: *b"NDDSPING",
            })
        );
        assert_eq!(packet.vendor_id(), 0x0101);
        assert_eq!(packet.version(), (2, 1));
        assert!(packet.message().is_none());
        // Seize octets sans le texte : un en-tete tronque, pas un ping.
        let mut other = bytes.clone();
        other[8] = b'X';
        assert_eq!(
            RtpsPacket::try_from(other.as_slice()),
            Err(RtpsParseError::Truncated {
                expected: 20,
                actual: 16
            })
        );

        // RTPX : l'en-tete reel de la trame 2 de RTPS_Discovery.pcapng puis
        // un DATA minimal de 20 octets (synthetique).
        let mut rtpx = hex::decode(RTPX_HEADER).unwrap();
        rtpx.extend_from_slice(&[0x15, 0x01, 0x14, 0x00]);
        rtpx.extend_from_slice(&[0; 20]);
        let RtpsPacket::Message(message) = RtpsPacket::try_from(rtpx.as_slice()).expect("RTPX")
        else {
            panic!("message attendu");
        };
        assert_eq!(message.header.magic, *b"RTPX");
        assert_eq!(message.header.vendor_id, 0x0101);
        assert_eq!(message.submessages.len(), 1);
        assert_eq!(message.submessages[0].kind, SubmessageKind::Data);
    }

    #[test]
    fn test_rejects_bad_magic_version_and_empty_messages() {
        let mut bytes = hex::decode(CYCLONE_FRAME_9).unwrap();
        assert_eq!(
            RtpsPacket::try_from(&bytes[..20]),
            Err(RtpsParseError::NoSubmessage)
        );
        assert!(matches!(
            RtpsPacket::try_from(&bytes[..10]),
            Err(RtpsParseError::Truncated {
                expected: 20,
                actual: 10
            })
        ));
        bytes[4] = 1;
        assert_eq!(
            RtpsPacket::try_from(bytes.as_slice()),
            Err(RtpsParseError::UnsupportedVersion { major: 1, minor: 1 })
        );
        bytes[4] = 2;
        bytes[0] = b'G';
        assert_eq!(
            RtpsPacket::try_from(bytes.as_slice()),
            Err(RtpsParseError::InvalidMagic(*b"GTPS"))
        );
    }

    #[test]
    fn test_rejects_submessages_that_do_not_tile_the_message() {
        let bytes = hex::decode(CYCLONE_FRAME_9).unwrap();
        // INFO_DST annonce 12 octets : en declarer 200 deborde.
        let mut overflow = bytes.clone();
        overflow[22] = 200;
        assert_eq!(
            RtpsPacket::try_from(overflow.as_slice()),
            Err(RtpsParseError::SubmessageOverflow {
                id: 0x0e,
                offset: 20,
                declared: 200,
                available: bytes.len() - 24,
            })
        );
        // Un octet de trop apres le dernier sous-message : en-tete tronque.
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            RtpsPacket::try_from(trailing.as_slice()),
            Err(RtpsParseError::Truncated {
                expected: bytes.len() + 4,
                actual: bytes.len() + 1,
            })
        );
        // Identifiant reserve.
        let mut reserved = bytes.clone();
        reserved[20] = 0x02;
        assert_eq!(
            RtpsPacket::try_from(reserved.as_slice()),
            Err(RtpsParseError::ReservedSubmessageId {
                id: 0x02,
                offset: 20
            })
        );
        // HEARTBEAT de 20 octets au lieu de 28.
        let mut short = bytes[..bytes.len() - 8].to_vec();
        short[bytes.len() - 32 + 2] = 20;
        assert_eq!(
            RtpsPacket::try_from(short.as_slice()),
            Err(RtpsParseError::SubmessageTooShort {
                id: 0x07,
                offset: bytes.len() - 32,
                expected: 28,
                actual: 20,
            })
        );
    }

    /// Octets synthetiques : INFO_TS sans horodatage (flag I,
    /// octetsToNextHeader nul), PAD, puis un sous-message vendeur en
    /// grand-boutiste.
    #[test]
    fn test_empty_info_ts_pad_and_vendor_submessages() {
        let mut bytes = hex::decode(CYCLONE_FRAME_9).unwrap()[..20].to_vec();
        bytes.extend_from_slice(&[0x09, 0x02, 0x00, 0x00]);
        bytes.extend_from_slice(&[0x01, 0x01, 0x00, 0x00]);
        bytes.extend_from_slice(&[0x80, 0x00, 0x00, 0x03, 0xaa, 0xbb, 0xcc]);
        let RtpsPacket::Message(message) =
            RtpsPacket::try_from(bytes.as_slice()).expect("synthetique")
        else {
            panic!("message attendu");
        };
        let kinds: Vec<SubmessageKind> = message.submessages.iter().map(|s| s.kind).collect();
        assert_eq!(
            kinds,
            [
                SubmessageKind::InfoTimestamp,
                SubmessageKind::Pad,
                SubmessageKind::VendorSpecific(0x80),
            ]
        );
        assert_eq!(
            message.submessages[0].details,
            SubmessageDetails::InfoTimestamp { timestamp: None }
        );
        assert!(message.submessages[1].body.is_empty());
        let vendor = &message.submessages[2];
        assert!(!vendor.little_endian);
        assert_eq!(vendor.body, &[0xaa, 0xbb, 0xcc]);
        assert_eq!(vendor.details, SubmessageDetails::Opaque);
    }
}
