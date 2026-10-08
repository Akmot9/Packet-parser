// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! PTP, Precision Time Protocol (IEEE 1588).
//!
//! Un meme message circule sur deux transports : UDP 319 (messages
//! d'evenement, horodates) et 320 (messages generaux), et directement sur
//! Ethernet, EtherType `0x88F7`. [`PtpPacket::try_from`] decode le message
//! seul et tolere des octets apres `messageLength` (bourrage Ethernet) ;
//! [`PtpPacket::try_from_udp`] n'admet apres lui que les deux octets de
//! l'annexe E (UDP/IPv6).
//!
//! PTPv2 (1588-2008, et 2019 qui garde le format) est decode en entier :
//! en-tete commun, corps des dix types de message, et TLV listes sans
//! decodage de leur valeur. PTPv1 (1588-2002), qu'aucun equipement recent
//! n'emet, est reconnu par son en-tete ; son corps reste brut.

use crate::{
    checks::application::ptp::{
        PTP_MESSAGE_ANNOUNCE, PTP_MESSAGE_DELAY_REQ, PTP_MESSAGE_DELAY_RESP, PTP_MESSAGE_FOLLOW_UP,
        PTP_MESSAGE_PDELAY_REQ, PTP_MESSAGE_PDELAY_RESP, PTP_MESSAGE_PDELAY_RESP_FOLLOW_UP,
        PTP_MESSAGE_SIGNALING, PTP_MESSAGE_SYNC, PTP_V1_HEADER_LENGTH, PTP_V2_HEADER_LENGTH,
        ensure_len, extract_message_type, extract_network_version, extract_v1_control,
        extract_version, validate_message_length, validate_udp_trailing, validate_v1_length,
    },
    errors::application::ptp::PtpPacketParseError,
};

/// Un message PTP, selon sa version.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PtpPacket<'a> {
    V2(PtpV2Message<'a>),
    V1(PtpV1Message<'a>),
}

impl<'a> TryFrom<&'a [u8]> for PtpPacket<'a> {
    type Error = PtpPacketParseError;

    /// Decode un message PTP. En v2, les octets qui suivent `messageLength`
    /// sont admis et exposes dans [`PtpV2Message::trailing`] : c'est le cas
    /// du bourrage Ethernet en couche 2.
    fn try_from(payload: &'a [u8]) -> Result<Self, Self::Error> {
        match extract_version(payload)? {
            1 => PtpV1Message::try_from(payload).map(Self::V1),
            _ => PtpV2Message::try_from(payload).map(Self::V2),
        }
    }
}

impl<'a> PtpPacket<'a> {
    /// Decode le payload d'un datagramme UDP. Plus strict que
    /// [`TryFrom::try_from`] : un message PTP occupe tout le datagramme, ou
    /// tout sauf les deux octets de correction de checksum de l'annexe E
    /// (UDP/IPv6).
    pub fn try_from_udp(payload: &'a [u8]) -> Result<Self, PtpPacketParseError> {
        let packet = Self::try_from(payload)?;
        if let Self::V2(message) = &packet {
            validate_udp_trailing(message.trailing.len())?;
        }
        Ok(packet)
    }

    /// Version PTP du message : 1 ou 2.
    pub fn version(&self) -> u8 {
        match self {
            Self::V2(_) => 2,
            Self::V1(_) => 1,
        }
    }

    /// sequenceId, present a la meme fin dans les deux versions.
    pub fn sequence_id(&self) -> u16 {
        match self {
            Self::V2(message) => message.header.sequence_id,
            Self::V1(message) => message.header.sequence_id,
        }
    }
}

/// Identite d'un port PTP : `clockIdentity` (EUI-64) et numero de port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PortIdentity {
    pub clock_identity: [u8; 8],
    pub port_number: u16,
}

/// Horodatage PTP : secondes sur 48 bits et nanosecondes, dans l'echelle
/// de temps du domaine (TAI par defaut, sans secondes intercalaires).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PtpTimestamp {
    pub seconds: u64,
    pub nanoseconds: u32,
}

/// Qualite d'horloge annoncee par un grand maitre (IEEE 1588-2008 §5.3.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClockQuality {
    pub clock_class: u8,
    pub clock_accuracy: u8,
    pub offset_scaled_log_variance: u16,
}

/// En-tete commun PTPv2, 34 octets (IEEE 1588-2008 §13.3).
///
/// ```mermaid
/// ---
/// title: PtpV2Header
/// ---
/// packet-beta
/// 0-3: "majorSdoId u4"
/// 4-7: "messageType u4"
/// 8-11: "minorVersionPTP u4"
/// 12-15: "versionPTP u4"
/// 16-31: "messageLength u16"
/// 32-39: "domainNumber u8"
/// 40-47: "minorSdoId u8"
/// 48-63: "flagField u16"
/// 64-127: "correctionField i64"
/// 128-159: "messageTypeSpecific u32"
/// 160-239: "sourcePortIdentity 10 octets"
/// 240-255: "sequenceId u16"
/// 256-263: "controlField u8"
/// 264-271: "logMessageInterval i8"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PtpV2Header {
    /// majorSdoId (1588-2019), transportSpecific en 1588-2008 : 1 pour
    /// 802.1AS (gPTP).
    pub major_sdo_id: u8,
    pub message_type: u8,
    pub minor_version_ptp: u8,
    pub version_ptp: u8,
    pub message_length: u16,
    pub domain_number: u8,
    /// minorSdoId (1588-2019), reserve en 1588-2008.
    pub minor_sdo_id: u8,
    pub flags: u16,
    /// Nanosecondes multipliees par 2^16.
    pub correction_field: i64,
    pub message_type_specific: u32,
    pub source_port_identity: PortIdentity,
    pub sequence_id: u16,
    /// Herite de PTPv1, conserve pour la compatibilite.
    pub control_field: u8,
    pub log_message_interval: i8,
}

/// Corps d'un message PTPv2, selon son messageType.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PtpV2Body {
    Sync {
        origin_timestamp: PtpTimestamp,
    },
    DelayReq {
        origin_timestamp: PtpTimestamp,
    },
    /// Pdelay_Req : l'horodatage est suivi de 10 octets reserves.
    PdelayReq {
        origin_timestamp: PtpTimestamp,
    },
    PdelayResp {
        request_receipt_timestamp: PtpTimestamp,
        requesting_port_identity: PortIdentity,
    },
    FollowUp {
        precise_origin_timestamp: PtpTimestamp,
    },
    DelayResp {
        receive_timestamp: PtpTimestamp,
        requesting_port_identity: PortIdentity,
    },
    PdelayRespFollowUp {
        response_origin_timestamp: PtpTimestamp,
        requesting_port_identity: PortIdentity,
    },
    Announce(PtpAnnounce),
    Signaling {
        target_port_identity: PortIdentity,
    },
    Management {
        target_port_identity: PortIdentity,
        starting_boundary_hops: u8,
        boundary_hops: u8,
        /// Quartet bas de l'octet : GET, SET, RESPONSE, COMMAND, ACKNOWLEDGE.
        action: u8,
    },
}

/// Corps d'un Announce (IEEE 1588-2008 §13.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PtpAnnounce {
    pub origin_timestamp: PtpTimestamp,
    pub current_utc_offset: i16,
    pub grandmaster_priority1: u8,
    pub grandmaster_clock_quality: ClockQuality,
    pub grandmaster_priority2: u8,
    pub grandmaster_identity: [u8; 8],
    pub steps_removed: u16,
    pub time_source: u8,
}

/// Message PTPv2 : en-tete, corps, TLV et octets hors message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PtpV2Message<'a> {
    pub header: PtpV2Header,
    pub body: PtpV2Body,
    /// TLV qui suivent le corps, jusqu'a `messageLength`.
    pub tlvs: PtpTlvs<'a>,
    /// Octets apres `messageLength` : bourrage Ethernet, ou octets de
    /// l'annexe E sur UDP/IPv6.
    pub trailing: &'a [u8],
}

/// TLV d'un message PTPv2 (IEEE 1588-2008 §14.1), type et valeur brute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PtpTlv<'a> {
    pub tlv_type: u16,
    pub value: &'a [u8],
}

/// Zone TLV d'un message PTPv2 : une vue sans etat, que chaque
/// [`PtpTlvs::iter`] (ou `for tlv in message.tlvs`) parcourt depuis le debut.
///
/// Le decodage du message ne depend pas de la validite des TLV : un TLV
/// tronque sort en erreur de l'iterateur, qui s'arrete ensuite. Zero-copie :
/// chaque valeur emprunte au paquet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtpTlvs<'a> {
    bytes: &'a [u8],
    /// Offset de `bytes` dans le message, pour situer une erreur.
    base: usize,
}

impl<'a> PtpTlvs<'a> {
    /// Les octets bruts de la zone TLV.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Parcourt les TLV dans l'ordre du message.
    pub fn iter(&self) -> PtpTlvIter<'a> {
        PtpTlvIter {
            bytes: self.bytes,
            base: self.base,
            offset: 0,
            failed: false,
        }
    }
}

impl<'a> IntoIterator for PtpTlvs<'a> {
    type Item = Result<PtpTlv<'a>, PtpPacketParseError>;
    type IntoIter = PtpTlvIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterateur rendu par [`PtpTlvs::iter`].
#[derive(Debug, Clone)]
pub struct PtpTlvIter<'a> {
    bytes: &'a [u8],
    base: usize,
    offset: usize,
    failed: bool,
}

impl<'a> Iterator for PtpTlvIter<'a> {
    type Item = Result<PtpTlv<'a>, PtpPacketParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.offset >= self.bytes.len() {
            return None;
        }
        let rest = &self.bytes[self.offset..];
        let truncated = |needed: usize| PtpPacketParseError::TruncatedTlv {
            tlv_type: rest.get(..2).map(|t| u16::from_be_bytes([t[0], t[1]])),
            offset: self.base + self.offset,
            needed,
            available: rest.len(),
        };
        let item = match rest {
            [t0, t1, l0, l1, value @ ..] => {
                let length = usize::from(u16::from_be_bytes([*l0, *l1]));
                match value.get(..length) {
                    Some(value) => {
                        self.offset += 4 + length;
                        Ok(PtpTlv {
                            tlv_type: u16::from_be_bytes([*t0, *t1]),
                            value,
                        })
                    }
                    None => Err(truncated(4 + length)),
                }
            }
            _ => Err(truncated(4)),
        };
        self.failed = item.is_err();
        Some(item)
    }
}

/// Lit une identite de port de 10 octets a `offset`.
fn port_identity(bytes: &[u8], offset: usize) -> PortIdentity {
    let mut clock_identity = [0u8; 8];
    clock_identity.copy_from_slice(&bytes[offset..offset + 8]);
    PortIdentity {
        clock_identity,
        port_number: u16::from_be_bytes([bytes[offset + 8], bytes[offset + 9]]),
    }
}

/// Lit un horodatage de 10 octets a `offset` : secondes u48, nanosecondes u32.
fn timestamp(bytes: &[u8], offset: usize) -> PtpTimestamp {
    let seconds = bytes[offset..offset + 6]
        .iter()
        .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
    PtpTimestamp {
        seconds,
        nanoseconds: u32::from_be_bytes([
            bytes[offset + 6],
            bytes[offset + 7],
            bytes[offset + 8],
            bytes[offset + 9],
        ]),
    }
}

/// Decode le corps d'un message dont la longueur minimale a deja ete
/// verifiee par `validate_message_length` : les lectures sont en bornes.
fn v2_body(message_type: u8, message: &[u8]) -> PtpV2Body {
    const BODY: usize = PTP_V2_HEADER_LENGTH;
    match message_type {
        PTP_MESSAGE_SYNC => PtpV2Body::Sync {
            origin_timestamp: timestamp(message, BODY),
        },
        PTP_MESSAGE_DELAY_REQ => PtpV2Body::DelayReq {
            origin_timestamp: timestamp(message, BODY),
        },
        PTP_MESSAGE_PDELAY_REQ => PtpV2Body::PdelayReq {
            origin_timestamp: timestamp(message, BODY),
        },
        PTP_MESSAGE_PDELAY_RESP => PtpV2Body::PdelayResp {
            request_receipt_timestamp: timestamp(message, BODY),
            requesting_port_identity: port_identity(message, BODY + 10),
        },
        PTP_MESSAGE_FOLLOW_UP => PtpV2Body::FollowUp {
            precise_origin_timestamp: timestamp(message, BODY),
        },
        PTP_MESSAGE_DELAY_RESP => PtpV2Body::DelayResp {
            receive_timestamp: timestamp(message, BODY),
            requesting_port_identity: port_identity(message, BODY + 10),
        },
        PTP_MESSAGE_PDELAY_RESP_FOLLOW_UP => PtpV2Body::PdelayRespFollowUp {
            response_origin_timestamp: timestamp(message, BODY),
            requesting_port_identity: port_identity(message, BODY + 10),
        },
        PTP_MESSAGE_ANNOUNCE => {
            let mut grandmaster_identity = [0u8; 8];
            grandmaster_identity.copy_from_slice(&message[BODY + 19..BODY + 27]);
            PtpV2Body::Announce(PtpAnnounce {
                origin_timestamp: timestamp(message, BODY),
                current_utc_offset: i16::from_be_bytes([message[BODY + 10], message[BODY + 11]]),
                // BODY + 12 : reserve
                grandmaster_priority1: message[BODY + 13],
                grandmaster_clock_quality: ClockQuality {
                    clock_class: message[BODY + 14],
                    clock_accuracy: message[BODY + 15],
                    offset_scaled_log_variance: u16::from_be_bytes([
                        message[BODY + 16],
                        message[BODY + 17],
                    ]),
                },
                grandmaster_priority2: message[BODY + 18],
                grandmaster_identity,
                steps_removed: u16::from_be_bytes([message[BODY + 27], message[BODY + 28]]),
                time_source: message[BODY + 29],
            })
        }
        PTP_MESSAGE_SIGNALING => PtpV2Body::Signaling {
            target_port_identity: port_identity(message, BODY),
        },
        // PTP_MESSAGE_MANAGEMENT, seul type restant apres extract_message_type
        _ => PtpV2Body::Management {
            target_port_identity: port_identity(message, BODY),
            starting_boundary_hops: message[BODY + 10],
            boundary_hops: message[BODY + 11],
            action: message[BODY + 12] & 0x0F,
        },
    }
}

impl<'a> TryFrom<&'a [u8]> for PtpV2Message<'a> {
    type Error = PtpPacketParseError;

    fn try_from(payload: &'a [u8]) -> Result<Self, Self::Error> {
        ensure_len(payload, PTP_V2_HEADER_LENGTH)?;
        let version_ptp = extract_version(payload)?;
        if version_ptp != 2 {
            return Err(PtpPacketParseError::UnsupportedVersion(version_ptp));
        }
        let message_type = extract_message_type(payload[0])?;
        let message_length = u16::from_be_bytes([payload[2], payload[3]]);
        // Les TLV commencent juste apres le corps fixe de leur type. Tout
        // message peut en porter (IEEE 1588-2008 §14.1 ; White Rabbit en met
        // dans ses Announce), pas seulement Signaling et Management.
        let (length, tlv_start) =
            validate_message_length(message_type, message_length, payload.len())?;
        let (message, trailing) = payload.split_at(length);

        let mut correction = [0u8; 8];
        correction.copy_from_slice(&message[8..16]);
        let header = PtpV2Header {
            major_sdo_id: message[0] >> 4,
            message_type,
            minor_version_ptp: message[1] >> 4,
            version_ptp,
            message_length,
            domain_number: message[4],
            minor_sdo_id: message[5],
            flags: u16::from_be_bytes([message[6], message[7]]),
            correction_field: i64::from_be_bytes(correction),
            message_type_specific: u32::from_be_bytes([
                message[16],
                message[17],
                message[18],
                message[19],
            ]),
            source_port_identity: port_identity(message, 20),
            sequence_id: u16::from_be_bytes([message[30], message[31]]),
            control_field: message[32],
            log_message_interval: i8::from_be_bytes([message[33]]),
        };

        Ok(PtpV2Message {
            header,
            body: v2_body(message_type, message),
            tlvs: PtpTlvs {
                bytes: &message[tlv_start..],
                base: tlv_start,
            },
            trailing,
        })
    }
}

/// En-tete commun PTPv1, 40 octets (IEEE 1588-2002 §6.4.2).
///
/// ```mermaid
/// ---
/// title: PtpV1Header
/// ---
/// packet-beta
/// 0-15: "versionPTP u16"
/// 16-31: "versionNetwork u16"
/// 32-159: "subdomain 16 octets"
/// 160-167: "messageType u8"
/// 168-175: "sourceCommunicationTechnology u8"
/// 176-223: "sourceUuid 6 octets"
/// 224-239: "sourcePortId u16"
/// 240-255: "sequenceId u16"
/// 256-263: "control u8"
/// 264-271: "reserved u8"
/// 272-287: "flags u16"
/// 288-319: "reserved u32"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PtpV1Header<'a> {
    pub version_ptp: u16,
    pub version_network: u16,
    /// Nom du sous-domaine, complete par des octets nuls (`_DFLT` par defaut).
    pub subdomain: &'a [u8],
    /// 1 : message d'evenement ; 2 : message general.
    pub message_type: u8,
    pub source_communication_technology: u8,
    pub source_uuid: [u8; 6],
    pub source_port_id: u16,
    pub sequence_id: u16,
    /// 0 Sync, 1 Delay_Req, 2 Follow_Up, 3 Delay_Resp, 4 Management.
    pub control: u8,
    pub flags: u16,
}

/// Message PTPv1 : en-tete decode, corps brut.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PtpV1Message<'a> {
    pub header: PtpV1Header<'a>,
    pub body: &'a [u8],
}

impl<'a> TryFrom<&'a [u8]> for PtpV1Message<'a> {
    type Error = PtpPacketParseError;

    fn try_from(payload: &'a [u8]) -> Result<Self, Self::Error> {
        ensure_len(payload, PTP_V1_HEADER_LENGTH)?;
        let version_ptp = u16::from_be_bytes([payload[0], payload[1]]);
        if version_ptp != 1 {
            return Err(PtpPacketParseError::InvalidV1VersionPtp(version_ptp));
        }
        let version_network = extract_network_version([payload[2], payload[3]])?;
        let message_type = payload[20];
        let control = extract_v1_control(message_type, payload[32])?;
        validate_v1_length(control, payload.len())?;

        let mut source_uuid = [0u8; 6];
        source_uuid.copy_from_slice(&payload[22..28]);
        Ok(PtpV1Message {
            header: PtpV1Header {
                version_ptp,
                version_network,
                subdomain: &payload[4..20],
                message_type,
                source_communication_technology: payload[21],
                source_uuid,
                source_port_id: u16::from_be_bytes([payload[28], payload[29]]),
                sequence_id: u16::from_be_bytes([payload[30], payload[31]]),
                control,
                flags: u16::from_be_bytes([payload[34], payload[35]]),
            },
            body: &payload[PTP_V1_HEADER_LENGTH..],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ptp/wireshark_6126_nodeb_startup.pcap` trame 113 (UDP 319) : un
    /// Delay_Req de 44 octets. tshark : flags 0x0400, clockIdentity
    /// 0x1880f5ffff31353d port 1, sequenceId 1, controlField 1,
    /// logMessageInterval 127.
    const NODEB_DELAY_REQ_FRAME_113: &str =
        "0102002c000004000000000000000000000000001880f5ffff31353d00010001017f0000000000051839f1a8";

    /// `ptp/ndpi_ptpv2.pcap` trame 1 (UDP/IPv6 320) : un Signaling de 54
    /// octets vers tous les ports (0xffffffffffffffff:65535), qui porte un TLV
    /// Request unicast transmission (0x0004) de 6 octets, puis les deux
    /// octets de l'annexe E.
    const NDPI_SIGNALING_FRAME_1: &str = "0c02003600000400000000000000000000000000002094fffe00000d0001000105ffffffffffffffffffffff00040006b0000000012c0000";

    fn bytes(hex_fixture: &str) -> Vec<u8> {
        hex::decode(hex_fixture).expect("hex valide")
    }

    #[test]
    fn delay_req_decodes_against_the_wire() {
        let payload = bytes(NODEB_DELAY_REQ_FRAME_113);
        let PtpPacket::V2(message) = PtpPacket::try_from_udp(&payload).expect("Delay_Req") else {
            panic!("PTPv2 attendu");
        };
        let header = message.header;
        assert_eq!(header.message_type, PTP_MESSAGE_DELAY_REQ);
        assert_eq!(header.message_length, 44);
        assert_eq!(header.flags, 0x0400);
        assert_eq!(
            header.source_port_identity,
            PortIdentity {
                clock_identity: [0x18, 0x80, 0xf5, 0xff, 0xff, 0x31, 0x35, 0x3d],
                port_number: 1,
            }
        );
        assert_eq!(header.sequence_id, 1);
        assert_eq!(header.control_field, 1);
        assert_eq!(header.log_message_interval, 127);
        assert!(matches!(message.body, PtpV2Body::DelayReq { .. }));
        assert_eq!(message.tlvs.iter().count(), 0);
        assert!(message.trailing.is_empty());
    }

    #[test]
    fn signaling_lists_its_tlv_and_keeps_the_annex_e_octets() {
        let payload = bytes(NDPI_SIGNALING_FRAME_1);
        let PtpPacket::V2(message) = PtpPacket::try_from_udp(&payload).expect("Signaling") else {
            panic!("PTPv2 attendu");
        };
        assert_eq!(message.header.message_length, 54);
        assert_eq!(message.header.log_message_interval, -1);
        assert_eq!(
            message.body,
            PtpV2Body::Signaling {
                target_port_identity: PortIdentity {
                    clock_identity: [0xff; 8],
                    port_number: 0xffff,
                }
            }
        );
        let tlvs: Vec<_> = message.tlvs.iter().collect();
        assert_eq!(
            tlvs,
            [Ok(PtpTlv {
                tlv_type: 0x0004,
                value: &[0xb0, 0x00, 0x00, 0x00, 0x01, 0x2c],
            })]
        );
        assert_eq!(message.trailing, [0x00, 0x00]);
    }

    /// Synthetique : un octet de plus que l'annexe E n'en autorise.
    #[test]
    fn udp_refuses_other_trailing_lengths_but_layer_2_keeps_them() {
        let mut payload = bytes(NDPI_SIGNALING_FRAME_1);
        payload.push(0);
        assert_eq!(
            PtpPacket::try_from_udp(&payload),
            Err(PtpPacketParseError::UnexpectedTrailingBytes { trailing: 3 })
        );
        assert!(PtpPacket::try_from(payload.as_slice()).is_ok());
    }

    /// Synthetique : TLV dont la longueur depasse messageLength.
    #[test]
    fn truncated_tlv_is_reported_by_the_iterator_only() {
        let mut payload = bytes(NDPI_SIGNALING_FRAME_1);
        payload[47] = 0x07; // lengthField 6 -> 7
        let PtpPacket::V2(message) = PtpPacket::try_from_udp(&payload).expect("message decode")
        else {
            panic!("PTPv2 attendu");
        };
        let tlvs: Vec<_> = message.tlvs.iter().collect();
        assert_eq!(
            tlvs,
            [Err(PtpPacketParseError::TruncatedTlv {
                tlv_type: Some(0x0004),
                offset: 44,
                needed: 11,
                available: 10,
            })]
        );
    }

    /// Synthetique : messageLength plus court que le corps de son type.
    #[test]
    fn message_length_shorter_than_the_body_is_refused() {
        let mut payload = bytes(NODEB_DELAY_REQ_FRAME_113);
        payload[3] = 43;
        assert!(matches!(
            PtpPacket::try_from(payload.as_slice()),
            Err(PtpPacketParseError::InvalidMessageLength { declared: 43, .. })
        ));
    }

    #[test]
    fn truncated_and_reserved_inputs_are_refused() {
        let payload = bytes(NODEB_DELAY_REQ_FRAME_113);
        assert!(matches!(
            PtpPacket::try_from(&payload[..33]),
            Err(PtpPacketParseError::Truncated { .. })
        ));
        let mut reserved = payload.clone();
        reserved[0] = 0x05;
        assert_eq!(
            PtpPacket::try_from(reserved.as_slice()),
            Err(PtpPacketParseError::ReservedMessageType(0x5))
        );
    }

    /// Synthetique : le quartet bas de l'octet 1 annonce PTPv1, mais le
    /// versionPTP u16 vaut 0x1001. L'erreur donne la valeur lue.
    #[test]
    fn v1_reports_the_versionptp_it_read() {
        let mut payload = [0u8; 124];
        payload[0] = 0x10;
        payload[1] = 0x01;
        assert_eq!(
            PtpPacket::try_from(&payload[..]),
            Err(PtpPacketParseError::InvalidV1VersionPtp(0x1001))
        );
    }
}
