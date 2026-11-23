// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Parseurs NetBIOS (RFC 1001/1002) : Name Service (NBNS, UDP 137),
//! Session Service (NBSS, TCP 139) et Datagram Service (NBDS, UDP 138,
//! #377).
//!
//! Le service de datagrammes porte les messages sans connexion d'un nom
//! NetBIOS a un autre : surtout les annonces et les elections du service
//! Browser de Windows, et les requetes NETLOGON, en SMB sur mailslot. Les
//! donnees utilisateur sont rendues telles quelles.

use std::{convert::TryFrom, net::Ipv4Addr};

use crate::{
    checks::application::netbios::{
        NBDS_DATAGRAM_HEADER_LENGTH, NBDS_HEADER_LENGTH, NBNS_HEADER_LENGTH,
        NBNS_QUESTION_MIN_LENGTH, NBNS_RECORD_MIN_LENGTH, NBSS_HEADER_LENGTH, extract_nbds_flags,
        extract_nbds_message_type, extract_nbds_name, extract_nbns_counts, extract_nbns_flags,
        extract_nbns_question, extract_nbns_record, extract_nbss_length, extract_nbss_message_type,
        validate_nbds_datagram_length, validate_nbds_end, validate_nbds_length,
        validate_nbns_min_length, validate_nbss_length_for_type, validate_nbss_min_length,
        validate_nbss_payload_available,
    },
    errors::application::netbios::{NbdsError, NbnsError, NbssError},
};

use super::bounded_capacity;

/// Nom NetBIOS decode du "first-level encoding" (RFC 1001 §14.1).
///
/// Sur le wire, le nom occupe 32 octets : chaque demi-octet des 16 octets
/// reels est additionne a 'A'. Une fois decode, les 15 premiers octets sont
/// le nom (complete par des espaces) et le seizieme est le suffixe de
/// service (0x00 workstation, 0x1b domain master browser, 0x20 file
/// server...).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetbiosName {
    /// Nom decode, 15 octets completes par des espaces.
    pub name: [u8; 15],
    /// Seizieme octet decode : suffixe de service.
    pub suffix: u8,
}

impl NetbiosName {
    /// Nom sans le remplissage (espaces et octets nuls de queue).
    pub fn trimmed(&self) -> &[u8] {
        let end = self
            .name
            .iter()
            .rposition(|byte| *byte != b' ' && *byte != 0)
            .map_or(0, |position| position + 1);
        &self.name[..end]
    }

    /// Nom en `&str` si le contenu decode est de l'ASCII imprimable.
    pub fn as_str(&self) -> Option<&str> {
        let trimmed = self.trimmed();
        if trimmed.iter().all(|byte| (0x20..=0x7e).contains(byte)) {
            core::str::from_utf8(trimmed).ok()
        } else {
            None
        }
    }
}

/// Flags NBNS decomposes (RFC 1002 §4.2.1.1).
///
/// Le mot de 16 bits suit le gabarit DNS mais avec un jeu d'opcodes propre
/// et un bit B (broadcast) dans la zone que DNS reserve a zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct NbnsFlags {
    /// Bit R : requete (false) ou reponse (true).
    pub response: bool,
    /// 0x0 query, 0x5 registration, 0x6 release, 0x7 WACK, 0x8 refresh,
    /// 0xf registration multi-domicile (extension Microsoft).
    pub opcode: u8,
    pub authoritative_answer: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    /// Bit B : requete diffusee en broadcast.
    pub broadcast: bool,
    pub rcode: u8,
}

/// Types de question et d'enregistrement NBNS (RFC 1002 §4.2.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NbnsRecordType {
    /// A (0x0001), historique.
    Address,
    /// NS (0x0002), historique.
    NameServer,
    /// NULL (0x000A).
    Null,
    /// NB (0x0020) : enregistrement de nom.
    NetBios,
    /// NBSTAT (0x0021) : statut de noeud.
    NodeStatus,
}

/// Question NBNS : nom decode, scope brut eventuel, type.
///
/// La classe, toujours IN, est validee puis omise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct NbnsQuestion<'a> {
    pub name: NetbiosName,
    /// Labels de scope bruts (longueur + octets), vides en pratique.
    pub scope: &'a [u8],
    pub question_type: NbnsRecordType,
}

/// Enregistrement NBNS, RDATA garde brut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct NbnsResourceRecord<'a> {
    pub name: NetbiosName,
    /// Labels de scope bruts (longueur + octets), vides en pratique.
    pub scope: &'a [u8],
    pub record_type: NbnsRecordType,
    pub ttl: u32,
    /// RDATA borne, structure dependante du type (flags + adresse pour NB).
    pub rdata: &'a [u8],
}

/// Paquet NetBIOS Name Service (RFC 1002 §4.2), UDP port 137.
///
/// L'en-tete reprend le gabarit DNS de 12 octets ; les noms utilisent le
/// "first-level encoding" de la RFC 1001 §14.1.
///
/// ```mermaid
/// ---
/// title: NbnsPacket
/// ---
/// packet-beta
/// 0-15: "NAME_TRN_ID u16"
/// 16-16: "R"
/// 17-20: "OPCODE"
/// 21-27: "NM_FLAGS (AA TC RD RA 0 0 B)"
/// 28-31: "RCODE"
/// 32-47: "QDCOUNT u16"
/// 48-63: "ANCOUNT u16"
/// 64-79: "NSCOUNT u16"
/// 80-95: "ARCOUNT u16"
/// 96-127: "Questions puis enregistrements (noms 32 octets first-level)"
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NbnsPacket<'a> {
    pub transaction_id: u16,
    pub flags: NbnsFlags,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
    pub questions: Vec<NbnsQuestion<'a>>,
    /// Enregistrements answer, authority puis additional, dans l'ordre wire.
    pub resource_records: Vec<NbnsResourceRecord<'a>>,
}

impl<'a> TryFrom<&'a [u8]> for NbnsPacket<'a> {
    type Error = NbnsError;

    fn try_from(packet: &'a [u8]) -> Result<Self, NbnsError> {
        validate_nbns_min_length(packet)?;

        let transaction_id = u16::from_be_bytes([packet[0], packet[1]]);
        let flags = extract_nbns_flags(u16::from_be_bytes([packet[2], packet[3]]))?;
        let [
            question_count,
            answer_count,
            authority_count,
            additional_count,
        ] = extract_nbns_counts(packet)?;

        let mut offset = NBNS_HEADER_LENGTH;

        let mut questions = Vec::with_capacity(bounded_capacity(
            question_count as usize,
            packet.len() - offset,
            NBNS_QUESTION_MIN_LENGTH,
        ));
        for _ in 0..question_count {
            let (question, next) = extract_nbns_question(packet, offset)?;
            questions.push(question);
            offset = next;
        }

        let record_count =
            answer_count as usize + authority_count as usize + additional_count as usize;
        let mut resource_records = Vec::with_capacity(bounded_capacity(
            record_count,
            packet.len().saturating_sub(offset),
            NBNS_RECORD_MIN_LENGTH,
        ));
        for _ in 0..record_count {
            let (record, next) = extract_nbns_record(packet, offset)?;
            resource_records.push(record);
            offset = next;
        }

        Ok(NbnsPacket {
            transaction_id,
            flags,
            question_count,
            answer_count,
            authority_count,
            additional_count,
            questions,
            resource_records,
        })
    }
}

/// Type de message NBSS (RFC 1002 §4.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NbssMessageType {
    /// 0x00 : session message, porte le payload applicatif (SMB).
    SessionMessage,
    /// 0x81 : session request, noms appele et appelant.
    SessionRequest,
    /// 0x82 : positive session response, payload vide.
    PositiveSessionResponse,
    /// 0x83 : negative session response, un octet de code d'erreur.
    NegativeSessionResponse,
    /// 0x84 : retarget session response, adresse IP + port.
    RetargetSessionResponse,
    /// 0x85 : session keep-alive, payload vide.
    SessionKeepAlive,
}

impl NbssMessageType {
    /// Valeur wire du type.
    pub const fn code(self) -> u8 {
        match self {
            NbssMessageType::SessionMessage => 0x00,
            NbssMessageType::SessionRequest => 0x81,
            NbssMessageType::PositiveSessionResponse => 0x82,
            NbssMessageType::NegativeSessionResponse => 0x83,
            NbssMessageType::RetargetSessionResponse => 0x84,
            NbssMessageType::SessionKeepAlive => 0x85,
        }
    }
}

/// En-tete NBSS de 4 octets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct NbssHeader {
    pub message_type: NbssMessageType,
    /// Longueur annoncee du payload : 16 bits plus le bit d'extension du
    /// champ flags, soit 17 bits utiles (max 131071).
    pub length: u32,
}

/// Paquet NetBIOS Session Service (RFC 1002 §4.3), TCP port 139.
///
/// Le meme en-tete encapsule aussi SMB en direct hosting sur TCP 445, ou le
/// type reste 0x00 et le champ flags sert d'octet haut de longueur — les 302
/// trames NBSS du corpus sont de cette forme.
///
/// ```mermaid
/// ---
/// title: NbssPacket
/// ---
/// packet-beta
/// 0-7: "TYPE u8 (0x00, 0x81..0x85)"
/// 8-14: "FLAGS reserves (0)"
/// 15-15: "E"
/// 16-31: "LENGTH u16 (bit 17 dans E)"
/// 32-63: "Payload borne par LENGTH"
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NbssPacket<'a> {
    pub header: NbssHeader,
    /// Payload borne par la longueur annoncee : les octets d'un eventuel
    /// message NBSS suivant dans le meme segment n'y fuient pas.
    pub payload: &'a [u8],
}

impl<'a> TryFrom<&'a [u8]> for NbssPacket<'a> {
    type Error = NbssError;

    fn try_from(packet: &'a [u8]) -> Result<Self, NbssError> {
        validate_nbss_min_length(packet)?;

        let message_type = extract_nbss_message_type(packet[0])?;
        let length = extract_nbss_length(packet)?;
        validate_nbss_length_for_type(message_type, length)?;
        validate_nbss_payload_available(packet.len(), length)?;

        Ok(NbssPacket {
            header: NbssHeader {
                message_type,
                length,
            },
            payload: &packet[NBSS_HEADER_LENGTH..NBSS_HEADER_LENGTH + length as usize],
        })
    }
}

/// Message type of an NBDS packet (RFC 1002 §4.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NbdsMessageType {
    /// 0x10: datagram to a unique name.
    DirectUnique,
    /// 0x11: datagram to a group name.
    DirectGroup,
    /// 0x12: datagram to every name.
    Broadcast,
    /// 0x13: a datagram could not be delivered.
    Error,
    /// 0x14: asks a datagram distribution server whether it knows a name.
    QueryRequest,
    /// 0x15: the server will relay to that name.
    PositiveQueryResponse,
    /// 0x16: the server will not.
    NegativeQueryResponse,
}

impl NbdsMessageType {
    /// Value of the type on the wire.
    pub const fn code(self) -> u8 {
        match self {
            NbdsMessageType::DirectUnique => 0x10,
            NbdsMessageType::DirectGroup => 0x11,
            NbdsMessageType::Broadcast => 0x12,
            NbdsMessageType::Error => 0x13,
            NbdsMessageType::QueryRequest => 0x14,
            NbdsMessageType::PositiveQueryResponse => 0x15,
            NbdsMessageType::NegativeQueryResponse => 0x16,
        }
    }
}

/// Flags of an NBDS packet (RFC 1002 §4.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct NbdsFlags {
    /// Node type of the sender: 0 B node, 1 P node, 2 M node, 3 NBDD.
    pub node_type: u8,
    /// Bit F: first fragment of the datagram.
    pub first: bool,
    /// Bit M: more fragments follow.
    pub more: bool,
}

/// A datagram carried by NBDS, types 0x10 to 0x12 ([`NbdsBody::Datagram`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct NbdsDatagram<'a> {
    /// Length of the two names and of the user data of the whole NetBIOS
    /// datagram. It is the number of bytes that follow the packet offset,
    /// except in a first fragment ([`NbdsFlags::more`]), which announces
    /// more bytes than it carries: the rest travels in a second packet.
    pub length: u16,
    /// Offset of this fragment in the user data of the whole datagram.
    pub packet_offset: u16,
    pub source_name: NetbiosName,
    /// Raw scope labels of the source name, empty in practice.
    pub source_scope: &'a [u8],
    pub destination_name: NetbiosName,
    /// Raw scope labels of the destination name, empty in practice.
    pub destination_scope: &'a [u8],
    /// What the datagram carries, most often SMB on a mailslot; not
    /// decoded. In a first fragment, the first bytes of it only.
    pub user_data: &'a [u8],
}

/// What follows the common header of an NBDS packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NbdsBody<'a> {
    /// Types 0x10 to 0x12: names and user data.
    Datagram(NbdsDatagram<'a>),
    /// Type 0x13: the error code, 0x82 (destination name not present),
    /// 0x83 (invalid source name format) or 0x84 (invalid destination name
    /// format).
    #[non_exhaustive]
    Error { code: u8 },
    /// Types 0x14 to 0x16: the name a datagram distribution server is
    /// asked about.
    #[non_exhaustive]
    Query {
        destination_name: NetbiosName,
        /// Raw scope labels of the name, empty in practice.
        destination_scope: &'a [u8],
    },
}

/// NetBIOS Datagram Service packet (RFC 1002 §4.4), UDP port 138.
///
/// ```mermaid
/// ---
/// title: NbdsPacket, datagram (types 0x10 to 0x12)
/// ---
/// packet-beta
/// 0-7: "MSG_TYPE u8"
/// 8-11: "reserved (0)"
/// 12-13: "SNT"
/// 14-14: "F"
/// 15-15: "M"
/// 16-31: "DGM_ID u16"
/// 32-63: "SOURCE_IP"
/// 64-79: "SOURCE_PORT u16"
/// 80-95: "DGM_LENGTH u16"
/// 96-111: "PACKET_OFFSET u16"
/// 112-175: "SOURCE_NAME (34 bytes, first-level encoding)"
/// 176-239: "DESTINATION_NAME (34 bytes)"
/// 240-287: "USER_DATA"
/// ```
///
/// An error (0x13) carries one byte of error code after the source port; a
/// query (0x14 to 0x16) carries the destination name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct NbdsPacket<'a> {
    pub message_type: NbdsMessageType,
    pub flags: NbdsFlags,
    /// Identifier of the datagram, shared by its fragments.
    pub datagram_id: u16,
    /// Address of the sender, as it writes it.
    pub source_ip: Ipv4Addr,
    pub source_port: u16,
    pub body: NbdsBody<'a>,
}

impl<'a> TryFrom<&'a [u8]> for NbdsPacket<'a> {
    type Error = NbdsError;

    fn try_from(packet: &'a [u8]) -> Result<Self, NbdsError> {
        validate_nbds_length(packet, NBDS_HEADER_LENGTH)?;

        let message_type = extract_nbds_message_type(packet[0])?;
        let flags = extract_nbds_flags(packet[1])?;
        let datagram_id = u16::from_be_bytes([packet[2], packet[3]]);
        let source_ip = Ipv4Addr::new(packet[4], packet[5], packet[6], packet[7]);
        let source_port = u16::from_be_bytes([packet[8], packet[9]]);

        let body = match message_type {
            NbdsMessageType::DirectUnique
            | NbdsMessageType::DirectGroup
            | NbdsMessageType::Broadcast => {
                validate_nbds_length(packet, NBDS_DATAGRAM_HEADER_LENGTH)?;
                let length = u16::from_be_bytes([packet[10], packet[11]]);
                let packet_offset = u16::from_be_bytes([packet[12], packet[13]]);
                validate_nbds_datagram_length(packet, flags, length)?;
                let (source_name, source_scope, next) =
                    extract_nbds_name(packet, NBDS_DATAGRAM_HEADER_LENGTH)?;
                let (destination_name, destination_scope, next) = extract_nbds_name(packet, next)?;
                NbdsBody::Datagram(NbdsDatagram {
                    length,
                    packet_offset,
                    source_name,
                    source_scope,
                    destination_name,
                    destination_scope,
                    user_data: &packet[next..],
                })
            }
            NbdsMessageType::Error => {
                validate_nbds_length(packet, NBDS_HEADER_LENGTH + 1)?;
                validate_nbds_end(packet, NBDS_HEADER_LENGTH + 1)?;
                NbdsBody::Error {
                    code: packet[NBDS_HEADER_LENGTH],
                }
            }
            NbdsMessageType::QueryRequest
            | NbdsMessageType::PositiveQueryResponse
            | NbdsMessageType::NegativeQueryResponse => {
                let (destination_name, destination_scope, next) =
                    extract_nbds_name(packet, NBDS_HEADER_LENGTH)?;
                validate_nbds_end(packet, next)?;
                NbdsBody::Query {
                    destination_name,
                    destination_scope,
                }
            }
        };

        Ok(NbdsPacket {
            message_type,
            flags,
            datagram_id,
            source_ip,
            source_port,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ApplicationProtocol, TransportProtocol};

    /// Trame 38172 : registration broadcast de JOHANNES-DELL<00>, question
    /// NB + enregistrement additional dont le nom est un pointeur c00c
    /// (pcaps_exemple/The-Ultimate-PCAP.pcapng, payload UDP 137 -> 137).
    const NBNS_REGISTRATION_HEX: &str = concat!(
        "d9302910000100000000000120454b455045494542454f454f45464644434e45",
        "454546454d454d4341434141410000200001c00c00200001000493e000066000",
        "a9fe8c84"
    );

    /// Trame 38229 : name query broadcast de WEBERLAB<1b>
    /// (pcaps_exemple/The-Ultimate-PCAP.pcapng, payload UDP 137 -> 137).
    const NBNS_QUERY_HEX: &str = concat!(
        "d93f011000010000000000002046484546454345464643454d45424543434143",
        "4143414341434143414341424c0000200001"
    );

    fn payload(hex_fixture: &str) -> Vec<u8> {
        hex::decode(hex_fixture).expect("invalid test hex fixture")
    }

    #[test]
    fn parses_a_captured_registration_with_pointer_name() {
        let bytes = payload(NBNS_REGISTRATION_HEX);
        let packet = NbnsPacket::try_from(bytes.as_slice()).expect("captured payload parses");

        assert_eq!(packet.transaction_id, 0xd930);
        assert!(!packet.flags.response);
        assert_eq!(packet.flags.opcode, 0x5);
        assert!(packet.flags.broadcast);
        assert_eq!(packet.question_count, 1);
        assert_eq!(packet.additional_count, 1);

        let question = &packet.questions[0];
        assert_eq!(question.name.as_str(), Some("JOHANNES-DELL"));
        assert_eq!(question.name.suffix, 0x00);
        assert!(question.scope.is_empty());
        assert_eq!(question.question_type, NbnsRecordType::NetBios);

        // Le nom de l'additional est le pointeur c00c vers la question.
        let record = &packet.resource_records[0];
        assert_eq!(record.name, question.name);
        assert_eq!(record.record_type, NbnsRecordType::NetBios);
        assert_eq!(record.ttl, 300_000);
        // RDATA : flags NB (0x6000) + adresse 169.254.140.132.
        assert_eq!(record.rdata, [0x60, 0x00, 0xa9, 0xfe, 0x8c, 0x84]);
    }

    #[test]
    fn parses_a_captured_name_query() {
        let bytes = payload(NBNS_QUERY_HEX);
        let packet = NbnsPacket::try_from(bytes.as_slice()).expect("captured payload parses");

        assert_eq!(packet.transaction_id, 0xd93f);
        assert_eq!(packet.flags.opcode, 0x0);
        assert!(packet.flags.broadcast);
        assert_eq!(packet.question_count, 1);
        assert!(packet.resource_records.is_empty());

        let question = &packet.questions[0];
        assert_eq!(question.name.as_str(), Some("WEBERLAB"));
        assert_eq!(question.name.suffix, 0x1b);
        assert_eq!(question.question_type, NbnsRecordType::NetBios);
    }

    /// Synthetique : en-tete incomplet.
    #[test]
    fn rejects_a_packet_shorter_than_the_header() {
        let result = NbnsPacket::try_from(&[0u8; 11][..]);

        assert_eq!(
            result,
            Err(NbnsError::InvalidLength {
                expected: 12,
                actual: 11
            })
        );
    }

    /// La reponse negative d'un serveur WINS a la requete de la trame 38229 :
    /// en-tete `8583` (reponse, AA, RD, NAM_ERR), un enregistrement NULL de
    /// TTL et RDLENGTH nuls (RFC 1002 §4.2.14). Construite a partir de la
    /// requete reelle, faute de reponse negative dans le corpus.
    fn negative_query_response(flags: [u8; 2], answers: u8) -> Vec<u8> {
        let query = payload(NBNS_QUERY_HEX);
        let mut bytes = query[..2].to_vec();
        bytes.extend_from_slice(&flags);
        bytes.extend_from_slice(&[0, 0, 0, answers, 0, 0, 0, 0]);
        // Le nom encode (34 octets), puis NULL, IN, TTL et RDLENGTH nuls.
        bytes.extend_from_slice(&query[12..46]);
        bytes.extend_from_slice(&[0x00, 0x0a, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        bytes
    }

    #[test]
    fn a_name_error_response_is_nbns() {
        let bytes = negative_query_response([0x85, 0x83], 1);

        let packet = NbnsPacket::try_from(bytes.as_slice()).expect("NAM_ERR response");
        assert!(packet.flags.response);
        assert_eq!(packet.flags.rcode, 0x3);
        assert_eq!(
            crate::classify_payload(TransportProtocol::Udp, Some(137), Some(137), &bytes)
                .map(|application| application.protocol),
            Some(ApplicationProtocol::Nbns)
        );
    }

    /// Le schema du §4.2.14 porte quatre compteurs nuls avant son
    /// enregistrement : le decodeur suit les compteurs et refuse cette forme.
    #[test]
    fn a_negative_response_with_the_literal_zero_counts_is_refused() {
        let bytes = negative_query_response([0x85, 0x83], 0);

        assert_eq!(
            NbnsPacket::try_from(bytes.as_slice()),
            Err(NbnsError::EmptyMessage)
        );
    }

    /// La registration de la trame 38172 passee en refresh a l'opcode 0x9,
    /// celui du schema de NAME REFRESH REQUEST (RFC 1002 §4.2.4).
    #[test]
    fn a_refresh_with_the_alternate_opcode_is_nbns() {
        let mut bytes = payload(NBNS_REGISTRATION_HEX);
        bytes[2..4].copy_from_slice(&[0x48, 0x10]);

        let packet = NbnsPacket::try_from(bytes.as_slice()).expect("refresh, opcode 9");
        assert_eq!(packet.flags.opcode, 0x9);
        assert_eq!(
            crate::classify_payload(TransportProtocol::Udp, Some(137), Some(137), &bytes)
                .map(|application| application.protocol),
            Some(ApplicationProtocol::Nbns)
        );
    }

    /// Synthetique : en-tete valide mais aucune question ni enregistrement.
    #[test]
    fn rejects_an_empty_message() {
        let bytes = [0x12u8, 0x34, 0x01, 0x10, 0, 0, 0, 0, 0, 0, 0, 0];

        assert_eq!(
            NbnsPacket::try_from(&bytes[..]),
            Err(NbnsError::EmptyMessage)
        );
    }

    /// Synthetique : un compteur de questions hostile (0xffff) sur un paquet
    /// minuscule doit echouer proprement, sans pre-allocation demesuree.
    #[test]
    fn bounds_a_hostile_question_count() {
        let mut bytes = payload(NBNS_QUERY_HEX);
        bytes[4] = 0xff;
        bytes[5] = 0xff;

        let result = NbnsPacket::try_from(bytes.as_slice());

        assert!(matches!(
            result,
            Err(NbnsError::TruncatedName { .. }) | Err(NbnsError::TruncatedRecord { .. })
        ));
    }

    /// Synthetique : un compteur d'enregistrements hostile est borne de la
    /// meme facon.
    #[test]
    fn bounds_a_hostile_record_count() {
        let mut bytes = payload(NBNS_REGISTRATION_HEX);
        bytes[10] = 0xff;
        bytes[11] = 0xff;

        let result = NbnsPacket::try_from(bytes.as_slice());

        assert!(matches!(
            result,
            Err(NbnsError::TruncatedName { .. }) | Err(NbnsError::TruncatedRecord { .. })
        ));
    }

    /// Synthetique : RDATA annonce au-dela de la fin du paquet.
    #[test]
    fn rejects_a_record_with_truncated_rdata() {
        let mut bytes = payload(NBNS_REGISTRATION_HEX);
        let rdata_length_offset = bytes.len() - 8;
        bytes[rdata_length_offset] = 0x40;

        let result = NbnsPacket::try_from(bytes.as_slice());

        assert!(matches!(result, Err(NbnsError::TruncatedRecord { .. })));
    }

    /// Synthetique : troncature au milieu du nom encode.
    #[test]
    fn rejects_a_question_with_truncated_name() {
        let bytes = payload(NBNS_QUERY_HEX);

        let result = NbnsPacket::try_from(&bytes[..20]);

        assert!(matches!(result, Err(NbnsError::TruncatedName { .. })));
    }

    /// Trame 39979 : premier segment du Negotiate Protocol Request SMB1,
    /// type 0x00 et longueur 69 (pcaps_exemple/The-Ultimate-PCAP.pcapng,
    /// payload TCP 49958 -> 445).
    const NBSS_NEGOTIATE_HEX: &str = concat!(
        "00000045ff534d4272000000001853c8000000000000000000000000fffffffe",
        "00000000002200024e54204c4d20302e31320002534d4220322e303032000253",
        "4d4220322e3f3f3f00"
    );

    #[test]
    fn parses_a_captured_session_message() {
        let bytes = payload(NBSS_NEGOTIATE_HEX);
        let packet = NbssPacket::try_from(bytes.as_slice()).expect("captured payload parses");

        assert_eq!(packet.header.message_type, NbssMessageType::SessionMessage);
        assert_eq!(packet.header.length, 69);
        assert_eq!(packet.payload.len(), 69);
        // Le payload commence a la signature SMB1.
        assert_eq!(&packet.payload[..4], b"\xffSMB");
    }

    /// Synthetique : en-tete incomplet.
    #[test]
    fn rejects_an_nbss_packet_shorter_than_the_header() {
        let result = NbssPacket::try_from(&[0x00u8, 0x00, 0x00][..]);

        assert_eq!(
            result,
            Err(NbssError::InvalidLength {
                expected: 4,
                actual: 3
            })
        );
    }

    /// Synthetique : type hors de la table RFC 1002.
    #[test]
    fn rejects_an_unknown_nbss_type() {
        let result = NbssPacket::try_from(&[0x7fu8, 0x00, 0x00, 0x00][..]);

        assert_eq!(result, Err(NbssError::UnknownMessageType(0x7f)));
    }

    /// Synthetique : longueur annoncee au-dela des octets disponibles —
    /// segment TCP tronque ou champ hostile.
    #[test]
    fn rejects_a_truncated_session_message() {
        let bytes = payload(NBSS_NEGOTIATE_HEX);

        let result = NbssPacket::try_from(&bytes[..20]);

        assert_eq!(
            result,
            Err(NbssError::TruncatedPayload {
                announced: 69,
                available: 16
            })
        );
    }

    /// Synthetique : le bit d'extension porte la longueur a 17 bits ; sur un
    /// petit buffer le parseur doit refuser sans paniquer ni allouer.
    #[test]
    fn bounds_a_17_bit_hostile_length() {
        let result = NbssPacket::try_from(&[0x00u8, 0x01, 0xff, 0xff][..]);

        assert_eq!(
            result,
            Err(NbssError::TruncatedPayload {
                announced: 131_071,
                available: 0
            })
        );
    }

    /// Synthetique : keep-alive (0x85), absent du corpus, payload vide exige.
    #[test]
    fn accepts_a_keep_alive_and_rejects_one_with_payload() {
        let keep_alive = NbssPacket::try_from(&[0x85u8, 0x00, 0x00, 0x00][..])
            .expect("keep-alive without payload parses");
        assert_eq!(
            keep_alive.header.message_type,
            NbssMessageType::SessionKeepAlive
        );
        assert!(keep_alive.payload.is_empty());

        let result = NbssPacket::try_from(&[0x85u8, 0x00, 0x00, 0x01, 0xaa][..]);
        assert_eq!(
            result,
            Err(NbssError::InvalidPayloadLength {
                message_type: 0x85,
                length: 1
            })
        );
    }

    /// Synthetique : negative session response (0x83), absent du corpus,
    /// exactement un octet de code d'erreur.
    #[test]
    fn validates_the_negative_session_response_length() {
        let negative = NbssPacket::try_from(&[0x83u8, 0x00, 0x00, 0x01, 0x8f][..])
            .expect("negative response with one error byte parses");
        assert_eq!(negative.payload, [0x8f]);

        let result = NbssPacket::try_from(&[0x83u8, 0x00, 0x00, 0x00][..]);
        assert_eq!(
            result,
            Err(NbssError::InvalidPayloadLength {
                message_type: 0x83,
                length: 0
            })
        );
    }

    /// Synthetique : session request (0x81), absent du corpus, doit porter au
    /// moins deux noms encodes de 34 octets.
    #[test]
    fn validates_the_session_request_minimum_length() {
        let result = NbssPacket::try_from(&[0x81u8, 0x00, 0x00, 0x04, 1, 2, 3, 4][..]);

        assert_eq!(
            result,
            Err(NbssError::InvalidPayloadLength {
                message_type: 0x81,
                length: 4
            })
        );
    }

    /// Trame 3 de pcaps_exemple/protocols/netbios/smb-browser-elections.pcapng
    /// (211 octets) : annonce de domaine de TUMBLEWEED<00> au groupe
    /// `\x01\x02__MSBROWSE__\x02<01>`.
    const NBDS_DOMAIN_ANNOUNCEMENT_HEX: &str = concat!(
        "11028216c0a87b02008a00c500002046454646454e4543454d45464648454645",
        "46454543414341434143414341414100204142414346504650454e4644454346",
        "434550464846444546465046504143414200ff534d4225000000000000000000",
        "0000000000000000000000000000000000001100002b000000000000000000e8",
        "0300000000000000002b00560003000100010002003c005c4d41494c534c4f54",
        "5c42524f575345000c00a0bb0d0053594e45524954590000000000000100030a",
        "00100080d4febb0154554d424c455745454400",
    );

    /// Trame 4 de la meme capture (179 octets) : election du service
    /// Browser, d'OBSIDIAN<00> a SYNERITY<1d>.
    const NBDS_ELECTION_HEX: &str = concat!(
        "110280d0c0a87b01008a00a5000020455045434644454a4545454a4542454f43",
        "41434143414341434143414341414100204644464a454f45464643454a464546",
        "4a4341434143414341434143414341424e00ff534d4225000000000000000000",
        "0000000000000000000000000000000000001100000b000000000000000000e8",
        "0300000000000000000b00560003000100010002001c005c4d41494c534c4f54",
        "5c42524f5753450002004f4253494449414e00",
    );

    /// Trame 34 de pcaps_exemple/protocols/sip/wireshark_aaa.pcap (201
    /// octets) : annonce d'hote de D002465<20> a ECI_DOMAIN<1d>, drapeaux
    /// 0x0e.
    const NBDS_HOST_ANNOUNCEMENT_HEX: &str = concat!(
        "110e84ecc0a80102008a00bb0000204545444144414443444544474446434143",
        "414341434143414341434143414341002045464544454a465045454550454e45",
        "42454a454f43414341434143414341424e00ff534d4225000000000000000000",
        "00000000000000000000000000000000000011000021000000000000000000e8",
        "03000000000000000021005600030001000000020032005c4d41494c534c4f54",
        "5c42524f57534500010080fc0a00443030323436350000000000000000000500",
        "031000000f0155aa00",
    );

    #[test]
    fn nbds_group_datagram_is_read() {
        let bytes = payload(NBDS_ELECTION_HEX);
        let packet = NbdsPacket::try_from(bytes.as_slice()).expect("datagramme NBDS");
        assert_eq!(packet.message_type, NbdsMessageType::DirectGroup);
        assert_eq!(packet.message_type.code(), 0x11);
        assert_eq!(packet.flags.node_type, 0);
        assert!(packet.flags.first && !packet.flags.more);
        assert_eq!(packet.datagram_id, 0x80d0);
        assert_eq!(packet.source_ip, Ipv4Addr::new(192, 168, 123, 1));
        assert_eq!(packet.source_port, 138);
        let NbdsBody::Datagram(datagram) = packet.body else {
            panic!("pas un datagramme");
        };
        assert_eq!(datagram.length, 165);
        assert_eq!(datagram.packet_offset, 0);
        assert_eq!(datagram.source_name.as_str(), Some("OBSIDIAN"));
        assert_eq!(datagram.source_name.suffix, 0x00);
        assert_eq!(datagram.destination_name.as_str(), Some("SYNERITY"));
        assert_eq!(datagram.destination_name.suffix, 0x1d);
        assert!(datagram.source_scope.is_empty() && datagram.destination_scope.is_empty());
        // Deux noms de 34 octets, puis du SMB sur mailslot.
        assert_eq!(datagram.user_data.len(), 165 - 68);
        assert!(datagram.user_data.starts_with(b"\xffSMB"));
    }

    #[test]
    fn nbds_names_keep_their_raw_bytes() {
        let bytes = payload(NBDS_DOMAIN_ANNOUNCEMENT_HEX);
        let packet = NbdsPacket::try_from(bytes.as_slice()).expect("datagramme NBDS");
        let NbdsBody::Datagram(datagram) = packet.body else {
            panic!("pas un datagramme");
        };
        assert_eq!(datagram.source_name.as_str(), Some("TUMBLEWEED"));
        // Le groupe des maitres explorateurs : des octets non imprimables.
        assert_eq!(&datagram.destination_name.name, b"\x01\x02__MSBROWSE__\x02");
        assert_eq!(datagram.destination_name.suffix, 0x01);
        assert_eq!(datagram.destination_name.as_str(), None);

        // Drapeaux 0x0e : type de noeud 3, premier fragment.
        let bytes = payload(NBDS_HOST_ANNOUNCEMENT_HEX);
        let packet = NbdsPacket::try_from(bytes.as_slice()).expect("datagramme NBDS");
        assert_eq!(packet.flags.node_type, 3);
        assert!(packet.flags.first && !packet.flags.more);
        assert_eq!(packet.source_ip, Ipv4Addr::new(192, 168, 1, 2));
    }

    /// Synthetique : l'election reelle, presentee comme le premier de deux
    /// fragments (drapeau `MORE`, longueur du datagramme entier). Le corpus
    /// n'a aucun datagramme fragmente (#382).
    #[test]
    fn nbds_first_fragment_announces_the_whole_datagram() {
        let whole = payload(NBDS_ELECTION_HEX);
        let fragment = |flags: u8, length: u16| {
            let mut bytes = whole.clone();
            bytes[1] = flags;
            bytes[10..12].copy_from_slice(&length.to_be_bytes());
            bytes
        };

        let bytes = fragment(0x03, 1000);
        let packet = NbdsPacket::try_from(bytes.as_slice()).expect("premier fragment");
        assert!(packet.flags.first && packet.flags.more);
        let NbdsBody::Datagram(datagram) = packet.body else {
            panic!("pas un datagramme");
        };
        // La longueur est celle du datagramme entier ; le paquet porte les
        // deux noms et le debut des donnees.
        assert_eq!(datagram.length, 1000);
        assert_eq!(datagram.packet_offset, 0);
        assert_eq!(datagram.source_name.as_str(), Some("OBSIDIAN"));
        assert_eq!(datagram.destination_name.as_str(), Some("SYNERITY"));
        assert_eq!(datagram.user_data.len(), 165 - 68);

        let length_error = |flags: u8, length: u16| {
            let bytes = fragment(flags, length);
            NbdsPacket::try_from(bytes.as_slice()).map(|_| ())
        };
        // Un premier fragment annonce plus qu'il ne porte.
        for announced in [165, 164] {
            assert_eq!(
                length_error(0x03, announced),
                Err(NbdsError::LengthMismatch {
                    announced: usize::from(announced),
                    actual: 165
                })
            );
        }
        assert_eq!(length_error(0x03, 166), Ok(()));
        // Sans `MORE`, le paquet porte tout le datagramme ; sans `FIRST`,
        // c'est un fragment de suite, qui n'est pas lu.
        for flags in [0x02, 0x00, 0x01] {
            assert_eq!(
                length_error(flags, 1000),
                Err(NbdsError::LengthMismatch {
                    announced: 1000,
                    actual: 165
                }),
                "{flags:#04x}"
            );
        }
    }

    /// La trame reelle, modifiee octet par octet.
    #[test]
    fn nbds_rejects_malformed_datagrams() {
        let bytes = payload(NBDS_ELECTION_HEX);
        let with = |index: usize, value: u8| {
            let mut bytes = bytes.clone();
            bytes[index] = value;
            NbdsPacket::try_from(bytes.as_slice()).map(|_| ())
        };
        assert_eq!(with(0, 0x0f), Err(NbdsError::UnknownMessageType(0x0f)));
        assert_eq!(with(0, 0x17), Err(NbdsError::UnknownMessageType(0x17)));
        assert_eq!(with(1, 0x12), Err(NbdsError::NonZeroReservedFlags(0x12)));
        // La longueur annoncee doit etre celle du datagramme UDP.
        assert_eq!(
            with(11, 0xa4),
            Err(NbdsError::LengthMismatch {
                announced: 164,
                actual: 165
            })
        );
        assert_eq!(
            NbdsPacket::try_from(&bytes[..bytes.len() - 1]).map(|_| ()),
            Err(NbdsError::LengthMismatch {
                announced: 165,
                actual: 164
            })
        );
        // Un nom qui n'est pas un label de 32 octets, ou mal encode.
        assert_eq!(
            with(14, 0x1f),
            Err(NbdsError::InvalidName(NbnsError::InvalidNameLength {
                offset: 14,
                length: 0x1f
            }))
        );
        assert_eq!(
            with(15, b'Q'),
            Err(NbdsError::InvalidName(NbnsError::InvalidNameEncoding {
                offset: 15
            }))
        );
        // Un pointeur de compression n'existe pas dans un nom NBDS.
        assert_eq!(
            with(48, 0xc0),
            Err(NbdsError::InvalidName(NbnsError::InvalidNameLength {
                offset: 48,
                length: 0xc0
            }))
        );
        assert_eq!(
            NbdsPacket::try_from(&bytes[..9]).map(|_| ()),
            Err(NbdsError::InvalidLength {
                expected: 10,
                actual: 9
            })
        );
        assert_eq!(
            NbdsPacket::try_from(&bytes[..12]).map(|_| ()),
            Err(NbdsError::InvalidLength {
                expected: 14,
                actual: 12
            })
        );
    }

    /// Synthetique : les types absents du corpus. Un message d'erreur
    /// (0x13) porte un octet de code ; une requete au serveur de
    /// datagrammes (0x14 a 0x16) porte le nom recherche, pris ici a la
    /// trame reelle.
    #[test]
    fn nbds_error_and_query_messages_are_read() {
        let real = payload(NBDS_ELECTION_HEX);
        let mut error = real[..10].to_vec();
        error[0] = 0x13;
        error.push(0x82);
        let packet = NbdsPacket::try_from(error.as_slice()).expect("erreur NBDS");
        assert_eq!(packet.message_type, NbdsMessageType::Error);
        assert_eq!(packet.body, NbdsBody::Error { code: 0x82 });
        error.push(0);
        assert_eq!(
            NbdsPacket::try_from(error.as_slice()),
            Err(NbdsError::TrailingBytes(1))
        );
        assert_eq!(
            NbdsPacket::try_from(&error[..10]),
            Err(NbdsError::InvalidLength {
                expected: 11,
                actual: 10
            })
        );

        for (code, message_type) in [
            (0x14, NbdsMessageType::QueryRequest),
            (0x15, NbdsMessageType::PositiveQueryResponse),
            (0x16, NbdsMessageType::NegativeQueryResponse),
        ] {
            let mut query = real[..10].to_vec();
            query[0] = code;
            // Le nom destinataire de la trame reelle : SYNERITY<1d>.
            query.extend_from_slice(&real[48..82]);
            let packet = NbdsPacket::try_from(query.as_slice()).expect("requete NBDS");
            assert_eq!(packet.message_type, message_type);
            let NbdsBody::Query {
                destination_name, ..
            } = packet.body
            else {
                panic!("pas une requete");
            };
            assert_eq!(destination_name.as_str(), Some("SYNERITY"));
            query.push(0);
            assert_eq!(
                NbdsPacket::try_from(query.as_slice()),
                Err(NbdsError::TrailingBytes(1))
            );
        }

        // Un datagramme direct (0x10) ou diffuse (0x12) se lit comme un
        // datagramme de groupe.
        for code in [0x10, 0x12] {
            let mut datagram = real.clone();
            datagram[0] = code;
            let packet = NbdsPacket::try_from(datagram.as_slice()).expect("datagramme");
            assert!(matches!(packet.body, NbdsBody::Datagram(_)));
        }
    }
}
