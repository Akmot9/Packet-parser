// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Parseurs NetBIOS (RFC 1001/1002) : Name Service (NBNS, UDP 137) et
//! Session Service (NBSS, TCP 139).
//!
//! Le Datagram Service (UDP 138) n'est pas implemente : le corpus du depot
//! n'en contient aucune trame, il n'y a donc rien a verrouiller par un golden
//! test.

use std::convert::TryFrom;

use crate::{
    checks::application::netbios::{
        NBNS_HEADER_LENGTH, NBNS_QUESTION_MIN_LENGTH, NBNS_RECORD_MIN_LENGTH, NBSS_HEADER_LENGTH,
        extract_nbns_counts, extract_nbns_flags, extract_nbns_question, extract_nbns_record,
        extract_nbss_length, extract_nbss_message_type, validate_nbns_min_length,
        validate_nbss_length_for_type, validate_nbss_min_length, validate_nbss_payload_available,
    },
    errors::application::netbios::{NbnsError, NbssError},
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
pub struct NbnsQuestion<'a> {
    pub name: NetbiosName,
    /// Labels de scope bruts (longueur + octets), vides en pratique.
    pub scope: &'a [u8],
    pub question_type: NbnsRecordType,
}

/// Enregistrement NBNS, RDATA garde brut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
