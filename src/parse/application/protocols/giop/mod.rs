// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! GIOP (General Inter-ORB Protocol), le protocole de CORBA — versions 1.0,
//! 1.1 et 1.2 (CORBA formal/04-03-12 chapitre 15), les huit types de message,
//! dans les deux endianness.
//!
//! Le parseur est **stateless** : il ne reassemble ni les segments TCP ni les
//! messages Fragment. Un message qui deborde du segment est accepte et marque
//! [`GiopPacket::truncated`] ; ses champs d'en-tete, presents dans le premier
//! segment, restent decodes. Les segments suivants, sans magic, ne sont pas
//! reconnaissables sans etat.

use std::convert::TryFrom;

use crate::{
    checks::application::giop::{
        GIOP_HEADER_LEN, GIOP_MAGIC, ensure_min_len, extract_flags, extract_message_size,
        extract_version, parse_magic, validate_message_type, validate_service_context_count,
        validate_target_discriminator,
    },
    errors::application::giop::GiopParseError,
};

mod cursor;
pub mod ior;
pub mod locate;
pub mod reply;

use cursor::Cursor;
pub use ior::{IiopProfile, Ior, TaggedProfile};
pub use locate::{
    GiopCancelRequest, GiopFragment, GiopLocateReply, GiopLocateReplyDetail, GiopLocateRequest,
    GiopLocateStatus,
};
pub use reply::{GiopReply, GiopReplyDetail, GiopReplyStatus, GiopSystemException};

//
// =========================
//   Types de messages GIOP
// =========================
//

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum GiopMessageType {
    Request,
    Reply,
    CancelRequest,
    LocateRequest,
    LocateReply,
    CloseConnection,
    MessageError,
    /// GIOP 1.1+.
    Fragment,
}

impl TryFrom<u8> for GiopMessageType {
    type Error = GiopParseError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use GiopMessageType::*;
        // La règle de validation (0..=7) vit dans checks ; ce match ne fait
        // que typer une valeur déjà validée.
        let value = validate_message_type(value)?;
        Ok(match value {
            0 => Request,
            1 => Reply,
            2 => CancelRequest,
            3 => LocateRequest,
            4 => LocateReply,
            5 => CloseConnection,
            6 => MessageError,
            7 => Fragment,
            // Inatteignable : validate_message_type garantit value <= 7.
            _ => return Err(GiopParseError::UnknownMessageType(value)),
        })
    }
}

//
// =========================
//        Header GIOP
// =========================
//

// Bit 0 des flags GIOP : 1 = message little-endian, 0 = big-endian. En GIOP
// 1.0 l'octet est le booleen `byte_order`, de meme position et de meme sens.
const GIOP_FLAG_LITTLE_ENDIAN: u8 = 0x01;
// Bit 1 (GIOP 1.1+) : d'autres fragments suivent ce message.
const GIOP_FLAG_MORE_FRAGMENTS: u8 = 0x02;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct GiopHeader {
    pub magic: [u8; 4],    // "GIOP"
    pub major_version: u8, // 1
    pub minor_version: u8, // 0, 1, 2
    pub flags: u8,         // bit 0 = endianness, bit 1 = more fragments
    pub message_type: GiopMessageType,
    pub message_length: u32, // taille du body uniquement
}

impl GiopHeader {
    pub const HEADER_LEN: usize = GIOP_HEADER_LEN;

    /// Le message (taille du header comprise) est encode en little-endian.
    pub fn is_little_endian(&self) -> bool {
        self.flags & GIOP_FLAG_LITTLE_ENDIAN != 0
    }

    /// D'autres messages Fragment suivent celui-ci. Le bit n'existe qu'a
    /// partir de GIOP 1.1 : en 1.0 l'octet est un booleen d'endianness.
    pub fn has_more_fragments(&self) -> bool {
        self.minor_version >= 1 && self.flags & GIOP_FLAG_MORE_FRAGMENTS != 0
    }
}

impl TryFrom<&[u8]> for GiopHeader {
    type Error = GiopParseError;

    fn try_from(payload: &[u8]) -> Result<Self, Self::Error> {
        // Séquence linéaire canonique : pré-check de longueur, puis un
        // extract_* par champ dans l'ordre du wire (l'ordre des checks est
        // inchangé, donc mêmes erreurs pour les mêmes inputs).
        ensure_min_len(payload)?;

        let magic = parse_magic(payload)?;
        let (major_version, minor_version) = extract_version(&payload[4..6])?;
        let flags = extract_flags(&payload[6])?;
        let message_type = GiopMessageType::try_from(payload[7])?;
        // MessageSize suit l'endianness annoncee par les flags (bit 0),
        // comme le reste du message — verifie sur la trame 19 little-endian
        // de pcaps_exemple/protocols/giop/corba.pcap (issue #58).
        let message_length =
            extract_message_size(&payload[8..12], flags & GIOP_FLAG_LITTLE_ENDIAN != 0)?;

        Ok(GiopHeader {
            magic,
            major_version,
            minor_version,
            flags,
            message_type,
            message_length,
        })
    }
}

//
// =========================
//      Structures GIOP
// =========================
//

/// GIOP Packet
///
/// ```mermaid
/// ---
/// title: GiopPacket
/// ---
/// packet-beta
/// 0-31: "Magic bytes[4]"
/// 32-39: "Major Version u8"
/// 40-47: "Minor Version u8"
/// 48-55: "Flags u8"
/// 56-63: "Message Type u8"
/// 64-95: "Message Length u32"
/// 96-159: "Body variable"
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct GiopPacket<'a> {
    pub header: GiopHeader,
    pub payload: GiopMessage<'a>,
    /// Le buffer ne contient pas tout le body annonce par `message_length` :
    /// le message deborde du segment TCP (ou la capture est tronquee par son
    /// snaplen). Le payload est alors decode sur les octets presents.
    pub truncated: bool,
    // Octets du buffer couverts par ce message (header compris).
    consumed: usize,
}

impl GiopPacket<'_> {
    /// Octets de ce message presents dans le buffer d'origine, header
    /// compris : borne par le buffer quand le message est tronque.
    pub fn wire_len(&self) -> usize {
        self.consumed
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GiopMessage<'a> {
    Request(GiopRequest<'a>),
    Reply(GiopReply<'a>),
    CancelRequest(GiopCancelRequest),
    LocateRequest(GiopLocateRequest<'a>),
    LocateReply(GiopLocateReply<'a>),
    /// Le serveur ferme la connexion : header seul.
    CloseConnection,
    /// Le pair n'a pas compris le message precedent : header seul.
    MessageError,
    Fragment(GiopFragment<'a>),
    /// Type de message valide dont le body n'a pas pu etre decode (body
    /// coupe au milieu de son en-tete, ou malforme). Le header reste fiable.
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TargetAddress<'a> {
    /// `object_key` de l'objet cible.
    KeyAddr(&'a [u8]),
    /// Profil complet ; TAG_UIPMC (3) pour une requete multicast MIOP.
    ProfileAddr(TaggedProfile<'a>),
    /// `GIOP::IORAddressingInfo` : l'IOR complet et l'index du profil retenu.
    ReferenceAddr {
        selected_profile_index: u32,
        ior: Ior<'a>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ServiceContext<'a> {
    pub context_id: u32,
    pub context_data: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct GiopRequest<'a> {
    pub request_id: u32,
    /// GIOP 1.2 : SyncScope (0..3). GIOP 1.0/1.1 : booleen
    /// `response_expected`.
    pub response_flags: u8,
    pub target: TargetAddress<'a>,
    pub operation: &'a str,
    pub service_contexts: Vec<ServiceContext<'a>>,
    /// `requesting_principal` de GIOP 1.0/1.1 (deprecie, supprime en 1.2).
    pub requesting_principal: Option<&'a [u8]>,
    /// Arguments CDR de l'operation, types par l'IDL : non decodes. Padding
    /// d'alignement exclu.
    pub stub_data: &'a [u8],
}

//
// =========================
//   Parsing GiopPacket
// =========================
//

impl<'a> TryFrom<&'a [u8]> for GiopPacket<'a> {
    type Error = GiopParseError;

    /// Decode le premier message GIOP du buffer. Pour un segment TCP qui en
    /// porte plusieurs, voir [`giop_messages`].
    fn try_from(buf: &'a [u8]) -> Result<Self, Self::Error> {
        let header = GiopHeader::try_from(buf)?;
        // Sur cible 32 bits, HEADER_LEN + message_length (jusqu'à u32::MAX)
        // peut déborder usize : checked_add avec repli sur InvalidSize.
        let total_needed = GiopHeader::HEADER_LEN
            .checked_add(header.message_length as usize)
            .ok_or(GiopParseError::InvalidSize)?;

        // Un message GIOP deborde couramment de son segment TCP (8 Ko de
        // body pour 1460 octets de MSS sur la trame 41 de
        // wireshark_11616_locate_fragment.pcap) : le premier segment est
        // accepte et marque, pas rejete. Le slicing est borne par le buffer.
        let consumed = total_needed.min(buf.len());
        let truncated = consumed < total_needed;
        let body = &buf[GiopHeader::HEADER_LEN..consumed];
        let payload = dispatch_body(&header, body);
        Ok(GiopPacket {
            header,
            payload,
            truncated,
            consumed,
        })
    }
}

/// Itere sur les messages GIOP consecutifs d'un meme payload TCP : un ORB
/// enchaine volontiers plusieurs messages courts dans un segment (la trame 57
/// de `wireshark_11616_locate_fragment.pcap` en porte deux).
///
/// L'iteration s'arrete au premier octet qui n'ouvre pas un message GIOP
/// valide, ou apres un message tronque.
pub fn giop_messages(payload: &[u8]) -> GiopMessages<'_> {
    GiopMessages { rest: payload }
}

/// Cherche le premier header GIOP valide **n'importe ou** dans un payload et
/// rend son offset.
///
/// Quand un message deborde de son segment TCP, le message suivant commence
/// au milieu d'un segment de continuation (offset 952 de la trame 48 de
/// `wireshark_11616_locate_fragment.pcap`). Le pipeline stateless ne peut pas
/// etiqueter ce segment, qui ne commence pas par le magic. Un appelant qui
/// suit les flux et **sait deja** que celui-ci porte du GIOP peut se
/// resynchroniser ici, puis lire avec [`giop_messages`]. C'est aussi le moyen
/// d'atteindre le message GIOP encapsule dans un datagramme MIOP.
///
/// A ne pas utiliser pour classifier du trafic inconnu : quatre octets de
/// magic au milieu de donnees applicatives ne prouvent rien. La signature
/// exigee est neanmoins stricte — magic, version 1.0 a 1.2, type de message
/// connu, bits de flags reserves a zero.
pub fn find_giop_message(payload: &[u8]) -> Option<usize> {
    // Bits 0-1 : endianness et fragments ; bits 2-3 : ZIOP. Le reste est
    // reserve et nul chez tous les ORB observes.
    const RESERVED_FLAGS: u8 = 0xF0;

    let mut start = 0;
    while let Some(found) = payload[start..]
        .windows(GIOP_MAGIC.len())
        .position(|window| window == GIOP_MAGIC)
    {
        let offset = start + found;
        if GiopHeader::try_from(&payload[offset..]).is_ok_and(|h| h.flags & RESERVED_FLAGS == 0) {
            return Some(offset);
        }
        start = offset + 1;
    }
    None
}

/// Iterateur rendu par [`giop_messages`].
#[derive(Debug, Clone)]
pub struct GiopMessages<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for GiopMessages<'a> {
    type Item = GiopPacket<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let packet = GiopPacket::try_from(self.rest).ok()?;
        // wire_len >= HEADER_LEN : l'iteration progresse toujours.
        self.rest = &self.rest[packet.wire_len()..];
        Some(packet)
    }
}

/// Dispatch du body selon message_type (issue #52).
///
/// Le dispatch ne doit pas changer la classification du paquet : le probing
/// aveugle appelle GiopPacket::try_from sur du trafic arbitraire, donc un
/// body illisible degrade en Other au lieu de faire echouer le paquet entier.
fn dispatch_body<'a>(header: &GiopHeader, body: &'a [u8]) -> GiopMessage<'a> {
    let little_endian = header.is_little_endian();
    // Les layouts different entre GIOP 1.0/1.1 et 1.2.
    let legacy = header.minor_version < 2;
    let parsed = match header.message_type {
        GiopMessageType::Request => if legacy {
            GiopRequest::parse_1_0_1_1(body, little_endian, header.minor_version)
        } else {
            GiopRequest::parse(body, little_endian)
        }
        .map(GiopMessage::Request),
        GiopMessageType::Reply => if legacy {
            GiopReply::parse_1_0_1_1(body, little_endian)
        } else {
            GiopReply::parse(body, little_endian)
        }
        .map(GiopMessage::Reply),
        GiopMessageType::CancelRequest => {
            GiopCancelRequest::parse(body, little_endian).map(GiopMessage::CancelRequest)
        }
        GiopMessageType::LocateRequest => if legacy {
            GiopLocateRequest::parse_1_0_1_1(body, little_endian)
        } else {
            GiopLocateRequest::parse(body, little_endian)
        }
        .map(GiopMessage::LocateRequest),
        GiopMessageType::LocateReply => {
            GiopLocateReply::parse(body, little_endian).map(GiopMessage::LocateReply)
        }
        GiopMessageType::CloseConnection => Ok(GiopMessage::CloseConnection),
        GiopMessageType::MessageError => Ok(GiopMessage::MessageError),
        GiopMessageType::Fragment => GiopFragment::parse(body, little_endian, header.minor_version)
            .map(GiopMessage::Fragment),
    };
    parsed.unwrap_or(GiopMessage::Other)
}

//
// =========================
//   Parsing d'un Request
// =========================
//

impl<'a> GiopRequest<'a> {
    /// Parse un Request header au layout GIOP 1.2 : request_id,
    /// response_flags, reserved, target, operation, service contexts, puis
    /// stub data aligne sur 8 octets.
    pub fn parse(body: &'a [u8], little_endian: bool) -> Result<Self, GiopParseError> {
        let mut cur = Cursor::new(body, little_endian);

        let request_id = cur.read_u32()?;
        let response_flags = cur.read_u8()?;
        let _reserved = cur.read_bytes(3)?;

        let target = parse_target_address(&mut cur)?;
        let operation = cur.read_str()?;
        let service_contexts = parse_service_context_list(&mut cur)?;

        // Le reste = stub data (arguments CDR), apres le padding vers 8.
        cur.align_body_1_2();
        Ok(GiopRequest {
            request_id,
            response_flags,
            target,
            operation,
            service_contexts,
            requesting_principal: None,
            stub_data: cur.rest(),
        })
    }

    /// Parse un Request header au layout historique GIOP 1.0/1.1 : service
    /// contexts en tete, puis request_id, response_expected, object_key,
    /// operation et requesting_principal. GIOP 1.1 intercale 3 octets
    /// reserves apres response_expected.
    ///
    /// Mapping vers la structure 1.2 : response_expected (boolean) est place
    /// dans response_flags, object_key devient TargetAddress::KeyAddr.
    fn parse_1_0_1_1(
        body: &'a [u8],
        little_endian: bool,
        minor_version: u8,
    ) -> Result<Self, GiopParseError> {
        let mut cur = Cursor::new(body, little_endian);

        let service_contexts = parse_service_context_list(&mut cur)?;
        let request_id = cur.read_u32()?;
        let response_flags = cur.read_u8()?;

        if minor_version == 1 {
            // Reserved 3 octets, specifiques a GIOP 1.1
            let _reserved = cur.read_bytes(3)?;
        }

        let target = TargetAddress::KeyAddr(cur.read_octet_sequence()?);
        let operation = cur.read_str()?;
        let requesting_principal = Some(cur.read_octet_sequence()?);

        // Le reste = stub data (arguments CDR), sans alignement sur 8.
        Ok(GiopRequest {
            request_id,
            response_flags,
            target,
            operation,
            service_contexts,
            requesting_principal,
            stub_data: cur.rest(),
        })
    }
}

fn parse_target_address<'a>(cur: &mut Cursor<'a>) -> Result<TargetAddress<'a>, GiopParseError> {
    // TargetAddress est une union discriminee par un short CDR (2 octets,
    // dans l'endianness du message), pas un octet : verifie sur les trames
    // reelles de corba.pcap (trame 4 : 00 00 = KeyAddr ; trame 19 : 01 00
    // little-endian = ProfileAddr).
    let discriminator = cur.read_u16()?;
    validate_target_discriminator(discriminator)?;

    Ok(match discriminator {
        0 => TargetAddress::KeyAddr(cur.read_octet_sequence()?),
        1 => TargetAddress::ProfileAddr(TaggedProfile::parse(cur)?),
        // IORAddressingInfo : selected_profile_index est un INDEX, pas une
        // longueur — le lire comme une longueur decalait le curseur en plein
        // IOR et corrompait operation et service contexts (revue 10.4.0).
        _ => TargetAddress::ReferenceAddr {
            selected_profile_index: cur.read_u32()?,
            ior: Ior::parse(cur)?,
        },
    })
}

fn parse_service_context_list<'a>(
    cur: &mut Cursor<'a>,
) -> Result<Vec<ServiceContext<'a>>, GiopParseError> {
    let count = cur.read_u32()? as usize;
    validate_service_context_count(count, cur.remaining())?;
    let mut contexts = Vec::with_capacity(count);

    for _ in 0..count {
        let context_id = cur.read_u32()?;
        let context_data = cur.read_octet_sequence()?;
        contexts.push(ServiceContext {
            context_id,
            context_data,
        });
    }

    Ok(contexts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_giop_header(msg_type: u8, message_length: u32) -> Vec<u8> {
        let mut bytes = b"GIOP".to_vec();
        bytes.extend_from_slice(&[1, 2]); // version 1.2
        bytes.push(0); // flags : big-endian
        bytes.push(msg_type);
        bytes.extend_from_slice(&message_length.to_be_bytes());
        bytes
    }

    #[test]
    fn test_parse_valid_header_and_packet() {
        let mut bytes = build_giop_header(1, 12); // Reply : en-tete seul, sans body
        bytes.extend_from_slice(&7u32.to_be_bytes()); // request_id
        bytes.extend_from_slice(&0u32.to_be_bytes()); // NO_EXCEPTION
        bytes.extend_from_slice(&0u32.to_be_bytes()); // 0 service context

        let packet = GiopPacket::try_from(bytes.as_slice()).expect("paquet GIOP valide");
        assert_eq!(&packet.header.magic, b"GIOP");
        assert_eq!(packet.header.major_version, 1);
        assert_eq!(packet.header.minor_version, 2);
        assert_eq!(packet.header.flags, 0);
        assert!(matches!(packet.header.message_type, GiopMessageType::Reply));
        assert_eq!(packet.header.message_length, 12);
        assert!(!packet.truncated);
        assert_eq!(packet.wire_len(), bytes.len());
        let GiopMessage::Reply(reply) = packet.payload else {
            panic!("attendu Reply, obtenu {:?}", packet.payload);
        };
        assert_eq!(reply.request_id, 7);
        assert_eq!(reply.reply_status, GiopReplyStatus::NoException);
        assert!(reply.body.is_empty());
    }

    #[test]
    fn test_all_message_types() {
        for (raw, expected) in [
            (0u8, "Request"),
            (1, "Reply"),
            (2, "CancelRequest"),
            (3, "LocateRequest"),
            (4, "LocateReply"),
            (5, "CloseConnection"),
            (6, "MessageError"),
            (7, "Fragment"),
        ] {
            let msg_type = GiopMessageType::try_from(raw).expect("type valide");
            assert_eq!(format!("{msg_type:?}"), expected);
        }

        assert!(matches!(
            GiopMessageType::try_from(8),
            Err(GiopParseError::UnknownMessageType(8))
        ));
    }

    #[test]
    fn test_header_too_short() {
        assert!(matches!(
            GiopHeader::try_from(&b"GIOP"[..]),
            Err(GiopParseError::InvalidSize)
        ));
    }

    #[test]
    fn test_truncated_header_eleven_bytes() {
        // Un octet de moins que le header complet de 12 octets
        let bytes = build_giop_header(0, 0);
        assert!(matches!(
            GiopPacket::try_from(&bytes[..GiopHeader::HEADER_LEN - 1]),
            Err(GiopParseError::InvalidSize)
        ));
    }

    #[test]
    fn test_invalid_magic() {
        let bytes = [b'N', b'O', b'P', b'E', 1, 0, 0, 0, 0, 0, 0, 0];
        assert!(matches!(
            GiopHeader::try_from(&bytes[..]),
            Err(GiopParseError::InvalidMagic)
        ));
    }

    #[test]
    fn test_unsupported_version() {
        let mut bytes = build_giop_header(0, 0);
        bytes[4] = 2; // major 2 non supporté
        assert!(matches!(
            GiopHeader::try_from(bytes.as_slice()),
            Err(GiopParseError::UnsupportedVersion(2, 2))
        ));

        let mut bytes = build_giop_header(0, 0);
        bytes[5] = 3; // minor 3 non supporté
        assert!(matches!(
            GiopHeader::try_from(bytes.as_slice()),
            Err(GiopParseError::UnsupportedVersion(1, 3))
        ));
    }

    #[test]
    fn test_truncated_body_is_accepted_and_flagged() {
        // message_length annonce 10 octets mais rien derrière le header : le
        // message deborde du segment. Il reste du GIOP, marque tronque ; le
        // body Request illisible degrade en Other.
        let bytes = build_giop_header(0, 10);
        let packet = GiopPacket::try_from(bytes.as_slice()).expect("premier segment accepte");
        assert!(packet.truncated);
        assert_eq!(packet.wire_len(), 12);
        assert_eq!(packet.payload, GiopMessage::Other);
    }

    #[test]
    fn test_declared_length_beyond_buffer() {
        // message_length annonce plus que ce que le buffer contient,
        // meme avec des octets de body presents
        let mut bytes = build_giop_header(1, 100);
        bytes.extend_from_slice(&[0u8; 4]); // seulement 4 octets de body

        let packet = GiopPacket::try_from(bytes.as_slice()).expect("premier segment accepte");
        assert!(packet.truncated);
        assert_eq!(packet.header.message_length, 100);
        assert_eq!(packet.wire_len(), 16);
    }

    /// Body CDR d'un Request big-endian : target KeyAddr, opération "op",
    /// un service context, puis stub data. Layout CDR-correct : le
    /// discriminant de TargetAddress est un short (2 octets) et chaque ulong
    /// est aligné sur 4 octets (padding), comme sur les trames réelles de
    /// `pcaps_exemple/protocols/giop/corba.pcap`.
    fn build_request_body_be() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&7u32.to_be_bytes()); // request_id
        body.push(3); // response_flags
        body.extend_from_slice(&[0, 0, 0]); // reserved
        body.extend_from_slice(&0u16.to_be_bytes()); // discriminant short KeyAddr
        body.extend_from_slice(&[0, 0]); // padding : ulong aligné sur 4
        body.extend_from_slice(&3u32.to_be_bytes()); // key len
        body.extend_from_slice(b"key");
        body.push(0); // padding
        body.extend_from_slice(&3u32.to_be_bytes()); // operation len ("op" + NUL)
        body.extend_from_slice(b"op\0");
        body.push(0); // padding
        body.extend_from_slice(&1u32.to_be_bytes()); // 1 service context
        body.extend_from_slice(&17u32.to_be_bytes()); // context_id
        body.extend_from_slice(&2u32.to_be_bytes()); // context len
        body.extend_from_slice(&[0xAA, 0xBB]);
        // Offset 42 du body = 54 du message : 2 octets de padding vers 8.
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(&[0x01, 0x02, 0x03]); // stub data
        body
    }

    #[test]
    fn test_parse_request_big_endian() {
        let body = build_request_body_be();
        let request = GiopRequest::parse(&body, false).expect("request valide");

        assert_eq!(request.request_id, 7);
        assert_eq!(request.response_flags, 3);
        match &request.target {
            TargetAddress::KeyAddr(key) => assert_eq!(*key, b"key"),
            other => panic!("attendu KeyAddr, obtenu {other:?}"),
        }
        assert_eq!(request.operation, "op");
        assert_eq!(request.service_contexts.len(), 1);
        assert_eq!(request.service_contexts[0].context_id, 17);
        assert_eq!(request.service_contexts[0].context_data, &[0xAA, 0xBB]);
        assert_eq!(request.stub_data, &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_parse_request_little_endian_without_stub() {
        let mut body = Vec::new();
        body.extend_from_slice(&42u32.to_le_bytes()); // request_id
        body.push(0); // response_flags
        body.extend_from_slice(&[0, 0, 0]); // reserved
        body.extend_from_slice(&1u16.to_le_bytes()); // discriminant ProfileAddr
        body.extend_from_slice(&[0, 0]); // padding
        body.extend_from_slice(&3u32.to_le_bytes()); // TaggedProfile : tag (TAG_UIPMC)
        body.extend_from_slice(&2u32.to_le_bytes()); // profile_data len
        body.extend_from_slice(&[0x10, 0x20]);
        body.extend_from_slice(&[0, 0]); // padding
        body.extend_from_slice(&5u32.to_le_bytes()); // operation "ping" + NUL
        body.extend_from_slice(b"ping\0");
        body.extend_from_slice(&[0, 0, 0]); // padding
        body.extend_from_slice(&0u32.to_le_bytes()); // 0 service context

        let request = GiopRequest::parse(&body, true).expect("request LE valide");
        assert_eq!(request.request_id, 42);
        match request.target {
            TargetAddress::ProfileAddr(profile) => {
                assert_eq!(profile.tag, ior::TAG_UIPMC);
                assert_eq!(profile.profile_data, &[0x10, 0x20]);
            }
            other => panic!("attendu ProfileAddr, obtenu {other:?}"),
        }
        assert_eq!(request.operation, "ping");
        assert!(request.service_contexts.is_empty());
        assert!(request.stub_data.is_empty());
    }

    #[test]
    fn test_parse_request_reference_addr() {
        let mut body = Vec::new();
        body.extend_from_slice(&1u32.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&[0, 0, 0]);
        body.extend_from_slice(&2u16.to_be_bytes()); // discriminant ReferenceAddr
        body.extend_from_slice(&[0, 0]); // padding
        // IORAddressingInfo : index, type_id (string d'un NUL), 0 profil.
        body.extend_from_slice(&1u32.to_be_bytes()); // selected_profile_index
        body.extend_from_slice(&1u32.to_be_bytes()); // longueur type_id
        body.push(0); // type_id = ""
        body.extend_from_slice(&[0, 0, 0]); // padding
        body.extend_from_slice(&0u32.to_be_bytes()); // 0 TaggedProfile
        body.extend_from_slice(&1u32.to_be_bytes()); // operation : chaîne vide NUL
        body.push(0);
        body.extend_from_slice(&[0, 0, 0]); // padding
        body.extend_from_slice(&0u32.to_be_bytes());

        let request = GiopRequest::parse(&body, false).expect("request valide");
        assert!(matches!(
            request.target,
            TargetAddress::ReferenceAddr {
                selected_profile_index: 1,
                ..
            }
        ));
        assert_eq!(request.requesting_principal, None);
        assert_eq!(request.operation, "");
    }

    #[test]
    fn test_parse_request_unknown_target_discriminator() {
        let mut body = Vec::new();
        body.extend_from_slice(&1u32.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&[0, 0, 0]);
        body.extend_from_slice(&9u16.to_be_bytes()); // discriminant inconnu

        assert!(matches!(
            GiopRequest::parse(&body, false),
            Err(GiopParseError::UnknownTargetDiscriminator(9))
        ));
    }

    #[test]
    fn test_parse_request_invalid_utf8_operation() {
        let mut body = Vec::new();
        body.extend_from_slice(&1u32.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&[0, 0, 0]);
        body.extend_from_slice(&0u16.to_be_bytes()); // KeyAddr
        body.extend_from_slice(&[0, 0]); // padding
        body.extend_from_slice(&0u32.to_be_bytes()); // key vide
        body.extend_from_slice(&2u32.to_be_bytes()); // operation : 2 octets invalides
        body.extend_from_slice(&[0xFF, 0xFE]);

        assert!(matches!(
            GiopRequest::parse(&body, false),
            Err(GiopParseError::InvalidUtf8)
        ));
    }

    #[test]
    fn test_parse_request_unexpected_eof() {
        assert!(matches!(
            GiopRequest::parse(&[0x00, 0x01], false),
            Err(GiopParseError::UnexpectedEof)
        ));

        // EOF au milieu de la target
        let mut body = Vec::new();
        body.extend_from_slice(&1u32.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&[0, 0, 0]);
        body.extend_from_slice(&0u16.to_be_bytes()); // KeyAddr
        body.extend_from_slice(&[0, 0]); // padding
        body.extend_from_slice(&100u32.to_be_bytes()); // len 100 mais rien derrière

        assert!(matches!(
            GiopRequest::parse(&body, false),
            Err(GiopParseError::UnexpectedEof)
        ));
    }

    #[test]
    fn test_parse_request_forged_service_context_count() {
        // Le compte annonce plus de contexts que le body ne peut en contenir :
        // rejeté avant toute allocation.
        let mut body = Vec::new();
        body.extend_from_slice(&1u32.to_be_bytes()); // request_id
        body.push(0); // response_flags
        body.extend_from_slice(&[0, 0, 0]); // reserved
        body.extend_from_slice(&0u16.to_be_bytes()); // KeyAddr
        body.extend_from_slice(&[0, 0]); // padding
        body.extend_from_slice(&0u32.to_be_bytes()); // key vide
        body.extend_from_slice(&1u32.to_be_bytes()); // operation vide NUL
        body.push(0);
        body.extend_from_slice(&[0, 0, 0]); // padding
        body.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes()); // compte forgé

        assert!(matches!(
            GiopRequest::parse(&body, false),
            Err(GiopParseError::InvalidServiceContextCount {
                count: 0xFFFF_FFFF,
                available: 0
            })
        ));
    }

    #[test]
    fn test_parse_request_truncated_service_context() {
        // Un context annoncé, son en-tête est présent mais context_data est tronqué.
        let mut body = Vec::new();
        body.extend_from_slice(&1u32.to_be_bytes()); // request_id
        body.push(0); // response_flags
        body.extend_from_slice(&[0, 0, 0]); // reserved
        body.extend_from_slice(&0u16.to_be_bytes()); // KeyAddr
        body.extend_from_slice(&[0, 0]); // padding
        body.extend_from_slice(&0u32.to_be_bytes()); // key vide
        body.extend_from_slice(&1u32.to_be_bytes()); // operation vide NUL
        body.push(0);
        body.extend_from_slice(&[0, 0, 0]); // padding
        body.extend_from_slice(&1u32.to_be_bytes()); // 1 service context
        body.extend_from_slice(&17u32.to_be_bytes()); // context_id
        body.extend_from_slice(&8u32.to_be_bytes()); // context len 8 mais 1 octet présent
        body.push(0xAA);

        assert!(matches!(
            GiopRequest::parse(&body, false),
            Err(GiopParseError::UnexpectedEof)
        ));
    }

    #[test]
    fn test_zero_copy_borrows_from_input() {
        // Les slices retournées doivent pointer dans le buffer d'origine.
        let body = build_request_body_be();
        let request = GiopRequest::parse(&body, false).expect("request valide");

        let range = body.as_ptr_range();
        let key = match request.target {
            TargetAddress::KeyAddr(key) => key,
            ref other => panic!("attendu KeyAddr, obtenu {other:?}"),
        };
        for slice in [
            key,
            request.operation.as_bytes(),
            request.service_contexts[0].context_data,
            request.stub_data,
        ] {
            assert!(range.contains(&slice.as_ptr()));
        }
    }

    //
    // Tests du dispatch du body selon message_type (issue #52).
    // Octets synthetiques : le golden test sur trame reelle est porte
    // par l'issue #58.
    //

    /// Header GIOP parametrable en version mineure et flags. Comme sur le
    /// wire, message_size est ecrit dans l'endianness annoncee par le bit 0
    /// des flags.
    fn build_giop_header_v(minor: u8, flags: u8, msg_type: u8, message_length: u32) -> Vec<u8> {
        let mut bytes = b"GIOP".to_vec();
        bytes.extend_from_slice(&[1, minor]);
        bytes.push(flags);
        bytes.push(msg_type);
        if flags & 0x01 != 0 {
            bytes.extend_from_slice(&message_length.to_le_bytes());
        } else {
            bytes.extend_from_slice(&message_length.to_be_bytes());
        }
        bytes
    }

    /// Body d'un Request au layout 1.0 big-endian : un service context en
    /// tete, object_key, operation, principal puis stub data. Paddings CDR
    /// devant chaque ulong non aligne.
    fn build_request_body_1_0_be() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&1u32.to_be_bytes()); // 1 service context
        body.extend_from_slice(&17u32.to_be_bytes()); // context_id
        body.extend_from_slice(&2u32.to_be_bytes()); // context len
        body.extend_from_slice(&[0xAA, 0xBB]);
        body.extend_from_slice(&[0, 0]); // padding
        body.extend_from_slice(&7u32.to_be_bytes()); // request_id
        body.push(1); // response_expected
        body.extend_from_slice(&[0, 0, 0]); // padding
        body.extend_from_slice(&3u32.to_be_bytes()); // object_key len
        body.extend_from_slice(b"key");
        body.push(0); // padding
        body.extend_from_slice(&3u32.to_be_bytes()); // operation "op" + NUL
        body.extend_from_slice(b"op\0");
        body.push(0); // padding
        body.extend_from_slice(&2u32.to_be_bytes()); // principal len
        body.extend_from_slice(&[0x01, 0x02]);
        body.extend_from_slice(&[0xCA, 0xFE]); // stub data
        body
    }

    #[test]
    fn test_dispatch_request_1_0_big_endian() {
        let body = build_request_body_1_0_be();
        let mut bytes = build_giop_header_v(0, 0, 0, body.len() as u32);
        bytes.extend_from_slice(&body);

        let packet = GiopPacket::try_from(bytes.as_slice()).expect("paquet GIOP valide");
        let request = match packet.payload {
            GiopMessage::Request(request) => request,
            other => panic!("attendu Request, obtenu {other:?}"),
        };
        assert_eq!(request.request_id, 7);
        assert_eq!(request.response_flags, 1);
        match request.target {
            TargetAddress::KeyAddr(key) => assert_eq!(key, b"key"),
            other => panic!("attendu KeyAddr, obtenu {other:?}"),
        }
        assert_eq!(request.operation, "op");
        assert_eq!(request.service_contexts.len(), 1);
        assert_eq!(request.service_contexts[0].context_id, 17);
        assert_eq!(request.requesting_principal, Some(&[0x01, 0x02][..]));
        assert_eq!(request.stub_data, &[0xCA, 0xFE]);
    }

    #[test]
    fn test_dispatch_request_1_0_little_endian() {
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes()); // 0 service context
        body.extend_from_slice(&42u32.to_le_bytes()); // request_id
        body.push(0); // response_expected
        body.extend_from_slice(&[0, 0, 0]); // padding
        body.extend_from_slice(&3u32.to_le_bytes()); // object_key len
        body.extend_from_slice(b"key");
        body.push(0); // padding
        body.extend_from_slice(&5u32.to_le_bytes()); // operation "ping" + NUL
        body.extend_from_slice(b"ping\0");
        body.extend_from_slice(&[0, 0, 0]); // padding
        body.extend_from_slice(&0u32.to_le_bytes()); // principal vide

        // Flags bit 0 = 1 : body little-endian
        let mut bytes = build_giop_header_v(0, 0x01, 0, body.len() as u32);
        bytes.extend_from_slice(&body);

        let packet = GiopPacket::try_from(bytes.as_slice()).expect("paquet GIOP valide");
        let request = match packet.payload {
            GiopMessage::Request(request) => request,
            other => panic!("attendu Request, obtenu {other:?}"),
        };
        assert_eq!(request.request_id, 42);
        assert_eq!(request.operation, "ping");
        assert!(request.service_contexts.is_empty());
        assert!(request.stub_data.is_empty());
    }

    #[test]
    fn test_dispatch_request_1_1_reserved_bytes() {
        // Layout 1.1 : identique a 1.0 avec 3 octets reserves apres
        // response_expected.
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_be_bytes()); // 0 service context
        body.extend_from_slice(&9u32.to_be_bytes()); // request_id
        body.push(1); // response_expected
        body.extend_from_slice(&[0, 0, 0]); // reserved 1.1
        body.extend_from_slice(&1u32.to_be_bytes()); // object_key len
        body.push(0x2A);
        body.extend_from_slice(&[0, 0, 0]); // padding
        body.extend_from_slice(&3u32.to_be_bytes()); // operation "op" + NUL
        body.extend_from_slice(b"op\0");
        body.push(0); // padding
        body.extend_from_slice(&0u32.to_be_bytes()); // principal vide

        let mut bytes = build_giop_header_v(1, 0, 0, body.len() as u32);
        bytes.extend_from_slice(&body);

        let packet = GiopPacket::try_from(bytes.as_slice()).expect("paquet GIOP valide");
        let request = match packet.payload {
            GiopMessage::Request(request) => request,
            other => panic!("attendu Request, obtenu {other:?}"),
        };
        assert_eq!(request.request_id, 9);
        assert_eq!(request.operation, "op");
    }

    #[test]
    fn test_dispatch_request_1_2_big_endian() {
        let body = build_request_body_be();
        let mut bytes = build_giop_header_v(2, 0, 0, body.len() as u32);
        bytes.extend_from_slice(&body);

        let packet = GiopPacket::try_from(bytes.as_slice()).expect("paquet GIOP valide");
        let request = match packet.payload {
            GiopMessage::Request(request) => request,
            other => panic!("attendu Request, obtenu {other:?}"),
        };
        assert_eq!(request.request_id, 7);
        assert_eq!(request.operation, "op");
        assert_eq!(request.stub_data, &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_dispatch_request_truncated_body_degrades_to_other() {
        // Body Request illisible (2 octets, EOF au milieu du header CDR) :
        // le paquet reste accepte comme GIOP, le payload degrade en Other.
        let mut bytes = build_giop_header_v(2, 0, 0, 2);
        bytes.extend_from_slice(&[0x00, 0x01]);

        let packet = GiopPacket::try_from(bytes.as_slice()).expect("paquet GIOP toujours accepte");
        assert!(matches!(packet.payload, GiopMessage::Other));
    }

    #[test]
    fn test_dispatch_reply_truncated_header_degrades_to_other() {
        // 4 octets : le request_id seul, reply_status absent.
        let mut bytes = build_giop_header_v(2, 0, 1, 4);
        bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let packet = GiopPacket::try_from(bytes.as_slice()).expect("paquet GIOP toujours accepte");
        assert_eq!(packet.payload, GiopMessage::Other);
    }

    #[test]
    fn test_dispatch_reply_1_0_and_1_2_layouts() {
        // 1.0 : contexts, request_id, status. 1.2 : request_id, status, contexts.
        let mut legacy = build_giop_header_v(0, 0, 1, 12);
        legacy.extend_from_slice(&0u32.to_be_bytes());
        legacy.extend_from_slice(&11u32.to_be_bytes());
        legacy.extend_from_slice(&1u32.to_be_bytes());
        let mut modern = build_giop_header_v(2, 0, 1, 12);
        modern.extend_from_slice(&11u32.to_be_bytes());
        modern.extend_from_slice(&1u32.to_be_bytes());
        modern.extend_from_slice(&0u32.to_be_bytes());

        for bytes in [legacy, modern] {
            let packet = GiopPacket::try_from(bytes.as_slice()).expect("paquet GIOP valide");
            let GiopMessage::Reply(reply) = packet.payload else {
                panic!("attendu Reply, obtenu {:?}", packet.payload);
            };
            assert_eq!(reply.request_id, 11);
            assert_eq!(reply.reply_status, GiopReplyStatus::UserException);
        }
    }

    #[test]
    fn test_dispatch_cancel_request_and_header_only_messages() {
        // Les types > 7 restent rejetes au niveau du header (classification
        // inchangee), voir test_all_message_types.
        let mut bytes = build_giop_header_v(2, 0, 2, 4);
        bytes.extend_from_slice(&5u32.to_be_bytes());
        let packet = GiopPacket::try_from(bytes.as_slice()).expect("paquet GIOP valide");
        assert_eq!(
            packet.payload,
            GiopMessage::CancelRequest(GiopCancelRequest { request_id: 5 })
        );

        let close = build_giop_header_v(0, 0, 5, 0);
        let packet = GiopPacket::try_from(close.as_slice()).expect("paquet GIOP valide");
        assert_eq!(packet.payload, GiopMessage::CloseConnection);

        let error = build_giop_header_v(1, 0, 6, 0);
        let packet = GiopPacket::try_from(error.as_slice()).expect("paquet GIOP valide");
        assert_eq!(packet.payload, GiopMessage::MessageError);
    }

    #[test]
    fn test_more_fragments_flag_only_exists_from_giop_1_1() {
        let header = |minor, flags| {
            GiopHeader::try_from(build_giop_header_v(minor, flags, 0, 0).as_slice())
                .expect("header valide")
        };
        assert!(header(2, 0x02).has_more_fragments());
        assert!(header(1, 0x03).has_more_fragments());
        assert!(!header(2, 0x01).has_more_fragments());
        // GIOP 1.0 : l'octet est un booleen d'endianness, pas des flags.
        assert!(!header(0, 0x02).has_more_fragments());
        assert!(header(1, 0x03).is_little_endian());
    }

    #[test]
    fn test_giop_messages_walks_consecutive_messages_in_one_payload() {
        // CancelRequest puis CloseConnection puis des octets etrangers.
        let mut payload = build_giop_header_v(2, 0, 2, 4);
        payload.extend_from_slice(&5u32.to_be_bytes());
        payload.extend_from_slice(&build_giop_header_v(2, 0, 5, 0));
        payload.extend_from_slice(b"not giop");

        let messages: Vec<_> = giop_messages(&payload).collect();
        assert_eq!(messages.len(), 2);
        assert_eq!(
            messages[0].payload,
            GiopMessage::CancelRequest(GiopCancelRequest { request_id: 5 })
        );
        assert_eq!(messages[1].payload, GiopMessage::CloseConnection);

        // Un message tronque termine l'iteration sans boucler.
        let truncated = build_giop_header_v(2, 0, 0, 500);
        assert_eq!(giop_messages(&truncated).count(), 1);
        assert_eq!(giop_messages(&[]).count(), 0);
    }

    #[test]
    fn test_find_giop_message_resynchronises_inside_a_continuation_segment() {
        // Queue d'un message precedent, faux magic (version 9.9), puis un
        // vrai CloseConnection.
        let mut payload = b"tail of a previous message GIOP\x09\x09".to_vec();
        payload.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        let real = payload.len();
        payload.extend_from_slice(&build_giop_header_v(2, 0, 5, 0));

        assert_eq!(find_giop_message(&payload), Some(real));
        let messages: Vec<_> = giop_messages(&payload[real..]).collect();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].payload, GiopMessage::CloseConnection);

        assert_eq!(find_giop_message(b"no magic here"), None);
        assert_eq!(find_giop_message(b"GIOP"), None, "header incomplet");
        // Bits de flags reserves : pas une resynchronisation credible.
        assert_eq!(find_giop_message(&build_giop_header_v(2, 0x80, 5, 0)), None);
        assert_eq!(find_giop_message(&build_giop_header_v(2, 0, 5, 0)), Some(0));
    }

    /// Synthetique (aucune trame ReferenceAddr dans corba.pcap) :
    /// IORAddressingInfo = index (ulong) + IOR (type_id + profils). L'index
    /// n'est pas une longueur — regression de la revue 10.4.0.
    #[test]
    fn reference_addr_walks_the_ior_instead_of_reading_the_index_as_a_length() {
        // Body CDR big-endian : disc 2, index 1, type_id "IDL:x\0" (6),
        // 1 profil (tag 0, 4 octets), puis operation "op\0" et 0 contexts.
        let mut body = Vec::new();
        body.extend_from_slice(&2u16.to_be_bytes()); // discriminant
        body.extend_from_slice(&[0, 0]); // padding CDR vers l'ulong
        body.extend_from_slice(&1u32.to_be_bytes()); // selected_profile_index
        body.extend_from_slice(&6u32.to_be_bytes());
        body.extend_from_slice(b"IDL:x\0");
        body.extend_from_slice(&[0, 0]); // padding vers le compteur
        body.extend_from_slice(&1u32.to_be_bytes()); // 1 profil
        body.extend_from_slice(&0u32.to_be_bytes()); // tag
        body.extend_from_slice(&4u32.to_be_bytes());
        body.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);

        let mut cur = Cursor::new(&body, false);
        let target = parse_target_address(&mut cur).expect("ReferenceAddr walks the IOR");
        let TargetAddress::ReferenceAddr {
            selected_profile_index,
            ior,
        } = target
        else {
            panic!("discriminant 2 must yield ReferenceAddr");
        };
        assert_eq!(selected_profile_index, 1);
        assert_eq!(ior.type_id, "IDL:x");
        assert_eq!(ior.profiles.len(), 1);
        assert_eq!(ior.profiles[0].tag, 0);
        assert_eq!(ior.profiles[0].profile_data, &[0xaa, 0xbb, 0xcc, 0xdd]);
        // L'IORAddressingInfo est marche en entier, curseur en fin de body.
        assert_eq!(cur.remaining(), 0);
    }
}
