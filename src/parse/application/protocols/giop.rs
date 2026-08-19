// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use std::convert::TryFrom;

use crate::{
    checks::application::giop::{
        GIOP_HEADER_LEN, ensure_available, ensure_min_len, extract_flags, extract_message_length,
        extract_version, parse_cdr_string, parse_magic, validate_message_type,
        validate_service_context_count, validate_target_discriminator, validate_total_length,
    },
    errors::application::giop::GiopParseError,
};

//
// =========================
//   Types de messages GIOP
// =========================
//

#[derive(Debug)]
pub enum GiopMessageType {
    Request,
    Reply,
    CancelRequest,
    LocateRequest,
    LocateReply,
    CloseConnection,
    MessageError,
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

#[derive(Debug)]
pub struct GiopHeader {
    pub magic: [u8; 4],    // "GIOP"
    pub major_version: u8, // 1
    pub minor_version: u8, // 0, 1, 2
    pub flags: u8,         // bit 0 = endianness du body
    pub message_type: GiopMessageType,
    pub message_length: u32, // taille du body uniquement
}

impl GiopHeader {
    pub const HEADER_LEN: usize = GIOP_HEADER_LEN;
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
        // MessageSize est toujours en big-endian dans le header
        let message_length = extract_message_length(&payload[8..12])?;

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
#[derive(Debug)]
pub struct GiopPacket<'a> {
    pub header: GiopHeader,
    pub payload: GiopMessage<'a>,
}

#[derive(Debug)]
pub enum GiopMessage<'a> {
    Request(GiopRequest<'a>),
    Reply(GiopReply),
    Fragment(GiopFragment),
    Other,
    // Les autres types peuvent être ajoutés plus tard
}

#[derive(Debug)]
pub enum TargetAddress<'a> {
    KeyAddr(&'a [u8]),
    ProfileAddr(&'a [u8]),
    ReferenceAddr(&'a [u8]),
}

#[derive(Debug)]
pub struct ServiceContext<'a> {
    pub context_id: u32,
    pub context_data: &'a [u8],
}

#[derive(Debug)]
pub struct GiopRequest<'a> {
    pub request_id: u32,
    pub response_flags: u8, // 0..3 (SyncScope)
    pub target: TargetAddress<'a>,
    pub operation: &'a str,
    pub service_contexts: Vec<ServiceContext<'a>>,
    pub stub_data: &'a [u8], // CDR payload (arguments), non décodé ici
}

// Placeholders pour plus tard
#[derive(Debug)]
pub struct GiopReply;

#[derive(Debug)]
pub struct GiopFragment;

//
// =========================
//   Parsing GiopPacket
// =========================
//

impl<'a> TryFrom<&'a [u8]> for GiopPacket<'a> {
    type Error = GiopParseError;

    fn try_from(buf: &'a [u8]) -> Result<Self, Self::Error> {
        let header = GiopHeader::try_from(buf)?;
        // Sur cible 32 bits, HEADER_LEN + message_length (jusqu'à u32::MAX)
        // peut déborder usize : checked_add avec repli sur InvalidSize.
        // Branche inatteignable sur cible 64 bits, donc iso-sémantique sur
        // les cibles actuelles.
        let total_needed = GiopHeader::HEADER_LEN
            .checked_add(header.message_length as usize)
            .ok_or(GiopParseError::InvalidSize)?;
        validate_total_length(total_needed, buf.len())?;

        // Body borne par la longueur annoncee, deja validee par
        // validate_total_length : le slicing ne peut pas paniquer.
        let body = &buf[GiopHeader::HEADER_LEN..total_needed];
        let payload = dispatch_body(&header, body);
        Ok(GiopPacket { header, payload })
    }
}

// Bit 0 des flags GIOP : 1 = body little-endian, 0 = big-endian.
const GIOP_FLAG_LITTLE_ENDIAN: u8 = 0x01;

/// Dispatch du body selon message_type (issue #52).
///
/// Le dispatch ne doit pas changer la classification du paquet : le probing
/// aveugle appelle GiopPacket::try_from sur du trafic arbitraire, donc un
/// body Request illisible degrade en Other au lieu de faire echouer le
/// paquet entier.
fn dispatch_body<'a>(header: &GiopHeader, body: &'a [u8]) -> GiopMessage<'a> {
    let little_endian = header.flags & GIOP_FLAG_LITTLE_ENDIAN != 0;
    match header.message_type {
        GiopMessageType::Request => {
            // Les layouts de Request header different entre 1.0/1.1 et 1.2.
            let parsed = match header.minor_version {
                0 | 1 => GiopRequest::parse_1_0_1_1(body, little_endian, header.minor_version),
                _ => GiopRequest::parse(body, little_endian),
            };
            match parsed {
                Ok(request) => GiopMessage::Request(request),
                Err(_) => GiopMessage::Other,
            }
        }
        // Le body Reply n'est pas encore decode : GiopReply est une unit
        // struct publique, lui ajouter des champs casserait SemVer. Le
        // decodage du Reply header est differe a l'epic #76.
        GiopMessageType::Reply => GiopMessage::Reply(GiopReply),
        // Les autres types restent en Other pour l'instant (epic #76).
        _ => GiopMessage::Other,
    }
}

//
// =========================
//   Petit curseur de lecture
// =========================
//

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
    little_endian: bool,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8], little_endian: bool) -> Self {
        Self {
            buf,
            pos: 0,
            little_endian,
        }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn read_u8(&mut self) -> Result<u8, GiopParseError> {
        ensure_available(self.remaining(), 1)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn read_u32(&mut self) -> Result<u32, GiopParseError> {
        ensure_available(self.remaining(), 4)?;
        let bytes = [
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ];
        self.pos += 4;
        Ok(if self.little_endian {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        })
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], GiopParseError> {
        ensure_available(self.remaining(), len)?;
        let slice = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    fn read_str(&mut self) -> Result<&'a str, GiopParseError> {
        // String CDR : ulong length, puis bytes (souvent terminés par 0)
        let len = self.read_u32()? as usize;
        let bytes = self.read_bytes(len)?;
        parse_cdr_string(bytes)
    }
}

//
// =========================
//   Parsing d'un Request
// =========================
//

impl<'a> GiopRequest<'a> {
    /// Parse un Request header au layout GIOP 1.2 : request_id,
    /// response_flags, reserved, target, operation, service contexts.
    pub fn parse(body: &'a [u8], little_endian: bool) -> Result<Self, GiopParseError> {
        let mut cur = Cursor::new(body, little_endian);

        let request_id = cur.read_u32()?;
        let response_flags = cur.read_u8()?;

        // Reserved 3 octets
        let _r1 = cur.read_u8()?;
        let _r2 = cur.read_u8()?;
        let _r3 = cur.read_u8()?;

        let target = parse_target_address(&mut cur)?;
        let operation = cur.read_str()?;
        let service_contexts = parse_service_context_list(&mut cur)?;

        // Le reste = stub data (arguments CDR)
        let stub_data = cur.read_bytes(cur.remaining())?;
        Ok(GiopRequest {
            request_id,
            response_flags,
            target,
            operation,
            service_contexts,
            stub_data,
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

        // object_key : sequence<octet>
        let key_len = cur.read_u32()? as usize;
        let key = cur.read_bytes(key_len)?;
        let target = TargetAddress::KeyAddr(key);

        let operation = cur.read_str()?;

        // requesting_principal : sequence<octet>, deprecie ; lu pour borner
        // le stub data mais non conserve dans la structure (epic #76).
        let principal_len = cur.read_u32()? as usize;
        let _principal = cur.read_bytes(principal_len)?;

        // Le reste = stub data (arguments CDR)
        let stub_data = cur.read_bytes(cur.remaining())?;
        Ok(GiopRequest {
            request_id,
            response_flags,
            target,
            operation,
            service_contexts,
            stub_data,
        })
    }
}

fn parse_target_address<'a>(cur: &mut Cursor<'a>) -> Result<TargetAddress<'a>, GiopParseError> {
    let discriminator = cur.read_u8()?;
    validate_target_discriminator(discriminator)?;

    let len = cur.read_u32()? as usize;
    let data = cur.read_bytes(len)?;

    Ok(match discriminator {
        // KeyAddr: sequence<octet>
        0 => TargetAddress::KeyAddr(data),
        // ProfileAddr : brut pour l'instant
        1 => TargetAddress::ProfileAddr(data),
        // ReferenceAddr : brut pour l'instant
        _ => TargetAddress::ReferenceAddr(data),
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
        let len = cur.read_u32()? as usize;
        let context_data = cur.read_bytes(len)?;
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
        let mut bytes = build_giop_header(1, 4); // Reply avec 4 octets de body
        bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let packet = GiopPacket::try_from(bytes.as_slice()).expect("paquet GIOP valide");
        assert_eq!(&packet.header.magic, b"GIOP");
        assert_eq!(packet.header.major_version, 1);
        assert_eq!(packet.header.minor_version, 2);
        assert_eq!(packet.header.flags, 0);
        assert!(matches!(packet.header.message_type, GiopMessageType::Reply));
        assert_eq!(packet.header.message_length, 4);
        // Un message de type Reply est dispatche sur la variante Reply
        // (placeholder : le body n'est pas encore decode, epic #76).
        assert!(matches!(packet.payload, GiopMessage::Reply(_)));
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
    fn test_truncated_body() {
        // message_length annonce 10 octets mais rien derrière le header
        let bytes = build_giop_header(0, 10);
        assert!(matches!(
            GiopPacket::try_from(bytes.as_slice()),
            Err(GiopParseError::TruncatedBody {
                expected: 22,
                actual: 12
            })
        ));
    }

    #[test]
    fn test_declared_length_beyond_buffer() {
        // message_length annonce plus que ce que le buffer contient,
        // meme avec des octets de body presents
        let mut bytes = build_giop_header(1, 100);
        bytes.extend_from_slice(&[0u8; 4]); // seulement 4 octets de body

        assert!(matches!(
            GiopPacket::try_from(bytes.as_slice()),
            Err(GiopParseError::TruncatedBody {
                expected: 112,
                actual: 16
            })
        ));
    }

    /// Body CDR d'un Request big-endian : target KeyAddr, opération "op",
    /// un service context, puis stub data.
    fn build_request_body_be() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&7u32.to_be_bytes()); // request_id
        body.push(3); // response_flags
        body.extend_from_slice(&[0, 0, 0]); // reserved
        body.push(0); // discriminator KeyAddr
        body.extend_from_slice(&3u32.to_be_bytes()); // key len
        body.extend_from_slice(b"key");
        body.extend_from_slice(&3u32.to_be_bytes()); // operation len ("op" + NUL)
        body.extend_from_slice(b"op\0");
        body.extend_from_slice(&1u32.to_be_bytes()); // 1 service context
        body.extend_from_slice(&17u32.to_be_bytes()); // context_id
        body.extend_from_slice(&2u32.to_be_bytes()); // context len
        body.extend_from_slice(&[0xAA, 0xBB]);
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
        body.push(1); // discriminator ProfileAddr
        body.extend_from_slice(&2u32.to_le_bytes());
        body.extend_from_slice(&[0x10, 0x20]);
        body.extend_from_slice(&5u32.to_le_bytes()); // operation "ping" + NUL
        body.extend_from_slice(b"ping\0");
        body.extend_from_slice(&0u32.to_le_bytes()); // 0 service context

        let request = GiopRequest::parse(&body, true).expect("request LE valide");
        assert_eq!(request.request_id, 42);
        assert!(matches!(request.target, TargetAddress::ProfileAddr(_)));
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
        body.push(2); // discriminator ReferenceAddr
        body.extend_from_slice(&1u32.to_be_bytes());
        body.push(0xFF);
        body.extend_from_slice(&1u32.to_be_bytes()); // operation : chaîne vide NUL
        body.push(0);
        body.extend_from_slice(&0u32.to_be_bytes());

        let request = GiopRequest::parse(&body, false).expect("request valide");
        assert!(matches!(request.target, TargetAddress::ReferenceAddr(_)));
        assert_eq!(request.operation, "");
    }

    #[test]
    fn test_parse_request_unknown_target_discriminator() {
        let mut body = Vec::new();
        body.extend_from_slice(&1u32.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&[0, 0, 0]);
        body.push(9); // discriminator inconnu

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
        body.push(0); // KeyAddr
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
        body.push(0); // KeyAddr
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
        body.push(0); // KeyAddr
        body.extend_from_slice(&0u32.to_be_bytes()); // key vide
        body.extend_from_slice(&1u32.to_be_bytes()); // operation vide NUL
        body.push(0);
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
        body.push(0); // KeyAddr
        body.extend_from_slice(&0u32.to_be_bytes()); // key vide
        body.extend_from_slice(&1u32.to_be_bytes()); // operation vide NUL
        body.push(0);
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

    /// Header GIOP parametrable en version mineure et flags.
    fn build_giop_header_v(minor: u8, flags: u8, msg_type: u8, message_length: u32) -> Vec<u8> {
        let mut bytes = b"GIOP".to_vec();
        bytes.extend_from_slice(&[1, minor]);
        bytes.push(flags);
        bytes.push(msg_type);
        bytes.extend_from_slice(&message_length.to_be_bytes());
        bytes
    }

    /// Body d'un Request au layout 1.0 big-endian : un service context en
    /// tete, object_key, operation, principal puis stub data.
    fn build_request_body_1_0_be() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&1u32.to_be_bytes()); // 1 service context
        body.extend_from_slice(&17u32.to_be_bytes()); // context_id
        body.extend_from_slice(&2u32.to_be_bytes()); // context len
        body.extend_from_slice(&[0xAA, 0xBB]);
        body.extend_from_slice(&7u32.to_be_bytes()); // request_id
        body.push(1); // response_expected
        body.extend_from_slice(&3u32.to_be_bytes()); // object_key len
        body.extend_from_slice(b"key");
        body.extend_from_slice(&3u32.to_be_bytes()); // operation "op" + NUL
        body.extend_from_slice(b"op\0");
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
        assert_eq!(request.stub_data, &[0xCA, 0xFE]);
    }

    #[test]
    fn test_dispatch_request_1_0_little_endian() {
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes()); // 0 service context
        body.extend_from_slice(&42u32.to_le_bytes()); // request_id
        body.push(0); // response_expected
        body.extend_from_slice(&3u32.to_le_bytes()); // object_key len
        body.extend_from_slice(b"key");
        body.extend_from_slice(&5u32.to_le_bytes()); // operation "ping" + NUL
        body.extend_from_slice(b"ping\0");
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
        body.extend_from_slice(&3u32.to_be_bytes()); // operation "op" + NUL
        body.extend_from_slice(b"op\0");
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
    fn test_dispatch_reply_placeholder() {
        let mut bytes = build_giop_header_v(2, 0, 1, 4);
        bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let packet = GiopPacket::try_from(bytes.as_slice()).expect("paquet GIOP valide");
        assert!(matches!(packet.payload, GiopMessage::Reply(_)));
    }

    #[test]
    fn test_dispatch_undispatched_type_stays_other() {
        // CancelRequest (2) : type valide mais non dispatche, reste Other.
        // Les types > 7 restent rejetes au niveau du header (classification
        // inchangee), voir test_all_message_types.
        let mut bytes = build_giop_header_v(2, 0, 2, 4);
        bytes.extend_from_slice(&0u32.to_be_bytes());

        let packet = GiopPacket::try_from(bytes.as_slice()).expect("paquet GIOP valide");
        assert!(matches!(
            packet.header.message_type,
            GiopMessageType::CancelRequest
        ));
        assert!(matches!(packet.payload, GiopMessage::Other));
    }
}
