// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use crate::errors::application::rtps::RtpsParseError;

/// En-tete d'un message : magic, version, vendorId, guidPrefix (DDSI-RTPS
/// 2.5, §9.4.4).
pub const RTPS_HEADER_LENGTH: usize = 20;

/// En-tete d'un sous-message : submessageId, flags, octetsToNextHeader
/// (§9.4.5.1).
pub const RTPS_SUBMESSAGE_HEADER_LENGTH: usize = 4;

pub const RTPS_MAGIC: [u8; 4] = *b"RTPS";

/// Variante `RTPX` du magic, emise par RTI Connext sur une partie de son
/// metatrafic unicast : meme en-tete, memes sous-messages, et tshark la
/// dissèque comme du RTPS.
pub const RTPS_MAGIC_EXTENSION: [u8; 4] = *b"RTPX";

/// « Ping » RTI Connext : magic, version, vendorId et le texte `NDDSPING`,
/// seize octets, sans guidPrefix ni sous-message. tshark le dissèque comme
/// du RTPS (« Ping String »).
pub const RTPS_PING_LENGTH: usize = 16;
pub const RTPS_PING_TEXT: [u8; 8] = *b"NDDSPING";

/// Bit E des flags : 1 pour un sous-message en petit-boutiste (§9.4.5.1.2).
pub const RTPS_FLAG_ENDIANNESS: u8 = 0x01;

/// Identifiants de sous-message (§9.4.5.1.1), DDS Security 1.1 (§7.3.6.2)
/// compris. Les valeurs 0x80 a 0xff sont reservees aux vendeurs.
/// HEADER_EXTENSION (DDSI-RTPS 2.5 §9.4.5.2) : premier sous-message, juste
/// apres l'en-tete, dont les flags annoncent les champs.
pub const SUBMESSAGE_HEADER_EXTENSION: u8 = 0x00;
pub const SUBMESSAGE_PAD: u8 = 0x01;
pub const SUBMESSAGE_ACKNACK: u8 = 0x06;
pub const SUBMESSAGE_HEARTBEAT: u8 = 0x07;
pub const SUBMESSAGE_GAP: u8 = 0x08;
pub const SUBMESSAGE_INFO_TS: u8 = 0x09;
pub const SUBMESSAGE_INFO_SRC: u8 = 0x0c;
pub const SUBMESSAGE_INFO_REPLY_IP4: u8 = 0x0d;
pub const SUBMESSAGE_INFO_DST: u8 = 0x0e;
pub const SUBMESSAGE_INFO_REPLY: u8 = 0x0f;
pub const SUBMESSAGE_NACK_FRAG: u8 = 0x12;
pub const SUBMESSAGE_HEARTBEAT_FRAG: u8 = 0x13;
pub const SUBMESSAGE_DATA: u8 = 0x15;
pub const SUBMESSAGE_DATA_FRAG: u8 = 0x16;
pub const SUBMESSAGE_SEC_BODY: u8 = 0x30;
pub const SUBMESSAGE_SEC_PREFIX: u8 = 0x31;
pub const SUBMESSAGE_SEC_POSTFIX: u8 = 0x32;
pub const SUBMESSAGE_SRTPS_PREFIX: u8 = 0x33;
pub const SUBMESSAGE_SRTPS_POSTFIX: u8 = 0x34;

/// Flags du HEADER_EXTENSION (§9.4.5.2) : L messageLength, T
/// rtpsSendTimestamp, U uExtension4, W wExtension8, C1 et C2 la somme de
/// controle (C2 seul CRC-32C, C1 seul CRC-64/XZ, les deux MD5, Table 9.8),
/// P une ParameterList jusqu'a la fin du corps.
pub const HEADER_EXTENSION_FLAG_LENGTH: u8 = 0x02;
pub const HEADER_EXTENSION_FLAG_TIMESTAMP: u8 = 0x04;
pub const HEADER_EXTENSION_FLAG_UEXTENSION4: u8 = 0x08;
pub const HEADER_EXTENSION_FLAG_WEXTENSION8: u8 = 0x10;
pub const HEADER_EXTENSION_FLAG_CHECKSUM2: u8 = 0x20;
pub const HEADER_EXTENSION_FLAG_CHECKSUM1: u8 = 0x40;
pub const HEADER_EXTENSION_FLAG_PARAMETERS: u8 = 0x80;

/// Longueur de la somme de controle qu'annoncent les flags C1 et C2 : zero
/// sans somme, 4 (CRC-32C), 8 (CRC-64/XZ) ou 16 (MD5).
pub const fn header_extension_checksum_length(flags: u8) -> usize {
    match (
        flags & HEADER_EXTENSION_FLAG_CHECKSUM1 != 0,
        flags & HEADER_EXTENSION_FLAG_CHECKSUM2 != 0,
    ) {
        (false, false) => 0,
        (false, true) => 4,
        (true, false) => 8,
        (true, true) => 16,
    }
}

/// Longueur de la partie fixe du corps d'un HEADER_EXTENSION, celle que les
/// flags annoncent avant la ParameterList optionnelle.
pub const fn header_extension_fixed_length(flags: u8) -> usize {
    let mut length = header_extension_checksum_length(flags);
    if flags & HEADER_EXTENSION_FLAG_LENGTH != 0 {
        length += 4;
    }
    if flags & HEADER_EXTENSION_FLAG_TIMESTAMP != 0 {
        length += 8;
    }
    if flags & HEADER_EXTENSION_FLAG_UEXTENSION4 != 0 {
        length += 4;
    }
    if flags & HEADER_EXTENSION_FLAG_WEXTENSION8 != 0 {
        length += 8;
    }
    length
}

pub fn ensure_len(buf: &[u8], needed: usize) -> Result<(), RtpsParseError> {
    if buf.len() < needed {
        return Err(RtpsParseError::Truncated {
            expected: needed,
            actual: buf.len(),
        });
    }
    Ok(())
}

/// Les quatre octets `RTPS` (ou `RTPX`, variante RTI) en tete du message,
/// rendus tels quels.
pub fn extract_magic(buf: &[u8]) -> Result<[u8; 4], RtpsParseError> {
    let magic: [u8; 4] =
        buf.get(..4)
            .and_then(|m| m.try_into().ok())
            .ok_or(RtpsParseError::Truncated {
                expected: RTPS_HEADER_LENGTH,
                actual: buf.len(),
            })?;
    if magic != RTPS_MAGIC && magic != RTPS_MAGIC_EXTENSION {
        return Err(RtpsParseError::InvalidMagic(magic));
    }
    Ok(magic)
}

/// Version du protocole : seule la 2.x est decodee (la 1.x de RTPS, d'un
/// autre format, n'a plus d'emetteur).
pub fn extract_version(major: u8, minor: u8) -> Result<(u8, u8), RtpsParseError> {
    if major != 2 {
        return Err(RtpsParseError::UnsupportedVersion { major, minor });
    }
    Ok((major, minor))
}

/// Un submessageId de la specification, de DDS Security ou de la plage
/// vendeur ; les autres valeurs sont reservees.
pub fn validate_submessage_id(id: u8, offset: usize) -> Result<u8, RtpsParseError> {
    match id {
        SUBMESSAGE_HEADER_EXTENSION
        | SUBMESSAGE_PAD
        | SUBMESSAGE_ACKNACK
        | SUBMESSAGE_HEARTBEAT
        | SUBMESSAGE_GAP
        | SUBMESSAGE_INFO_TS
        | SUBMESSAGE_INFO_SRC
        | SUBMESSAGE_INFO_REPLY_IP4
        | SUBMESSAGE_INFO_DST
        | SUBMESSAGE_INFO_REPLY
        | SUBMESSAGE_NACK_FRAG
        | SUBMESSAGE_HEARTBEAT_FRAG
        | SUBMESSAGE_DATA
        | SUBMESSAGE_DATA_FRAG
        | SUBMESSAGE_SEC_BODY
        | SUBMESSAGE_SEC_PREFIX
        | SUBMESSAGE_SEC_POSTFIX
        | SUBMESSAGE_SRTPS_PREFIX
        | SUBMESSAGE_SRTPS_POSTFIX
        | 0x80..=0xff => Ok(id),
        _ => Err(RtpsParseError::ReservedSubmessageId { id, offset }),
    }
}

/// Longueur du corps d'un sous-message : `octetsToNextHeader`, ou, s'il
/// vaut zero, le reste du message — sauf pour PAD et INFO_TS, dont zero
/// signifie un corps vide (§9.4.5.1.3).
pub fn submessage_body_length(
    id: u8,
    offset: usize,
    declared: u16,
    available: usize,
) -> Result<usize, RtpsParseError> {
    let declared = usize::from(declared);
    if declared == 0 && !matches!(id, SUBMESSAGE_PAD | SUBMESSAGE_INFO_TS) {
        return Ok(available);
    }
    if declared > available {
        return Err(RtpsParseError::SubmessageOverflow {
            id,
            offset,
            declared,
            available,
        });
    }
    Ok(declared)
}

/// Lit un entier de 16 bits dans l'ordre d'octets du sous-message.
pub fn read_u16(bytes: [u8; 2], little_endian: bool) -> u16 {
    if little_endian {
        u16::from_le_bytes(bytes)
    } else {
        u16::from_be_bytes(bytes)
    }
}

/// Lit un entier de 32 bits dans l'ordre d'octets du sous-message.
pub fn read_u32(bytes: [u8; 4], little_endian: bool) -> u32 {
    if little_endian {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    }
}

/// Un `SequenceNumber_t` (§9.3.2) : `high` signe sur 32 bits puis `low`
/// non signe, chacun dans l'ordre d'octets du sous-message.
pub fn read_sequence_number(bytes: [u8; 8], little_endian: bool) -> i64 {
    let high = read_u32([bytes[0], bytes[1], bytes[2], bytes[3]], little_endian) as i32;
    let low = read_u32([bytes[4], bytes[5], bytes[6], bytes[7]], little_endian);
    (i64::from(high) << 32) | i64::from(low)
}

/// Le corps d'un sous-message doit porter au moins les champs que son type
/// impose.
pub fn validate_body_length(
    id: u8,
    offset: usize,
    expected: usize,
    actual: usize,
) -> Result<(), RtpsParseError> {
    if actual < expected {
        return Err(RtpsParseError::SubmessageTooShort {
            id,
            offset,
            expected,
            actual,
        });
    }
    Ok(())
}

/// Octets d'un bitmap de `numBits` bits : des mots de 32 bits (§9.4.2.6).
pub fn bitmap_length(num_bits: u32) -> usize {
    // numBits <= 256 dans la specification ; borne ici par le u32.
    (num_bits as usize).div_ceil(32) * 4
}

// Couche DDS (#317) : QoS en ligne, encapsulation, decouverte.

/// Flag Q d'un DATA et d'un DATA_FRAG : des QoS en ligne precedent les
/// donnees (§9.4.5.3.1, §9.4.5.4.1).
pub const DATA_FLAG_INLINE_QOS: u8 = 0x02;
/// Flag D d'un DATA : le corps porte des donnees serialisees.
pub const DATA_FLAG_DATA: u8 = 0x04;
/// Flag K d'un DATA : le corps porte une cle serialisee.
pub const DATA_FLAG_KEY: u8 = 0x08;

/// En-tete d'un parametre : parameterId u16 puis length u16 (§9.4.2.11).
pub const RTPS_PARAMETER_HEADER_LENGTH: usize = 4;
/// En-tete d'encapsulation des donnees serialisees : identifiant de
/// representation puis options, deux octets chacun (§10.2).
pub const RTPS_ENCAPSULATION_HEADER_LENGTH: usize = 4;

/// Identifiants de parametre (Table 9.13). Le bit 15 marque un PID
/// propre a une implementation, le bit 14 un PID qu'un recepteur doit
/// comprendre pour accepter le sous-message (§9.6.2.2.1).
pub const PID_VENDOR_SPECIFIC_FLAG: u16 = 0x8000;
pub const PID_MUST_UNDERSTAND_FLAG: u16 = 0x4000;
pub const PID_SENTINEL: u16 = 0x0001;
pub const PID_PARTICIPANT_LEASE_DURATION: u16 = 0x0002;
pub const PID_TOPIC_NAME: u16 = 0x0005;
pub const PID_TYPE_NAME: u16 = 0x0007;
pub const PID_DOMAIN_ID: u16 = 0x000f;
pub const PID_PROTOCOL_VERSION: u16 = 0x0015;
/// `PID_VENDORID` dans la specification, le nom que rend
/// `RtpsParameter::name` ; `PID_VENDOR_ID` dans tshark, comme ici.
pub const PID_VENDOR_ID: u16 = 0x0016;
pub const PID_RELIABILITY: u16 = 0x001a;
pub const PID_DURABILITY: u16 = 0x001d;
pub const PID_UNICAST_LOCATOR: u16 = 0x002f;
pub const PID_MULTICAST_LOCATOR: u16 = 0x0030;
pub const PID_DEFAULT_UNICAST_LOCATOR: u16 = 0x0031;
pub const PID_METATRAFFIC_UNICAST_LOCATOR: u16 = 0x0032;
pub const PID_METATRAFFIC_MULTICAST_LOCATOR: u16 = 0x0033;
pub const PID_DEFAULT_MULTICAST_LOCATOR: u16 = 0x0048;
pub const PID_PARTICIPANT_GUID: u16 = 0x0050;
pub const PID_BUILTIN_ENDPOINT_SET: u16 = 0x0058;
pub const PID_ENDPOINT_GUID: u16 = 0x005a;
pub const PID_ENTITY_NAME: u16 = 0x0062;
pub const PID_KEY_HASH: u16 = 0x0070;
pub const PID_STATUS_INFO: u16 = 0x0071;

/// Types de `Locator_t` (§9.3.2).
pub const LOCATOR_KIND_UDPV4: i32 = 1;
pub const LOCATOR_KIND_UDPV6: i32 = 2;

/// Writers integres de la decouverte (§9.3.1.4, Table 9.2 ; DDS Security
/// 1.1 Table 9 pour les variantes securisees).
pub const ENTITYID_SPDP_PARTICIPANT_WRITER: u32 = 0x0001_00c2;
pub const ENTITYID_SEDP_TOPICS_WRITER: u32 = 0x0000_02c2;
pub const ENTITYID_SEDP_PUBLICATIONS_WRITER: u32 = 0x0000_03c2;
pub const ENTITYID_SEDP_SUBSCRIPTIONS_WRITER: u32 = 0x0000_04c2;
pub const ENTITYID_SPDP_PARTICIPANT_SECURE_WRITER: u32 = 0xff01_01c2;
pub const ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER: u32 = 0xff00_03c2;
pub const ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER: u32 = 0xff00_04c2;

/// Identifiants de representation des donnees serialisees (DDS-XTypes 1.3
/// §7.6.3.1.2, Table 60).
pub const ENCAPSULATION_CDR_BE: u16 = 0x0000;
pub const ENCAPSULATION_CDR_LE: u16 = 0x0001;
pub const ENCAPSULATION_PL_CDR_BE: u16 = 0x0002;
pub const ENCAPSULATION_PL_CDR_LE: u16 = 0x0003;
pub const ENCAPSULATION_XML: u16 = 0x0004;
pub const ENCAPSULATION_CDR2_BE: u16 = 0x0010;
pub const ENCAPSULATION_CDR2_LE: u16 = 0x0011;
pub const ENCAPSULATION_PL_CDR2_BE: u16 = 0x0012;
pub const ENCAPSULATION_PL_CDR2_LE: u16 = 0x0013;
pub const ENCAPSULATION_D_CDR2_BE: u16 = 0x0014;
pub const ENCAPSULATION_D_CDR2_LE: u16 = 0x0015;

/// Offset, dans le corps d'un DATA ou d'un DATA_FRAG, de ce qui suit ses
/// champs fixes : QoS en ligne s'il y en a, sinon donnees.
/// `octetsToInlineQos` se compte depuis l'octet qui suit ce champ, lui-meme
/// a l'offset 2 ; il doit pointer entre la fin des champs fixes (`fixed`
/// octets, 20 pour un DATA, 32 pour un DATA_FRAG) et la fin du corps, qui
/// porte au moins `fixed` octets.
pub fn inline_qos_offset(
    body: &[u8],
    little_endian: bool,
    fixed: usize,
) -> Result<usize, RtpsParseError> {
    let octets = read_u16([body[2], body[3]], little_endian);
    let offset = 4 + usize::from(octets);
    if offset < fixed || offset > body.len() {
        return Err(RtpsParseError::InvalidOctetsToInlineQos {
            octets_to_inline_qos: octets,
            body: body.len(),
        });
    }
    Ok(offset)
}

/// Une ParameterList qui commence en tete de `bytes` (§9.4.2.11) : rend la
/// longueur des parametres avant le PID_SENTINEL, et celle de la liste
/// sentinel compris. La longueur du sentinel est ignoree, comme le veut la
/// specification ; un parametre qui deborde, ou une liste sans sentinel,
/// est refuse.
pub fn parameter_list_length(
    bytes: &[u8],
    little_endian: bool,
) -> Result<(usize, usize), RtpsParseError> {
    let mut offset = 0;
    loop {
        if offset == bytes.len() {
            return Err(RtpsParseError::ParameterListUnterminated {
                length: bytes.len(),
            });
        }
        let Some(header) = bytes.get(offset..offset + RTPS_PARAMETER_HEADER_LENGTH) else {
            return Err(RtpsParseError::ParameterTruncated {
                offset,
                expected: RTPS_PARAMETER_HEADER_LENGTH,
                actual: bytes.len() - offset,
            });
        };
        let id = read_u16([header[0], header[1]], little_endian);
        if id == PID_SENTINEL {
            return Ok((offset, offset + RTPS_PARAMETER_HEADER_LENGTH));
        }
        let length = usize::from(read_u16([header[2], header[3]], little_endian));
        let available = bytes.len() - offset - RTPS_PARAMETER_HEADER_LENGTH;
        if length > available {
            return Err(RtpsParseError::ParameterTruncated {
                offset,
                expected: length,
                actual: available,
            });
        }
        offset += RTPS_PARAMETER_HEADER_LENGTH + length;
    }
}

/// Une chaine CDR en tete de la valeur d'un parametre : longueur u32, NUL
/// final compris, puis les octets. Rend les octets sans le NUL ; `None` si
/// la longueur deborde de la valeur.
pub fn cdr_string(value: &[u8], little_endian: bool) -> Option<&[u8]> {
    let length = read_u32(value.get(..4)?.try_into().ok()?, little_endian);
    let text = value.get(4..4 + usize::try_from(length).ok()?)?;
    Some(text.strip_suffix(&[0]).unwrap_or(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magic_and_version() {
        assert_eq!(extract_magic(b"RTPS\x02\x01"), Ok(*b"RTPS"));
        assert_eq!(extract_magic(b"RTPX\x02\x01"), Ok(*b"RTPX"));
        assert_eq!(
            extract_magic(b"RTPZ\x02\x01"),
            Err(RtpsParseError::InvalidMagic(*b"RTPZ"))
        );
        assert!(matches!(
            extract_magic(b"RT"),
            Err(RtpsParseError::Truncated { .. })
        ));
        assert_eq!(extract_version(2, 5), Ok((2, 5)));
        assert_eq!(
            extract_version(1, 2),
            Err(RtpsParseError::UnsupportedVersion { major: 1, minor: 2 })
        );
    }

    #[test]
    fn test_submessage_ids() {
        for id in [
            0x00, 0x01, 0x06, 0x07, 0x08, 0x09, 0x0c, 0x0d, 0x0e, 0x0f, 0x12, 0x13, 0x15, 0x16,
            0x30, 0x34, 0x80, 0xff,
        ] {
            assert_eq!(validate_submessage_id(id, 20), Ok(id), "{id:#04x}");
        }
        for id in [0x02, 0x05, 0x0a, 0x10, 0x14, 0x17, 0x2f, 0x35, 0x7f] {
            assert_eq!(
                validate_submessage_id(id, 20),
                Err(RtpsParseError::ReservedSubmessageId { id, offset: 20 }),
                "{id:#04x}"
            );
        }
    }

    #[test]
    fn test_header_extension_fixed_length_follows_the_flags() {
        assert_eq!(header_extension_fixed_length(0x01), 0);
        // L, T et CRC-32C (la trame de #186).
        assert_eq!(header_extension_fixed_length(0x27), 16);
        // U, W et MD5.
        assert_eq!(header_extension_fixed_length(0x78), 28);
        // L et CRC-64/XZ.
        assert_eq!(header_extension_fixed_length(0x43), 12);
        // P seul : rien de fixe.
        assert_eq!(header_extension_fixed_length(0x81), 0);
        assert_eq!(header_extension_checksum_length(0x20), 4);
        assert_eq!(header_extension_checksum_length(0x40), 8);
        assert_eq!(header_extension_checksum_length(0x60), 16);
    }

    #[test]
    fn test_body_length_follows_octets_to_next_header() {
        assert_eq!(submessage_body_length(SUBMESSAGE_DATA, 20, 48, 100), Ok(48));
        // Zero : le reste du message, sauf PAD et INFO_TS.
        assert_eq!(submessage_body_length(SUBMESSAGE_DATA, 20, 0, 100), Ok(100));
        assert_eq!(submessage_body_length(SUBMESSAGE_PAD, 20, 0, 100), Ok(0));
        assert_eq!(
            submessage_body_length(SUBMESSAGE_INFO_TS, 20, 0, 100),
            Ok(0)
        );
        assert_eq!(
            submessage_body_length(SUBMESSAGE_DATA, 20, 101, 100),
            Err(RtpsParseError::SubmessageOverflow {
                id: SUBMESSAGE_DATA,
                offset: 20,
                declared: 101,
                available: 100
            })
        );
    }

    #[test]
    fn test_endianness_and_sequence_numbers() {
        assert_eq!(read_u16([0x30, 0x00], true), 48);
        assert_eq!(read_u16([0x00, 0x30], false), 48);
        assert_eq!(read_u32([0xc2, 0x03, 0x00, 0x00], false), 0xc203_0000);
        assert_eq!(read_sequence_number([0, 0, 0, 0, 1, 0, 0, 0], true), 1);
        assert_eq!(
            read_sequence_number([0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0], false),
            -1 << 32
        );
        assert_eq!(bitmap_length(0), 0);
        assert_eq!(bitmap_length(1), 4);
        assert_eq!(bitmap_length(32), 4);
        assert_eq!(bitmap_length(33), 8);
        assert_eq!(bitmap_length(256), 32);
    }
}
