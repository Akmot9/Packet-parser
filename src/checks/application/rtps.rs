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
        SUBMESSAGE_PAD
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
            0x01, 0x06, 0x07, 0x08, 0x09, 0x0c, 0x0d, 0x0e, 0x0f, 0x12, 0x13, 0x15, 0x16, 0x30,
            0x34, 0x80, 0xff,
        ] {
            assert_eq!(validate_submessage_id(id, 20), Ok(id), "{id:#04x}");
        }
        for id in [0x00, 0x02, 0x05, 0x0a, 0x10, 0x14, 0x17, 0x2f, 0x35, 0x7f] {
            assert_eq!(
                validate_submessage_id(id, 20),
                Err(RtpsParseError::ReservedSubmessageId { id, offset: 20 }),
                "{id:#04x}"
            );
        }
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
