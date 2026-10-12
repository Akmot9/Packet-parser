// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use crate::errors::internet::goose::GooseParseError;

/// APPID, longueur, reserve 1, reserve 2 (IEC 61850-8-1 §8.1.3).
pub const GOOSE_HEADER_LENGTH: usize = 8;

/// Bit S de la reserve 1 : trame de simulation (edition 2).
pub const GOOSE_RESERVED1_SIMULATION: u16 = 0x8000;

/// Etiquette BER du goosePdu : `[APPLICATION 1]`, forme construite.
pub const GOOSE_PDU_TAG: u8 = 0x61;

/// Etiquettes des champs du PDU (IEC 61850-8-1 annexe A, GOOSEpdu).
pub const GOOSE_TAG_GOCB_REF: u8 = 0x80;
pub const GOOSE_TAG_TIME_ALLOWED_TO_LIVE: u8 = 0x81;
pub const GOOSE_TAG_DATA_SET: u8 = 0x82;
pub const GOOSE_TAG_GO_ID: u8 = 0x83;
pub const GOOSE_TAG_TIMESTAMP: u8 = 0x84;
pub const GOOSE_TAG_ST_NUM: u8 = 0x85;
pub const GOOSE_TAG_SQ_NUM: u8 = 0x86;
pub const GOOSE_TAG_SIMULATION: u8 = 0x87;
pub const GOOSE_TAG_CONF_REV: u8 = 0x88;
pub const GOOSE_TAG_NDS_COM: u8 = 0x89;
pub const GOOSE_TAG_NUM_DAT_SET_ENTRIES: u8 = 0x8a;
pub const GOOSE_TAG_ALL_DATA: u8 = 0xab;
pub const GOOSE_TAG_SECURITY: u8 = 0x8c;

/// UtcTime (IEC 61850-8-1 §8.1.3.7) : secondes, fraction, qualite.
pub const GOOSE_TIMESTAMP_LENGTH: usize = 8;

pub fn ensure_len(buf: &[u8], needed: usize) -> Result<(), GooseParseError> {
    if buf.len() < needed {
        return Err(GooseParseError::Truncated {
            expected: needed,
            actual: buf.len(),
        });
    }
    Ok(())
}

/// La longueur declaree couvre exactement ce qui suit l'EtherType.
pub fn validate_length(declared: u16, actual: usize) -> Result<(), GooseParseError> {
    if usize::from(declared) != actual || usize::from(declared) < GOOSE_HEADER_LENGTH {
        return Err(GooseParseError::LengthMismatch { declared, actual });
    }
    Ok(())
}

pub fn validate_pdu_tag(tag: u8) -> Result<(), GooseParseError> {
    if tag != GOOSE_PDU_TAG {
        return Err(GooseParseError::InvalidPduTag(tag));
    }
    Ok(())
}

/// Longueur BER (X.690 §8.1.3) a `offset` dans `bytes` : la valeur et le
/// nombre d'octets qu'elle occupe.
pub fn extract_ber_length(bytes: &[u8], offset: usize) -> Result<(usize, usize), GooseParseError> {
    let first = *bytes
        .get(offset)
        .ok_or(GooseParseError::InvalidBerLength(offset))?;
    if first & 0x80 == 0 {
        return Ok((usize::from(first), 1));
    }
    let octets = usize::from(first & 0x7f);
    if octets == 0 || octets > 4 {
        return Err(GooseParseError::InvalidBerLength(offset));
    }
    let digits = bytes
        .get(offset + 1..offset + 1 + octets)
        .ok_or(GooseParseError::InvalidBerLength(offset))?;
    let length = digits
        .iter()
        .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
    Ok((length, 1 + octets))
}

pub fn validate_element_fits(
    tag: u8,
    declared: usize,
    available: usize,
) -> Result<(), GooseParseError> {
    if declared > available {
        return Err(GooseParseError::ElementOverflow {
            tag,
            declared,
            available,
        });
    }
    Ok(())
}

/// Un INTEGER BER non negatif sur 32 bits : un a quatre octets, ou cinq
/// avec un premier octet nul.
pub fn extract_u32(tag: u8, value: &[u8]) -> Result<u32, GooseParseError> {
    let digits = match value {
        [] => return Err(GooseParseError::IntegerTooLong { tag, length: 0 }),
        [0, rest @ ..] if rest.len() == 4 => rest,
        digits if digits.len() <= 4 => digits,
        _ => {
            return Err(GooseParseError::IntegerTooLong {
                tag,
                length: value.len(),
            });
        }
    };
    Ok(digits
        .iter()
        .fold(0u32, |acc, &b| (acc << 8) | u32::from(b)))
}

pub fn extract_bool(tag: u8, value: &[u8]) -> Result<bool, GooseParseError> {
    match value {
        [byte] => Ok(*byte != 0),
        _ => Err(GooseParseError::InvalidBoolean {
            tag,
            length: value.len(),
        }),
    }
}

pub fn validate_timestamp_length(len: usize) -> Result<(), GooseParseError> {
    if len != GOOSE_TIMESTAMP_LENGTH {
        return Err(GooseParseError::InvalidTimestamp(len));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_goose_checks() {
        assert_eq!(validate_length(145, 145), Ok(()));
        assert_eq!(
            validate_length(145, 146),
            Err(GooseParseError::LengthMismatch {
                declared: 145,
                actual: 146
            })
        );
        assert_eq!(
            validate_length(7, 7),
            Err(GooseParseError::LengthMismatch {
                declared: 7,
                actual: 7
            })
        );
        assert_eq!(validate_pdu_tag(0x61), Ok(()));
        assert_eq!(
            validate_pdu_tag(0x60),
            Err(GooseParseError::InvalidPduTag(0x60))
        );
        assert_eq!(extract_ber_length(&[0x1a], 0), Ok((26, 1)));
        assert_eq!(extract_ber_length(&[0x81, 0x86], 0), Ok((134, 2)));
        assert_eq!(extract_ber_length(&[0x82, 0x01, 0x00], 0), Ok((256, 3)));
        assert_eq!(
            extract_ber_length(&[0x85, 0, 0, 0, 0, 1], 0),
            Err(GooseParseError::InvalidBerLength(0))
        );
        assert_eq!(
            extract_ber_length(&[0x82, 0x01], 0),
            Err(GooseParseError::InvalidBerLength(0))
        );
        assert_eq!(extract_u32(0x85, &[0x01]), Ok(1));
        assert_eq!(extract_u32(0x85, &[0x00, 0x9c, 0x40]), Ok(40000));
        assert_eq!(
            extract_u32(0x85, &[0x00, 0xff, 0xff, 0xff, 0xff]),
            Ok(u32::MAX)
        );
        assert_eq!(
            extract_u32(0x85, &[0x01, 0, 0, 0, 0]),
            Err(GooseParseError::IntegerTooLong {
                tag: 0x85,
                length: 5
            })
        );
        assert_eq!(extract_bool(0x87, &[0x00]), Ok(false));
        assert_eq!(extract_bool(0x87, &[0xff]), Ok(true));
        assert_eq!(
            extract_bool(0x87, &[0, 0]),
            Err(GooseParseError::InvalidBoolean {
                tag: 0x87,
                length: 2
            })
        );
        assert_eq!(validate_timestamp_length(8), Ok(()));
        assert_eq!(
            validate_timestamp_length(7),
            Err(GooseParseError::InvalidTimestamp(7))
        );
    }
}
