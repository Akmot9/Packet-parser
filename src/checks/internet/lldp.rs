// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use crate::errors::internet::lldp::LldpParseError;

/// En-tete d'un TLV : sept bits de type, neuf bits de longueur.
pub const TLV_HEADER_LENGTH: usize = 2;

/// Types de TLV de base (IEEE 802.1AB §8.4, tableau 8-1).
pub const TLV_END_OF_LLDPDU: u8 = 0;
pub const TLV_CHASSIS_ID: u8 = 1;
pub const TLV_PORT_ID: u8 = 2;
pub const TLV_TIME_TO_LIVE: u8 = 3;
pub const TLV_PORT_DESCRIPTION: u8 = 4;
pub const TLV_SYSTEM_NAME: u8 = 5;
pub const TLV_SYSTEM_DESCRIPTION: u8 = 6;
pub const TLV_SYSTEM_CAPABILITIES: u8 = 7;
pub const TLV_MANAGEMENT_ADDRESS: u8 = 8;
pub const TLV_ORGANIZATIONALLY_SPECIFIC: u8 = 127;

/// Les trois TLV obligatoires, dans l'ordre ou ils ouvrent le LLDPDU.
pub const MANDATORY_TLVS: [u8; 3] = [TLV_CHASSIS_ID, TLV_PORT_ID, TLV_TIME_TO_LIVE];

/// Chassis ID et Port ID : un octet de sous-type et un identifiant de 1 a
/// 255 octets (§8.5.2, §8.5.3).
const ID_TLV_LENGTHS: std::ops::RangeInclusive<usize> = 2..=256;

/// Management Address (§8.5.9) : longueur de l'adresse, sous-type et
/// adresse (2 a 32 octets), sous-type de numerotation d'interface, numero
/// d'interface sur quatre octets, longueur de l'OID et OID (0 a 128 octets).
const MANAGEMENT_ADDRESS_LENGTHS: std::ops::RangeInclusive<usize> = 9..=167;

/// TLV d'organisation (§8.6) : OUI sur trois octets et sous-type, puis 0 a
/// 507 octets d'information.
pub const ORGANIZATION_HEADER_LENGTH: usize = 4;

/// Le TLV qui commence a `offset` : son type, sa valeur et l'offset du
/// suivant.
pub fn split_tlv(lldpdu: &[u8], offset: usize) -> Result<(u8, &[u8], usize), LldpParseError> {
    let header = lldpdu
        .get(offset..offset + TLV_HEADER_LENGTH)
        .ok_or(LldpParseError::TruncatedTlvHeader { offset })?;
    let tlv_type = header[0] >> 1;
    let length = usize::from(u16::from_be_bytes([header[0] & 0x01, header[1]]));
    let start = offset + TLV_HEADER_LENGTH;
    let value = lldpdu
        .get(start..start + length)
        .ok_or(LldpParseError::TlvOverflow {
            tlv_type,
            offset,
            declared: length,
            available: lldpdu.len() - start,
        })?;
    Ok((tlv_type, value, start + length))
}

/// La taille d'un TLV dans les bornes de la norme, pour les TLV dont le
/// decodeur lit la structure ; les chaines (descriptions, nom) et les types
/// reserves ne sont pas bornes.
pub fn validate_tlv_length(tlv_type: u8, length: usize) -> Result<(), LldpParseError> {
    let valid = match tlv_type {
        TLV_END_OF_LLDPDU => length == 0,
        TLV_CHASSIS_ID | TLV_PORT_ID => ID_TLV_LENGTHS.contains(&length),
        TLV_TIME_TO_LIVE => length == 2,
        TLV_SYSTEM_CAPABILITIES => length == 4,
        TLV_MANAGEMENT_ADDRESS => MANAGEMENT_ADDRESS_LENGTHS.contains(&length),
        TLV_ORGANIZATIONALLY_SPECIFIC => length >= ORGANIZATION_HEADER_LENGTH,
        _ => true,
    };
    if !valid {
        return Err(LldpParseError::InvalidTlvLength { tlv_type, length });
    }
    Ok(())
}

/// Longueur de l'adresse d'un Management Address, sous-type compris (2 a
/// 32 octets), et de son OID (au plus 128 octets).
pub const MANAGEMENT_ADDRESS_FIELD_LENGTHS: std::ops::RangeInclusive<usize> = 2..=32;
pub const MANAGEMENT_OID_MAX_LENGTH: usize = 128;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_tlv_reads_the_nine_bit_length() {
        // Type 6 (System Description), longueur 0x1f3 = 499.
        let mut bytes = vec![0x0d, 0xf3];
        bytes.extend([b'a'; 499]);
        bytes.extend([0x00, 0x00]);
        let (tlv_type, value, next) = split_tlv(&bytes, 0).unwrap();
        assert_eq!((tlv_type, value.len(), next), (6, 499, 501));
        assert_eq!(split_tlv(&bytes, next).unwrap(), (0, &[][..], 503));
    }

    #[test]
    fn test_split_tlv_rejects_truncation() {
        assert_eq!(
            split_tlv(&[0x02], 0),
            Err(LldpParseError::TruncatedTlvHeader { offset: 0 })
        );
        assert_eq!(
            split_tlv(&[0x02, 0x07, 0x04, 0x00], 0),
            Err(LldpParseError::TlvOverflow {
                tlv_type: 1,
                offset: 0,
                declared: 7,
                available: 2
            })
        );
    }

    #[test]
    fn test_tlv_length_bounds() {
        for (tlv_type, length) in [(0u8, 0usize), (1, 2), (1, 256), (3, 2), (7, 4), (8, 9)] {
            assert_eq!(validate_tlv_length(tlv_type, length), Ok(()), "{tlv_type}");
        }
        for (tlv_type, length) in [
            (0u8, 2usize),
            (1, 1),
            (2, 257),
            (3, 4),
            (7, 2),
            (8, 8),
            (127, 3),
        ] {
            assert!(
                validate_tlv_length(tlv_type, length).is_err(),
                "{tlv_type}/{length}"
            );
        }
        // Les chaines et les types reserves ne sont pas bornes.
        assert_eq!(validate_tlv_length(6, 499), Ok(()));
        assert_eq!(validate_tlv_length(42, 0), Ok(()));
    }
}
