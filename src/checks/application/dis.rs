// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use crate::errors::application::dis::DisParseError;

/// En-tete d'un PDU (IEEE 1278.1-2012, §6.2.66) : version, exercice, type,
/// famille, horodatage, longueur, statut (v7) ou bourrage.
pub const DIS_HEADER_LENGTH: usize = 12;

/// Version 7 : IEEE 1278.1-2012, la premiere a porter un champ PDU Status.
pub const DIS_VERSION_2012: u8 = 7;

/// Types de PDU decodes en valeurs typees.
pub const DIS_PDU_ENTITY_STATE: u8 = 1;
pub const DIS_PDU_TRANSMITTER: u8 = 25;
pub const DIS_PDU_SIGNAL: u8 = 26;

/// Dernier type de la norme (Attribute).
pub const DIS_PDU_TYPE_MAX: u8 = 72;

/// Derniere famille de la norme (Information Operations) ; 129 a 255 sont
/// experimentales.
pub const DIS_FAMILY_MAX: u8 = 13;
pub const DIS_FAMILY_EXPERIMENTAL_MIN: u8 = 129;

/// Champs fixes d'un Entity State (§7.2.2) : identifiants, type, vitesse,
/// position, orientation, apparence, dead reckoning, marquage, capacites.
pub const DIS_ENTITY_STATE_FIXED_LENGTH: usize = 132;
/// Un parametre d'articulation ou d'attache (§6.2.94).
pub const DIS_VARIABLE_PARAMETER_LENGTH: usize = 16;
/// Transmitter (§7.7.2), sans ses parametres de modulation ni son antenne.
pub const DIS_TRANSMITTER_FIXED_LENGTH: usize = 92;
/// Signal (§7.7.3), avant les echantillons.
pub const DIS_SIGNAL_FIXED_LENGTH: usize = 20;

pub fn ensure_len(buf: &[u8], needed: usize) -> Result<(), DisParseError> {
    if buf.len() < needed {
        return Err(DisParseError::Truncated {
            expected: needed,
            actual: buf.len(),
        });
    }
    Ok(())
}

pub fn extract_version(byte: u8) -> Result<u8, DisParseError> {
    if !(1..=DIS_VERSION_2012).contains(&byte) {
        return Err(DisParseError::UnsupportedVersion(byte));
    }
    Ok(byte)
}

pub fn extract_pdu_type(byte: u8) -> Result<u8, DisParseError> {
    if !(1..=DIS_PDU_TYPE_MAX).contains(&byte) {
        return Err(DisParseError::ReservedPduType(byte));
    }
    Ok(byte)
}

/// Famille de la norme ou experimentale. Zero (« other ») est admis : une
/// capture reelle du corpus l'emploie pour des PDU radio.
pub fn extract_protocol_family(byte: u8) -> Result<u8, DisParseError> {
    if byte > DIS_FAMILY_MAX && byte < DIS_FAMILY_EXPERIMENTAL_MIN {
        return Err(DisParseError::ReservedProtocolFamily(byte));
    }
    Ok(byte)
}

/// Longueur declaree : au moins l'en-tete, et au plus les octets restants.
pub fn extract_length(bytes: [u8; 2], available: usize) -> Result<u16, DisParseError> {
    let declared = u16::from_be_bytes(bytes);
    if usize::from(declared) < DIS_HEADER_LENGTH {
        return Err(DisParseError::InvalidLength(declared));
    }
    if usize::from(declared) > available {
        return Err(DisParseError::LengthOverflow {
            declared,
            available,
        });
    }
    Ok(declared)
}

/// Le corps d'un PDU doit porter au moins les champs fixes de son type.
pub fn validate_body_length(
    pdu_type: u8,
    expected: usize,
    actual: usize,
) -> Result<(), DisParseError> {
    if actual < expected {
        return Err(DisParseError::BodyTooShort {
            pdu_type,
            expected,
            actual,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_fields() {
        for version in 1..=7 {
            assert_eq!(extract_version(version), Ok(version));
        }
        for version in [0, 8, 0xff] {
            assert_eq!(
                extract_version(version),
                Err(DisParseError::UnsupportedVersion(version))
            );
        }
        assert_eq!(extract_pdu_type(1), Ok(1));
        assert_eq!(extract_pdu_type(72), Ok(72));
        assert_eq!(
            extract_pdu_type(73),
            Err(DisParseError::ReservedPduType(73))
        );
        assert_eq!(extract_pdu_type(0), Err(DisParseError::ReservedPduType(0)));
        assert_eq!(extract_protocol_family(0), Ok(0));
        assert_eq!(extract_protocol_family(13), Ok(13));
        assert_eq!(extract_protocol_family(129), Ok(129));
        assert_eq!(
            extract_protocol_family(14),
            Err(DisParseError::ReservedProtocolFamily(14))
        );
    }

    #[test]
    fn test_length_bounds() {
        assert_eq!(extract_length([0x00, 0x68], 104), Ok(104));
        assert_eq!(extract_length([0x00, 0x30], 160), Ok(48));
        assert_eq!(
            extract_length([0x00, 0x0b], 100),
            Err(DisParseError::InvalidLength(11))
        );
        assert_eq!(
            extract_length([0x00, 0x68], 100),
            Err(DisParseError::LengthOverflow {
                declared: 104,
                available: 100
            })
        );
        assert_eq!(validate_body_length(26, 20, 20), Ok(()));
        assert_eq!(
            validate_body_length(26, 20, 8),
            Err(DisParseError::BodyTooShort {
                pdu_type: 26,
                expected: 20,
                actual: 8
            })
        );
    }
}
