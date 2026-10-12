// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use crate::errors::application::radius::RadiusParseError;

/// Code, identifiant, longueur, authentificateur de seize octets (RFC 2865 §3).
pub const RADIUS_HEADER_LENGTH: usize = 20;

/// Bornes de la longueur declaree (RFC 2865 §3).
pub const RADIUS_LENGTH_MIN: u16 = 20;
pub const RADIUS_LENGTH_MAX: u16 = 4096;

/// Type et longueur d'un attribut (RFC 2865 §5).
pub const RADIUS_ATTRIBUTE_HEADER_LENGTH: usize = 2;

/// Vendor-Specific (RFC 2865 §5.26) : identifiant de vendeur sur quatre
/// octets en tete de la valeur.
pub const RADIUS_VENDOR_ID_LENGTH: usize = 4;

pub fn ensure_len(buf: &[u8], needed: usize) -> Result<(), RadiusParseError> {
    if buf.len() < needed {
        return Err(RadiusParseError::Truncated {
            expected: needed,
            actual: buf.len(),
        });
    }
    Ok(())
}

/// Codes des RFC 2865 (1 a 3, 11 a 13), 2866 (4 et 5) et 5176 (40 a 45).
pub fn validate_code(code: u8) -> Result<(), RadiusParseError> {
    if !matches!(code, 1..=5 | 11..=13 | 40..=45) {
        return Err(RadiusParseError::UnknownCode(code));
    }
    Ok(())
}

/// Longueur declaree : dans ses bornes, et egale au datagramme — les
/// octets au-dela sont a ignorer selon la RFC, mais un parseur qui
/// n'exige pas l'egalite sonderait mal a l'aveugle.
pub fn validate_length(declared: u16, actual: usize) -> Result<(), RadiusParseError> {
    if !(RADIUS_LENGTH_MIN..=RADIUS_LENGTH_MAX).contains(&declared) {
        return Err(RadiusParseError::InvalidLength(declared));
    }
    if usize::from(declared) != actual {
        return Err(RadiusParseError::LengthMismatch { declared, actual });
    }
    Ok(())
}

/// Longueur d'un attribut : au moins son en-tete, au plus le reste.
pub fn validate_attribute_length(
    attribute_type: u8,
    length: u8,
    available: usize,
) -> Result<usize, RadiusParseError> {
    let length_usize = usize::from(length);
    if length_usize < RADIUS_ATTRIBUTE_HEADER_LENGTH {
        return Err(RadiusParseError::AttributeTooShort {
            attribute_type,
            length,
        });
    }
    if length_usize > available {
        return Err(RadiusParseError::AttributeOverflow {
            attribute_type,
            needed: length_usize,
            available,
        });
    }
    Ok(length_usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_radius_checks() {
        for code in [1, 2, 3, 4, 5, 11, 12, 13, 40, 45] {
            assert_eq!(validate_code(code), Ok(()));
        }
        for code in [0, 6, 10, 14, 39, 46, 255] {
            assert_eq!(
                validate_code(code),
                Err(RadiusParseError::UnknownCode(code))
            );
        }
        assert_eq!(validate_length(139, 139), Ok(()));
        assert_eq!(
            validate_length(19, 19),
            Err(RadiusParseError::InvalidLength(19))
        );
        assert_eq!(
            validate_length(4097, 4097),
            Err(RadiusParseError::InvalidLength(4097))
        );
        assert_eq!(
            validate_length(139, 140),
            Err(RadiusParseError::LengthMismatch {
                declared: 139,
                actual: 140
            })
        );
        assert_eq!(validate_attribute_length(1, 14, 119), Ok(14));
        assert_eq!(
            validate_attribute_length(1, 1, 119),
            Err(RadiusParseError::AttributeTooShort {
                attribute_type: 1,
                length: 1
            })
        );
        assert_eq!(
            validate_attribute_length(80, 18, 10),
            Err(RadiusParseError::AttributeOverflow {
                attribute_type: 80,
                needed: 18,
                available: 10
            })
        );
    }
}
