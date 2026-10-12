// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use crate::errors::application::bacnet::BacnetParseError;

/// Type BVLC de BACnet/IP (annexe J.2.1).
pub const BVLC_TYPE_BACNET_IP: u8 = 0x81;

/// Type, fonction, longueur sur deux octets.
pub const BVLC_HEADER_LENGTH: usize = 4;

/// Fonctions BVLC (annexe J.2) : de BVLC-Result (0x00) a
/// Secure-BVLL (0x0c).
pub const BVLC_FUNCTION_MAX: u8 = 0x0c;

/// Version et controle.
pub const NPDU_HEADER_LENGTH: usize = 2;
pub const NPDU_VERSION: u8 = 1;

/// Bits du controle NPDU (clause 6.2.2).
pub const NPDU_CONTROL_NETWORK_MESSAGE: u8 = 0x80;
pub const NPDU_CONTROL_DESTINATION: u8 = 0x20;
pub const NPDU_CONTROL_SOURCE: u8 = 0x08;
pub const NPDU_CONTROL_EXPECTING_REPLY: u8 = 0x04;
pub const NPDU_CONTROL_PRIORITY: u8 = 0x03;

/// Types d'APDU (clause 20.1), quartet haut du premier octet.
pub const APDU_TYPE_MAX: u8 = 7;

pub fn ensure_len(buf: &[u8], needed: usize) -> Result<(), BacnetParseError> {
    if buf.len() < needed {
        return Err(BacnetParseError::Truncated {
            expected: needed,
            actual: buf.len(),
        });
    }
    Ok(())
}

pub fn validate_bvlc_type(byte: u8) -> Result<(), BacnetParseError> {
    if byte != BVLC_TYPE_BACNET_IP {
        return Err(BacnetParseError::InvalidBvlcType(byte));
    }
    Ok(())
}

pub fn validate_bvlc_function(byte: u8) -> Result<(), BacnetParseError> {
    if byte > BVLC_FUNCTION_MAX {
        return Err(BacnetParseError::UnknownBvlcFunction(byte));
    }
    Ok(())
}

/// La longueur BVLC couvre exactement le datagramme : c'est elle qui rend la
/// sonde aveugle sure.
pub fn validate_bvlc_length(declared: u16, actual: usize) -> Result<(), BacnetParseError> {
    if usize::from(declared) != actual {
        return Err(BacnetParseError::LengthMismatch { declared, actual });
    }
    Ok(())
}

pub fn validate_npdu_version(byte: u8) -> Result<(), BacnetParseError> {
    if byte != NPDU_VERSION {
        return Err(BacnetParseError::UnsupportedNpduVersion(byte));
    }
    Ok(())
}

pub fn extract_apdu_type(byte: u8) -> Result<u8, BacnetParseError> {
    let apdu_type = byte >> 4;
    if apdu_type > APDU_TYPE_MAX {
        return Err(BacnetParseError::UnknownApduType(apdu_type));
    }
    Ok(apdu_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bacnet_checks() {
        assert_eq!(validate_bvlc_type(0x81), Ok(()));
        assert_eq!(
            validate_bvlc_type(0x82),
            Err(BacnetParseError::InvalidBvlcType(0x82))
        );
        assert_eq!(validate_bvlc_function(0x0a), Ok(()));
        assert_eq!(validate_bvlc_function(0x0c), Ok(()));
        assert_eq!(
            validate_bvlc_function(0x0d),
            Err(BacnetParseError::UnknownBvlcFunction(0x0d))
        );
        assert_eq!(validate_bvlc_length(17, 17), Ok(()));
        assert_eq!(
            validate_bvlc_length(17, 18),
            Err(BacnetParseError::LengthMismatch {
                declared: 17,
                actual: 18
            })
        );
        assert_eq!(validate_npdu_version(1), Ok(()));
        assert_eq!(
            validate_npdu_version(2),
            Err(BacnetParseError::UnsupportedNpduVersion(2))
        );
        assert_eq!(extract_apdu_type(0x30), Ok(3));
        assert_eq!(extract_apdu_type(0x05), Ok(0));
        assert_eq!(
            extract_apdu_type(0x80),
            Err(BacnetParseError::UnknownApduType(8))
        );
    }
}
