// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use crate::errors::application::ike::IkeParseError;

/// En-tete IKE (RFC 7296 §3.1, meme forme qu'ISAKMP RFC 2408 §3.1) : deux
/// SPI de huit octets, payload suivant, version, type d'echange, drapeaux,
/// identifiant de message, longueur.
pub const IKE_HEADER_LENGTH: usize = 28;

/// En-tete generique d'un payload (RFC 7296 §3.2) : payload suivant,
/// drapeau critique et reserve, longueur sur deux octets (en-tete compris).
pub const IKE_PAYLOAD_HEADER_LENGTH: usize = 4;

/// Marqueur non-ESP d'un message IKE sur UDP 4500 (RFC 3948 §2.2).
pub const NON_ESP_MARKER: [u8; 4] = [0, 0, 0, 0];

/// NAT-keepalive : un seul octet 0xFF (RFC 3948 §2.3).
pub const NAT_KEEPALIVE: [u8; 1] = [0xff];

/// IKEv1 (ISAKMP) : version majeure 1.
pub const IKE_MAJOR_V1: u8 = 1;
/// IKEv2 : version majeure 2.
pub const IKE_MAJOR_V2: u8 = 2;

/// IKEv1, drapeau E (RFC 2408 §3.1) : les payloads sont chiffres.
pub const IKEV1_FLAG_ENCRYPTION: u8 = 0x01;
/// IKEv1, drapeau C (commit).
pub const IKEV1_FLAG_COMMIT: u8 = 0x02;
/// IKEv1, drapeau A (authentication only).
pub const IKEV1_FLAG_AUTHENTICATION_ONLY: u8 = 0x04;
/// IKEv2, drapeau I : message emis par l'initiateur de l'IKE SA.
pub const IKEV2_FLAG_INITIATOR: u8 = 0x08;
/// IKEv2, drapeau V : l'emetteur sait parler une version majeure superieure.
pub const IKEV2_FLAG_VERSION: u8 = 0x10;
/// IKEv2, drapeau R : le message est une reponse.
pub const IKEV2_FLAG_RESPONSE: u8 = 0x20;

/// IKEv2, en-tete generique de payload : bit critique (RFC 7296 §3.2).
pub const IKE_PAYLOAD_FLAG_CRITICAL: u8 = 0x80;

/// IKEv2, payload Encrypted and Authenticated (SK) : le dernier du message.
pub const IKEV2_PAYLOAD_ENCRYPTED: u8 = 46;
/// IKEv2, Encrypted Fragment (SKF, RFC 7383) : le dernier lui aussi.
pub const IKEV2_PAYLOAD_ENCRYPTED_FRAGMENT: u8 = 53;

pub fn ensure_len(buf: &[u8], needed: usize) -> Result<(), IkeParseError> {
    if buf.len() < needed {
        return Err(IkeParseError::Truncated {
            expected: needed,
            actual: buf.len(),
        });
    }
    Ok(())
}

/// Version majeure 1 ou 2 ; la mineure est ignoree (RFC 7296 §3.1).
pub fn extract_major_version(byte: u8) -> Result<u8, IkeParseError> {
    let major = byte >> 4;
    if major != IKE_MAJOR_V1 && major != IKE_MAJOR_V2 {
        return Err(IkeParseError::UnsupportedVersion(major));
    }
    Ok(major)
}

/// IKEv2 : le SPI de l'initiateur n'est jamais nul.
pub fn validate_initiator_spi(major: u8, spi: u64) -> Result<(), IkeParseError> {
    if major == IKE_MAJOR_V2 && spi == 0 {
        return Err(IkeParseError::ZeroInitiatorSpi);
    }
    Ok(())
}

/// La longueur declaree couvre exactement le message.
pub fn validate_length(declared: u32, actual: usize) -> Result<(), IkeParseError> {
    if declared as usize != actual {
        return Err(IkeParseError::LengthMismatch { declared, actual });
    }
    Ok(())
}

/// Longueur d'un payload : au moins son en-tete, au plus le reste.
pub fn validate_payload_length(
    payload_type: u8,
    length: u16,
    available: usize,
) -> Result<usize, IkeParseError> {
    let length = usize::from(length);
    if length < IKE_PAYLOAD_HEADER_LENGTH {
        return Err(IkeParseError::InvalidPayloadLength {
            payload_type,
            length: length as u16,
        });
    }
    if length > available {
        return Err(IkeParseError::PayloadOverflow {
            payload_type,
            needed: length,
            available,
        });
    }
    Ok(length)
}

pub fn validate_no_trailing(trailing: usize) -> Result<(), IkeParseError> {
    if trailing != 0 {
        return Err(IkeParseError::UnexpectedTrailingBytes { trailing });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_checks() {
        assert_eq!(extract_major_version(0x10), Ok(1));
        assert_eq!(extract_major_version(0x20), Ok(2));
        assert_eq!(extract_major_version(0x2f), Ok(2));
        assert_eq!(
            extract_major_version(0x30),
            Err(IkeParseError::UnsupportedVersion(3))
        );
        assert_eq!(
            extract_major_version(0x00),
            Err(IkeParseError::UnsupportedVersion(0))
        );
        assert_eq!(validate_initiator_spi(2, 1), Ok(()));
        assert_eq!(validate_initiator_spi(1, 0), Ok(()));
        assert_eq!(
            validate_initiator_spi(2, 0),
            Err(IkeParseError::ZeroInitiatorSpi)
        );
        assert_eq!(validate_length(374, 374), Ok(()));
        assert_eq!(
            validate_length(374, 375),
            Err(IkeParseError::LengthMismatch {
                declared: 374,
                actual: 375
            })
        );
    }

    #[test]
    fn test_payload_checks() {
        assert_eq!(validate_payload_length(33, 40, 346), Ok(40));
        assert_eq!(
            validate_payload_length(33, 3, 346),
            Err(IkeParseError::InvalidPayloadLength {
                payload_type: 33,
                length: 3
            })
        );
        assert_eq!(
            validate_payload_length(40, 72, 60),
            Err(IkeParseError::PayloadOverflow {
                payload_type: 40,
                needed: 72,
                available: 60
            })
        );
        assert_eq!(validate_no_trailing(0), Ok(()));
        assert_eq!(
            validate_no_trailing(5),
            Err(IkeParseError::UnexpectedTrailingBytes { trailing: 5 })
        );
    }
}
