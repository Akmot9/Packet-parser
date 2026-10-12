// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use crate::errors::application::rdp::RdpParseError;

/// En-tete TPKT (RFC 1006) : version, reserve, longueur sur deux octets.
pub const TPKT_HEADER_LENGTH: usize = 4;
pub const TPKT_VERSION: u8 = 3;
/// En-tete TPKT puis un TPDU COTP minimal (LI, type, un octet).
pub const TPKT_MIN_LENGTH: u16 = 7;

/// Jeton de connexion (MS-RDPBCGR §2.2.1.1) : `Cookie: mstshash=<user>` puis
/// CR LF.
pub const RDP_COOKIE_PREFIX: &[u8] = b"Cookie: mstshash=";
pub const RDP_TOKEN_TERMINATOR: &[u8] = b"\r\n";

/// Structures de negociation (§2.2.1.1.1, §2.2.1.2.1, §2.2.1.2.2) : type,
/// drapeaux, longueur 8, puis quatre octets.
pub const RDP_NEG_LENGTH: u16 = 8;
pub const RDP_NEG_REQUEST: u8 = 0x01;
pub const RDP_NEG_RESPONSE: u8 = 0x02;
pub const RDP_NEG_FAILURE: u8 = 0x03;

/// Protocoles de securite (§2.2.1.1.1) : bits de `requestedProtocols`.
pub const PROTOCOL_RDP: u32 = 0x0000_0000;
pub const PROTOCOL_SSL: u32 = 0x0000_0001;
pub const PROTOCOL_HYBRID: u32 = 0x0000_0002;
pub const PROTOCOL_RDSTLS: u32 = 0x0000_0004;
pub const PROTOCOL_HYBRID_EX: u32 = 0x0000_0008;

/// Connect-Initial et Connect-Response MCS (T.125 §7, BER) : etiquettes
/// `[APPLICATION 101]` et `[APPLICATION 102]`.
pub const MCS_CONNECT_INITIAL_TAG: [u8; 2] = [0x7f, 0x65];
pub const MCS_CONNECT_RESPONSE_TAG: [u8; 2] = [0x7f, 0x66];

/// Les identifiants d'utilisateur MCS commencent a 1001 (T.125 §7).
pub const MCS_USER_ID_BASE: u16 = 1001;

pub fn ensure_len(buf: &[u8], needed: usize) -> Result<(), RdpParseError> {
    if buf.len() < needed {
        return Err(RdpParseError::Truncated {
            expected: needed,
            actual: buf.len(),
        });
    }
    Ok(())
}

pub fn validate_tpkt_header(version: u8, reserved: u8) -> Result<(), RdpParseError> {
    if version != TPKT_VERSION || reserved != 0 {
        return Err(RdpParseError::InvalidTpkt { version, reserved });
    }
    Ok(())
}

pub fn extract_tpkt_length(bytes: [u8; 2]) -> Result<u16, RdpParseError> {
    let length = u16::from_be_bytes(bytes);
    if length < TPKT_MIN_LENGTH {
        return Err(RdpParseError::TpktTooShort(length));
    }
    Ok(length)
}

pub fn validate_negotiation_length(structure_type: u8, length: u16) -> Result<(), RdpParseError> {
    if length != RDP_NEG_LENGTH {
        return Err(RdpParseError::InvalidNegotiation {
            structure_type,
            length,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rdp_checks() {
        assert_eq!(validate_tpkt_header(3, 0), Ok(()));
        assert_eq!(
            validate_tpkt_header(2, 0),
            Err(RdpParseError::InvalidTpkt {
                version: 2,
                reserved: 0
            })
        );
        assert_eq!(extract_tpkt_length([0x00, 0x2f]), Ok(47));
        assert_eq!(
            extract_tpkt_length([0x00, 0x06]),
            Err(RdpParseError::TpktTooShort(6))
        );
        assert_eq!(validate_negotiation_length(1, 8), Ok(()));
        assert_eq!(
            validate_negotiation_length(2, 9),
            Err(RdpParseError::InvalidNegotiation {
                structure_type: 2,
                length: 9
            })
        );
    }
}
