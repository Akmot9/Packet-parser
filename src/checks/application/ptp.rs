// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use crate::errors::application::ptp::PtpPacketParseError;

/// Taille de l'en-tete commun PTPv2 (IEEE 1588-2008 §13.3.1).
pub const PTP_V2_HEADER_LENGTH: usize = 34;
/// Taille de l'en-tete commun PTPv1 (IEEE 1588-2002 §6.4.2), control et
/// flags compris.
pub const PTP_V1_HEADER_LENGTH: usize = 40;

/// Octets de correction de checksum qu'un message PTP sur UDP/IPv6 peut
/// porter apres `messageLength` (IEEE 1588-2008, annexe E.1).
pub const PTP_UDP_IPV6_TRAILER_LENGTH: usize = 2;

pub const PTP_MESSAGE_SYNC: u8 = 0x0;
pub const PTP_MESSAGE_DELAY_REQ: u8 = 0x1;
pub const PTP_MESSAGE_PDELAY_REQ: u8 = 0x2;
pub const PTP_MESSAGE_PDELAY_RESP: u8 = 0x3;
pub const PTP_MESSAGE_FOLLOW_UP: u8 = 0x8;
pub const PTP_MESSAGE_DELAY_RESP: u8 = 0x9;
pub const PTP_MESSAGE_PDELAY_RESP_FOLLOW_UP: u8 = 0xA;
pub const PTP_MESSAGE_ANNOUNCE: u8 = 0xB;
pub const PTP_MESSAGE_SIGNALING: u8 = 0xC;
pub const PTP_MESSAGE_MANAGEMENT: u8 = 0xD;

/// Control PTPv1 : Sync, Delay_Req, Follow_Up, Delay_Resp, Management.
pub const PTP_V1_CONTROL_MANAGEMENT: u8 = 4;
/// messageType PTPv1 d'un message d'evenement (Sync, Delay_Req), horodate.
pub const PTP_V1_EVENT_MESSAGE: u8 = 1;
/// messageType PTPv1 d'un message general (Follow_Up, Delay_Resp, Management).
pub const PTP_V1_GENERAL_MESSAGE: u8 = 2;

pub fn ensure_len(buf: &[u8], needed: usize) -> Result<(), PtpPacketParseError> {
    if buf.len() < needed {
        return Err(PtpPacketParseError::Truncated {
            expected: needed,
            actual: buf.len(),
        });
    }
    Ok(())
}

/// Version PTP : quartet bas de l'octet 1, a la meme place en v1 (octet de
/// poids faible du `versionPTP` u16) et en v2. C'est ce que la norme de 2008
/// a garanti pour qu'un recepteur distingue les deux.
pub fn extract_version(payload: &[u8]) -> Result<u8, PtpPacketParseError> {
    ensure_len(payload, 2)?;
    let version = payload[1] & 0x0F;
    match version {
        1 | 2 => Ok(version),
        other => Err(PtpPacketParseError::UnsupportedVersion(other)),
    }
}

/// Taille minimale d'un message PTPv2 selon son type, en-tete compris
/// (IEEE 1588-2008 §13.5 a §13.13). `None` pour un type reserve.
pub const fn minimum_v2_length(message_type: u8) -> Option<usize> {
    match message_type {
        // en-tete + un horodatage de 10 octets
        PTP_MESSAGE_SYNC | PTP_MESSAGE_DELAY_REQ | PTP_MESSAGE_FOLLOW_UP => Some(44),
        // en-tete + horodatage + identite de port (ou 10 octets reserves)
        PTP_MESSAGE_PDELAY_REQ
        | PTP_MESSAGE_PDELAY_RESP
        | PTP_MESSAGE_DELAY_RESP
        | PTP_MESSAGE_PDELAY_RESP_FOLLOW_UP => Some(54),
        PTP_MESSAGE_ANNOUNCE => Some(64),
        // en-tete + targetPortIdentity
        PTP_MESSAGE_SIGNALING => Some(44),
        // en-tete + targetPortIdentity + hops, action, reserve
        PTP_MESSAGE_MANAGEMENT => Some(48),
        _ => None,
    }
}

/// messageType PTPv2 (quartet bas de l'octet 0), refuse s'il est reserve.
pub fn extract_message_type(byte: u8) -> Result<u8, PtpPacketParseError> {
    let message_type = byte & 0x0F;
    if minimum_v2_length(message_type).is_none() {
        return Err(PtpPacketParseError::ReservedMessageType(message_type));
    }
    Ok(message_type)
}

/// `messageLength` doit couvrir le corps de son type et tenir dans les octets
/// recus. Il peut etre plus court qu'eux : bourrage Ethernet en couche 2,
/// octets de l'annexe E sur UDP/IPv6.
pub fn validate_message_length(
    message_type: u8,
    declared: u16,
    available: usize,
) -> Result<usize, PtpPacketParseError> {
    let minimum = minimum_v2_length(message_type)
        .ok_or(PtpPacketParseError::ReservedMessageType(message_type))?;
    let length = usize::from(declared);
    if length < minimum || length > available {
        return Err(PtpPacketParseError::InvalidMessageLength {
            message_type,
            declared,
            minimum,
            available,
        });
    }
    Ok(length)
}

/// Sur UDP, un message PTP occupe tout le datagramme, ou le datagramme moins
/// les deux octets de l'annexe E (UDP/IPv6). Rien d'autre ne le suit.
pub fn validate_udp_trailing(trailing: usize) -> Result<(), PtpPacketParseError> {
    if trailing != 0 && trailing != PTP_UDP_IPV6_TRAILER_LENGTH {
        return Err(PtpPacketParseError::UnexpectedTrailingBytes { trailing });
    }
    Ok(())
}

/// `versionNetwork` PTPv1 (octets 2-3) : 1 est la seule valeur definie.
pub fn extract_network_version(bytes: [u8; 2]) -> Result<u16, PtpPacketParseError> {
    let version = u16::from_be_bytes(bytes);
    if version != 1 {
        return Err(PtpPacketParseError::UnsupportedNetworkVersion(version));
    }
    Ok(version)
}

/// Taille exacte d'un message PTPv1 selon son control (IEEE 1588-2002
/// §6.4) ; le Management, de taille variable, n'a que l'en-tete pour minimum.
const fn v1_length(control: u8) -> Option<usize> {
    match control {
        // Sync, Delay_Req
        0 | 1 => Some(124),
        // Follow_Up
        2 => Some(52),
        // Delay_Resp
        3 => Some(60),
        PTP_V1_CONTROL_MANAGEMENT => Some(PTP_V1_HEADER_LENGTH),
        _ => None,
    }
}

/// control PTPv1 (octet 32), et sa coherence avec messageType (octet 20) :
/// Sync et Delay_Req sont des messages d'evenement, les autres generaux.
pub fn extract_v1_control(message_type: u8, control: u8) -> Result<u8, PtpPacketParseError> {
    if v1_length(control).is_none() {
        return Err(PtpPacketParseError::ReservedControl(control));
    }
    let expected = if control <= 1 {
        PTP_V1_EVENT_MESSAGE
    } else {
        PTP_V1_GENERAL_MESSAGE
    };
    if message_type != expected {
        return Err(PtpPacketParseError::InconsistentMessageType {
            message_type,
            control,
        });
    }
    Ok(control)
}

/// Un message PTPv1 n'annonce pas sa longueur : elle est fixee par son
/// control, et seul le Management peut depasser l'en-tete.
pub fn validate_v1_length(control: u8, actual: usize) -> Result<(), PtpPacketParseError> {
    let Some(expected) = v1_length(control) else {
        return Err(PtpPacketParseError::ReservedControl(control));
    };
    let valid = if control == PTP_V1_CONTROL_MANAGEMENT {
        actual >= expected
    } else {
        actual == expected
    };
    if !valid {
        return Err(PtpPacketParseError::InvalidV1Length {
            control,
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
    fn version_is_the_low_nibble_of_byte_1() {
        assert_eq!(extract_version(&[0x00, 0x02]), Ok(2));
        // minorVersionPTP (quartet haut) ne change pas la version
        assert_eq!(extract_version(&[0x00, 0x12]), Ok(2));
        assert_eq!(extract_version(&[0x00, 0x01]), Ok(1));
        assert_eq!(
            extract_version(&[0x00, 0x03]),
            Err(PtpPacketParseError::UnsupportedVersion(3))
        );
        assert_eq!(
            extract_version(&[0x00]),
            Err(PtpPacketParseError::Truncated {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn reserved_message_types_are_refused() {
        for reserved in [0x4, 0x5, 0x6, 0x7, 0xE, 0xF] {
            assert_eq!(
                extract_message_type(reserved),
                Err(PtpPacketParseError::ReservedMessageType(reserved))
            );
        }
        // majorSdoId (quartet haut) ignore : 802.1AS l'a a 1
        assert_eq!(extract_message_type(0x1B), Ok(PTP_MESSAGE_ANNOUNCE));
    }

    #[test]
    fn message_length_bounds() {
        assert_eq!(validate_message_length(PTP_MESSAGE_SYNC, 44, 46), Ok(44));
        assert!(validate_message_length(PTP_MESSAGE_SYNC, 43, 46).is_err());
        assert!(validate_message_length(PTP_MESSAGE_SYNC, 47, 46).is_err());
        assert!(validate_message_length(PTP_MESSAGE_ANNOUNCE, 54, 64).is_err());
    }

    #[test]
    fn udp_trailing_allows_only_the_annex_e_octets() {
        assert!(validate_udp_trailing(0).is_ok());
        assert!(validate_udp_trailing(2).is_ok());
        assert_eq!(
            validate_udp_trailing(1),
            Err(PtpPacketParseError::UnexpectedTrailingBytes { trailing: 1 })
        );
    }

    #[test]
    fn v1_control_matches_message_type_and_length() {
        assert_eq!(extract_v1_control(1, 0), Ok(0));
        assert_eq!(extract_v1_control(2, 3), Ok(3));
        assert_eq!(
            extract_v1_control(2, 0),
            Err(PtpPacketParseError::InconsistentMessageType {
                message_type: 2,
                control: 0
            })
        );
        assert_eq!(
            extract_v1_control(2, 5),
            Err(PtpPacketParseError::ReservedControl(5))
        );
        assert!(validate_v1_length(0, 124).is_ok());
        assert!(validate_v1_length(0, 126).is_err());
        assert!(validate_v1_length(PTP_V1_CONTROL_MANAGEMENT, 80).is_ok());
        assert!(validate_v1_length(PTP_V1_CONTROL_MANAGEMENT, 39).is_err());
        assert_eq!(extract_network_version([0, 1]), Ok(1));
        assert!(extract_network_version([0, 2]).is_err());
    }
}
