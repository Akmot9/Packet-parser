// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use crate::errors::application::ams::AmsParseError;

pub const AMS_HEADER_LEN: usize = 32;

/// En-tete AMS/TCP : deux octets reserves a zero, puis la longueur du
/// message AMS qui suit, sur quatre octets en petit-boutiste (documentation
/// Beckhoff « AMS/TCP Packet », dissecteur Wireshark `packet-ams.c`).
pub const AMS_TCP_HEADER_LEN: usize = 6;

/// State flags que nomme Wireshark : 0x0001 RESPONSE, 0x0002 NO RETURN,
/// 0x0004 ADS COMMAND, 0x0008 SYSTEM COMMAND, 0x0010 HIGH PRIORITY,
/// 0x0020 TIMESTAMP ADDED, 0x0040 UDP COMMAND, 0x0080 INIT COMMAND et
/// 0x8000 BROADCAST. Les autres bits sont refuses.
pub const AMS_KNOWN_STATE_FLAGS: u16 = 0x80FF;

/// Lit l'en-tete AMS/TCP et rend le premier message AMS du segment.
///
/// Les octets reserves doivent etre nuls et la longueur doit tenir dans le
/// segment. Un segment peut enchainer plusieurs messages : seul le premier
/// est rendu, comme pour DNS sur TCP. Un message a cheval sur plusieurs
/// segments releve du reassemblage TCP, hors de portee d'un parseur
/// stateless.
pub fn extract_ams_tcp_message(bytes: &[u8]) -> Result<&[u8], AmsParseError> {
    if bytes.len() < AMS_TCP_HEADER_LEN {
        return Err(AmsParseError::HeaderTooShort {
            expected: AMS_TCP_HEADER_LEN,
            actual: bytes.len(),
        });
    }
    let reserved = u16::from_le_bytes([bytes[0], bytes[1]]);
    if reserved != 0 {
        return Err(AmsParseError::InvalidTcpReserved(reserved));
    }
    let length = u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
    let rest = &bytes[AMS_TCP_HEADER_LEN..];
    usize::try_from(length)
        .ok()
        .and_then(|declared| rest.get(..declared))
        .ok_or(AmsParseError::TcpLengthExceedsSegment {
            length,
            available: rest.len(),
        })
}

pub fn validate_ams_header_length(len: usize) -> Result<(), AmsParseError> {
    if len < AMS_HEADER_LEN {
        return Err(AmsParseError::HeaderTooShort {
            expected: AMS_HEADER_LEN,
            actual: len,
        });
    }

    Ok(())
}

pub fn validate_cb_data_length(cb_data: u32, actual: usize) -> Result<(), AmsParseError> {
    if actual != cb_data as usize {
        return Err(AmsParseError::InvalidCbDataLength { cb_data, actual });
    }

    Ok(())
}

pub fn validate_cmd_id(cmd_id: u16) -> Result<(), AmsParseError> {
    if !matches!(cmd_id, 0x0001..=0x0009) {
        return Err(AmsParseError::UnknownCommand(cmd_id));
    }

    Ok(())
}

pub fn validate_state_flags(flags: u16) -> Result<(), AmsParseError> {
    if flags & !AMS_KNOWN_STATE_FLAGS != 0 {
        return Err(AmsParseError::InvalidStateFlags(flags));
    }

    Ok(())
}

/// Vérifie que la slice du champ Target Net ID contient bien 6 octets et
/// retourne l'identifiant brut. Inatteignable en erreur après
/// `validate_ams_header_length` (le champ occupe les octets 0..6 du header).
pub fn extract_target_net_id(payload: &[u8]) -> Result<[u8; 6], AmsParseError> {
    if payload.len() < 6 {
        return Err(AmsParseError::HeaderTooShort {
            expected: 6,
            actual: payload.len(),
        });
    }
    Ok([
        payload[0], payload[1], payload[2], payload[3], payload[4], payload[5],
    ])
}

/// Vérifie que la slice du champ Target Port contient bien 2 octets et
/// retourne le port décodé en little-endian (octets 6..8 du header).
pub fn extract_target_port(payload: &[u8]) -> Result<u16, AmsParseError> {
    if payload.len() < 2 {
        return Err(AmsParseError::HeaderTooShort {
            expected: 2,
            actual: payload.len(),
        });
    }
    Ok(u16::from_le_bytes([payload[0], payload[1]]))
}

/// Vérifie que la slice du champ Sender Net ID contient bien 6 octets et
/// retourne l'identifiant brut (octets 8..14 du header).
pub fn extract_sender_net_id(payload: &[u8]) -> Result<[u8; 6], AmsParseError> {
    if payload.len() < 6 {
        return Err(AmsParseError::HeaderTooShort {
            expected: 6,
            actual: payload.len(),
        });
    }
    Ok([
        payload[0], payload[1], payload[2], payload[3], payload[4], payload[5],
    ])
}

/// Vérifie que la slice du champ Sender Port contient bien 2 octets et
/// retourne le port décodé en little-endian (octets 14..16 du header).
pub fn extract_sender_port(payload: &[u8]) -> Result<u16, AmsParseError> {
    if payload.len() < 2 {
        return Err(AmsParseError::HeaderTooShort {
            expected: 2,
            actual: payload.len(),
        });
    }
    Ok(u16::from_le_bytes([payload[0], payload[1]]))
}

/// Vérifie que la slice du champ Command ID contient bien 2 octets et
/// retourne la valeur décodée en little-endian (octets 16..18 du header).
/// Décodage seul : l'appartenance aux commandes connues reste vérifiée par
/// `validate_cmd_id`, appelée après l'extraction pour préserver la
/// précédence d'erreurs.
pub fn extract_cmd_id(payload: &[u8]) -> Result<u16, AmsParseError> {
    if payload.len() < 2 {
        return Err(AmsParseError::HeaderTooShort {
            expected: 2,
            actual: payload.len(),
        });
    }
    Ok(u16::from_le_bytes([payload[0], payload[1]]))
}

/// Vérifie que la slice du champ State Flags contient bien 2 octets et
/// retourne la valeur décodée en little-endian (octets 18..20 du header).
/// Décodage seul : les bits réservés restent vérifiés par
/// `validate_state_flags`, appelée après l'extraction pour préserver la
/// précédence d'erreurs.
pub fn extract_state_flags(payload: &[u8]) -> Result<u16, AmsParseError> {
    if payload.len() < 2 {
        return Err(AmsParseError::HeaderTooShort {
            expected: 2,
            actual: payload.len(),
        });
    }
    Ok(u16::from_le_bytes([payload[0], payload[1]]))
}

/// Vérifie que la slice du champ cbData contient bien 4 octets et retourne
/// la longueur déclarée décodée en little-endian (octets 20..24 du header).
/// La cohérence avec la longueur réelle des données reste vérifiée par
/// `validate_cb_data_length`.
pub fn extract_cb_data(payload: &[u8]) -> Result<u32, AmsParseError> {
    if payload.len() < 4 {
        return Err(AmsParseError::HeaderTooShort {
            expected: 4,
            actual: payload.len(),
        });
    }
    Ok(u32::from_le_bytes([
        payload[0], payload[1], payload[2], payload[3],
    ]))
}

/// Vérifie que la slice du champ Error Code contient bien 4 octets et
/// retourne le code décodé en little-endian (octets 24..28 du header).
pub fn extract_error_code(payload: &[u8]) -> Result<u32, AmsParseError> {
    if payload.len() < 4 {
        return Err(AmsParseError::HeaderTooShort {
            expected: 4,
            actual: payload.len(),
        });
    }
    Ok(u32::from_le_bytes([
        payload[0], payload[1], payload[2], payload[3],
    ]))
}

/// Vérifie que la slice du champ Invoke ID contient bien 4 octets et
/// retourne l'identifiant décodé en little-endian (octets 28..32 du header).
pub fn extract_invoke_id(payload: &[u8]) -> Result<u32, AmsParseError> {
    if payload.len() < 4 {
        return Err(AmsParseError::HeaderTooShort {
            expected: 4,
            actual: payload.len(),
        });
    }
    Ok(u32::from_le_bytes([
        payload[0], payload[1], payload[2], payload[3],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_net_ids_valid() {
        assert_eq!(
            extract_target_net_id(&[0, 0, 0, 0, 0, 130]).unwrap(),
            [0, 0, 0, 0, 0, 130]
        );
        assert_eq!(
            extract_sender_net_id(&[192, 168, 1, 1, 1, 1]).unwrap(),
            [192, 168, 1, 1, 1, 1]
        );
    }

    #[test]
    fn test_extract_net_ids_too_short() {
        assert!(matches!(
            extract_target_net_id(&[0, 0, 0]),
            Err(AmsParseError::HeaderTooShort {
                expected: 6,
                actual: 3
            })
        ));
        assert!(matches!(
            extract_sender_net_id(&[]),
            Err(AmsParseError::HeaderTooShort {
                expected: 6,
                actual: 0
            })
        ));
    }

    #[test]
    fn test_extract_ports_little_endian() {
        assert_eq!(extract_target_port(&851u16.to_le_bytes()).unwrap(), 851);
        assert_eq!(extract_sender_port(&33000u16.to_le_bytes()).unwrap(), 33000);
    }

    #[test]
    fn test_extract_u16_fields_too_short() {
        assert!(matches!(
            extract_target_port(&[0x01]),
            Err(AmsParseError::HeaderTooShort {
                expected: 2,
                actual: 1
            })
        ));
        assert!(matches!(
            extract_sender_port(&[]),
            Err(AmsParseError::HeaderTooShort {
                expected: 2,
                actual: 0
            })
        ));
        assert!(matches!(
            extract_cmd_id(&[]),
            Err(AmsParseError::HeaderTooShort {
                expected: 2,
                actual: 0
            })
        ));
        assert!(matches!(
            extract_state_flags(&[0x04]),
            Err(AmsParseError::HeaderTooShort {
                expected: 2,
                actual: 1
            })
        ));
    }

    #[test]
    fn test_extract_cmd_id_and_state_flags_decode_only() {
        // Décodage seul : la validation sémantique reste portée par
        // validate_cmd_id / validate_state_flags.
        assert_eq!(extract_cmd_id(&0xFFFFu16.to_le_bytes()).unwrap(), 0xFFFF);
        assert_eq!(
            extract_state_flags(&0x0100u16.to_le_bytes()).unwrap(),
            0x0100
        );
    }

    /// Les bits que nomme Wireshark passent, ADS + UDP (0x0044) compris
    /// (#290) ; les autres restent refuses.
    #[test]
    fn state_flags_accept_the_bits_wireshark_names() {
        for flags in [
            0x0000, 0x0004, 0x0005, 0x0044, 0x0010, 0x0080, 0x8000, 0x80FF,
        ] {
            assert!(validate_state_flags(flags).is_ok(), "0x{flags:04x}");
        }
        for flags in [0x0100, 0x4000, 0xFFFF] {
            assert!(
                matches!(
                    validate_state_flags(flags),
                    Err(AmsParseError::InvalidStateFlags(f)) if f == flags
                ),
                "0x{flags:04x}"
            );
        }
    }

    #[test]
    fn ams_tcp_header_yields_the_message_it_announces() {
        let mut bytes = vec![0, 0, 3, 0, 0, 0, 0xAA, 0xBB, 0xCC];
        assert_eq!(
            extract_ams_tcp_message(&bytes).unwrap(),
            &[0xAA, 0xBB, 0xCC]
        );

        // Un second message dans le meme segment est laisse de cote.
        bytes.extend_from_slice(&[0, 0, 1, 0, 0, 0, 0xDD]);
        assert_eq!(
            extract_ams_tcp_message(&bytes).unwrap(),
            &[0xAA, 0xBB, 0xCC]
        );
    }

    #[test]
    fn ams_tcp_header_refuses_reserved_bits_and_overlong_lengths() {
        assert!(matches!(
            extract_ams_tcp_message(&[0, 0, 0, 0, 0]),
            Err(AmsParseError::HeaderTooShort {
                expected: 6,
                actual: 5
            })
        ));
        assert!(matches!(
            extract_ams_tcp_message(&[1, 0, 0, 0, 0, 0]),
            Err(AmsParseError::InvalidTcpReserved(0x0001))
        ));
        assert!(matches!(
            extract_ams_tcp_message(&[0, 0, 4, 0, 0, 0, 1, 2, 3]),
            Err(AmsParseError::TcpLengthExceedsSegment {
                length: 4,
                available: 3
            })
        ));
        assert!(matches!(
            extract_ams_tcp_message(&[0, 0, 0xFF, 0xFF, 0xFF, 0xFF]),
            Err(AmsParseError::TcpLengthExceedsSegment {
                length: u32::MAX,
                available: 0
            })
        ));
    }

    #[test]
    fn test_extract_u32_fields_little_endian() {
        assert_eq!(extract_cb_data(&4u32.to_le_bytes()).unwrap(), 4);
        assert_eq!(
            extract_error_code(&0xDEAD_BEEFu32.to_le_bytes()).unwrap(),
            0xDEAD_BEEF
        );
        assert_eq!(extract_invoke_id(&7u32.to_le_bytes()).unwrap(), 7);
    }

    #[test]
    fn test_extract_u32_fields_too_short() {
        assert!(matches!(
            extract_cb_data(&[1, 2, 3]),
            Err(AmsParseError::HeaderTooShort {
                expected: 4,
                actual: 3
            })
        ));
        assert!(matches!(
            extract_error_code(&[]),
            Err(AmsParseError::HeaderTooShort {
                expected: 4,
                actual: 0
            })
        ));
        assert!(matches!(
            extract_invoke_id(&[0; 2]),
            Err(AmsParseError::HeaderTooShort {
                expected: 4,
                actual: 2
            })
        ));
    }
}
