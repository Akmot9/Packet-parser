// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use crate::errors::application::modbus_tcp::ModbusTcpError;

pub const MBAP_MIN_SIZE: usize = 7;

pub fn validate_mbap_min_size(value: &[u8]) -> Result<(), ModbusTcpError> {
    if value.len() < MBAP_MIN_SIZE {
        return Err(ModbusTcpError::BufferTooSmall {
            needed: MBAP_MIN_SIZE,
            actual: value.len(),
        });
    }

    Ok(())
}

pub fn validate_protocol_identifier(protocol_identifier: u16) -> Result<(), ModbusTcpError> {
    if protocol_identifier != 0 {
        return Err(ModbusTcpError::InvalidProtocolIdentifier {
            got: protocol_identifier,
        });
    }

    Ok(())
}

pub fn validate_length_field(length: u16) -> Result<(), ModbusTcpError> {
    if length < 1 {
        return Err(ModbusTcpError::InvalidLengthField { got: length });
    }

    Ok(())
}

pub fn validate_declared_total_length(value: &[u8], length: u16) -> Result<usize, ModbusTcpError> {
    let expected_total = 6usize + length as usize;
    if value.len() < expected_total {
        return Err(ModbusTcpError::LengthMismatch {
            expected: expected_total,
            actual: value.len(),
        });
    }

    Ok(expected_total)
}

pub fn validate_pdu_not_empty(pdu: &[u8]) -> Result<(), ModbusTcpError> {
    if pdu.is_empty() {
        return Err(ModbusTcpError::PduTooSmall {
            needed: 1,
            actual: pdu.len(),
        });
    }

    Ok(())
}

/// Vérifie que les octets 0-1 de l'en-tête MBAP sont présents et extrait le
/// Transaction Identifier (big-endian).
pub fn extract_transaction_identifier(value: &[u8]) -> Result<u16, ModbusTcpError> {
    if value.len() < 2 {
        return Err(ModbusTcpError::BufferTooSmall {
            needed: 2,
            actual: value.len(),
        });
    }

    Ok(u16::from_be_bytes([value[0], value[1]]))
}

/// Vérifie que le Protocol Identifier (octets 2-3, big-endian) vaut 0 et le
/// retourne.
pub fn extract_protocol_identifier(value: &[u8]) -> Result<u16, ModbusTcpError> {
    if value.len() < 4 {
        return Err(ModbusTcpError::BufferTooSmall {
            needed: 4,
            actual: value.len(),
        });
    }

    let protocol_identifier = u16::from_be_bytes([value[2], value[3]]);
    validate_protocol_identifier(protocol_identifier)?;

    Ok(protocol_identifier)
}

/// Vérifie que le champ Length (octets 4-5, big-endian) vaut au moins 1 et le
/// retourne.
pub fn extract_length(value: &[u8]) -> Result<u16, ModbusTcpError> {
    if value.len() < 6 {
        return Err(ModbusTcpError::BufferTooSmall {
            needed: 6,
            actual: value.len(),
        });
    }

    let length = u16::from_be_bytes([value[4], value[5]]);
    validate_length_field(length)?;

    Ok(length)
}

/// Vérifie que l'octet 6 de l'en-tête MBAP est présent et extrait le
/// Unit Identifier.
pub fn extract_unit_identifier(value: &[u8]) -> Result<u8, ModbusTcpError> {
    if value.len() < MBAP_MIN_SIZE {
        return Err(ModbusTcpError::BufferTooSmall {
            needed: MBAP_MIN_SIZE,
            actual: value.len(),
        });
    }

    Ok(value[6])
}

/// Vérifie que la PDU n'est pas vide puis la scinde en (function code,
/// données) sans copie.
pub fn extract_function_code(pdu: &[u8]) -> Result<(u8, &[u8]), ModbusTcpError> {
    validate_pdu_not_empty(pdu)?;

    Ok((pdu[0], &pdu[1..]))
}

/// Le mot de deux octets (big-endian) a l'offset `at` des donnees d'une PDU.
fn word(data: &[u8], at: usize) -> Option<u16> {
    data.get(at..at + 2)
        .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
}

/// Une requete de lecture ou d'ecriture multiple porte une quantite dans
/// les bornes de la specification (Modbus Application Protocol v1.1b3,
/// §6.1 a §6.17).
fn quantity_in(data: &[u8], at: usize, max: u16) -> bool {
    word(data, at).is_some_and(|quantity| (1..=max).contains(&quantity))
}

/// Codes d'exception de la specification (§7) : 1 a 6, 8, 10 et 11.
fn is_exception_code(code: u8) -> bool {
    matches!(code, 1..=6 | 8 | 10 | 11)
}

/// La PDU d'un vrai message Modbus/TCP, pour la sonde aveugle (#167) : un
/// code fonction public d'usage courant et des donnees de la taille qu'il
/// impose, en requete ou en reponse. Sans cela, tout protocole qui prefixe
/// ses messages de deux octets et d'une longueur sur quatre — LDAP d'Active
/// Directory (`30 84 00 00 ..`), DICOM, le transport d'Elasticsearch —
/// passait pour du Modbus, son code fonction etant un octet quelconque.
///
/// `data` suit le code fonction. Les codes de ligne serie (7, 8, 11, 12, 17),
/// d'acces aux fichiers (20, 21), de file (24) et definis par l'utilisateur
/// sont refuses : sur le port 502, le decodeur tolerant les accepte.
pub fn is_plausible_pdu(function_code: u8, data: &[u8]) -> bool {
    let len = data.len();
    // Une reponse de lecture : un nombre d'octets, puis les valeurs.
    let read_response = |even: bool| {
        data.first().is_some_and(|&count| {
            count > 0 && (!even || count % 2 == 0) && len == 1 + usize::from(count)
        })
    };
    match function_code {
        // Read Coils, Read Discrete Inputs : adresse et quantite (1 a 2 000).
        0x01 | 0x02 => (len == 4 && quantity_in(data, 2, 2000)) || read_response(false),
        // Read Holding / Input Registers : adresse et quantite (1 a 125).
        0x03 | 0x04 => (len == 4 && quantity_in(data, 2, 125)) || read_response(true),
        // Write Single Coil : valeur 0x0000 ou 0xFF00, en echo.
        0x05 => len == 4 && matches!(word(data, 2), Some(0x0000 | 0xFF00)),
        // Write Single Register : adresse et valeur, en echo.
        0x06 => len == 4,
        // Write Multiple Coils : la reponse rend adresse et quantite ; la
        // requete y ajoute un nombre d'octets egal a quantite / 8 arrondi.
        0x0F => {
            quantity_in(data, 2, 1968)
                && word(data, 2).is_some_and(|quantity| {
                    len == 4
                        || (len >= 5
                            && usize::from(data[4]) == usize::from(quantity).div_ceil(8)
                            && len == 5 + usize::from(data[4]))
                })
        }
        // Write Multiple Registers : deux octets par registre (1 a 123).
        0x10 => {
            quantity_in(data, 2, 123)
                && word(data, 2).is_some_and(|quantity| {
                    len == 4
                        || (len >= 5
                            && usize::from(data[4]) == 2 * usize::from(quantity)
                            && len == 5 + usize::from(data[4]))
                })
        }
        // Mask Write Register : adresse, masque ET, masque OU, en echo.
        0x16 => len == 6,
        // Read/Write Multiple Registers : lecture (1 a 125), ecriture (1 a
        // 121) et ses valeurs ; la reponse est celle d'une lecture.
        0x17 => {
            (len >= 9
                && quantity_in(data, 2, 125)
                && quantity_in(data, 6, 121)
                && word(data, 6).is_some_and(|quantity| {
                    usize::from(data[8]) == 2 * usize::from(quantity)
                        && len == 9 + usize::from(data[8])
                }))
                || read_response(true)
        }
        // Encapsulated Interface Transport : CANopen (13) ou Read Device
        // Identification (14).
        0x2B => data.first().is_some_and(|&mei| matches!(mei, 0x0D | 0x0E)),
        // Reponse d'exception a l'un des codes ci-dessus : le code fonction
        // plus 0x80, puis un code d'exception.
        0x81..=0x86 | 0x8F | 0x90 | 0x96 | 0x97 | 0xAB => len == 1 && is_exception_code(data[0]),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// En-tête MBAP + PDU de la trame 2 (requête Read Input Registers) :
    /// TI=0, PI=0, Length=6, Unit=255, Function=4, Reference=2258, WordCount=2.
    const FRAME_2: [u8; 12] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0xFF, 0x04, 0x08, 0xD2, 0x00, 0x02,
    ];

    #[test]
    fn test_extract_transaction_identifier() {
        assert_eq!(extract_transaction_identifier(&FRAME_2), Ok(0));
        assert!(matches!(
            extract_transaction_identifier(&[0x00]),
            Err(ModbusTcpError::BufferTooSmall {
                needed: 2,
                actual: 1
            })
        ));
    }

    #[test]
    fn test_extract_protocol_identifier() {
        assert_eq!(extract_protocol_identifier(&FRAME_2), Ok(0));
        assert!(matches!(
            extract_protocol_identifier(&[0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x01]),
            Err(ModbusTcpError::InvalidProtocolIdentifier { got: 2 })
        ));
        assert!(matches!(
            extract_protocol_identifier(&[0x00, 0x00, 0x00]),
            Err(ModbusTcpError::BufferTooSmall {
                needed: 4,
                actual: 3
            })
        ));
    }

    #[test]
    fn test_extract_length() {
        assert_eq!(extract_length(&FRAME_2), Ok(6));
        assert!(matches!(
            extract_length(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF]),
            Err(ModbusTcpError::InvalidLengthField { got: 0 })
        ));
        assert!(matches!(
            extract_length(&[0x00, 0x00, 0x00, 0x00, 0x00]),
            Err(ModbusTcpError::BufferTooSmall {
                needed: 6,
                actual: 5
            })
        ));
    }

    #[test]
    fn test_extract_unit_identifier() {
        assert_eq!(extract_unit_identifier(&FRAME_2), Ok(0xFF));
        assert!(matches!(
            extract_unit_identifier(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x06]),
            Err(ModbusTcpError::BufferTooSmall {
                needed: MBAP_MIN_SIZE,
                actual: 6
            })
        ));
    }

    #[test]
    fn test_extract_function_code() {
        // PDU de la trame 2 : function 0x04, données 08 D2 00 02.
        let (function_code, pdu_data) = extract_function_code(&FRAME_2[7..]).expect("PDU valide");
        assert_eq!(function_code, 0x04);
        assert_eq!(pdu_data, &[0x08, 0xD2, 0x00, 0x02]);

        assert!(matches!(
            extract_function_code(&[]),
            Err(ModbusTcpError::PduTooSmall {
                needed: 1,
                actual: 0
            })
        ));
    }

    /// Modbus.pcap trames 1 et 2 : Read Holding Registers (une valeur) et sa
    /// reponse ; puis les formes de la specification, reponses d'exception
    /// comprises.
    #[test]
    fn test_plausible_pdus() {
        assert!(is_plausible_pdu(0x03, &[0x00, 0x01, 0x00, 0x01]));
        assert!(is_plausible_pdu(0x03, &[0x02, 0x00, 0x00]));
        assert!(is_plausible_pdu(0x01, &[0x00, 0x13, 0x00, 0x25]));
        assert!(is_plausible_pdu(
            0x01,
            &[0x05, 0xcd, 0x6b, 0xb2, 0x0e, 0x1b]
        ));
        assert!(is_plausible_pdu(0x05, &[0x00, 0xac, 0xff, 0x00]));
        assert!(is_plausible_pdu(0x06, &[0x00, 0x01, 0x00, 0x03]));
        // Write Multiple Coils : dix bobines, deux octets.
        assert!(is_plausible_pdu(
            0x0f,
            &[0x00, 0x13, 0x00, 0x0a, 0x02, 0xcd, 0x01]
        ));
        assert!(is_plausible_pdu(0x0f, &[0x00, 0x13, 0x00, 0x0a]));
        // Write Multiple Registers : deux registres, quatre octets.
        assert!(is_plausible_pdu(
            0x10,
            &[0x00, 0x01, 0x00, 0x02, 0x04, 0x00, 0x0a, 0x01, 0x02]
        ));
        assert!(is_plausible_pdu(
            0x16,
            &[0x00, 0x04, 0x00, 0xf2, 0x00, 0x25]
        ));
        assert!(is_plausible_pdu(
            0x17,
            &[
                0x00, 0x03, 0x00, 0x06, 0x00, 0x0e, 0x00, 0x03, 0x06, 0, 0xff, 0, 0xff, 0, 0xff
            ]
        ));
        assert!(is_plausible_pdu(0x2b, &[0x0e, 0x01, 0x00]));
        assert!(is_plausible_pdu(0x83, &[0x02]));
        assert!(is_plausible_pdu(0x81, &[0x0b]));
    }

    #[test]
    fn test_implausible_pdus() {
        // Le debut d'un message LDAP : INTEGER (02 01) lu comme unite 2 et
        // code 1, puis le messageID, un octet de protocolOp...
        assert!(!is_plausible_pdu(
            0x01,
            &[0x08, 0x60, 0x84, 0x00, 0x00, 0x00, 0x41]
        ));
        // Quantites hors bornes, nombre d'octets incoherent.
        assert!(!is_plausible_pdu(0x03, &[0x00, 0x01, 0x00, 0x00]));
        assert!(!is_plausible_pdu(0x03, &[0x00, 0x01, 0x00, 0x7e]));
        assert!(!is_plausible_pdu(0x01, &[0x00, 0x01, 0x07, 0xd1]));
        assert!(!is_plausible_pdu(0x03, &[0x03, 0x00, 0x00, 0x00]));
        assert!(!is_plausible_pdu(0x05, &[0x00, 0xac, 0x12, 0x34]));
        assert!(!is_plausible_pdu(
            0x10,
            &[0x00, 0x01, 0x00, 0x02, 0x03, 0x00, 0x0a, 0x01]
        ));
        assert!(!is_plausible_pdu(
            0x0f,
            &[0x00, 0x13, 0x00, 0x0a, 0x01, 0xcd]
        ));
        // Exception : un octet, un code de la specification.
        assert!(!is_plausible_pdu(0x83, &[0x07]));
        assert!(!is_plausible_pdu(0x83, &[0x02, 0x00]));
        // Code nul (transport d'Elasticsearch), codes de ligne serie,
        // definis par l'utilisateur, exception d'un code inconnu.
        for function_code in [0x00, 0x07, 0x08, 0x11, 0x41, 0x5a, 0x6b, 0x80, 0xa4] {
            assert!(!is_plausible_pdu(function_code, &[0x00, 0x01, 0x00, 0x01]));
        }
    }
}
