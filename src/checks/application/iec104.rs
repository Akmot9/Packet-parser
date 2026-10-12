// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use crate::errors::application::iec104::Iec104ParseError;

/// Octet de depart de tout APDU (IEC 60870-5-104 §5).
pub const IEC104_START_BYTE: u8 = 0x68;

/// Depart, longueur, champ de controle de quatre octets.
pub const IEC104_APCI_LENGTH: usize = 6;

/// La longueur compte le champ de controle et l'ASDU, pas les deux premiers
/// octets : de 4 (controle seul) a 253 (APDU de 255 octets).
pub const IEC104_LENGTH_MIN: u8 = 4;
pub const IEC104_LENGTH_MAX: u8 = 253;

/// En-tete d'ASDU (IEC 60870-5-101 §7.2, parametres de la -104) : type,
/// qualificatif de structure variable, cause de transmission sur deux
/// octets, adresse commune sur deux octets.
pub const IEC104_ASDU_HEADER_LENGTH: usize = 6;

/// Adresse d'objet d'information sur trois octets (-104).
pub const IEC104_IOA_LENGTH: usize = 3;

/// Fonctions du format U (§5.1) : TESTFR, STOPDT, STARTDT, activation ou
/// confirmation.
pub const IEC104_STARTDT_ACT: u8 = 0x04;
pub const IEC104_STARTDT_CON: u8 = 0x08;
pub const IEC104_STOPDT_ACT: u8 = 0x10;
pub const IEC104_STOPDT_CON: u8 = 0x20;
pub const IEC104_TESTFR_ACT: u8 = 0x40;
pub const IEC104_TESTFR_CON: u8 = 0x80;

pub fn ensure_len(buf: &[u8], needed: usize) -> Result<(), Iec104ParseError> {
    if buf.len() < needed {
        return Err(Iec104ParseError::Truncated {
            expected: needed,
            actual: buf.len(),
        });
    }
    Ok(())
}

pub fn validate_start_byte(byte: u8) -> Result<(), Iec104ParseError> {
    if byte != IEC104_START_BYTE {
        return Err(Iec104ParseError::InvalidStartByte(byte));
    }
    Ok(())
}

pub fn extract_length(byte: u8) -> Result<u8, Iec104ParseError> {
    if !(IEC104_LENGTH_MIN..=IEC104_LENGTH_MAX).contains(&byte) {
        return Err(Iec104ParseError::InvalidLength(byte));
    }
    Ok(byte)
}

/// Les formats S et U ne portent pas d'ASDU.
pub fn validate_control_only(format: &'static str, length: u8) -> Result<(), Iec104ParseError> {
    if length != IEC104_LENGTH_MIN {
        return Err(Iec104ParseError::ControlOnlyFormat { format, length });
    }
    Ok(())
}

/// Le premier octet de controle d'un APDU U : les deux bits bas a un, puis
/// exactement une fonction.
pub fn validate_unnumbered_function(control: u8) -> Result<u8, Iec104ParseError> {
    let function = control & 0xfc;
    if !matches!(
        function,
        IEC104_STARTDT_ACT
            | IEC104_STARTDT_CON
            | IEC104_STOPDT_ACT
            | IEC104_STOPDT_CON
            | IEC104_TESTFR_ACT
            | IEC104_TESTFR_CON
    ) {
        return Err(Iec104ParseError::InvalidUnnumberedFunction(control));
    }
    Ok(function)
}

pub fn validate_asdu_length(len: usize) -> Result<(), Iec104ParseError> {
    if len < IEC104_ASDU_HEADER_LENGTH {
        return Err(Iec104ParseError::AsduTooShort(len));
    }
    Ok(())
}

pub fn validate_object_count(type_id: u8, count: u8) -> Result<(), Iec104ParseError> {
    if count == 0 {
        return Err(Iec104ParseError::EmptyAsdu(type_id));
    }
    Ok(())
}

/// Taille de l'element d'information d'un type d'ASDU (IEC 60870-5-101
/// §7.3), sans l'adresse d'objet. `None` pour les types inconnus et ceux
/// dont la taille depend du contenu (segments de fichier).
pub fn element_size(type_id: u8) -> Option<usize> {
    const CP24: usize = 3;
    const CP56: usize = 7;
    Some(match type_id {
        1 | 3 => 1,
        2 | 4 => 1 + CP24,
        5 => 2,
        6 => 2 + CP24,
        7 | 13 | 15 => 5,
        8 | 14 | 16 => 5 + CP24,
        9 | 11 => 3,
        10 | 12 => 3 + CP24,
        17 => 1 + 2 + CP24,
        18 | 19 => 1 + 1 + 2 + CP24,
        20 => 5,
        21 => 2,
        30 | 31 => 1 + CP56,
        32 => 2 + CP56,
        33 | 36 | 37 => 5 + CP56,
        34 | 35 => 3 + CP56,
        38 => 1 + 2 + CP56,
        39 | 40 => 1 + 1 + 2 + CP56,
        45..=47 => 1,
        48 | 49 => 3,
        50 => 5,
        51 => 4,
        58..=60 => 1 + CP56,
        61 | 62 => 3 + CP56,
        63 => 5 + CP56,
        64 => 4 + CP56,
        70 | 100 | 101 | 105 | 113 => 1,
        102 => 0,
        103 => CP56,
        104 | 106 => 2,
        107 => 2 + CP56,
        110 | 111 => 3,
        112 => 5,
        120 => 6,
        121 => 7,
        122 | 124 => 4,
        123 => 5,
        126 => 13,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iec104_checks() {
        assert_eq!(validate_start_byte(0x68), Ok(()));
        assert_eq!(
            validate_start_byte(0x69),
            Err(Iec104ParseError::InvalidStartByte(0x69))
        );
        assert_eq!(extract_length(4), Ok(4));
        assert_eq!(extract_length(253), Ok(253));
        assert_eq!(extract_length(3), Err(Iec104ParseError::InvalidLength(3)));
        assert_eq!(
            extract_length(254),
            Err(Iec104ParseError::InvalidLength(254))
        );
        assert_eq!(validate_control_only("U", 4), Ok(()));
        assert_eq!(
            validate_control_only("S", 5),
            Err(Iec104ParseError::ControlOnlyFormat {
                format: "S",
                length: 5
            })
        );
        assert_eq!(validate_unnumbered_function(0x07), Ok(0x04));
        assert_eq!(validate_unnumbered_function(0x83), Ok(0x80));
        assert_eq!(
            validate_unnumbered_function(0x0f),
            Err(Iec104ParseError::InvalidUnnumberedFunction(0x0f))
        );
        assert_eq!(validate_asdu_length(6), Ok(()));
        assert_eq!(
            validate_asdu_length(5),
            Err(Iec104ParseError::AsduTooShort(5))
        );
        assert_eq!(
            validate_object_count(1, 0),
            Err(Iec104ParseError::EmptyAsdu(1))
        );
        assert_eq!(element_size(1), Some(1));
        assert_eq!(element_size(36), Some(12));
        assert_eq!(element_size(100), Some(1));
        assert_eq!(element_size(102), Some(0));
        assert_eq!(element_size(103), Some(7));
        assert_eq!(element_size(125), None);
        assert_eq!(element_size(200), None);
    }
}
