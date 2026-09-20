// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use crate::errors::application::umas::UmasError;

/// Code fonction Modbus reserve a Schneider Electric qui transporte UMAS.
pub const UMAS_MODBUS_FUNCTION_CODE: u8 = 0x5A;

/// Taille minimale d'un PDU UMAS : identifiant de session (1) + code
/// fonction (1).
pub const UMAS_PDU_MIN_LEN: usize = 2;

/// Valide que le PDU Modbus porte bien le code fonction UMAS.
///
/// C'est la garde de la sonde : combinee a la validation de l'enveloppe
/// Modbus/TCP (identifiant de protocole nul, longueur declaree coherente),
/// elle evite d'etiqueter UMAS un Modbus ordinaire.
pub fn validate_umas_function_code(function_code: u8) -> Result<(), UmasError> {
    if function_code != UMAS_MODBUS_FUNCTION_CODE {
        return Err(UmasError::NotUmas { got: function_code });
    }

    Ok(())
}

/// Extrait l'identifiant de session et le code fonction UMAS, et rend les
/// donnees qui suivent (zero-copie).
pub fn extract_umas_header(pdu_data: &[u8]) -> Result<(u8, u8, &[u8]), UmasError> {
    if pdu_data.len() < UMAS_PDU_MIN_LEN {
        return Err(UmasError::PduTooSmall {
            needed: UMAS_PDU_MIN_LEN,
            actual: pdu_data.len(),
        });
    }

    Ok((pdu_data[0], pdu_data[1], &pdu_data[UMAS_PDU_MIN_LEN..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_umas_function_code() {
        assert!(validate_umas_function_code(0x5A).is_ok());
        for function_code in [0x03, 0x10, 0x59, 0x5B, 0xDA] {
            assert!(matches!(
                validate_umas_function_code(function_code),
                Err(UmasError::NotUmas { got }) if got == function_code
            ));
        }
    }

    #[test]
    fn test_extract_umas_header() {
        // Session 0x01, fonction 0x34, deux octets de donnees.
        assert_eq!(
            extract_umas_header(&[0x01, 0x34, 0xAA, 0xBB]),
            Ok((0x01, 0x34, &[0xAA, 0xBB][..]))
        );
        // Sans donnees : la tranche rendue est vide, pas une erreur.
        assert_eq!(
            extract_umas_header(&[0x00, 0x02]),
            Ok((0x00, 0x02, &[][..]))
        );

        for pdu in [&[][..], &[0x00][..]] {
            assert!(matches!(
                extract_umas_header(pdu),
                Err(UmasError::PduTooSmall { needed: 2, actual }) if actual == pdu.len()
            ));
        }
    }
}
