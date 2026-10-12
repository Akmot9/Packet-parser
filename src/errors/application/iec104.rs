// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

/// Erreurs de decodage d'un segment IEC 60870-5-104.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Iec104ParseError {
    #[error("IEC 104 segment truncated: expected at least {expected} bytes, got {actual}")]
    Truncated { expected: usize, actual: usize },

    /// Tout APDU commence par `0x68`.
    #[error("IEC 104 start byte {0:#04x} is not 0x68")]
    InvalidStartByte(u8),

    /// La longueur compte le champ de controle et l'ASDU : de 4 a 253.
    #[error("IEC 104 APDU length {0} is outside 4..=253")]
    InvalidLength(u8),

    /// Un APDU de format S ou U ne porte que son champ de controle.
    #[error("IEC 104 {format} APDU declares {length} bytes, control field only is 4")]
    ControlOnlyFormat { format: &'static str, length: u8 },

    /// Format U : exactement une des six fonctions.
    #[error("IEC 104 U-format control {0:#04x} is not one of the six functions")]
    InvalidUnnumberedFunction(u8),

    /// Un ASDU porte au moins son en-tete de six octets.
    #[error("IEC 104 ASDU of {0} bytes is shorter than its 6-byte header")]
    AsduTooShort(usize),

    /// Le qualificatif de structure variable annonce zero objet.
    #[error("IEC 104 ASDU type {0} announces no information object")]
    EmptyAsdu(u8),
}
