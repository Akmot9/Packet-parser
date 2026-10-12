// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

/// Erreurs de decodage d'un PDU DIS (IEEE 1278.1).
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum DisParseError {
    #[error("DIS PDU truncated: expected at least {expected} bytes, got {actual}")]
    Truncated { expected: usize, actual: usize },

    /// Versions 1 a 7 (DIS PDU version 1.0 a IEEE 1278.1-2012).
    #[error("Unsupported DIS protocol version {0}")]
    UnsupportedVersion(u8),

    /// Types 1 a 72 de la norme ; les autres sont reserves.
    #[error("Reserved DIS PDU type {0}")]
    ReservedPduType(u8),

    /// Familles 0 a 13 de la norme, ou experimentales (129 a 255).
    #[error("Reserved DIS protocol family {0}")]
    ReservedProtocolFamily(u8),

    /// La longueur declaree ne couvre pas l'en-tete de douze octets.
    #[error("DIS PDU length {0} is shorter than the 12-byte header")]
    InvalidLength(u16),

    /// La longueur declaree depasse les octets restants du datagramme.
    #[error("DIS PDU declares {declared} bytes, {available} available")]
    LengthOverflow { declared: u16, available: usize },

    /// Les PDU ne pavent pas exactement le datagramme : il reste des
    /// octets qui ne forment pas un PDU.
    #[error("{trailing} bytes follow the last DIS PDU without forming a PDU")]
    UnexpectedTrailingBytes { trailing: usize },

    /// Le corps est plus court que les champs fixes de son type.
    #[error(
        "DIS PDU type {pdu_type} body is too short: expected at least {expected} bytes, got {actual}"
    )]
    BodyTooShort {
        pdu_type: u8,
        expected: usize,
        actual: usize,
    },
}
