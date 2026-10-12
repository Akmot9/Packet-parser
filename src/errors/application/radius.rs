// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

/// Erreurs de decodage d'un paquet RADIUS (RFC 2865).
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum RadiusParseError {
    #[error("RADIUS packet truncated: expected at least {expected} bytes, got {actual}")]
    Truncated { expected: usize, actual: usize },

    /// Codes de la RFC 2865, 2866 et 5176 seulement.
    #[error("Unknown RADIUS code {0}")]
    UnknownCode(u8),

    /// La longueur declaree va de 20 a 4096 (RFC 2865 §3).
    #[error("RADIUS length {0} is outside 20..=4096")]
    InvalidLength(u16),

    /// La longueur declaree couvre exactement le datagramme.
    #[error("RADIUS length {declared} does not match the {actual} bytes of the datagram")]
    LengthMismatch { declared: u16, actual: usize },

    /// Un attribut tient au moins sur ses deux octets d'en-tete.
    #[error(
        "RADIUS attribute {attribute_type} declares {length} bytes, less than its 2-byte header"
    )]
    AttributeTooShort { attribute_type: u8, length: u8 },

    /// Un attribut deborde du paquet.
    #[error("RADIUS attribute {attribute_type} needs {needed} bytes, {available} remain")]
    AttributeOverflow {
        attribute_type: u8,
        needed: usize,
        available: usize,
    },
}
