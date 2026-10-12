// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

/// Erreurs de decodage d'une trame GOOSE (IEC 61850-8-1 §8, EtherType
/// `0x88B8`).
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum GooseParseError {
    #[error("GOOSE frame truncated: expected at least {expected} bytes, got {actual}")]
    Truncated { expected: usize, actual: usize },

    /// La longueur compte l'APPID, la longueur, les reserves et le PDU, et
    /// couvre exactement la trame.
    #[error("GOOSE length {declared} does not match the {actual} bytes after the EtherType")]
    LengthMismatch { declared: u16, actual: usize },

    /// Le PDU commence par l'etiquette `[APPLICATION 1]` (`0x61`).
    #[error("GOOSE PDU tag {0:#04x} is not 0x61")]
    InvalidPduTag(u8),

    /// Longueur BER illisible (forme longue de plus de quatre octets, ou
    /// coupee).
    #[error("Invalid BER length at offset {0}")]
    InvalidBerLength(usize),

    /// Un element BER annonce plus que ce qui reste.
    #[error("BER element tagged {tag:#04x} declares {declared} bytes, {available} remain")]
    ElementOverflow {
        tag: u8,
        declared: usize,
        available: usize,
    },

    /// Un champ obligatoire du PDU manque.
    #[error("GOOSE PDU lacks the mandatory field tagged {0:#04x}")]
    MissingField(u8),

    /// Un entier BER tient sur un a cinq octets.
    #[error("BER integer tagged {tag:#04x} of {length} bytes does not fit in 32 bits")]
    IntegerTooLong { tag: u8, length: usize },

    /// Un booleen BER tient sur un octet.
    #[error("BER boolean tagged {tag:#04x} spans {length} bytes, not 1")]
    InvalidBoolean { tag: u8, length: usize },

    /// L'horodatage UtcTime tient sur huit octets.
    #[error("GOOSE timestamp spans {0} bytes, not 8")]
    InvalidTimestamp(usize),

    /// Le PDU laisse des octets qui ne forment pas un element.
    #[error("{0} bytes follow the last GOOSE PDU field")]
    UnexpectedTrailingBytes(usize),
}
