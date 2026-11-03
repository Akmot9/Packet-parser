// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

/// Erreurs de decodage d'un message Valmet DNA ou de sa balise.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValmetDnaParseError {
    #[error("Valmet DNA message truncated: expected at least {expected} bytes, got {actual}")]
    Truncated { expected: usize, actual: usize },

    /// Chaque message commence par `AB 01`.
    #[error("Invalid Valmet DNA magic {0:#06x}, expected 0xab01")]
    InvalidMagic(u16),

    /// La longueur declaree compte les octets qui suivent la magie : le
    /// datagramme moins deux.
    #[error("Valmet DNA length {declared} does not match the {actual} bytes of the datagram")]
    LengthMismatch { declared: u16, actual: usize },

    /// Un telegramme d'etat fait 126 octets ; un message a etiquette, 72
    /// octets plus son etiquette.
    #[error("Valmet DNA message kind {kind:#010x} is {actual} bytes, expected {expected}")]
    InvalidMessageLength {
        kind: u32,
        expected: usize,
        actual: usize,
    },

    /// La longueur de l'etiquette est ecrite deux fois (offsets 28 et 70).
    #[error("Valmet DNA tag length {declared} differs from its echo {echo}")]
    TagLengthMismatch { declared: u16, echo: u16 },

    /// La balise fait 42 octets.
    #[error("Valmet DNA beacon is {actual} bytes, expected 42")]
    InvalidBeaconLength { actual: usize },

    /// La balise commence par quatre octets nuls.
    #[error("Valmet DNA beacon prefix {0:#010x} is not zero")]
    InvalidBeaconPrefix(u32),

    /// Puis `AB CC`.
    #[error("Invalid Valmet DNA beacon magic {0:#06x}, expected 0xabcc")]
    InvalidBeaconMagic(u16),
}
