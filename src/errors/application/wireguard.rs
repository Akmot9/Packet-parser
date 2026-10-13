// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

/// Erreurs de decodage d'un message WireGuard.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum WireGuardParseError {
    #[error("WireGuard message truncated: expected at least {expected} bytes, got {actual}")]
    Truncated { expected: usize, actual: usize },

    /// Types 1 a 4 seulement : initiation, reponse, cookie, donnees.
    #[error("Unknown WireGuard message type {0}")]
    UnknownMessageType(u8),

    /// Les messages de handshake et de cookie ont une taille fixe.
    #[error("WireGuard message type {message_type} is {actual} bytes, expected {expected}")]
    InvalidLength {
        message_type: u8,
        expected: usize,
        actual: usize,
    },
}
