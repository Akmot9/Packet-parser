// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

/// Erreurs de decodage d'un message RTPS (OMG DDSI-RTPS 2.x). Chaque
/// variante nomme ce qui a ete refuse : la sonde de detection s'appuie sur
/// ce decodeur, et un datagramme dont les sous-messages ne pavent pas
/// exactement le message n'est jamais etiquete.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum RtpsParseError {
    #[error("RTPS message truncated: expected at least {expected} bytes, got {actual}")]
    Truncated { expected: usize, actual: usize },

    #[error("RTPS magic expected, got {0:02x?}")]
    InvalidMagic([u8; 4]),

    /// Seules les versions 2.x (DDSI-RTPS) sont decodees.
    #[error("Unsupported RTPS protocol version {major}.{minor}")]
    UnsupportedVersion { major: u8, minor: u8 },

    /// Un message sans aucun sous-message ne porte rien : refuse.
    #[error("RTPS message carries no submessage")]
    NoSubmessage,

    /// Un submessageId reserve (hors de ceux de la specification, de DDS
    /// Security et de la plage vendeur 0x80 a 0xff).
    #[error("Reserved RTPS submessageId {id:#04x} at offset {offset}")]
    ReservedSubmessageId { id: u8, offset: usize },

    /// `octetsToNextHeader` depasse la fin du message.
    #[error(
        "RTPS submessage {id:#04x} at offset {offset} declares {declared} bytes, {available} available"
    )]
    SubmessageOverflow {
        id: u8,
        offset: usize,
        declared: usize,
        available: usize,
    },

    /// Le corps est plus court que ce que le type de sous-message impose
    /// (identifiants d'entite, numeros de sequence, bitmaps...).
    #[error(
        "RTPS submessage {id:#04x} at offset {offset} is too short: expected at least {expected} bytes, got {actual}"
    )]
    SubmessageTooShort {
        id: u8,
        offset: usize,
        expected: usize,
        actual: usize,
    },
}
