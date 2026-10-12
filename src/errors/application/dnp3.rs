// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

/// Erreurs de decodage d'une trame DNP3 (IEEE 1815).
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Dnp3ParseError {
    #[error("DNP3 frame truncated: expected at least {expected} bytes, got {actual}")]
    Truncated { expected: usize, actual: usize },

    /// Toute trame commence par `05 64`.
    #[error("DNP3 start bytes {0:02x?} are not 05 64")]
    InvalidStartBytes([u8; 2]),

    /// Le champ LENGTH compte le controle et les deux adresses : au moins 5.
    #[error("DNP3 length {0} is shorter than the 5 bytes of control and addresses")]
    InvalidLength(u8),

    /// Le CRC de l'en-tete de liaison ne correspond pas.
    #[error("DNP3 link header CRC {actual:#06x} does not match computed {expected:#06x}")]
    HeaderCrcMismatch { expected: u16, actual: u16 },

    /// Le CRC d'un bloc de donnees utilisateur ne correspond pas.
    #[error("DNP3 data block {block} CRC {actual:#06x} does not match computed {expected:#06x}")]
    BlockCrcMismatch {
        block: usize,
        expected: u16,
        actual: u16,
    },

    /// Les trames de liaison doivent paver exactement le payload.
    #[error("{trailing} bytes follow the last DNP3 link frame without forming a frame")]
    UnexpectedTrailingBytes { trailing: usize },

    /// Un premier fragment de transport porte au moins le controle
    /// applicatif et le code de fonction.
    #[error("DNP3 application fragment of {actual} bytes is shorter than its header")]
    ApplicationHeaderTooShort { actual: usize },
}
