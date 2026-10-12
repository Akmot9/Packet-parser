// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

/// Erreurs de decodage d'un paquet ESP (RFC 4303).
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum EspError {
    /// Moins que le SPI et le numero de sequence.
    #[error("ESP packet too short: expected at least {expected} bytes, got {actual}")]
    PacketTooShort { expected: usize, actual: usize },

    /// Le SPI zero est reserve a un usage local et ne circule jamais
    /// (RFC 4303 §2.1).
    #[error("ESP SPI 0 is reserved and never sent on the wire")]
    ReservedSpi,
}
