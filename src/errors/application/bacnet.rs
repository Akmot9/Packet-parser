// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

/// Erreurs de decodage d'un datagramme BACnet/IP (ASHRAE 135, annexe J).
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum BacnetParseError {
    #[error("BACnet/IP datagram truncated: expected at least {expected} bytes, got {actual}")]
    Truncated { expected: usize, actual: usize },

    /// Tout BVLC commence par `0x81`.
    #[error("BVLC type {0:#04x} is not 0x81 (BACnet/IP)")]
    InvalidBvlcType(u8),

    /// Fonctions BVLC 0x00 a 0x0c.
    #[error("Unknown BVLC function {0:#04x}")]
    UnknownBvlcFunction(u8),

    /// La longueur BVLC couvre exactement le datagramme (annexe J.2).
    #[error("BVLC length {declared} does not match the {actual} bytes of the datagram")]
    LengthMismatch { declared: u16, actual: usize },

    /// Version NPDU 1, la seule definie (clause 6.2.1).
    #[error("NPDU version {0} is not 1")]
    UnsupportedNpduVersion(u8),

    /// Type d'APDU 0 a 7 (clause 20.1).
    #[error("Unknown APDU type {0}")]
    UnknownApduType(u8),
}
