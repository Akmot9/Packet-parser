// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AmsParseError {
    #[error("AMS header too short: expected at least {expected} bytes, got {actual}")]
    HeaderTooShort { expected: usize, actual: usize },

    #[error("AMS payload length ({cb_data}) does not match actual data length ({actual})")]
    InvalidCbDataLength { cb_data: u32, actual: usize },

    #[error("Unknown AMS command id: 0x{0:04x}")]
    UnknownCommand(u16),

    #[error("Invalid AMS state flags: reserved bits set (0x{0:04x})")]
    InvalidStateFlags(u16),

    /// En-tete AMS/TCP dont les deux octets reserves ne sont pas nuls.
    #[error("Invalid AMS/TCP header: reserved bytes must be zero (0x{0:04x})")]
    InvalidTcpReserved(u16),

    /// Longueur AMS/TCP plus grande que ce qui suit l'en-tete dans le segment.
    #[error("AMS/TCP length ({length}) exceeds the {available} bytes after its header")]
    TcpLengthExceedsSegment { length: u32, available: usize },
}
