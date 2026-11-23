// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

/// Errors raised while parsing a Skinny (SCCP, Skinny Client Control
/// Protocol) message.
#[non_exhaustive]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SkinnyError {
    #[error("Skinny message too short: expected at least {expected} bytes, got {actual}")]
    TooShort { expected: usize, actual: usize },

    /// The data length counts the message identifier, four bytes, and the
    /// body.
    #[error("Skinny data length {0} is below the 4 bytes of the message identifier")]
    InvalidDataLength(u32),

    /// A header version that no known release of the protocol uses.
    #[error("unsupported Skinny header version {0:#x}")]
    UnsupportedHeaderVersion(u32),
}
