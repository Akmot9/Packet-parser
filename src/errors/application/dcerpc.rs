// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

/// Errors raised while parsing a connection-oriented DCE/RPC PDU
/// (DCE 1.1: RPC, C706 §12.6).
#[non_exhaustive]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DceRpcError {
    #[error("DCE/RPC PDU too short: expected at least {expected} bytes, got {actual}")]
    TooShort { expected: usize, actual: usize },

    #[error("unsupported DCE/RPC version {major}.{minor}: expected 5.0 or 5.1")]
    UnsupportedVersion { major: u8, minor: u8 },

    #[error("unknown connection-oriented DCE/RPC PDU type {0}")]
    UnknownPduType(u8),

    /// A data representation label that names no integer, character or
    /// floating-point format, or whose reserved bytes are not zero.
    #[error("invalid DCE/RPC data representation {0:02X?}")]
    InvalidDataRepresentation([u8; 4]),

    #[error("DCE/RPC fragment length {frag_length} is below the {minimum} bytes of its header")]
    FragmentTooShort { frag_length: u16, minimum: usize },

    #[error("DCE/RPC auth length {auth_length} does not fit a fragment of {frag_length} bytes")]
    InvalidAuthLength { auth_length: u16, frag_length: u16 },
}
