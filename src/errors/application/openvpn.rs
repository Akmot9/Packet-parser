// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

/// Errors raised while parsing an OpenVPN wire-protocol packet.
#[non_exhaustive]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum OpenVpnError {
    #[error("OpenVPN packet is empty")]
    EmptyPacket,

    #[error("unknown OpenVPN opcode {opcode:#04x}: defined opcodes are 1 to 10")]
    UnknownOpcode { opcode: u8 },

    #[error(
        "OpenVPN packet too short for its opcode: expected at least {expected} bytes, got {actual}"
    )]
    TooShort { expected: usize, actual: usize },

    #[error(
        "OpenVPN hard/soft reset larger than the {max} bytes such a message can carry: got {actual}"
    )]
    ResetTooLong { max: usize, actual: usize },

    #[error("OpenVPN hard reset carries key id {key_id}: a new session always starts at key id 0")]
    HardResetWithNonZeroKeyId { key_id: u8 },

    #[error("OpenVPN TCP record needs a 2-byte length prefix: got {actual} bytes")]
    TcpLengthMissing { actual: usize },

    #[error("OpenVPN TCP record declares {declared} bytes but only {available} follow the prefix")]
    TcpRecordTruncated { declared: usize, available: usize },
}
