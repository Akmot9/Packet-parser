// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

/// Errors raised while parsing a syslog message (RFC 3164, RFC 5424) or a
/// frame of syslog over TCP (RFC 6587).
#[non_exhaustive]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SyslogError {
    #[error("syslog message too short: expected at least {expected} bytes, got {actual}")]
    TooShort { expected: usize, actual: usize },

    /// A message opens with its priority, `<`: this one does not.
    #[error("syslog message does not open with a priority (first byte {0:#04x})")]
    MissingPriority(u8),

    /// The priority is one to three digits between `<` and `>`, without a
    /// leading zero, from 0 to 191.
    #[error("invalid syslog priority")]
    InvalidPriority,

    /// The octet count of a frame is one to ten digits, the first one not a
    /// zero, followed by a space, and fits in 32 bits.
    #[error("invalid syslog octet count")]
    InvalidOctetCount,
}
