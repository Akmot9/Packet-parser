// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

/// Errors raised while parsing an ICMPv6 message (IP next header 58, RFC 4443).
#[non_exhaustive]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Icmpv6Error {
    #[error("ICMPv6 message too short: expected at least {expected} bytes, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("ICMPv6 echo body too short: expected at least {expected} bytes, got {actual}")]
    InvalidEchoLength { expected: usize, actual: usize },

    #[error(
        "ICMPv6 error message too short to carry the invoking packet: expected at least {expected} bytes, got {actual}"
    )]
    InvalidErrorPayloadLength { expected: usize, actual: usize },

    #[error(
        "ICMPv6 neighbor discovery message too short to carry its target address: expected at least {expected} bytes, got {actual}"
    )]
    InvalidNeighborLength { expected: usize, actual: usize },

    #[error(
        "ICMPv6 router discovery message too short: expected at least {expected} bytes, got {actual}"
    )]
    InvalidRouterLength { expected: usize, actual: usize },

    #[error("ICMPv6 code {code} is not defined for message type {message_type}")]
    InvalidCodeForType { message_type: u8, code: u8 },
}
