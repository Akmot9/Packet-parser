// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

/// Errors raised while parsing an ICMPv4 message (IP protocol 1, RFC 792).
#[non_exhaustive]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum IcmpError {
    #[error("ICMP message too short: expected at least {expected} bytes, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("ICMP echo body too short: expected at least {expected} bytes, got {actual}")]
    InvalidEchoLength { expected: usize, actual: usize },

    #[error(
        "ICMP error message too short to carry the original datagram: expected at least {expected} bytes, got {actual}"
    )]
    InvalidErrorPayloadLength { expected: usize, actual: usize },

    #[error("ICMP code {code} is not defined for message type {message_type}")]
    InvalidCodeForType { message_type: u8, code: u8 },
}
