// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

/// Errors raised while parsing an RTCP datagram (RFC 3550 §6).
#[non_exhaustive]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RtcpError {
    #[error("RTCP packet too short: expected at least {expected} bytes, got {actual}")]
    TooShort { expected: usize, actual: usize },

    #[error("invalid RTCP version: expected 2, got {0}")]
    InvalidVersion(u8),

    #[error("unknown RTCP packet type {0}: expected 200 to 207")]
    UnknownPacketType(u8),

    /// The length field runs past the datagram.
    #[error("RTCP packet of {declared} bytes in the {available} that remain")]
    TruncatedPacket { declared: usize, available: usize },

    /// The packet is shorter than its type and count require.
    #[error(
        "RTCP packet type {packet_type} with count {count} needs {expected} bytes, got {actual}"
    )]
    PacketTooShortForType {
        packet_type: u8,
        count: u8,
        expected: usize,
        actual: usize,
    },

    /// Padding on a packet that is not the last, or a padding count that is
    /// zero, not a multiple of four or longer than the packet body.
    #[error("invalid RTCP padding")]
    InvalidPadding,
}
