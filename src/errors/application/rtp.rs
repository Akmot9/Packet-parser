// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

/// Errors raised while parsing an RTP packet (RFC 3550 §5.1).
#[non_exhaustive]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RtpError {
    #[error("RTP packet too short: expected at least {expected} bytes, got {actual}")]
    TooShort { expected: usize, actual: usize },

    #[error("invalid RTP version: expected 2, got {0}")]
    InvalidVersion(u8),

    #[error("payload type {0} is an RTCP packet type (RFC 5761 §4), not RTP")]
    RtcpPayloadType(u8),

    #[error("RTP CSRC list truncated: {count} identifiers need {expected} bytes, got {actual}")]
    TruncatedCsrcList {
        count: u8,
        expected: usize,
        actual: usize,
    },

    #[error("RTP header extension truncated: expected {expected} bytes, got {actual}")]
    TruncatedExtension { expected: usize, actual: usize },

    #[error("invalid RTP padding: {padding} bytes announced, {available} after the header")]
    InvalidPadding { padding: u8, available: usize },
}
