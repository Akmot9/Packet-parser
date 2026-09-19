// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
#[non_exhaustive]
pub enum GiopParseError {
    #[error("Invalid GIOP packet length")]
    InvalidSize,

    #[error("Invalid GIOP magic (expected 'GIOP')")]
    InvalidMagic,

    #[error("Unsupported GIOP version {0}.{1}")]
    UnsupportedVersion(u8, u8),

    #[error("Unknown GIOP message type {0}")]
    UnknownMessageType(u8),

    #[error("Invalid UTF-8 in string field")]
    InvalidUtf8,

    #[error("Unexpected end of buffer")]
    UnexpectedEof,

    #[error("Unknown GIOP TargetAddress discriminator {0}")]
    UnknownTargetDiscriminator(u16),

    #[error("Unknown GIOP reply status {0}")]
    UnknownReplyStatus(u32),

    #[error("Unknown GIOP locate status {0}")]
    UnknownLocateStatus(u32),

    #[error("Invalid GIOP profile count {count} (only {available} bytes available)")]
    InvalidProfileCount { count: usize, available: usize },

    #[error(
        "Invalid GIOP service context count {count} (only {available} bytes available in body)"
    )]
    InvalidServiceContextCount { count: usize, available: usize },
}
