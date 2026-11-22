// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

/// Errors raised while parsing .NET Message Framing records ([MC-NMF]).
#[non_exhaustive]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum NmfError {
    #[error("empty NMF segment")]
    Empty,

    #[error("unknown NMF record type {0:#04X}")]
    UnknownRecordType(u8),

    #[error("NMF record {record_type:#04X} truncated: expected {expected} bytes, got {actual}")]
    TruncatedRecord {
        record_type: u8,
        expected: usize,
        actual: usize,
    },

    #[error("unsupported NMF version {major}.{minor}: expected 1.0")]
    UnsupportedVersion { major: u8, minor: u8 },

    #[error("invalid NMF mode {0}: expected 1 to 4")]
    InvalidMode(u8),

    /// A size that runs past the segment, takes more than five bytes or does
    /// not fit in 32 bits ([MC-NMF] §2.2.2).
    #[error("malformed NMF record size")]
    MalformedSize,

    #[error("NMF record {record_type:#04X} carries a string that is not valid UTF-8")]
    InvalidString { record_type: u8 },
}
