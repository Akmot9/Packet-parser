// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

/// Errors raised while parsing an SSH identification string (RFC 4253 §4.2).
#[non_exhaustive]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SshError {
    #[error("SSH identification too short: expected at least {expected} bytes, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("payload does not start with the SSH- identification prefix")]
    MissingPrefix,

    #[error(
        "SSH identification string exceeds the {max} bytes allowed by RFC 4253 §4.2: got {actual}"
    )]
    IdentificationTooLong { max: usize, actual: usize },

    #[error("SSH identification string is not terminated by a line feed")]
    MissingLineTerminator,

    #[error("unsupported SSH protocol version: expected 2.0 or 1.99")]
    UnsupportedProtocolVersion,

    #[error("SSH identification string is missing the separator after the protocol version")]
    MissingVersionSeparator,

    #[error("SSH software version is empty")]
    EmptySoftwareVersion,

    #[error("SSH identification string contains a non-printable byte at offset {offset}")]
    NonPrintableByte { offset: usize },
}
