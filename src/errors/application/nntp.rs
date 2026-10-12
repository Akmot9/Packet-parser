// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum NntpParseError {
    #[error("Invalid UTF-8 in NNTP payload")]
    InvalidUtf8,

    #[error("Empty NNTP payload")]
    EmptyPayload,

    #[error("Incomplete NNTP line: missing CRLF terminator")]
    IncompleteLine,

    #[error("Unknown NNTP command: {0}")]
    UnknownCommand(String),

    #[error("Invalid NNTP command syntax: {0}")]
    InvalidCommandSyntax(String),

    #[error("Invalid NNTP response code: {0}")]
    InvalidResponseCode(String),

    /// A CR or LF outside a CRLF line terminator, in the first line or in the
    /// data block that follows it (RFC 3977 §3.1.1; issue #109).
    #[error("Bare CR or LF at offset {offset} in NNTP payload: lines end with CRLF only")]
    BareLineBreak { offset: usize },

    /// A control character other than TAB and the CRLF terminator in the
    /// command or response line (RFC 3977 §9.8: `A-CHAR = %x21-7E`), or a NUL
    /// anywhere in the payload (RFC 3977 §3.1.1; issue #109).
    #[error("Control character 0x{byte:02X} at offset {offset} in NNTP payload")]
    ControlCharacter { offset: usize, byte: u8 },
}
