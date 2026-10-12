// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SmtpParseError {
    #[error("Invalid UTF-8 in SMTP payload")]
    InvalidUtf8,

    #[error("Empty SMTP payload")]
    EmptyPayload,

    #[error("Incomplete SMTP line: missing CRLF terminator")]
    IncompleteLine,

    #[error("Unknown SMTP command: {0}")]
    UnknownCommand(String),

    #[error("Invalid SMTP command syntax: {0}")]
    InvalidCommandSyntax(String),

    #[error("Invalid SMTP reply code: {0}")]
    InvalidReplyCode(String),

    #[error("Multi-line SMTP reply is missing its terminator line")]
    MissingReplyTerminator,

    #[error("Invalid SMTP multi-line reply: {0}")]
    InvalidMultilineReply(String),

    /// A CR or LF outside a CRLF line terminator, anywhere in the payload:
    /// RFC 5321 §2.3.8 forbids bare CR and LF on the wire (issue #109).
    #[error("Bare CR or LF at offset {offset} in SMTP payload: lines end with CRLF only")]
    BareLineBreak { offset: usize },

    /// A control character other than TAB and the CRLF terminator (NUL, ESC,
    /// DEL...), anywhere in the payload: commands and replies are text only
    /// (RFC 5321 §4.1.2 and §4.2; issue #109).
    #[error("Control character 0x{byte:02X} at offset {offset} in SMTP payload")]
    ControlCharacter { offset: usize, byte: u8 },
}
