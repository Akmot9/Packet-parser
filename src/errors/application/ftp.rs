// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum FtpParseError {
    #[error("Invalid UTF-8 in FTP payload")]
    InvalidUtf8,

    #[error("Empty FTP payload")]
    EmptyPayload,

    #[error("Incomplete FTP line: missing CRLF terminator")]
    IncompleteLine,

    #[error("Unknown FTP command: {0}")]
    UnknownCommand(String),

    #[error("Invalid FTP command syntax: {0}")]
    InvalidCommandSyntax(String),

    #[error("Invalid FTP reply code: {0}")]
    InvalidReplyCode(String),

    #[error("Multi-line FTP reply is missing its terminator line")]
    MissingReplyTerminator,

    /// A CR or LF outside a CRLF line terminator, anywhere in the payload.
    /// RFC 959 §5.3.2 excludes both from every argument (`<char>`), and the
    /// control connection carries Telnet NVT text only (issue #109).
    #[error("Bare CR or LF at offset {offset} in FTP payload: lines end with CRLF only")]
    BareLineBreak { offset: usize },

    /// A control character other than TAB and the CRLF terminator (NUL, ESC,
    /// DEL...), anywhere in the payload: the control connection carries text
    /// only (issue #109).
    #[error("Control character 0x{byte:02X} at offset {offset} in FTP payload")]
    ControlCharacter { offset: usize, byte: u8 },
}
