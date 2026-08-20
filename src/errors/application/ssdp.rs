// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

/// Errors raised while parsing an SSDP message (HTTPU, UPnP Device
/// Architecture 1.1 §1).
#[non_exhaustive]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SsdpError {
    #[error("SSDP message too short: expected at least {expected} bytes, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("SSDP message is not valid UTF-8")]
    InvalidUtf8,

    #[error("SSDP head is not terminated by an empty line (CRLF CRLF)")]
    MissingHeaderTerminator,

    #[error("unknown SSDP method: expected M-SEARCH or NOTIFY")]
    UnknownMethod,

    #[error("SSDP request-URI is not *")]
    InvalidRequestUri,

    #[error("unsupported HTTP version in SSDP start line: expected HTTP/1.1")]
    UnsupportedHttpVersion,

    #[error("invalid SSDP status line: expected HTTP/1.1 200 OK")]
    InvalidStatusLine,

    #[error("invalid SSDP header line: expected Name: value")]
    InvalidHeader,

    #[error("SSDP M-SEARCH is missing the MAN: \"ssdp:discover\" header")]
    MissingDiscoverMan,
}
