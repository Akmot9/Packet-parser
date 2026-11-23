// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

/// Errors raised while parsing a SIP message (RFC 3261 §7).
#[non_exhaustive]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SipError {
    #[error("SIP head is not terminated by an empty line (CRLF CRLF)")]
    MissingHeaderTerminator,

    #[error("SIP head is not valid UTF-8")]
    InvalidUtf8,

    #[error("unknown SIP method: not in the IANA registry, or not a SIP request line")]
    UnknownMethod,

    #[error("invalid SIP Request-URI: expected scheme \":\" and visible ASCII")]
    InvalidRequestUri,

    #[error("unsupported SIP version: expected SIP/2.0")]
    InvalidVersion,

    #[error("invalid SIP status code: expected three digits from 100 to 699")]
    InvalidStatusCode,

    #[error("invalid SIP header line: expected token \":\" value")]
    InvalidHeader,

    #[error("SIP message is missing the mandatory {0} header")]
    MissingHeader(&'static str),

    #[error("invalid SIP CSeq: expected a number below 2^31 and a known method")]
    InvalidCseq,

    #[error("SIP CSeq method {cseq} differs from the request method {request}")]
    CseqMethodMismatch {
        request: &'static str,
        cseq: &'static str,
    },

    #[error("invalid SIP Content-Length: expected decimal digits")]
    InvalidContentLength,

    /// Only a field whose value is a comma-separated list may span several
    /// header rows (RFC 3261 §7.3.1); `Content-Length` is not one, and two
    /// rows would leave the end of the body undecided.
    #[error("SIP message carries the {0} header more than once")]
    DuplicateHeader(&'static str),
}
