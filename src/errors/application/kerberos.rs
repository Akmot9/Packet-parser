// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

/// Errors raised while parsing a Kerberos V5 message (RFC 4120 §5) or the
/// record that carries it over TCP (RFC 4120 §7.2.2).
#[non_exhaustive]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum KerberosError {
    /// The bytes stop before the end of a header, or before the end of the
    /// `msg-type` field.
    #[error("Kerberos {field} too short: expected at least {expected} bytes, got {actual}")]
    TooShort {
        field: &'static str,
        expected: usize,
        actual: usize,
    },

    /// The first byte is none of the `[APPLICATION n]` tags of the ten
    /// messages of RFC 4120 §5.10.
    #[error("unknown Kerberos message tag {0:#04x}")]
    UnknownMessageTag(u8),

    #[error("Kerberos {field}: expected tag {expected:#04x}, got {actual:#04x}")]
    UnexpectedTag {
        field: &'static str,
        expected: u8,
        actual: u8,
    },

    /// DER keeps the definite form of length only; this decoder reads at
    /// most four length octets, and at most 2^31 - 1 bytes.
    #[error("Kerberos {field}: unsupported DER length")]
    InvalidLength { field: &'static str },

    #[error(
        "Kerberos {field}: {length} bytes do not fit in the {available} bytes of its container"
    )]
    LengthOverflow {
        field: &'static str,
        length: usize,
        available: usize,
    },

    /// The SEQUENCE of the message must fill its `[APPLICATION n]` element.
    #[error("Kerberos message of {message} bytes holds a SEQUENCE of {sequence} bytes")]
    SequenceLengthMismatch { message: usize, sequence: usize },

    /// `pvno` must be the INTEGER 5.
    #[error("Kerberos pvno is not the INTEGER 5")]
    InvalidProtocolVersion,

    /// `msg-type` must be an INTEGER equal to the number of the
    /// `[APPLICATION n]` tag.
    #[error("Kerberos msg-type is not the INTEGER {expected} of the tag of the message")]
    MessageTypeMismatch { expected: u8 },

    /// Over TCP, the four bytes before the message are its length, with a
    /// high bit that is reserved and null (RFC 4120 §7.2.2).
    #[error("Kerberos record of {record} bytes holds a message of {message} bytes")]
    RecordLengthMismatch { record: u32, message: usize },

    /// A record mark that no message can follow: its reserved high bit is
    /// set, or it announces fewer bytes than the header of a message
    /// (RFC 4120 §7.2.2).
    #[error("invalid Kerberos record mark {0:#010x}")]
    InvalidRecordMark(u32),
}
