// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

/// Errors raised while parsing an LDAP PDU: an `LDAPMessage` (RFC 4511) or
/// a buffer of the SASL security layer (RFC 4422 §3.7).
#[non_exhaustive]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LdapError {
    /// The bytes stop before the end of a header: what came before is
    /// well-formed as far as it goes.
    #[error("LDAP {field} too short: expected at least {expected} bytes, got {actual}")]
    TooShort {
        field: &'static str,
        expected: usize,
        actual: usize,
    },

    #[error("LDAP {field}: expected tag {expected:#04x}, got {actual:#04x}")]
    UnexpectedTag {
        field: &'static str,
        expected: u8,
        actual: u8,
    },

    /// RFC 4511 §5.1 keeps the definite form of length only; this decoder
    /// reads at most four length octets, and at most 2^31 - 1 bytes.
    #[error("LDAP {field}: unsupported BER length")]
    InvalidLength { field: &'static str },

    #[error("LDAP {field}: {length} bytes do not fit in the {available} bytes of its container")]
    LengthOverflow {
        field: &'static str,
        length: usize,
        available: usize,
    },

    /// RFC 4511 §4.1.1.1: an INTEGER from 0 to 2^31 - 1.
    #[error("LDAP message identifier is not an INTEGER from 0 to 2^31 - 1")]
    InvalidMessageId,

    /// The tag is none of the protocol operations of RFC 4511 §4.1.1.
    #[error("unknown LDAP operation tag {0:#04x}")]
    UnknownOperation(u8),

    /// Inside the SEQUENCE, only the controls may follow the operation.
    #[error("LDAP message: {0} bytes follow the controls")]
    TrailingBytes(usize),

    /// An UnbindRequest is a NULL, an AbandonRequest a message identifier.
    #[error("LDAP operation {operation}: invalid length {length}")]
    InvalidOperationLength { operation: u8, length: usize },

    /// The length of a SASL buffer covers at least the header of its
    /// token, and at most 2^24 - 1 bytes (RFC 4752 §3.1).
    #[error("LDAP SASL buffer: invalid length {0}")]
    InvalidSaslLength(u32),

    /// The buffer opens with none of the tokens that the decoder reads: a
    /// Kerberos V5 Wrap token (RFC 4121 §4.2.6.2, or RFC 1964 §1.2.2 in the
    /// framing of RFC 2743) or an NTLMSSP signature.
    #[error("LDAP SASL buffer: neither a Kerberos V5 Wrap token nor an NTLMSSP signature")]
    UnsupportedSaslToken,
}
