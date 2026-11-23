// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

/// Errors raised while parsing an ONC RPC message (RFC 5531 §9) or the
/// record fragment that carries it over TCP (RFC 5531 §11).
#[non_exhaustive]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum OncRpcError {
    /// The bytes stop before the end of the header of the message.
    #[error("ONC RPC {field} too short: expected at least {expected} bytes, got {actual}")]
    TooShort {
        field: &'static str,
        expected: usize,
        actual: usize,
    },

    /// `msg_type` is 0 for a call and 1 for a reply.
    #[error("unknown ONC RPC message type {0}")]
    UnknownMessageType(u32),

    /// A call announces the version 2 of the protocol.
    #[error("unsupported ONC RPC version {0}, expected 2")]
    UnsupportedVersion(u32),

    /// The flavor of an `opaque_auth` is a number of the IANA registry of
    /// RPC authentication flavors.
    #[error("ONC RPC {field}: unassigned authentication flavor {flavor}")]
    UnknownAuthFlavor { field: &'static str, flavor: u32 },

    /// The body of an `opaque_auth` holds at most 400 bytes.
    #[error("ONC RPC {field}: authentication body of {length} bytes, at most 400")]
    AuthBodyTooLong { field: &'static str, length: u32 },

    /// `reply_stat` is 0 (accepted) or 1 (denied).
    #[error("unknown ONC RPC reply status {0}")]
    UnknownReplyStatus(u32),

    /// `accept_stat` goes from 0 to 5.
    #[error("unknown ONC RPC accept status {0}")]
    UnknownAcceptStatus(u32),

    /// `reject_stat` is 0 (RPC version mismatch) or 1 (authentication
    /// error).
    #[error("unknown ONC RPC reject status {0}")]
    UnknownRejectStatus(u32),

    /// A reply without results ends with its status.
    #[error("ONC RPC reply: {0} bytes follow a status that carries no result")]
    TrailingBytes(usize),

    /// The first fragment of a record holds the header of its message: a
    /// fragment that ends before it, or that announces fewer bytes than the
    /// shortest message of its kind (40 for a call, 24 for an accepted
    /// reply, 20 otherwise), is not read, whether the segment carries it
    /// whole or not.
    #[error("ONC RPC record fragment of {length} bytes ends before the header of its message")]
    FragmentTooShort { length: u32 },
}
