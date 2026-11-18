// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

/// Error types for QUIC packet parsing (RFC 9000 / RFC 9001, Long Header).
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum QuicError {
    #[error("Packet truncated: needed {needed} more bytes, only {remaining} remaining")]
    Truncated { needed: usize, remaining: usize },

    #[error("Truncated varint: needed {needed} continuation bytes, only {remaining} remaining")]
    TruncatedVarint { needed: usize, remaining: usize },

    #[error("Not a Long Header packet: header form bit must be 1")]
    NotLongHeader,

    #[error("Fixed bit is 0: must be 1 per RFC 9000 §17.2")]
    FixedBitNotSet,

    #[error("Unsupported QUIC version: {0:#010x}")]
    UnsupportedVersion(u32),

    /// Champ Length trop court pour l'echantillon de la protection d'en-tete :
    /// le numero de paquet compte pour 4 octets, puis 16 octets d'echantillon
    /// (RFC 9001 §5.4.2). Un recepteur doit rejeter ce paquet.
    #[error(
        "Length field {length_field} is below the {min} bytes that the header protection sample requires"
    )]
    LengthFieldTooSmall { length_field: u64, min: u64 },

    #[error("Payload too short: expected {expected} bytes, only {available} available")]
    PayloadTooShort { expected: usize, available: usize },

    /// Un Connection ID de plus de 20 octets dans un en-tete long de QUIC
    /// v1 : RFC 9000 §17.2, « Endpoints that receive a version 1 long header
    /// with a value larger than 20 MUST drop the packet » (#299).
    #[error("Connection ID of {length} bytes exceeds the {max} bytes of QUIC version 1")]
    ConnectionIdTooLong { length: u8, max: u8 },
}
