// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

/// Erreurs de decodage d'un message PTP (IEEE 1588-2002 et 1588-2008/2019).
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum PtpPacketParseError {
    #[error("PTP message truncated: expected at least {expected} bytes, got {actual}")]
    Truncated { expected: usize, actual: usize },

    #[error("Unsupported PTP version {0}")]
    UnsupportedVersion(u8),

    #[error("Reserved PTPv2 messageType {0:#x}")]
    ReservedMessageType(u8),

    #[error(
        "PTPv2 messageLength {declared} invalid for messageType {message_type:#x}: \
         at least {minimum} bytes required, {available} available"
    )]
    InvalidMessageLength {
        message_type: u8,
        declared: u16,
        minimum: usize,
        available: usize,
    },

    #[error("PTPv1 versionPTP must be 1, got {0:#06x}")]
    InvalidV1VersionPtp(u16),

    #[error("Unsupported PTPv1 versionNetwork {0}")]
    UnsupportedNetworkVersion(u16),

    #[error("Reserved PTPv1 control {0}")]
    ReservedControl(u8),

    #[error("PTPv1 messageType {message_type} does not match control {control}")]
    InconsistentMessageType { message_type: u8, control: u8 },

    #[error("PTPv1 control {control} message must be {expected} bytes, got {actual}")]
    InvalidV1Length {
        control: u8,
        expected: usize,
        actual: usize,
    },

    #[error("{trailing} bytes follow the PTP message on UDP, only 0 or 2 are allowed")]
    UnexpectedTrailingBytes { trailing: usize },

    #[error("PTP TLV truncated at offset {offset}: needs {needed} bytes, {available} available")]
    TruncatedTlv {
        /// Type du TLV tronque, quand ses deux premiers octets sont presents.
        tlv_type: Option<u16>,
        offset: usize,
        needed: usize,
        available: usize,
    },
}
