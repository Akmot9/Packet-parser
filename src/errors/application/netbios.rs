// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Erreurs des deux services NetBIOS couverts (RFC 1001/1002) :
//! le Name Service (NBNS, UDP 137) et le Session Service (NBSS, TCP 139).
//! Le Datagram Service (UDP 138) n'est pas implemente : le corpus du depot
//! n'en contient aucune trame.

use thiserror::Error;

/// Errors raised while parsing a NetBIOS Name Service packet (RFC 1002 §4.2).
#[non_exhaustive]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum NbnsError {
    #[error("NBNS packet too short: expected at least {expected} bytes, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("invalid NBNS opcode: {0}")]
    InvalidOpcode(u8),

    #[error("invalid NBNS rcode: {0}")]
    InvalidRcode(u8),

    #[error("reserved NM_FLAGS bits are set in NBNS flags {0:#06x}")]
    NonZeroReservedFlags(u16),

    #[error("NBNS message carries no question and no resource record")]
    EmptyMessage,

    #[error("NBNS name truncated at offset {offset}")]
    TruncatedName { offset: usize },

    #[error("invalid NBNS first-level label length at offset {offset}: expected 32, got {length}")]
    InvalidNameLength { offset: usize, length: u8 },

    #[error("invalid NBNS first-level encoding byte at offset {offset}: expected 'A'..='P'")]
    InvalidNameEncoding { offset: usize },

    #[error("invalid NBNS scope label at offset {offset}")]
    InvalidScopeLabel { offset: usize },

    #[error("NBNS encoded name exceeds 255 bytes at offset {offset}")]
    NameTooLong { offset: usize },

    #[error("invalid NBNS compression pointer at offset {offset}")]
    InvalidPointer { offset: usize },

    #[error("NBNS record truncated at offset {offset}")]
    TruncatedRecord { offset: usize },

    #[error("invalid NBNS question type: {0:#06x}")]
    InvalidQuestionType(u16),

    #[error("invalid NBNS record type: {0:#06x}")]
    InvalidRecordType(u16),

    #[error("invalid NBNS class: {0:#06x}")]
    InvalidClass(u16),
}

/// Errors raised while parsing a NetBIOS Session Service packet (RFC 1002 §4.3).
#[non_exhaustive]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum NbssError {
    #[error("NBSS packet too short: expected at least {expected} bytes, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("unknown NBSS message type: {0:#04x}")]
    UnknownMessageType(u8),

    #[error("reserved NBSS flag bits are set: {0:#04x}")]
    NonZeroReservedFlags(u8),

    #[error("NBSS payload truncated: header announces {announced} bytes, {available} available")]
    TruncatedPayload { announced: usize, available: usize },

    #[error("invalid NBSS payload length {length} for message type {message_type:#04x}")]
    InvalidPayloadLength { message_type: u8, length: u32 },
}
