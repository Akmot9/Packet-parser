// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

/// Erreurs de parsing des BPDU Spanning Tree (IEEE 802.1D / 802.1Q).
#[derive(Debug, Error, PartialEq)]
pub enum StpError {
    #[error("BPDU too short: expected at least {expected} bytes, got {actual} bytes")]
    InvalidLength { expected: usize, actual: usize },

    #[error("Invalid STP protocol identifier: 0x{0:04X}")]
    InvalidProtocolIdentifier(u16),

    #[error("Invalid STP protocol version: {0}")]
    InvalidVersion(u8),

    #[error("Invalid BPDU type: 0x{0:02X}")]
    InvalidBpduType(u8),

    #[error("Incoherent STP version {version} for BPDU type 0x{bpdu_type:02X}")]
    IncoherentVersionType { version: u8, bpdu_type: u8 },

    #[error("Invalid version 1 length: expected 0, got {0}")]
    InvalidVersion1Length(u8),

    #[error("Version 3 length {announced} exceeds available bytes {available}")]
    InvalidVersion3Length { announced: usize, available: usize },
}
