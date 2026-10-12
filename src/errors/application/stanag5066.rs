// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

/// Erreurs de decodage d'un S_PDU STANAG 5066 SIS (Subnetwork Interface
/// Sublayer, Ed. 4 brouillon v1.6, annexe A).
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Stanag5066ParseError {
    #[error("STANAG 5066 S_PDU truncated: expected at least {expected} bytes, got {actual}")]
    Truncated { expected: usize, actual: usize },

    /// Les deux premiers octets ne sont pas le preambule `90 EB`.
    #[error("STANAG 5066 sync preamble expected, got {0:02x?}")]
    InvalidPreamble([u8; 2]),

    /// Seule la version 0 est definie.
    #[error("Unsupported STANAG 5066 SIS version {0}")]
    UnsupportedVersion(u8),

    /// `S_Primitive size` compte le type : zero est impossible.
    #[error("STANAG 5066 S_Primitive size must be at least 1")]
    EmptyPrimitive,

    /// Un type de S_PDU hors de 1 a 27.
    #[error("Reserved STANAG 5066 S_PDU type {0}")]
    ReservedPduType(u8),

    /// La primitive est plus courte que les champs fixes de son type.
    #[error(
        "STANAG 5066 S_PDU type {pdu_type} is too short: expected at least {expected} bytes, got {actual}"
    )]
    PrimitiveTooShort {
        pdu_type: u8,
        expected: usize,
        actual: usize,
    },

    /// Les octets qui suivent un S_PDU complet ne commencent pas un autre
    /// S_PDU (preambule `90 EB 00`).
    #[error("{trailing} bytes follow the STANAG 5066 S_PDU without a sync preamble")]
    UnexpectedTrailingBytes { trailing: usize },
}
