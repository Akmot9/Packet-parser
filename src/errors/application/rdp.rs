// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

use crate::errors::application::copt::CotpParseError;

/// Erreurs de decodage d'un segment RDP (MS-RDPBCGR) : TPKT, COTP X.224,
/// negociation, MCS.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum RdpParseError {
    #[error("RDP segment truncated: expected at least {expected} bytes, got {actual}")]
    Truncated { expected: usize, actual: usize },

    /// RFC 1006 : version 3, octet reserve nul.
    #[error("TPKT header version {version} reserved {reserved} is not 3/0")]
    InvalidTpkt { version: u8, reserved: u8 },

    /// Un TPKT porte au moins son en-tete et un TPDU COTP de trois octets.
    #[error("TPKT length {0} is shorter than the 7 bytes of its header and a COTP TPDU")]
    TpktTooShort(u16),

    #[error("COTP: {0}")]
    Cotp(#[from] CotpParseError),

    /// RDP ne circule que dans des CR, CC et DT.
    #[error("COTP TPDU {0:#04x} is not a connection request, confirm or data TPDU")]
    UnexpectedTpdu(u8),

    /// Une structure de negociation declare une autre longueur que ses huit
    /// octets. Une structure coupee donne [`Self::Truncated`], des octets en
    /// trop [`Self::UnexpectedX224Data`].
    #[error("RDP negotiation structure {structure_type} declares {length} bytes, not 8")]
    InvalidNegotiation { structure_type: u8, length: u16 },

    /// Donnees X.224 qui ne sont ni un cookie, ni un jeton, ni une
    /// structure de negociation.
    #[error("{0} bytes of X.224 user data are neither a cookie nor a negotiation structure")]
    UnexpectedX224Data(usize),

    /// Choix PER d'un DomainMCSPDU que la norme ne definit pas.
    #[error("Unknown MCS PDU choice {0}")]
    UnknownMcsPdu(u8),

    /// Longueur BER d'un Connect-Initial ou Connect-Response illisible.
    #[error("Invalid BER length in MCS connect PDU")]
    InvalidBerLength,

    /// La demande de negociation annonce une correlation info
    /// (CORRELATION_INFO_PRESENT), mais ce qui la suit n'a pas le type
    /// `0x06` et la longueur 36 d'un RDP_NEG_CORRELATION_INFO
    /// (MS-RDPBCGR §2.2.1.1.2). En fin d'enum : ajoutee apres la 11.6.0.
    #[error(
        "RDP correlation info has type {structure_type:#04x} and declares {length} bytes, not 0x06 and 36"
    )]
    InvalidCorrelationInfo { structure_type: u8, length: u16 },
}
