// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum TcpError {
    #[error("Packet too short to be a valid TCP header")]
    PacketTooShort,

    #[error("Invalid data offset: {0}")]
    InvalidDataOffset(u8),

    /// SYN et FIN ensemble : aucune pile conforme n'emet cette combinaison
    /// (ouvrir et fermer la connexion dans le meme segment). C'est une
    /// signature classique de scan et d'evasion de pare-feu.
    #[error("Invalid TCP flags {flags:#04x}: SYN and FIN are both set")]
    InvalidFlags { flags: u8 },

    /// Bits reserves non nuls (RFC 9293 §3.1 : « must be zero »).
    #[error("TCP reserved bits are set: {bits:#05b}")]
    ReservedBitsSet { bits: u8 },
}
