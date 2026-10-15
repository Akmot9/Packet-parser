// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

/// Erreurs de decodage d'un LLDPDU (IEEE 802.1AB, EtherType `0x88CC`).
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum LldpParseError {
    /// Un en-tete de TLV (deux octets) commence a `offset` mais la trame
    /// s'arrete avant.
    #[error("LLDP TLV header truncated at offset {offset}")]
    TruncatedTlvHeader { offset: usize },

    /// Un TLV annonce plus que ce qui reste de la trame.
    #[error(
        "LLDP TLV type {tlv_type} at offset {offset} declares {declared} bytes, {available} remain"
    )]
    TlvOverflow {
        tlv_type: u8,
        offset: usize,
        declared: usize,
        available: usize,
    },

    /// Les trois premiers TLV sont, dans l'ordre, Chassis ID, Port ID et
    /// Time To Live (IEEE 802.1AB §8.2).
    #[error("LLDPDU TLV {position} must be type {expected}, found {found:?}")]
    MissingMandatoryTlv {
        position: usize,
        expected: u8,
        found: Option<u8>,
    },

    /// Un TLV dont la taille sort des bornes de la norme : Chassis ID et
    /// Port ID de 2 a 256 octets, Time To Live et System Capabilities de 2
    /// et 4 octets, End of LLDPDU vide, Management Address de 9 a 167
    /// octets, TLV d'organisation d'au moins 4.
    #[error("LLDP TLV type {tlv_type} has an invalid length {length}")]
    InvalidTlvLength { tlv_type: u8, length: usize },

    /// Les longueurs internes d'un Management Address ne pavent pas sa
    /// valeur.
    #[error("LLDP management address TLV is malformed")]
    InvalidManagementAddress,
}
