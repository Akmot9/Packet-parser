// Copyright (c) 2024 Cyprien Avico <avicocyprien@yahoo.com>
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

/// Erreurs du decodeur PROFINET : la validation du Frame ID de toute trame
/// RT (`validate_frame`), puis le decodage DCP des seuls Frame ID DCP
/// (`ProfinetPacket::try_from`).
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProfinetPacketError {
    /// Le message DCP n'a pas son en-tete fixe de 12 octets.
    #[error("Packet too short: minimum length required is 12 bytes, found {0} bytes")]
    PacketTooShort(usize),

    /// Frame ID hors de toute plage attribuee (IEC 61158-6-10).
    #[error("Unknown Frame ID: {0:#06x}")]
    UnknownFrameId(u16),

    /// Moins de 4 octets pour l'en-tete d'un bloc DCP.
    #[error("Invalid DCP block length: expected at least 4 bytes, found {0} bytes")]
    InvalidDcpBlockLength(usize),

    /// Le bloc NameOfStation ne contient pas de l'UTF-8.
    #[error("Invalid name of station encoding")]
    InvalidNameOfStation,

    // --- Ajoutees en fin d'enum (issues #133 et #141). ---
    /// Moins de deux octets : pas de Frame ID.
    #[error("PROFINET frame too short for a Frame ID: {0} bytes")]
    FrameTooShort(usize),

    /// Le Frame ID est attribue mais n'est pas un Frame ID DCP : ce n'est
    /// pas un message DCP, `ProfinetPacket` ne s'applique pas.
    #[error("Frame ID {0:#06x} is not a DCP frame")]
    NotDcp(u16),

    /// `DCPDataLength` annonce plus d'octets que la trame n'en porte apres
    /// l'en-tete.
    #[error("DCP data length {declared} exceeds the {available} bytes after the header")]
    DcpDataOverflow { declared: u16, available: usize },

    /// `DCPBlockLength` annonce plus d'octets que le message n'en porte
    /// apres l'en-tete du bloc.
    #[error(
        "DCP block option {option}/{suboption} declares {declared} bytes, {available} available"
    )]
    DcpBlockOverflow {
        option: u8,
        suboption: u8,
        declared: u16,
        available: usize,
    },

    /// Le bloc est trop court pour le BlockInfo (reponse) ou le
    /// BlockQualifier (requete Set) que son service impose.
    #[error(
        "DCP block option {option}/{suboption} declares {declared} bytes, {needed} needed for its BlockInfo or BlockQualifier"
    )]
    DcpBlockTooShort {
        option: u8,
        suboption: u8,
        declared: u16,
        needed: u16,
    },
}
