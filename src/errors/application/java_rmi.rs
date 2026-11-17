// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Erreurs du decodeur Java RMI (JRMP, *Java RMI Specification*, chapitre 10).

use thiserror::Error;

/// Un segment qui n'est pas un message JRMP.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum JavaRmiError {
    /// Le segment s'arrete avant la fin d'une structure fixe.
    #[error("Java RMI message too short: expected at least {expected} bytes, got {actual}")]
    TooShort { expected: usize, actual: usize },

    /// Le premier octet n'est le type d'aucun message JRMP.
    #[error("Unknown Java RMI message type 0x{0:02x}")]
    UnknownMessageType(u8),

    /// Un `J` qui n'ouvre pas la magie `JRMI` de l'en-tete de flux.
    #[error("Invalid Java RMI header magic 0x{0:08x}, expected 0x4a524d49 (JRMI)")]
    InvalidHeaderMagic(u32),

    /// Version de l'en-tete de flux autre que 1 ou 2.
    #[error("Unsupported Java RMI protocol version {0}")]
    InvalidVersion(u16),

    /// Protocole de l'en-tete autre que Stream, SingleOp ou Multiplex.
    #[error("Unknown Java RMI protocol 0x{0:02x}")]
    UnknownProtocol(u8),

    /// Message de taille fixe (Ping, PingAck, ProtocolNotSupported,
    /// DgcAck) ou ProtocolAck dont la taille ne correspond pas au segment.
    #[error("Java RMI message 0x{message:02x} must be {expected} bytes long, got {actual}")]
    UnexpectedLength {
        message: u8,
        expected: usize,
        actual: usize,
    },

    /// Port d'un EndpointIdentifier au-dela de 65 535.
    #[error("Java RMI endpoint port {0} is not a TCP port")]
    InvalidPort(u32),

    /// Un Call ou un Return sans la magie `AC ED` du flux de serialisation.
    #[error("Invalid Java serialization stream magic 0x{0:04x}, expected 0xaced")]
    InvalidStreamMagic(u16),

    /// Version du flux de serialisation autre que 5.
    #[error("Unsupported Java serialization stream version {0}")]
    InvalidStreamVersion(u16),

    /// L'en-tete d'un Call ou d'un Return n'est pas dans un bloc de donnees
    /// (`TC_BLOCKDATA` 0x77 ou `TC_BLOCKDATALONG` 0x7a).
    #[error("Expected a Java serialization block data marker, got 0x{0:02x}")]
    ExpectedBlockData(u8),

    /// Bloc de donnees plus court que l'en-tete d'appel (34 octets) ou de
    /// retour (15 octets).
    #[error("Java RMI block data of {actual} bytes is shorter than the {expected}-byte header")]
    BlockTooShort { expected: usize, actual: u32 },

    /// Type de retour autre que 1 (normal) ou 2 (exceptionnel).
    #[error("Unknown Java RMI return type {0}")]
    InvalidReturnType(u8),
}
