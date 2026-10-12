// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

/// Erreurs de decodage d'un message IKE (RFC 2408 pour IKEv1, RFC 7296 pour
/// IKEv2) ou de son encapsulation UDP (RFC 3948).
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum IkeParseError {
    #[error("IKE message truncated: expected at least {expected} bytes, got {actual}")]
    Truncated { expected: usize, actual: usize },

    /// Versions majeures 1 (ISAKMP/IKEv1) et 2 (IKEv2) seules.
    #[error("Unsupported IKE major version {0}")]
    UnsupportedVersion(u8),

    /// Le SPI de l'initiateur ne doit jamais etre nul (RFC 7296 §3.1).
    #[error("IKEv2 initiator SPI is zero")]
    ZeroInitiatorSpi,

    /// La longueur de l'en-tete couvre tout le message, exactement.
    #[error("IKE header declares {declared} bytes, got {actual}")]
    LengthMismatch { declared: u32, actual: usize },

    /// Un en-tete generique de payload annonce moins que ses quatre octets.
    #[error("IKE payload {payload_type} declares {length} bytes, less than its 4-byte header")]
    InvalidPayloadLength { payload_type: u8, length: u16 },

    /// Un payload deborde du message.
    #[error("IKE payload {payload_type} needs {needed} bytes, {available} remain")]
    PayloadOverflow {
        payload_type: u8,
        needed: usize,
        available: usize,
    },

    /// La chaine des payloads s'arrete avant la fin du message, ou le
    /// payload chiffre d'IKEv2 n'est pas le dernier (RFC 7296 §3.14).
    #[error("{trailing} bytes follow the last IKE payload")]
    UnexpectedTrailingBytes { trailing: usize },

    /// Sur UDP 4500 (RFC 3948) : ni marqueur non-ESP, ni keepalive d'un
    /// octet, ni assez d'octets pour un SPI.
    #[error("UDP-encapsulated IPsec payload of {length} bytes is neither IKE, ESP nor keepalive")]
    InvalidUdpEncapsulation { length: usize },
}
