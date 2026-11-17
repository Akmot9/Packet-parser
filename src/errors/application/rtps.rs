// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

/// Erreurs de decodage d'un message RTPS (OMG DDSI-RTPS 2.x). Chaque
/// variante nomme ce qui a ete refuse : la sonde de detection s'appuie sur
/// ce decodeur, et un datagramme dont les sous-messages ne pavent pas
/// exactement le message n'est jamais etiquete.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum RtpsParseError {
    #[error("RTPS message truncated: expected at least {expected} bytes, got {actual}")]
    Truncated { expected: usize, actual: usize },

    #[error("RTPS magic expected, got {0:02x?}")]
    InvalidMagic([u8; 4]),

    /// Seules les versions 2.x (DDSI-RTPS) sont decodees.
    #[error("Unsupported RTPS protocol version {major}.{minor}")]
    UnsupportedVersion { major: u8, minor: u8 },

    /// Un message sans aucun sous-message ne porte rien : refuse.
    #[error("RTPS message carries no submessage")]
    NoSubmessage,

    /// Un submessageId reserve (hors de ceux de la specification 2.5,
    /// HEADER_EXTENSION compris, de DDS Security et de la plage vendeur 0x80
    /// a 0xff).
    #[error("Reserved RTPS submessageId {id:#04x} at offset {offset}")]
    ReservedSubmessageId { id: u8, offset: usize },

    /// `octetsToNextHeader` depasse la fin du message.
    #[error(
        "RTPS submessage {id:#04x} at offset {offset} declares {declared} bytes, {available} available"
    )]
    SubmessageOverflow {
        id: u8,
        offset: usize,
        declared: usize,
        available: usize,
    },

    /// Le corps est plus court que ce que le type de sous-message impose
    /// (identifiants d'entite, numeros de sequence, bitmaps...).
    #[error(
        "RTPS submessage {id:#04x} at offset {offset} is too short: expected at least {expected} bytes, got {actual}"
    )]
    SubmessageTooShort {
        id: u8,
        offset: usize,
        expected: usize,
        actual: usize,
    },

    /// Un HEADER_EXTENSION ailleurs qu'en premier sous-message, juste apres
    /// l'en-tete (DDSI-RTPS 2.5 §8.3.3.2). En fin d'enum : ajoutee apres la
    /// 11.6.0.
    #[error("RTPS HEADER_EXTENSION at offset {offset}, not right after the header")]
    MisplacedHeaderExtension { offset: usize },

    /// Le `messageLength` du HEADER_EXTENSION ne vaut pas la longueur du
    /// message, qui est celle du datagramme (§9.5 : un message par
    /// datagramme UDP). En fin d'enum : ajoutee apres la 11.6.0.
    #[error(
        "RTPS HEADER_EXTENSION declares a message of {declared} bytes, the datagram has {actual}"
    )]
    HeaderExtensionLengthMismatch { declared: u32, actual: usize },

    /// L'`octetsToInlineQos` d'un DATA ou d'un DATA_FRAG pointe dans ses
    /// champs fixes ou au-dela de son corps (#317).
    #[error(
        "RTPS octetsToInlineQos {octets_to_inline_qos} does not point between the fixed fields and the end of the {body}-byte submessage body"
    )]
    InvalidOctetsToInlineQos {
        octets_to_inline_qos: u16,
        body: usize,
    },

    /// Un parametre d'une ParameterList deborde de la liste : son en-tete,
    /// ou la valeur que sa longueur annonce (#317).
    #[error("RTPS parameter at offset {offset} needs {expected} bytes, {actual} left in the list")]
    ParameterTruncated {
        offset: usize,
        expected: usize,
        actual: usize,
    },

    /// Une ParameterList sans PID_SENTINEL (§9.4.2.11) (#317).
    #[error("RTPS parameter list of {length} bytes has no PID_SENTINEL")]
    ParameterListUnterminated { length: usize },

    /// Des donnees serialisees plus courtes que leur en-tete
    /// d'encapsulation de quatre octets (#317).
    #[error("RTPS serialized payload of {actual} bytes, shorter than its encapsulation header")]
    SerializedPayloadTooShort { actual: usize },

    /// Des donnees de decouverte dont l'encapsulation n'est pas PL_CDR, la
    /// seule que la specification prevoit pour SPDP et SEDP (#317).
    #[error("RTPS discovery data encapsulated as {encapsulation:#06x}, not PL_CDR")]
    NotAParameterList { encapsulation: u16 },
}
