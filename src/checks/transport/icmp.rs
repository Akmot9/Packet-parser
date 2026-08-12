// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Controles de taille et de coherence pour ICMPv4 (RFC 792).
//!
//! Le parseur de `src/parse/transport/protocols/icmp.rs` se contente
//! d'enchainer ces fonctions : aucune validation n'est ecrite en ligne dans le
//! parseur, conformement a METHODE_AJOUT_PROTOCOLE.md.

use crate::errors::transport::icmp::IcmpError;

/// Type, code et checksum : l'en-tete commun a tous les messages ICMP.
pub const ICMP_HEADER_LENGTH: usize = 4;

/// En-tete commun + identifiant + numero de sequence.
pub const ICMP_ECHO_HEADER_LENGTH: usize = 8;

/// En-tete commun + 4 octets inutilises, avant le datagramme original.
pub const ICMP_ERROR_HEADER_LENGTH: usize = 8;

/// RFC 792 impose de citer l'en-tete IP original plus ses 8 premiers octets
/// de donnees, soit 28 octets pour un en-tete IPv4 sans option.
pub const ICMP_MIN_ORIGINAL_DATAGRAM_LENGTH: usize = 28;

/// Verifie qu'il reste de quoi lire type, code et checksum.
pub fn validate_icmp_min_length(payload: &[u8]) -> Result<(), IcmpError> {
    if payload.len() < ICMP_HEADER_LENGTH {
        return Err(IcmpError::InvalidLength {
            expected: ICMP_HEADER_LENGTH,
            actual: payload.len(),
        });
    }
    Ok(())
}

/// Verifie qu'un message Echo porte bien son identifiant et sa sequence.
pub fn validate_icmp_echo_length(payload: &[u8]) -> Result<(), IcmpError> {
    if payload.len() < ICMP_ECHO_HEADER_LENGTH {
        return Err(IcmpError::InvalidEchoLength {
            expected: ICMP_ECHO_HEADER_LENGTH,
            actual: payload.len(),
        });
    }
    Ok(())
}

/// Verifie qu'un message d'erreur cite un datagramme original exploitable.
///
/// Un routeur tronque parfois au-dela du minimum RFC 792 ; on refuse alors le
/// message plutot que de laisser le consommateur lire un en-tete IP partiel.
pub fn validate_icmp_error_length(payload: &[u8]) -> Result<(), IcmpError> {
    let expected = ICMP_ERROR_HEADER_LENGTH + ICMP_MIN_ORIGINAL_DATAGRAM_LENGTH;
    if payload.len() < expected {
        return Err(IcmpError::InvalidErrorPayloadLength {
            expected,
            actual: payload.len(),
        });
    }
    Ok(())
}

/// Verifie que le code est defini pour ce type de message.
///
/// Les plages viennent de RFC 792 et du registre IANA « ICMP Type Numbers ».
/// Un type inconnu n'impose aucune contrainte de code : le message reste
/// parsable en `Other`, sans pretendre l'interpreter.
pub fn extract_icmp_code(message_type: u8, code: u8) -> Result<u8, IcmpError> {
    let max_code = match message_type {
        // Echo reply, Echo request : code toujours 0.
        0 | 8 => 0,
        // Destination unreachable : codes 0 a 15.
        3 => 15,
        // Redirect : codes 0 a 3.
        5 => 3,
        // Time exceeded : 0 (TTL en transit) ou 1 (reassemblage).
        11 => 1,
        // Parameter problem : codes 0 a 2.
        12 => 2,
        _ => return Ok(code),
    };

    if code > max_code {
        return Err(IcmpError::InvalidCodeForType { message_type, code });
    }
    Ok(code)
}
