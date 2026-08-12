// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Controles de taille et de coherence pour ICMPv6 (RFC 4443, RFC 4861).
//!
//! ICMPv6 partage la forme d'en-tete d'ICMPv4 — type, code, checksum — mais sa
//! numerotation de types est disjointe : 128 est un Echo request la ou 8 l'est
//! en v4. Les deux protocoles ont donc des checks separes, et melanger leurs
//! constantes serait une source d'erreur silencieuse.

use crate::errors::transport::icmpv6::Icmpv6Error;

/// Type, code et checksum.
pub const ICMPV6_HEADER_LENGTH: usize = 4;

/// En-tete commun + identifiant + numero de sequence.
pub const ICMPV6_ECHO_HEADER_LENGTH: usize = 8;

/// En-tete commun + 4 octets dependant du type, avant le paquet invoquant.
pub const ICMPV6_ERROR_HEADER_LENGTH: usize = 8;

/// En-tete commun + reserve/flags (4 octets) + adresse cible (16 octets).
pub const ICMPV6_NEIGHBOR_HEADER_LENGTH: usize = 24;

/// En-tete commun + 4 octets reserves, avant les options (RFC 4861 §4.1).
pub const ICMPV6_ROUTER_SOLICITATION_HEADER_LENGTH: usize = 8;

/// En-tete commun + hop limit, flags, lifetime, reachable time et retrans
/// timer, avant les options (RFC 4861 §4.2).
pub const ICMPV6_ROUTER_ADVERTISEMENT_HEADER_LENGTH: usize = 16;

/// RFC 4443 §3 : un message d'erreur cite le paquet fautif, dont l'en-tete
/// IPv6 fixe fait 40 octets.
pub const ICMPV6_MIN_INVOKING_PACKET_LENGTH: usize = 40;

/// Verifie qu'il reste de quoi lire type, code et checksum.
pub fn validate_icmpv6_min_length(payload: &[u8]) -> Result<(), Icmpv6Error> {
    if payload.len() < ICMPV6_HEADER_LENGTH {
        return Err(Icmpv6Error::InvalidLength {
            expected: ICMPV6_HEADER_LENGTH,
            actual: payload.len(),
        });
    }
    Ok(())
}

/// Verifie qu'un Echo porte bien son identifiant et sa sequence.
pub fn validate_icmpv6_echo_length(payload: &[u8]) -> Result<(), Icmpv6Error> {
    if payload.len() < ICMPV6_ECHO_HEADER_LENGTH {
        return Err(Icmpv6Error::InvalidEchoLength {
            expected: ICMPV6_ECHO_HEADER_LENGTH,
            actual: payload.len(),
        });
    }
    Ok(())
}

/// Verifie qu'un message d'erreur cite un paquet invoquant exploitable.
pub fn validate_icmpv6_error_length(payload: &[u8]) -> Result<(), Icmpv6Error> {
    let expected = ICMPV6_ERROR_HEADER_LENGTH + ICMPV6_MIN_INVOKING_PACKET_LENGTH;
    if payload.len() < expected {
        return Err(Icmpv6Error::InvalidErrorPayloadLength {
            expected,
            actual: payload.len(),
        });
    }
    Ok(())
}

/// Verifie qu'un message de decouverte de voisins porte son adresse cible.
pub fn validate_icmpv6_neighbor_length(payload: &[u8]) -> Result<(), Icmpv6Error> {
    if payload.len() < ICMPV6_NEIGHBOR_HEADER_LENGTH {
        return Err(Icmpv6Error::InvalidNeighborLength {
            expected: ICMPV6_NEIGHBOR_HEADER_LENGTH,
            actual: payload.len(),
        });
    }
    Ok(())
}

/// Verifie qu'une Router Solicitation porte au moins ses octets reserves.
pub fn validate_icmpv6_router_solicitation_length(payload: &[u8]) -> Result<(), Icmpv6Error> {
    if payload.len() < ICMPV6_ROUTER_SOLICITATION_HEADER_LENGTH {
        return Err(Icmpv6Error::InvalidRouterLength {
            expected: ICMPV6_ROUTER_SOLICITATION_HEADER_LENGTH,
            actual: payload.len(),
        });
    }
    Ok(())
}

/// Verifie qu'une Router Advertisement porte tous ses champs fixes.
pub fn validate_icmpv6_router_advertisement_length(payload: &[u8]) -> Result<(), Icmpv6Error> {
    if payload.len() < ICMPV6_ROUTER_ADVERTISEMENT_HEADER_LENGTH {
        return Err(Icmpv6Error::InvalidRouterLength {
            expected: ICMPV6_ROUTER_ADVERTISEMENT_HEADER_LENGTH,
            actual: payload.len(),
        });
    }
    Ok(())
}

/// Verifie que le code est defini pour ce type de message.
///
/// Plages issues de RFC 4443 et du registre IANA « ICMPv6 Parameters ». Un
/// type inconnu n'impose aucune contrainte : le message reste lisible en
/// `Other` sans pretendre l'interpreter.
pub fn extract_icmpv6_code(message_type: u8, code: u8) -> Result<u8, Icmpv6Error> {
    let max_code = match message_type {
        // Destination unreachable : codes 0 a 7.
        1 => 7,
        // Packet too big : code toujours 0.
        2 => 0,
        // Time exceeded : 0 (hop limit) ou 1 (reassemblage).
        3 => 1,
        // Parameter problem : codes 0 a 2.
        4 => 2,
        // Echo request/reply, et les quatre messages de decouverte de voisins
        // (RFC 4861) : code toujours 0.
        128 | 129 | 133 | 134 | 135 | 136 => 0,
        _ => return Ok(code),
    };

    if code > max_code {
        return Err(Icmpv6Error::InvalidCodeForType { message_type, code });
    }
    Ok(code)
}
