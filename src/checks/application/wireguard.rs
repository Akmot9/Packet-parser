// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use crate::errors::application::wireguard::WireGuardParseError;

/// Type du message et trois octets reserves.
pub const MESSAGE_HEADER_LENGTH: usize = 4;

/// Handshake Initiation : en-tete, index de l'emetteur, cle ephemere (32),
/// cle statique chiffree (48), horodatage TAI64N chiffre (28), mac1, mac2.
pub const HANDSHAKE_INITIATION_LENGTH: usize = 148;

/// Handshake Response : en-tete, index de l'emetteur et du destinataire, cle
/// ephemere (32), « rien » chiffre (16), mac1, mac2.
pub const HANDSHAKE_RESPONSE_LENGTH: usize = 92;

/// Cookie Reply : en-tete, index du destinataire, nonce (24), cookie chiffre
/// (32).
pub const COOKIE_REPLY_LENGTH: usize = 64;

/// Transport Data : en-tete, index du destinataire et compteur sur huit
/// octets, puis le paquet chiffre et son tag Poly1305.
pub const TRANSPORT_HEADER_LENGTH: usize = 16;

/// Tag d'authentification ChaCha20-Poly1305.
pub const AUTHENTICATION_TAG_LENGTH: usize = 16;

/// Le plus court Transport Data : un keepalive, paquet chiffre vide.
pub const TRANSPORT_DATA_MIN_LENGTH: usize = TRANSPORT_HEADER_LENGTH + AUTHENTICATION_TAG_LENGTH;

/// Au-dela de 2^60 messages, une session doit etre renouvelee
/// (`REKEY_AFTER_MESSAGES`, livre blanc de WireGuard §6.2) : aucun compteur reel n'y
/// arrive.
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;

/// Le paquet clair est complete par des zeros jusqu'a un multiple de seize
/// octets (livre blanc §5.4.6)...
pub const PADDING_MULTIPLE: usize = 16;

/// ... sauf quand ce multiple depasserait la MTU du paquet : Linux
/// (`calculate_skb_padding`) et wireguard-go (`calculatePaddingSize`)
/// s'arretent alors a la MTU. La sonde aveugle suppose une MTU d'au moins
/// 552 octets, le plancher de la PMTU IPv4 de Linux (`DEFAULT_MIN_PMTU`,
/// 512 + 20 + 20, `net/ipv4/route.c`) ; rien d'autre ne l'impose (RFC 791
/// n'exige que 68 octets), si bien qu'un tunnel configure plus bas, a une
/// MTU qui n'est pas un multiple de seize, n'est reconnu que sur 51820 ou
/// par Decode As.
pub const MIN_TUNNEL_MTU: usize = 552;

pub fn ensure_len(buf: &[u8], needed: usize) -> Result<(), WireGuardParseError> {
    if buf.len() < needed {
        return Err(WireGuardParseError::Truncated {
            expected: needed,
            actual: buf.len(),
        });
    }
    Ok(())
}

/// La taille d'un message selon son type : fixe pour les handshakes et le
/// cookie, au moins un keepalive pour les donnees.
pub fn validate_message_length(message_type: u8, length: usize) -> Result<(), WireGuardParseError> {
    let expected = match message_type {
        1 => HANDSHAKE_INITIATION_LENGTH,
        2 => HANDSHAKE_RESPONSE_LENGTH,
        3 => COOKIE_REPLY_LENGTH,
        4 => return ensure_len_value(length, TRANSPORT_DATA_MIN_LENGTH),
        _ => return Err(WireGuardParseError::UnknownMessageType(message_type)),
    };
    if length != expected {
        return Err(WireGuardParseError::InvalidLength {
            message_type,
            expected,
            actual: length,
        });
    }
    Ok(())
}

fn ensure_len_value(length: usize, needed: usize) -> Result<(), WireGuardParseError> {
    if length < needed {
        return Err(WireGuardParseError::Truncated {
            expected: needed,
            actual: length,
        });
    }
    Ok(())
}

/// Le compteur d'un vrai Transport Data, pour la sonde aveugle.
pub fn is_plausible_counter(counter: u64) -> bool {
    counter < REKEY_AFTER_MESSAGES
}

/// La taille d'un Transport Data de Linux ou de wireguard-go, pour la sonde
/// aveugle : le paquet clair (message moins en-tete
/// et tag) est un multiple de seize octets, ou s'arrete a une MTU d'au moins
/// [`MIN_TUNNEL_MTU`] octets. boringtun (Cloudflare) et ses derives
/// (NordSecurity neptun, Firezone) ne completent pas le paquet clair
/// (« spec requires padding to 16 bytes, but actually works fine without
/// it », `noise/session.rs`) : hors de 51820 et des ports declares, seuls
/// leurs handshakes, leurs keepalives et les paquets dont la taille tombe
/// juste sont reconnus.
pub fn is_padded_transport_length(length: usize) -> bool {
    let Some(plaintext) = length.checked_sub(TRANSPORT_DATA_MIN_LENGTH) else {
        return false;
    };
    plaintext.is_multiple_of(PADDING_MULTIPLE) || plaintext >= MIN_TUNNEL_MTU
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixed_lengths() {
        assert_eq!(validate_message_length(1, 148), Ok(()));
        assert_eq!(validate_message_length(2, 92), Ok(()));
        assert_eq!(validate_message_length(3, 64), Ok(()));
        for (message_type, expected) in [(1u8, 148usize), (2, 92), (3, 64)] {
            for actual in [expected - 1, expected + 1, 32] {
                assert_eq!(
                    validate_message_length(message_type, actual),
                    Err(WireGuardParseError::InvalidLength {
                        message_type,
                        expected,
                        actual
                    })
                );
            }
        }
    }

    #[test]
    fn test_transport_data_needs_a_keepalive() {
        assert_eq!(validate_message_length(4, 32), Ok(()));
        assert_eq!(validate_message_length(4, 1452), Ok(()));
        assert_eq!(
            validate_message_length(4, 31),
            Err(WireGuardParseError::Truncated {
                expected: 32,
                actual: 31
            })
        );
    }

    #[test]
    fn test_unknown_types() {
        for message_type in [0u8, 5, 0xc1, 0xff] {
            assert_eq!(
                validate_message_length(message_type, 148),
                Err(WireGuardParseError::UnknownMessageType(message_type))
            );
        }
    }

    #[test]
    fn test_counter_bound() {
        assert!(is_plausible_counter(0));
        assert!(is_plausible_counter((1 << 60) - 1));
        assert!(!is_plausible_counter(1 << 60));
        assert!(!is_plausible_counter(u64::MAX));
    }

    /// Acceptes : le keepalive (32), des paquets clairs de 48, 64 et 256
    /// octets, le message de 1 452 octets dont le clair s'arrete a la MTU
    /// 1420 de wg-quick, et des clairs de 552 (la PMTU plancher de Linux),
    /// 553 et 1 468 octets. Refuses : un clair de 551 octets ni multiple de
    /// seize ni a une MTU plausible, et les messages de boringtun, qui ne
    /// complete pas — 116 octets pour un ping de 84 octets, 89 pour une
    /// requete DNS de 57.
    #[test]
    fn test_padding_rule() {
        for length in [32usize, 80, 96, 288, 1452, 584, 585, 1500] {
            assert!(is_padded_transport_length(length), "{length}");
        }
        for length in [0usize, 31, 33, 81, 100, 583, 116, 89] {
            assert!(!is_padded_transport_length(length), "{length}");
        }
    }
}
