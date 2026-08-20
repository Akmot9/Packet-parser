// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Controles pour le protocole de transport OpenVPN (« OpenVPN wire
//! protocol », doc de reference : ssl_pkt.h d'OpenVPN).
//!
//! Le premier octet porte l'opcode sur les 5 bits hauts et le key id sur les
//! 3 bits bas. Les messages du canal de controle (tout sauf `P_DATA_*`)
//! portent ensuite une session id de 8 octets. Ce qui suit la session id est
//! volontairement laisse opaque : en mode `tls-auth`/`tls-crypt` un HMAC, un
//! replay packet-id et un net-time s'intercalent avant l'ack array, et rien
//! dans le paquet n'annonce leur presence ni la taille du HMAC (elle depend
//! du digest negocie hors bande). Le corpus du depot
//! (`pcaps_exemple/protocols/openvpn/`) est en `tls-auth` SHA-1.
//!
//! Anti-faux-positifs pour le probing : opcode connu (1 a 10), longueur
//! minimale par famille d'opcodes, key id 0 sur les hard resets (ce qui
//! rejette les record types TLS 0x14-0x17, qui miment l'opcode 2 avec un key
//! id 4 a 7), et bornage des resets — un hard/soft reset ne transporte pas de
//! payload TLS libre, sa taille est donc structurellement limitee.

use crate::{
    errors::application::openvpn::OpenVpnError,
    parse::application::protocols::openvpn::OpenVpnOpcode,
};

/// Taille de la session id portee par tout message du canal de controle.
pub const OPENVPN_SESSION_ID_LEN: usize = 8;

/// Minimum d'un message de controle sans `tls-auth` : opcode (1) +
/// session id (8) + longueur d'ack array (1) + message packet-id (4).
pub const OPENVPN_CONTROL_MIN_LEN: usize = 14;

/// Minimum d'un `P_ACK_V1` : un ACK acquitte au moins un packet-id et porte
/// alors la session id distante — opcode (1) + session id (8) + longueur
/// d'ack array (1) + un packet-id (4) + remote session id (8).
pub const OPENVPN_ACK_MIN_LEN: usize = 22;

/// Minimum d'un `P_DATA_V1`. Un datagramme chiffre reel porte au moins un
/// packet-id (4) et un bloc de chiffrement avec IV ou tag : sous 16 octets
/// ce n'est pas un tunnel OpenVPN plausible. Sans cette borne, la moitie de
/// l'espace des premiers octets (opcodes data, tout key id) suffisait a
/// etiqueter OpenVPN n'importe quel petit datagramme partageant le port —
/// la sonde data serait un controle a un octet, contraire a la regle
/// « le contenu confirme le port ».
pub const OPENVPN_DATA_V1_MIN_LEN: usize = 16;

/// Le peer id de `P_DATA_V2` tient sur 3 octets.
pub const OPENVPN_DATA_V2_PEER_ID_LEN: usize = 3;

/// Minimum d'un `P_DATA_V2` : opcode + peer id (3) + une charge chiffree
/// plausible (meme raisonnement que `P_DATA_V1`).
pub const OPENVPN_DATA_V2_MIN_LEN: usize = 19;

/// Borne haute d'un hard/soft reset. Ces messages ne transportent pas de
/// payload TLS libre ; le plus gros cas legitime est
/// `P_CONTROL_HARD_RESET_CLIENT_V3` qui embarque une clef client tls-crypt-v2
/// (WKc, bornee a 1024 octets par la spec). 1280 couvre opcode + session id +
/// HMAC + replay packet-id + net-time + acks + WKc avec de la marge, tout en
/// rejetant les gros paquets quelconques dont le premier octet mime un reset.
pub const OPENVPN_RESET_MAX_LEN: usize = 1280;

/// Taille du prefixe de longueur des enregistrements OpenVPN sur TCP.
pub const OPENVPN_TCP_LENGTH_PREFIX_LEN: usize = 2;

/// Extrait l'opcode (5 bits hauts) et le key id (3 bits bas) du premier octet.
///
/// C'est le controle qui porte la signature : un opcode hors de 1..=10 rejette
/// le paquet. Le key id, sur 3 bits, est toujours structurellement valide.
pub fn extract_openvpn_opcode_and_key_id(
    payload: &[u8],
) -> Result<(OpenVpnOpcode, u8), OpenVpnError> {
    let first = *payload.first().ok_or(OpenVpnError::EmptyPacket)?;
    let opcode = OpenVpnOpcode::from_wire(first >> 3)
        // L'erreur porte l'opcode 5 bits, pas l'octet brut : un octet 0x03
        // est l'opcode 0 avec key id 3, pas l'opcode 3.
        .ok_or(OpenVpnError::UnknownOpcode { opcode: first >> 3 })?;
    Ok((opcode, first & 0b0000_0111))
}

/// Verifie la longueur totale du paquet contre le minimum de son opcode, puis
/// borne les resets.
///
/// Les minimums sont ceux d'un canal **sans** `tls-auth` : un HMAC eventuel ne
/// fait que grossir le paquet, jamais le raccourcir, donc ils restent valides
/// pour tous les modes.
pub fn validate_openvpn_length(opcode: OpenVpnOpcode, actual: usize) -> Result<(), OpenVpnError> {
    let expected = match opcode {
        OpenVpnOpcode::DataV1 => OPENVPN_DATA_V1_MIN_LEN,
        OpenVpnOpcode::DataV2 => OPENVPN_DATA_V2_MIN_LEN,
        OpenVpnOpcode::AckV1 => OPENVPN_ACK_MIN_LEN,
        _ => OPENVPN_CONTROL_MIN_LEN,
    };
    if actual < expected {
        return Err(OpenVpnError::TooShort { expected, actual });
    }
    if opcode.is_reset() && actual > OPENVPN_RESET_MAX_LEN {
        return Err(OpenVpnError::ResetTooLong {
            max: OPENVPN_RESET_MAX_LEN,
            actual,
        });
    }
    Ok(())
}

/// Un hard reset ouvre une session : son key id est toujours 0.
///
/// C'est le controle qui neutralise la famille de collisions TLS : les record
/// types 0x14 a 0x17 (ChangeCipherSpec, Alert, Handshake, Application Data)
/// donnent en apparence l'opcode 2 (`P_CONTROL_HARD_RESET_SERVER_V1`) avec un
/// key id 4 a 7 — tous rejetes ici.
pub fn validate_openvpn_hard_reset_key_id(
    opcode: OpenVpnOpcode,
    key_id: u8,
) -> Result<(), OpenVpnError> {
    if opcode.is_hard_reset() && key_id != 0 {
        return Err(OpenVpnError::HardResetWithNonZeroKeyId { key_id });
    }
    Ok(())
}

/// Lit la session id (u64 big-endian) qui suit l'opcode et rend le reste.
pub fn extract_openvpn_session_id(after_opcode: &[u8]) -> Result<(u64, &[u8]), OpenVpnError> {
    let (session_id, rest) = after_opcode
        .split_first_chunk::<OPENVPN_SESSION_ID_LEN>()
        .ok_or(OpenVpnError::TooShort {
            expected: OPENVPN_SESSION_ID_LEN,
            actual: after_opcode.len(),
        })?;
    Ok((u64::from_be_bytes(*session_id), rest))
}

/// Lit le peer id 24 bits d'un `P_DATA_V2` et rend le reste.
pub fn extract_openvpn_peer_id(after_opcode: &[u8]) -> Result<(u32, &[u8]), OpenVpnError> {
    let (peer_id, rest) = after_opcode
        .split_first_chunk::<OPENVPN_DATA_V2_PEER_ID_LEN>()
        .ok_or(OpenVpnError::TooShort {
            expected: OPENVPN_DATA_V2_PEER_ID_LEN,
            actual: after_opcode.len(),
        })?;
    Ok((
        u32::from_be_bytes([0, peer_id[0], peer_id[1], peer_id[2]]),
        rest,
    ))
}

/// Decoupe le premier enregistrement d'un flux TCP OpenVPN.
///
/// Sur TCP chaque message est prefixe de sa longueur sur u16 big-endian ;
/// plusieurs messages peuvent etre coalises dans un meme segment. Rend
/// l'enregistrement (prefixe exclu) et les octets qui le suivent.
pub fn read_openvpn_tcp_record(stream: &[u8]) -> Result<(&[u8], &[u8]), OpenVpnError> {
    let (prefix, rest) = stream
        .split_first_chunk::<OPENVPN_TCP_LENGTH_PREFIX_LEN>()
        .ok_or(OpenVpnError::TcpLengthMissing {
            actual: stream.len(),
        })?;
    let declared = usize::from(u16::from_be_bytes(*prefix));
    if rest.len() < declared {
        return Err(OpenVpnError::TcpRecordTruncated {
            declared,
            available: rest.len(),
        });
    }
    Ok((&rest[..declared], &rest[declared..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_opcode_and_key_id_from_first_byte() {
        // 0x38 : P_CONTROL_HARD_RESET_CLIENT_V2, key id 0 (trame 1 de
        // pcaps_exemple/protocols/openvpn/OpenVPN_UDP_tls-auth.pcapng).
        assert_eq!(
            extract_openvpn_opcode_and_key_id(&[0x38]),
            Ok((OpenVpnOpcode::ControlHardResetClientV2, 0))
        );
        // Synthetique : meme opcode avec key id 5 (0x38 | 0x05).
        assert_eq!(
            extract_openvpn_opcode_and_key_id(&[0x3d]),
            Ok((OpenVpnOpcode::ControlHardResetClientV2, 5))
        );
    }

    #[test]
    fn rejects_empty_and_unknown_opcodes() {
        assert_eq!(
            extract_openvpn_opcode_and_key_id(&[]),
            Err(OpenVpnError::EmptyPacket)
        );
        // Opcode 0 : jamais defini. L'erreur porte l'opcode 5 bits, pas
        // l'octet brut : 0x03 est l'opcode 0 avec key id 3.
        assert_eq!(
            extract_openvpn_opcode_and_key_id(&[0x03]),
            Err(OpenVpnError::UnknownOpcode { opcode: 0 })
        );
        // Opcode 12 : au-dela du dernier defini (P_CONTROL_WKC_V1 = 11).
        assert_eq!(
            extract_openvpn_opcode_and_key_id(&[0x60]),
            Err(OpenVpnError::UnknownOpcode { opcode: 12 })
        );
        // 0xFF : opcode 31.
        assert_eq!(
            extract_openvpn_opcode_and_key_id(&[0xff]),
            Err(OpenVpnError::UnknownOpcode { opcode: 31 })
        );
        // Opcode 11 (P_CONTROL_WKC_V1, OpenVPN 2.6) est desormais reconnu.
        assert_eq!(
            extract_openvpn_opcode_and_key_id(&[0x58]),
            Ok((OpenVpnOpcode::ControlWkcV1, 0))
        );
    }

    #[test]
    fn every_defined_opcode_round_trips_through_the_wire_byte() {
        for wire in 1u8..=10 {
            let byte = wire << 3;
            let (opcode, key_id) =
                extract_openvpn_opcode_and_key_id(&[byte]).expect("defined opcode");
            assert_eq!(opcode as u8, wire);
            assert_eq!(key_id, 0);
        }
    }

    #[test]
    fn validates_per_opcode_minimum_lengths() {
        assert_eq!(
            validate_openvpn_length(OpenVpnOpcode::ControlV1, OPENVPN_CONTROL_MIN_LEN),
            Ok(())
        );
        assert_eq!(
            validate_openvpn_length(OpenVpnOpcode::ControlV1, OPENVPN_CONTROL_MIN_LEN - 1),
            Err(OpenVpnError::TooShort {
                expected: OPENVPN_CONTROL_MIN_LEN,
                actual: OPENVPN_CONTROL_MIN_LEN - 1
            })
        );
        assert_eq!(
            validate_openvpn_length(OpenVpnOpcode::AckV1, OPENVPN_ACK_MIN_LEN - 1),
            Err(OpenVpnError::TooShort {
                expected: OPENVPN_ACK_MIN_LEN,
                actual: OPENVPN_ACK_MIN_LEN - 1
            })
        );
        assert_eq!(
            validate_openvpn_length(OpenVpnOpcode::DataV1, OPENVPN_DATA_V1_MIN_LEN),
            Ok(())
        );
        assert_eq!(
            validate_openvpn_length(OpenVpnOpcode::DataV2, OPENVPN_DATA_V2_MIN_LEN - 1),
            Err(OpenVpnError::TooShort {
                expected: OPENVPN_DATA_V2_MIN_LEN,
                actual: OPENVPN_DATA_V2_MIN_LEN - 1
            })
        );
    }

    #[test]
    fn bounds_resets_but_not_control_or_data() {
        assert_eq!(
            validate_openvpn_length(
                OpenVpnOpcode::ControlHardResetClientV2,
                OPENVPN_RESET_MAX_LEN + 1
            ),
            Err(OpenVpnError::ResetTooLong {
                max: OPENVPN_RESET_MAX_LEN,
                actual: OPENVPN_RESET_MAX_LEN + 1
            })
        );
        assert_eq!(
            validate_openvpn_length(OpenVpnOpcode::ControlSoftResetV1, OPENVPN_RESET_MAX_LEN),
            Ok(())
        );
        // Un P_CONTROL_V1 transporte le handshake TLS : pas de borne haute.
        assert_eq!(
            validate_openvpn_length(OpenVpnOpcode::ControlV1, 60_000),
            Ok(())
        );
        assert_eq!(
            validate_openvpn_length(OpenVpnOpcode::DataV1, 60_000),
            Ok(())
        );
    }

    #[test]
    fn hard_resets_must_carry_key_id_zero() {
        assert_eq!(
            validate_openvpn_hard_reset_key_id(OpenVpnOpcode::ControlHardResetClientV2, 0),
            Ok(())
        );
        assert_eq!(
            validate_openvpn_hard_reset_key_id(OpenVpnOpcode::ControlHardResetServerV1, 6),
            Err(OpenVpnError::HardResetWithNonZeroKeyId { key_id: 6 })
        );
        // Un soft reset est une renegociation : key id non nul legitime.
        assert_eq!(
            validate_openvpn_hard_reset_key_id(OpenVpnOpcode::ControlSoftResetV1, 1),
            Ok(())
        );
        // Le canal de donnees n'est pas concerne.
        assert_eq!(
            validate_openvpn_hard_reset_key_id(OpenVpnOpcode::DataV1, 3),
            Ok(())
        );
    }

    #[test]
    fn extracts_the_session_id_big_endian() {
        // Session id de la trame 1 du corpus UDP : 0x813814621d67462d.
        let after_opcode = [0x81, 0x38, 0x14, 0x62, 0x1d, 0x67, 0x46, 0x2d, 0xde];
        let (session_id, rest) = extract_openvpn_session_id(&after_opcode).expect("8 octets");
        assert_eq!(session_id, 9_311_214_641_221_158_445);
        assert_eq!(rest, &[0xde]);
    }

    #[test]
    fn session_id_extraction_rejects_truncation() {
        assert_eq!(
            extract_openvpn_session_id(&[0x01, 0x02]),
            Err(OpenVpnError::TooShort {
                expected: OPENVPN_SESSION_ID_LEN,
                actual: 2
            })
        );
    }

    #[test]
    fn extracts_the_24_bit_peer_id() {
        let (peer_id, rest) = extract_openvpn_peer_id(&[0x00, 0x00, 0x2a, 0xaa]).expect("3 octets");
        assert_eq!(peer_id, 42);
        assert_eq!(rest, &[0xaa]);
        assert_eq!(
            extract_openvpn_peer_id(&[0x00]),
            Err(OpenVpnError::TooShort {
                expected: OPENVPN_DATA_V2_PEER_ID_LEN,
                actual: 1
            })
        );
    }

    #[test]
    fn splits_tcp_records_on_their_length_prefix() {
        // Synthetique : deux enregistrements de 1 et 2 octets.
        let stream = [0x00, 0x01, 0xaa, 0x00, 0x02, 0xbb, 0xcc];
        let (first, rest) = read_openvpn_tcp_record(&stream).expect("premier enregistrement");
        assert_eq!(first, &[0xaa]);
        let (second, tail) = read_openvpn_tcp_record(rest).expect("second enregistrement");
        assert_eq!(second, &[0xbb, 0xcc]);
        assert!(tail.is_empty());
    }

    #[test]
    fn rejects_truncated_tcp_prefix_and_record() {
        assert_eq!(
            read_openvpn_tcp_record(&[0x00]),
            Err(OpenVpnError::TcpLengthMissing { actual: 1 })
        );
        assert_eq!(
            read_openvpn_tcp_record(&[0x00, 0x2a, 0x38]),
            Err(OpenVpnError::TcpRecordTruncated {
                declared: 42,
                available: 1
            })
        );
    }
}
