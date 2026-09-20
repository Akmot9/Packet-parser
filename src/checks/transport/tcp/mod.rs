// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use crate::errors::transport::tcp::TcpError;

const TCP_MIN_LENGTH: usize = 20;

pub fn validate_tcp_min_length(packet: &[u8]) -> Result<(), TcpError> {
    if packet.len() < TCP_MIN_LENGTH {
        return Err(TcpError::PacketTooShort);
    }
    Ok(())
}

pub fn validate_tcp_data_offset_words(data_offset_words: u8) -> Result<(), TcpError> {
    if !(5..=15).contains(&data_offset_words) {
        return Err(TcpError::InvalidDataOffset(data_offset_words));
    }
    Ok(())
}

pub fn validate_tcp_data_offset_available(
    packet_len: usize,
    data_offset: usize,
) -> Result<(), TcpError> {
    if packet_len < data_offset {
        return Err(TcpError::PacketTooShort);
    }
    Ok(())
}

/// Anomalie semantique, pas structurelle : l'en-tete reste lisible. Voir
/// `TcpPacket::anomaly`.
pub fn validate_tcp_reserved(reserved: u8) -> Result<(), TcpError> {
    if reserved != 0 {
        return Err(TcpError::ReservedBitsSet { bits: reserved });
    }
    Ok(())
}

/// Anomalie semantique, pas structurelle : l'en-tete reste lisible. Voir
/// `TcpPacket::anomaly`.
pub fn validate_tcp_flags(flags: u8) -> Result<(), TcpError> {
    if (flags & 0x03) == 0x03 {
        return Err(TcpError::InvalidFlags { flags });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn min_length_and_data_offset_bounds_are_enforced() {
        assert!(matches!(
            validate_tcp_min_length(&[0u8; 19]),
            Err(TcpError::PacketTooShort)
        ));
        assert!(validate_tcp_min_length(&[0u8; 20]).is_ok());

        assert!(matches!(
            validate_tcp_data_offset_words(4),
            Err(TcpError::InvalidDataOffset(4))
        ));
        assert!(validate_tcp_data_offset_words(5).is_ok());
        assert!(validate_tcp_data_offset_words(15).is_ok());

        assert!(matches!(
            validate_tcp_data_offset_available(20, 24),
            Err(TcpError::PacketTooShort)
        ));
        assert!(validate_tcp_data_offset_available(24, 24).is_ok());
    }

    /// Les bits reserves doivent etre nuls (RFC 9293 §3.1) ; l'erreur nomme
    /// le motif et porte les bits fautifs (#24).
    #[test]
    fn non_zero_reserved_bits_are_reported_with_their_value() {
        assert!(validate_tcp_reserved(0).is_ok());
        for reserved in [0x01, 0x02, 0x04, 0x07] {
            assert!(matches!(
                validate_tcp_reserved(reserved),
                Err(TcpError::ReservedBitsSet { bits }) if bits == reserved
            ));
        }
    }

    /// La combinaison d'evasion SYN+FIN est une anomalie nommee (#24). Elle
    /// ne fait plus disparaitre la couche transport : voir le test
    /// bout-en-bout de `parse/mod.rs`.
    #[test]
    fn syn_fin_combination_is_reported_with_the_flags_byte() {
        const SYN: u8 = 0x02;
        const FIN: u8 = 0x01;
        assert!(matches!(
            validate_tcp_flags(SYN | FIN),
            Err(TcpError::InvalidFlags { flags: 0x03 })
        ));
        assert!(matches!(
            validate_tcp_flags(SYN | FIN | 0x10),
            Err(TcpError::InvalidFlags { flags: 0x13 })
        ));
        // Chaque drapeau seul reste valide, y compris accompagne d'ACK/PSH.
        for flags in [SYN, FIN, SYN | 0x10, FIN | 0x10, 0x18] {
            assert!(validate_tcp_flags(flags).is_ok(), "flags {flags:#04x}");
        }
    }
}
