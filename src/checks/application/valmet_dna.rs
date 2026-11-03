// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Constantes et controles du decodeur Valmet DNA. Le protocole est
//! proprietaire et sans specification publique : tout ici vient de
//! l'observation du trafic, voir
//! [`crate::parse::application::protocols::valmet_dna`].

use crate::errors::application::valmet_dna::ValmetDnaParseError;

/// Les deux premiers octets de chaque message : `AB 01`. Le groupe multicast
/// observe, 239.0.171.1, les porte aussi dans ses deux derniers octets.
pub const VALMET_DNA_MAGIC: u16 = 0xAB01;

/// Magie, noeud source, destination, longueur, famille de message.
pub const VALMET_DNA_HEADER_LENGTH: usize = 12;

/// La longueur declaree compte les octets qui suivent la magie : elle vaut
/// le datagramme moins deux.
pub const VALMET_DNA_LENGTH_EXCLUDES: usize = 2;

/// Famille `0x00000FFF` : le telegramme d'etat periodique, 126 octets.
pub const STATUS_KIND: u32 = 0x0000_0FFF;
pub const STATUS_TELEGRAM_LENGTH: usize = 126;
/// Offsets, depuis le debut du datagramme, des champs nommes du telegramme
/// d'etat : adresse IPv4 du noeud (celle de l'en-tete IP), horloge BCD,
/// numero du noeud (l'octet bas de son identifiant), groupe multicast, et
/// les deux compteurs de 32 bits (le second repete le premier du
/// telegramme precedent).
pub const STATUS_NODE_IP_OFFSET: usize = 36;
pub const STATUS_CLOCK_OFFSET: usize = 42;
pub const STATUS_NODE_NUMBER_OFFSET: usize = 58;
pub const STATUS_GROUP_OFFSET: usize = 70;
pub const STATUS_TICK_OFFSET: usize = 106;
pub const STATUS_PREVIOUS_TICK_OFFSET: usize = 110;

/// Famille `0x001E00D0` : le message a etiquette, un en-tete fixe de 72
/// octets puis l'etiquette, dont la longueur est ecrite deux fois (offsets
/// 28 et 70) et qui pave exactement le datagramme.
pub const TAG_KIND: u32 = 0x001E_00D0;
pub const TAG_MESSAGE_HEADER_LENGTH: usize = 72;
pub const TAG_LENGTH_OFFSET: usize = 28;
pub const TAG_LENGTH_ECHO_OFFSET: usize = 70;

/// La balise de 42 octets d'UDP 4516 -> 4517 : quatre octets nuls, `AB CC`,
/// un code, un compteur, puis l'horloge BCD (offset 28) et l'adresse IPv4 du
/// noeud (offset 38).
pub const BEACON_MAGIC: u16 = 0xABCC;
pub const BEACON_LENGTH: usize = 42;
pub const BEACON_CODE_OFFSET: usize = 6;
pub const BEACON_COUNTER_OFFSET: usize = 8;
pub const BEACON_CLOCK_OFFSET: usize = 28;
pub const BEACON_NODE_IP_OFFSET: usize = 38;

/// L'horloge BCD : dix octets.
pub const CLOCK_LENGTH: usize = 10;

pub fn ensure_len(buf: &[u8], needed: usize) -> Result<(), ValmetDnaParseError> {
    if buf.len() < needed {
        return Err(ValmetDnaParseError::Truncated {
            expected: needed,
            actual: buf.len(),
        });
    }
    Ok(())
}

/// Chaque message commence par `AB 01`.
pub fn validate_magic(magic: u16) -> Result<(), ValmetDnaParseError> {
    if magic != VALMET_DNA_MAGIC {
        return Err(ValmetDnaParseError::InvalidMagic(magic));
    }
    Ok(())
}

/// Longueur declaree : le datagramme moins deux, exactement — c'est, avec la
/// magie, ce qui permet de sonder a l'aveugle.
pub fn validate_length(declared: u16, actual: usize) -> Result<(), ValmetDnaParseError> {
    if usize::from(declared) + VALMET_DNA_LENGTH_EXCLUDES != actual {
        return Err(ValmetDnaParseError::LengthMismatch { declared, actual });
    }
    Ok(())
}

/// Un telegramme d'etat fait exactement 126 octets.
pub fn validate_status_length(actual: usize) -> Result<(), ValmetDnaParseError> {
    if actual != STATUS_TELEGRAM_LENGTH {
        return Err(ValmetDnaParseError::InvalidMessageLength {
            kind: STATUS_KIND,
            expected: STATUS_TELEGRAM_LENGTH,
            actual,
        });
    }
    Ok(())
}

/// L'etiquette : sa longueur est ecrite deux fois et, ajoutee a l'en-tete
/// fixe, donne exactement le datagramme. Rend la longueur de l'etiquette.
pub fn validate_tag_length(
    declared: u16,
    echo: u16,
    actual: usize,
) -> Result<usize, ValmetDnaParseError> {
    if declared != echo {
        return Err(ValmetDnaParseError::TagLengthMismatch { declared, echo });
    }
    let expected = TAG_MESSAGE_HEADER_LENGTH + usize::from(declared);
    if expected != actual {
        return Err(ValmetDnaParseError::InvalidMessageLength {
            kind: TAG_KIND,
            expected,
            actual,
        });
    }
    Ok(usize::from(declared))
}

/// La balise : 42 octets, quatre octets nuls, puis `AB CC`.
pub fn validate_beacon_frame(payload: &[u8]) -> Result<(), ValmetDnaParseError> {
    if payload.len() != BEACON_LENGTH {
        return Err(ValmetDnaParseError::InvalidBeaconLength {
            actual: payload.len(),
        });
    }
    let prefix = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    if prefix != 0 {
        return Err(ValmetDnaParseError::InvalidBeaconPrefix(prefix));
    }
    let magic = u16::from_be_bytes([payload[4], payload[5]]);
    if magic != BEACON_MAGIC {
        return Err(ValmetDnaParseError::InvalidBeaconMagic(magic));
    }
    Ok(())
}

/// Un octet BCD : deux chiffres decimaux, `None` si un quartet depasse 9.
pub fn bcd(byte: u8) -> Option<u8> {
    let (high, low) = (byte >> 4, byte & 0x0F);
    (high <= 9 && low <= 9).then(|| high * 10 + low)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valmet_dna_checks() {
        assert_eq!(validate_magic(0xAB01), Ok(()));
        assert_eq!(
            validate_magic(0xAB02),
            Err(ValmetDnaParseError::InvalidMagic(0xAB02))
        );
        assert_eq!(validate_length(124, 126), Ok(()));
        assert_eq!(
            validate_length(126, 126),
            Err(ValmetDnaParseError::LengthMismatch {
                declared: 126,
                actual: 126
            })
        );
        assert_eq!(validate_status_length(126), Ok(()));
        assert_eq!(
            validate_status_length(125),
            Err(ValmetDnaParseError::InvalidMessageLength {
                kind: STATUS_KIND,
                expected: 126,
                actual: 125
            })
        );
        assert_eq!(validate_tag_length(43, 43, 115), Ok(43));
        assert_eq!(validate_tag_length(0, 0, 72), Ok(0));
        assert_eq!(
            validate_tag_length(43, 42, 115),
            Err(ValmetDnaParseError::TagLengthMismatch {
                declared: 43,
                echo: 42
            })
        );
        assert_eq!(
            validate_tag_length(43, 43, 116),
            Err(ValmetDnaParseError::InvalidMessageLength {
                kind: TAG_KIND,
                expected: 115,
                actual: 116
            })
        );
        let mut beacon = vec![0, 0, 0, 0, 0xAB, 0xCC];
        beacon.resize(BEACON_LENGTH, 0);
        assert_eq!(validate_beacon_frame(&beacon), Ok(()));
        assert_eq!(
            validate_beacon_frame(&beacon[..41]),
            Err(ValmetDnaParseError::InvalidBeaconLength { actual: 41 })
        );
        beacon[5] = 0xCD;
        assert_eq!(
            validate_beacon_frame(&beacon),
            Err(ValmetDnaParseError::InvalidBeaconMagic(0xABCD))
        );
        beacon[3] = 1;
        assert_eq!(
            validate_beacon_frame(&beacon),
            Err(ValmetDnaParseError::InvalidBeaconPrefix(1))
        );
        assert_eq!(bcd(0x00), Some(0));
        assert_eq!(bcd(0x59), Some(59));
        assert_eq!(bcd(0x99), Some(99));
        assert_eq!(bcd(0x5A), None);
        assert_eq!(bcd(0xA5), None);
        assert_eq!(bcd(0xFF), None);
    }
}
