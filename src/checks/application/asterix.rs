// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use crate::errors::application::asterix::AsterixError;

/// En-tete d'un data block : CAT (1 octet) et LEN (2 octets, big-endian,
/// en-tete compris) — EUROCONTROL-SPEC-0149 Part 1, §5.1.
pub const ASTERIX_BLOCK_HEADER_LEN: usize = 3;

/// Plus petit data block decodable : en-tete, un octet de FSPEC et au moins
/// un octet de data item. Un LEN inferieur ne peut porter aucun record.
pub const ASTERIX_BLOCK_MIN_LEN: usize = ASTERIX_BLOCK_HEADER_LEN + 2;

/// Lit l'en-tete d'un data block et valide sa longueur declaree contre les
/// octets disponibles. Rend `(categorie, longueur totale du bloc)`.
pub fn read_block_header(buf: &[u8]) -> Result<(u8, usize), AsterixError> {
    if buf.len() < ASTERIX_BLOCK_HEADER_LEN {
        return Err(AsterixError::Truncated {
            needed: ASTERIX_BLOCK_HEADER_LEN,
            actual: buf.len(),
        });
    }
    let category = buf[0];
    let declared = u16::from_be_bytes([buf[1], buf[2]]);
    let length = usize::from(declared);
    if length < ASTERIX_BLOCK_MIN_LEN || length > buf.len() {
        return Err(AsterixError::InvalidBlockLength {
            category,
            declared,
            available: buf.len(),
        });
    }
    Ok((category, length))
}

/// Longueur d'un champ extensible : chaque octet porte un bit FX (bit 1)
/// qui annonce un octet de plus. Rend le nombre d'octets, `None` si le
/// buffer s'epuise avant un FX a zero.
pub fn fx_extent(buf: &[u8]) -> Option<usize> {
    buf.iter()
        .position(|octet| octet & 0x01 == 0)
        .map(|last| last + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_block_header_accepts_a_minimal_block() {
        assert_eq!(read_block_header(&[48, 0, 5, 0x80, 0x00]), Ok((48, 5)));
    }

    #[test]
    fn test_read_block_header_rejects_short_and_oversized_lengths() {
        assert_eq!(
            read_block_header(&[48, 0]),
            Err(AsterixError::Truncated {
                needed: 3,
                actual: 2
            })
        );
        // LEN 4 : pas de place pour FSPEC + item.
        assert_eq!(
            read_block_header(&[48, 0, 4, 0x80]),
            Err(AsterixError::InvalidBlockLength {
                category: 48,
                declared: 4,
                available: 4
            })
        );
        // LEN au-dela du buffer.
        assert_eq!(
            read_block_header(&[48, 0, 9, 0x80, 0x00]),
            Err(AsterixError::InvalidBlockLength {
                category: 48,
                declared: 9,
                available: 5
            })
        );
    }

    #[test]
    fn test_fx_extent() {
        assert_eq!(fx_extent(&[0x00]), Some(1));
        assert_eq!(fx_extent(&[0x01, 0x01, 0xfe, 0xff]), Some(3));
        assert_eq!(fx_extent(&[0x01, 0x01]), None);
        assert_eq!(fx_extent(&[]), None);
    }
}
