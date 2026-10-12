// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use crate::errors::application::dnp3::Dnp3ParseError;

/// Octets de depart de toute trame de liaison (IEEE 1815-2012 §9.2.4.1).
pub const DNP3_START_BYTES: [u8; 2] = [0x05, 0x64];

/// En-tete de liaison : depart, longueur, controle, destination, source,
/// CRC — dix octets.
pub const DNP3_LINK_HEADER_LENGTH: usize = 10;

/// Les huit octets de l'en-tete couverts par son CRC.
pub const DNP3_LINK_HEADER_CRC_SPAN: usize = 8;

/// LENGTH compte le controle et les deux adresses, hors CRC.
pub const DNP3_LINK_LENGTH_MIN: u8 = 5;

/// Les donnees utilisateur vont par blocs de seize octets, chacun suivi de
/// son CRC.
pub const DNP3_BLOCK_LENGTH: usize = 16;
pub const DNP3_CRC_LENGTH: usize = 2;

/// En-tete applicatif d'une requete : controle et code de fonction.
pub const DNP3_APPLICATION_HEADER_LENGTH: usize = 2;
/// Les reponses ajoutent deux octets d'indications internes (IIN).
pub const DNP3_APPLICATION_RESPONSE_HEADER_LENGTH: usize = 4;

/// Codes de fonction applicatifs des reponses (§4.2.2.7).
pub const DNP3_FUNCTION_RESPONSE: u8 = 0x81;
pub const DNP3_FUNCTION_UNSOLICITED_RESPONSE: u8 = 0x82;
pub const DNP3_FUNCTION_AUTHENTICATION_RESPONSE: u8 = 0x83;

/// Polynome 0x3D65 renverse : CRC-16/DNP, resultat complemente.
const DNP3_CRC_POLYNOMIAL_REFLECTED: u16 = 0xA6BC;

const fn crc_table() -> [u16; 256] {
    let mut table = [0u16; 256];
    let mut index = 0;
    while index < 256 {
        let mut crc = index as u16;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ DNP3_CRC_POLYNOMIAL_REFLECTED
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[index] = crc;
        index += 1;
    }
    table
}

const DNP3_CRC_TABLE: [u16; 256] = crc_table();

/// CRC-16/DNP (IEEE 1815-2012 §9.2.4.2) : polynome 0x3D65, reflechi,
/// complemente, transmis octet de poids faible en tete.
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        crc = (crc >> 8) ^ DNP3_CRC_TABLE[usize::from((crc ^ u16::from(byte)) & 0xff)];
    }
    !crc
}

pub fn ensure_len(buf: &[u8], needed: usize) -> Result<(), Dnp3ParseError> {
    if buf.len() < needed {
        return Err(Dnp3ParseError::Truncated {
            expected: needed,
            actual: buf.len(),
        });
    }
    Ok(())
}

pub fn validate_start_bytes(bytes: [u8; 2]) -> Result<(), Dnp3ParseError> {
    if bytes != DNP3_START_BYTES {
        return Err(Dnp3ParseError::InvalidStartBytes(bytes));
    }
    Ok(())
}

/// LENGTH, et le nombre d'octets de donnees utilisateur qu'il annonce.
pub fn extract_length(byte: u8) -> Result<(u8, usize), Dnp3ParseError> {
    if byte < DNP3_LINK_LENGTH_MIN {
        return Err(Dnp3ParseError::InvalidLength(byte));
    }
    Ok((byte, usize::from(byte - DNP3_LINK_LENGTH_MIN)))
}

/// Longueur sur le fil d'une trame dont les donnees utilisateur font
/// `user_len` octets : l'en-tete, puis un CRC tous les seize octets.
pub fn link_frame_wire_length(user_len: usize) -> usize {
    DNP3_LINK_HEADER_LENGTH + user_len + user_len.div_ceil(DNP3_BLOCK_LENGTH) * DNP3_CRC_LENGTH
}

pub fn validate_header_crc(header: &[u8], actual: u16) -> Result<(), Dnp3ParseError> {
    let expected = crc16(&header[..DNP3_LINK_HEADER_CRC_SPAN]);
    if expected != actual {
        return Err(Dnp3ParseError::HeaderCrcMismatch { expected, actual });
    }
    Ok(())
}

pub fn validate_block_crc(block: usize, data: &[u8], actual: u16) -> Result<(), Dnp3ParseError> {
    let expected = crc16(data);
    if expected != actual {
        return Err(Dnp3ParseError::BlockCrcMismatch {
            block,
            expected,
            actual,
        });
    }
    Ok(())
}

/// Taille d'un objet selon son groupe et sa variation (IEEE 1815-2012
/// annexe A), ce qui permet de passer d'un en-tete d'objets au suivant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ObjectSize {
    /// Objets a taille fixe, en octets.
    Bytes(usize),
    /// Objets tasses bit a bit (entrees binaires, indications internes).
    Bits(u8),
    /// Taille portee par le prefixe de taille du qualificatif (fichiers,
    /// jeux de donnees, authentification).
    Prefixed,
    /// Aucune donnee : objets de classe, variation 0 d'une requete.
    None,
}

/// IEEE 1815-2012 annexe A : les groupes courants de la norme. `None` quand
/// le couple est inconnu — le decodeur s'arrete alors sur cet en-tete.
pub fn object_size(group: u8, variation: u8) -> Option<ObjectSize> {
    use ObjectSize::{Bits, Bytes, Prefixed};
    Some(match (group, variation) {
        // Entrees binaires, sorties binaires, indications internes.
        (1 | 10, 1) | (12, 3) | (80, 1) => Bits(1),
        (3, 1) => Bits(2),
        (1 | 3 | 10, 2) | (2 | 4 | 11 | 13, 1) => Bytes(1),
        (2 | 4 | 11 | 13, 2) => Bytes(7),
        (2 | 4, 3) => Bytes(3),
        // Commandes binaires : CROB et PCB.
        (12, 1 | 2) => Bytes(11),
        // Compteurs, compteurs geles et leurs evenements.
        (20..=23, 1 | 3) => Bytes(5),
        (20..=23, 2 | 4) => Bytes(3),
        (20, 5 | 7) | (21, 9 | 11) => Bytes(4),
        (20, 6 | 8) | (21, 10 | 12) => Bytes(2),
        (21..=23, 5 | 7) => Bytes(11),
        (21..=23, 6 | 8) => Bytes(9),
        // Entrees analogiques, gelees, evenements, bandes mortes.
        (30, 1 | 5) | (31, 1 | 7) | (40 | 41, 1 | 3) => Bytes(5),
        (30 | 31 | 40 | 41, 2) => Bytes(3),
        (30, 3) | (31, 5) | (34, 2 | 3) => Bytes(4),
        (30, 4) | (31, 6) | (34, 1) => Bytes(2),
        (30, 6) | (31, 4 | 8) | (40 | 41, 4) => Bytes(9),
        (31, 3) => Bytes(11),
        (32..=33 | 42..=43, 1 | 5) => Bytes(5),
        (32..=33 | 42..=43, 2) => Bytes(3),
        (32..=33 | 42..=43, 3 | 7) => Bytes(11),
        (32..=33 | 42..=43, 4 | 6) => Bytes(9),
        (32..=33 | 42..=43, 8) => Bytes(15),
        // Temps et delais.
        (50, 1 | 3) | (51, 1 | 2) => Bytes(6),
        (50, 2) => Bytes(10),
        (50, 4) => Bytes(11),
        (52, 1 | 2) => Bytes(2),
        // Donnees de classe : des en-tetes sans objet.
        (60, 1..=4) => ObjectSize::None,
        // Fichiers, profils, jeux de donnees, authentification : taille dans
        // le prefixe du qualificatif.
        (70, 1..=8) | (82 | 83 | 85 | 86 | 87 | 88 | 90 | 91 | 120, _) => Prefixed,
        (81, 1) => Bytes(3),
        (101, 1) => Bytes(2),
        (101, 2) => Bytes(4),
        (101, 3) => Bytes(8),
        (102, 1) => Bytes(1),
        // Chaines d'octets et terminal virtuel : la variation est la taille.
        (110..=113, size) => Bytes(usize::from(size)),
        _ => return None,
    })
}

/// Les fonctions dont les en-tetes d'objets ne sont suivis d'aucune
/// donnee (§4.2.2.7) : lectures, confirmations, gels immediats,
/// redemarrages, messages non sollicites, mesures de delai, assignation de
/// classe, horodatage. Exception, traitee par le decodeur : un objet
/// prefixe par sa taille porte toujours ses donnees, meme dans une lecture.
pub fn function_carries_object_data(function_code: u8) -> bool {
    !matches!(
        function_code,
        0 | 1 | 7..=10 | 13 | 14 | 20 | 21 | 22 | 23 | 24
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// pcaps_exemple/protocols/dnp3/dnp3_read.pcap, trame 4 : en-tete
    /// `05 64 14 c4 02 00 03 00`, CRC 0x0345 selon tshark.
    #[test]
    fn test_crc16_matches_tshark() {
        assert_eq!(
            crc16(&[0x05, 0x64, 0x14, 0xc4, 0x02, 0x00, 0x03, 0x00]),
            0x0345
        );
        // Bloc de donnees de la meme trame, CRC 0xac42.
        assert_eq!(
            crc16(&[
                0xc7, 0xc8, 0x01, 0x3c, 0x02, 0x06, 0x3c, 0x03, 0x06, 0x3c, 0x04, 0x06, 0x3c, 0x01,
                0x06
            ]),
            0xac42
        );
        assert_eq!(
            validate_header_crc(&[0x05, 0x64, 0x14, 0xc4, 0x02, 0x00, 0x03, 0x00], 0x0345),
            Ok(())
        );
        assert_eq!(
            validate_header_crc(&[0x05, 0x64, 0x14, 0xc4, 0x02, 0x00, 0x03, 0x00], 0x0346),
            Err(Dnp3ParseError::HeaderCrcMismatch {
                expected: 0x0345,
                actual: 0x0346
            })
        );
    }

    #[test]
    fn test_lengths_and_sizes() {
        assert_eq!(extract_length(5), Ok((5, 0)));
        assert_eq!(extract_length(20), Ok((20, 15)));
        assert_eq!(extract_length(4), Err(Dnp3ParseError::InvalidLength(4)));
        assert_eq!(link_frame_wire_length(0), 10);
        assert_eq!(link_frame_wire_length(15), 27);
        assert_eq!(link_frame_wire_length(16), 28);
        assert_eq!(link_frame_wire_length(17), 31);
        assert_eq!(link_frame_wire_length(250), 10 + 250 + 32);
        assert_eq!(validate_start_bytes([0x05, 0x64]), Ok(()));
        assert_eq!(
            validate_start_bytes([0x05, 0x65]),
            Err(Dnp3ParseError::InvalidStartBytes([0x05, 0x65]))
        );
        assert_eq!(object_size(1, 1), Some(ObjectSize::Bits(1)));
        assert_eq!(object_size(12, 1), Some(ObjectSize::Bytes(11)));
        assert_eq!(object_size(30, 3), Some(ObjectSize::Bytes(4)));
        assert_eq!(object_size(30, 5), Some(ObjectSize::Bytes(5)));
        assert_eq!(object_size(40, 3), Some(ObjectSize::Bytes(5)));
        assert_eq!(object_size(60, 2), Some(ObjectSize::None));
        assert_eq!(object_size(70, 5), Some(ObjectSize::Prefixed));
        assert_eq!(object_size(110, 7), Some(ObjectSize::Bytes(7)));
        assert_eq!(object_size(255, 0), None);
        assert!(!function_carries_object_data(1));
        assert!(function_carries_object_data(2));
        assert!(function_carries_object_data(0x81));
    }
}
