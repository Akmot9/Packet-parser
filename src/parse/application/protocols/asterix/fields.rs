// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Champs partages par plusieurs categories : leur codage est fixe par la
//! Part 1 et repris a l'identique dans les UAP (identifiant de source,
//! temps, code Mode 3/A, niveau de vol, adresse et identification aeronef).
//!
//! Chaque type garde la valeur telle qu'elle est sur le wire et expose sa
//! conversion en unites physiques a cote, jamais a la place : la valeur brute
//! est ce qu'un test recoupe avec tshark, la conversion est un confort.

use core::fmt;

/// Identifiant de la source de donnees : System Area Code et System
/// Identification Code (I0xx/010).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct DataSourceIdentifier {
    pub sac: u8,
    pub sic: u8,
}

impl DataSourceIdentifier {
    pub(crate) fn from_item(data: &[u8]) -> Option<Self> {
        match data {
            [sac, sic] => Some(Self {
                sac: *sac,
                sic: *sic,
            }),
            _ => None,
        }
    }
}

/// Temps en secondes depuis minuit UTC, LSB 1/128 s sur 3 octets
/// (I048/140, I034/030, I021/071, I021/073 ...).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct TimeOfDay {
    /// Valeur brute, en 1/128 s.
    pub raw: u32,
}

impl TimeOfDay {
    pub(crate) fn from_item(data: &[u8]) -> Option<Self> {
        match data {
            [a, b, c] => Some(Self {
                raw: u32::from_be_bytes([0, *a, *b, *c]),
            }),
            _ => None,
        }
    }

    pub fn seconds(self) -> f64 {
        f64::from(self.raw) / 128.0
    }
}

/// Code Mode 3/A en representation octale (I048/070, I021/070) : les douze
/// bits A4 A2 A1 B4 B2 B1 C4 C2 C1 D4 D2 D1, precedes des indicateurs de
/// validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Mode3ACode {
    /// V = 0 : code valide.
    pub validated: bool,
    /// G = 1 : code brouille (garbled).
    pub garbled: bool,
    /// L = 1 : code lisse par le pisteur, pas lu dans la reponse.
    pub smoothed: bool,
    /// Les douze bits, tels quels : `0o1000` pour le code 1000.
    pub code: u16,
}

impl Mode3ACode {
    pub(crate) fn from_item(data: &[u8]) -> Option<Self> {
        match data {
            [high, low] => Some(Self {
                validated: high & 0x80 == 0,
                garbled: high & 0x40 != 0,
                smoothed: high & 0x20 != 0,
                code: u16::from_be_bytes([high & 0x0f, *low]),
            }),
            _ => None,
        }
    }
}

impl fmt::Display for Mode3ACode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04o}", self.code)
    }
}

/// Niveau de vol en representation binaire (I048/090, I021/145) : LSB 1/4
/// FL sur 14 bits signes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct FlightLevel {
    pub validated: bool,
    pub garbled: bool,
    /// Valeur brute, en quarts de niveau de vol.
    pub quarter_levels: i16,
}

impl FlightLevel {
    pub(crate) fn from_item(data: &[u8]) -> Option<Self> {
        match data {
            [high, low] => Some(Self {
                validated: high & 0x80 == 0,
                garbled: high & 0x40 != 0,
                quarter_levels: sign_extend_14(u16::from_be_bytes([high & 0x3f, *low])),
            }),
            _ => None,
        }
    }

    pub fn flight_level(self) -> f64 {
        f64::from(self.quarter_levels) / 4.0
    }
}

/// Adresse ICAO 24 bits d'un aeronef (I048/220, I021/080).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AircraftAddress(pub u32);

impl AircraftAddress {
    pub(crate) fn from_item(data: &[u8]) -> Option<Self> {
        match data {
            [a, b, c] => Some(Self(u32::from_be_bytes([0, *a, *b, *c]))),
            _ => None,
        }
    }
}

impl fmt::Display for AircraftAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:06X}", self.0)
    }
}

/// Identification aeronef sur huit caracteres (I048/240, I021/170) :
/// six octets de caracteres 6 bits, alphabet de l'Annexe 10 de l'OACI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct AircraftIdentification {
    /// Les huit caracteres, en ASCII ; `?` pour un code hors alphabet.
    pub chars: [u8; 8],
}

impl AircraftIdentification {
    pub(crate) fn from_item(data: &[u8]) -> Option<Self> {
        let octets: [u8; 6] = data.try_into().ok()?;
        let packed = u64::from_be_bytes([
            0, 0, octets[0], octets[1], octets[2], octets[3], octets[4], octets[5],
        ]);
        let mut chars = [b'?'; 8];
        for (index, slot) in chars.iter_mut().enumerate() {
            let shift = 42 - 6 * index;
            *slot = icao_char(((packed >> shift) & 0x3f) as u8);
        }
        Some(Self { chars })
    }

    /// Les huit caracteres, espaces de bourrage compris.
    pub fn as_str(&self) -> &str {
        // Construit par `icao_char`, qui ne rend que de l'ASCII.
        core::str::from_utf8(&self.chars).unwrap_or("????????")
    }

    /// L'identification sans les espaces de bourrage.
    pub fn trimmed(&self) -> &str {
        self.as_str().trim_end_matches(' ')
    }
}

impl fmt::Display for AircraftIdentification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.trimmed())
    }
}

/// Alphabet 6 bits de l'OACI (Annexe 10, Vol. IV, §3.1.2.9) : 1 a 26 pour
/// A a Z, 32 pour l'espace, 48 a 57 pour les chiffres. Le reste est
/// indefini.
fn icao_char(code: u8) -> u8 {
    match code {
        1..=26 => b'A' + code - 1,
        32 => b' ',
        48..=57 => b'0' + code - 48,
        _ => b'?',
    }
}

/// Numero de piste sur douze bits (I048/161, I021/161).
pub(crate) fn track_number(data: &[u8]) -> Option<u16> {
    match data {
        [high, low] => Some(u16::from_be_bytes([high & 0x0f, *low])),
        _ => None,
    }
}

/// Etend le signe d'une valeur sur 14 bits.
pub(crate) fn sign_extend_14(value: u16) -> i16 {
    // Decalage a gauche de deux bits, puis droite arithmetique : l'entier
    // est reinterprete, aucune operation ne deborde.
    ((value << 2) as i16) >> 2
}

/// Etend le signe d'une valeur sur 24 bits.
pub(crate) fn sign_extend_24(value: u32) -> i32 {
    ((value << 8) as i32) >> 8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_of_day_lsb_is_1_128th_of_a_second() {
        let time = TimeOfDay::from_item(&[0x38, 0x41, 0x76]).unwrap();
        assert_eq!(time.raw, 3_686_774);
        assert_eq!(time.seconds(), 28_802.921_875);
        assert_eq!(TimeOfDay::from_item(&[0, 0]), None);
    }

    #[test]
    fn test_mode_3a_code_is_read_in_octal() {
        let code = Mode3ACode::from_item(&[0x02, 0x00]).unwrap();
        assert_eq!(code.code, 0o1000);
        assert_eq!(code.to_string(), "1000");
        assert!(code.validated && !code.garbled && !code.smoothed);

        let flagged = Mode3ACode::from_item(&[0xef, 0xff]).unwrap();
        assert!(!flagged.validated && flagged.garbled && flagged.smoothed);
        assert_eq!(flagged.to_string(), "7777");
    }

    #[test]
    fn test_flight_level_is_signed_quarter_levels() {
        let level = FlightLevel::from_item(&[0x05, 0x28]).unwrap();
        assert_eq!(level.quarter_levels, 1320);
        assert_eq!(level.flight_level(), 330.0);
        // -1/4 FL : les quatorze bits a un.
        let below = FlightLevel::from_item(&[0x3f, 0xff]).unwrap();
        assert_eq!(below.quarter_levels, -1);
        assert_eq!(
            FlightLevel::from_item(&[0xc0, 0x00])
                .unwrap()
                .quarter_levels,
            0
        );
    }

    #[test]
    fn test_aircraft_identification_decodes_the_icao_alphabet() {
        // "DLH65A  " — trame cat048.raw des echantillons CroatiaControlLtd.
        let ident =
            AircraftIdentification::from_item(&[0x10, 0xc2, 0x36, 0xd4, 0x18, 0x20]).unwrap();
        assert_eq!(ident.as_str(), "DLH65A  ");
        assert_eq!(ident.trimmed(), "DLH65A");
        assert_eq!(ident.to_string(), "DLH65A");
        // Un code hors alphabet (0) sort en `?`.
        let odd = AircraftIdentification::from_item(&[0; 6]).unwrap();
        assert_eq!(odd.as_str(), "????????");
        assert_eq!(AircraftIdentification::from_item(&[0; 5]), None);
    }

    #[test]
    fn test_aircraft_address_displays_six_hex_digits() {
        let address = AircraftAddress::from_item(&[0x3c, 0x66, 0x0c]).unwrap();
        assert_eq!(address.0, 0x3c660c);
        assert_eq!(address.to_string(), "3C660C");
    }

    #[test]
    fn test_sign_extension() {
        assert_eq!(sign_extend_14(0x2000), -8192);
        assert_eq!(sign_extend_14(0x1fff), 8191);
        assert_eq!(sign_extend_24(0xfa65ba), -367_174);
        assert_eq!(sign_extend_24(0x2bb73e), 2_864_958);
    }

    #[test]
    fn test_track_number_uses_twelve_bits() {
        assert_eq!(track_number(&[0xfd, 0xeb]), Some(3563));
        assert_eq!(track_number(&[0x00]), None);
    }
}
