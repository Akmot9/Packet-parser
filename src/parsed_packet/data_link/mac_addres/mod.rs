use core::fmt;
use std::{
    convert::TryFrom,
    fmt::{Display, Formatter},
};
use oui::*;
use thiserror::Error;
use serde::{Serialize, Deserialize};

mod oui;

const MAC_LEN: usize = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MacAddress([u8; MAC_LEN]);


impl TryFrom<&[u8]> for MacAddress {
    type Error = MacParseError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        validate_mac_length(bytes)?;
        let mut addr = [0u8; MAC_LEN];
        addr.copy_from_slice(bytes);
        Ok(Self(addr))
    }
}

fn validate_mac_length(packets: &[u8]) -> Result<(), MacParseError> {
    if packets.len() != MAC_LEN {
        return Err(MacParseError::InvalidLength {
            actual: packets.len(),
        });
    }
    Ok(())
}

#[derive(Error, Debug, PartialEq, Eq, Clone, Copy)]
pub enum MacParseError {
    #[error("Invalid MAC address length: expected 6 bytes, found {actual} bytes")]
    InvalidLength { actual: usize },
}

impl Display for MacAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl MacAddress {
    pub fn get_oui(&self) -> Oui {
        Oui::from_bytes(&self.0[0..3])
    }
    
    pub fn display_with_oui(&self) -> String {
        match self.get_oui() {
            Oui::Unknown => format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
            ),
            oui => format!(
                "{:?}:{:02x}:{:02x}:{:02x}",
                oui, self.0[3], self.0[4], self.0[5]
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_mac_address_with_known_oui() {
        // Adresse MAC avec OUI correspondant à ASUSTek
        let bytes = [0x2C, 0xFD, 0xA1, 0x3C, 0x4D, 0x5E];
        let mac = MacAddress::try_from(&bytes[..]).expect("Conversion should succeed");

        // Affichage attendu : "ASUSTek:3c:4d:5e"
        assert_eq!(mac.display_with_oui(), "ASUSTek:3c:4d:5e");
    }

    #[test]
    fn display_mac_address_with_unknown_oui() {
        // Adresse MAC avec OUI inconnu
        let bytes = [0xAA, 0xBB, 0xCC, 0x3C, 0x4D, 0x5E];
        let mac = MacAddress::try_from(&bytes[..]).expect("Conversion should succeed");

        // Affichage attendu : "aa:bb:cc:3c:4d:5e"
        assert_eq!(mac.display_with_oui(), "aa:bb:cc:3c:4d:5e");
    }

    #[test]
    fn valid_mac_address_conversion() {
        // Tableau de bytes représentant une adresse MAC valide
        let bytes = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
        let mac = MacAddress::try_from(&bytes[..]).expect("Conversion should succeed");

        // Vérification de l'égalité entre l'adresse MAC et le tableau d'origine
        assert_eq!(mac, MacAddress([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]));
    }

    #[test]
    fn invalid_mac_address_length() {
        // Tableau de bytes de taille incorrecte (5 bytes)
        let bytes = [0x00, 0x1A, 0x2B, 0x3C, 0x4D];
        let result = MacAddress::try_from(&bytes[..]);

        // Vérification que l'erreur retournée correspond à InvalidLength avec la taille effective
        assert_eq!(
            result,
            Err(MacParseError::InvalidLength { actual: bytes.len() })
        );
    }

    #[test]
    fn display_mac_address_format() {
        // Adresse MAC valide pour tester le format d'affichage
        let mac = MacAddress([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]);

        // Vérification de l'affichage formaté
        assert_eq!(mac.to_string(), "00:1a:2b:3c:4d:5e");
    }

    #[test]
    fn valid_mac_address_conversion_all_zeros() {
        // Adresse MAC avec tous les octets à zéro
        let bytes = [0x00; 6];
        let mac = MacAddress::try_from(&bytes[..]).expect("Conversion should succeed");

        // Vérification de l'égalité entre l'adresse MAC et le tableau d'origine
        assert_eq!(mac, MacAddress([0x00; 6]));
    }

    #[test]
    fn invalid_mac_address_format_too_long() {
        // Tableau de bytes de taille incorrecte (7 bytes)
        let bytes = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F];
        let result = MacAddress::try_from(&bytes[..]);

        // Vérification que l'erreur retournée correspond à InvalidLength avec la taille effective
        assert_eq!(
            result,
            Err(MacParseError::InvalidLength { actual: bytes.len() })
        );
    }
}
