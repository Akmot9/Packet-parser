// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use crate::errors::transport::esp::EspError;

/// SPI et numero de sequence (RFC 4303 §2) ; tout ce qui suit est chiffre
/// ou authentifie, et sa structure depend de l'algorithme negocie.
pub const ESP_HEADER_SIZE: usize = 8;

pub fn validate_esp_min_length(data: &[u8]) -> Result<(), EspError> {
    if data.len() < ESP_HEADER_SIZE {
        return Err(EspError::PacketTooShort {
            expected: ESP_HEADER_SIZE,
            actual: data.len(),
        });
    }
    Ok(())
}

/// Le SPI zero est reserve (RFC 4303 §2.1) ; sur UDP 4500, quatre octets
/// nuls sont le marqueur non-ESP d'un message IKE (RFC 3948 §2.2).
pub fn validate_spi(spi: u32) -> Result<(), EspError> {
    if spi == 0 {
        return Err(EspError::ReservedSpi);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_esp_checks() {
        assert_eq!(validate_esp_min_length(&[0u8; 8]), Ok(()));
        assert_eq!(
            validate_esp_min_length(&[0u8; 7]),
            Err(EspError::PacketTooShort {
                expected: 8,
                actual: 7
            })
        );
        assert_eq!(validate_spi(0x5fbd_60dc), Ok(()));
        assert_eq!(validate_spi(0), Err(EspError::ReservedSpi));
    }
}
