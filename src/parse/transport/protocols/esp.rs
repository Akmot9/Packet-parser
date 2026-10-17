// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! ESP, Encapsulating Security Payload (RFC 4303) : le paquet IPsec qui
//! chiffre et authentifie. Seuls le SPI et le numero de sequence ont une
//! place fixe ; tout ce qui suit — vecteur d'initialisation, donnees,
//! bourrage, en-tete suivant, ICV — depend de l'algorithme negocie par IKE
//! et reste des octets. Quand la confidentialite est retenue, le chiffre ne
//! couvre que les donnees et le trailer (bourrage, sa longueur, en-tete
//! suivant) : le vecteur d'initialisation, en general, et l'ICV circulent en
//! clair (RFC 4303 §2, §2.3 et §2.8), mais seule l'association de securite
//! en donne la taille. Porte par le protocole IP 50 (`TransportDetails::Esp`),
//! ou par UDP 4500 derriere un NAT (RFC 3948, voir `ike::UdpEncapsulation`).

use std::convert::TryFrom;

use crate::{
    checks::transport::esp::{ESP_HEADER_SIZE, validate_esp_min_length, validate_spi},
    errors::transport::esp::EspError,
};

/// Paquet ESP (RFC 4303 §2).
///
/// ```mermaid
/// ---
/// title: EspPacket
/// ---
/// packet-beta
/// 0-31: "Security Parameters Index (SPI) u32"
/// 32-63: "Sequence Number u32"
/// 64-127: "IV (clair), Payload Data, Padding, Pad Length, Next Header (chiffres), ICV (clair)"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct EspPacket<'a> {
    /// Identifie l'association de securite avec l'adresse de destination.
    pub spi: u32,
    /// Compteur anti-rejeu, croissant par association.
    pub sequence: u32,
    /// Tout ce qui suit le numero de sequence : IV eventuel, donnees,
    /// bourrage, longueur du bourrage, en-tete suivant et ICV eventuel, que
    /// seule l'association de securite permet de decouper.
    pub payload: &'a [u8],
}

impl<'a> TryFrom<&'a [u8]> for EspPacket<'a> {
    type Error = EspError;

    fn try_from(data: &'a [u8]) -> Result<Self, Self::Error> {
        validate_esp_min_length(data)?;
        let spi = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        validate_spi(spi)?;
        Ok(EspPacket {
            spi,
            sequence: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            payload: &data[ESP_HEADER_SIZE..],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// pcaps_exemple/protocols/ipsec/ikev2_s2s_ipsec_vpn_aes_gcm.pcapng,
    /// trame 5 : ESP natif (protocole IP 50), SPI 0x5fbd60dc, sequence 1,
    /// AES-GCM (tshark 4.6.6).
    const NATIVE_ESP: &str = concat!(
        "5fbd60dc000000010000000000000001fe32d6d07bb84c7f20c1b8d9f81965bf",
        "648259aea99a61b0727baa0e95e33b1e2d3ec2598d60151077c0de2712074890",
        "90d2eba6921d31ef30b2eb24189bb5fff2cb057e5835e9cb4d27f7f9bcea4ffd",
        "6581f0009065848457c9a8a2756672a8d2002f334d61675a"
    );

    #[test]
    fn test_decodes_a_native_esp_packet_against_tshark() {
        let bytes = hex::decode(NATIVE_ESP).unwrap();
        assert_eq!(bytes.len(), 120);
        let esp = EspPacket::try_from(bytes.as_slice()).expect("ESP");
        assert_eq!(esp.spi, 0x5fbd_60dc);
        assert_eq!(esp.sequence, 1);
        assert_eq!(esp.payload.len(), 112);
        assert!(bytes.as_ptr_range().contains(&esp.payload.as_ptr()));
    }

    #[test]
    fn test_rejects_short_packets_and_the_reserved_spi() {
        let bytes = hex::decode(NATIVE_ESP).unwrap();
        assert_eq!(
            EspPacket::try_from(&bytes[..7]),
            Err(EspError::PacketTooShort {
                expected: 8,
                actual: 7
            })
        );
        let mut zero = bytes.clone();
        zero[..4].copy_from_slice(&[0, 0, 0, 0]);
        assert_eq!(
            EspPacket::try_from(zero.as_slice()),
            Err(EspError::ReservedSpi)
        );
        // Huit octets suffisent : SPI et sequence, rien derriere.
        let minimal = EspPacket::try_from(&bytes[..8]).expect("en-tete seul");
        assert_eq!((minimal.sequence, minimal.payload.len()), (1, 0));
    }
}
