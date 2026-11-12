// Copyright (c) 2024 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

pub mod protocols;
use serde::Serialize;

use crate::{errors::application::ApplicationError, parse::dispatch::classify_blind};

/// The `Application` struct contains information about the layer 7 protocol and its parsed data.
///
/// [`Application::try_from`] only receives application bytes and therefore
/// cannot enforce transport or port constraints. For classification of a
/// complete packet, use [`crate::parse::PacketFlow`]: it prevents, for
/// example, a valid-looking S7Comm payload carried over UDP from being
/// labelled as S7Comm and keeps weak COTP signatures behind TCP port 102.
#[derive(Debug, Clone, Serialize, Eq)]
#[non_exhaustive]
pub struct Application {
    pub application_protocol: &'static str,
}

impl TryFrom<&[u8]> for Application {
    type Error = ApplicationError;

    fn try_from(packet: &[u8]) -> Result<Self, Self::Error> {
        if packet.is_empty() {
            return Err(ApplicationError::EmptyPacket);
        }

        // La cascade est celle de la table : ses regles sans port, dans son
        // ordre (#216). Plus de liste de sondes ecrite a la main ici.
        Ok(Application {
            application_protocol: classify_blind(packet),
        })
    }
}

impl PartialEq for Application {
    fn eq(&self, other: &Self) -> bool {
        self.application_protocol == other.application_protocol
    }
}

use std::hash::{Hash, Hasher};

impl Hash for Application {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.application_protocol.hash(state);
    }
}

#[cfg(test)]
mod tests {

    use crate::parse::application::Application;
    use std::convert::TryFrom;

    #[test]
    fn test_ntp_packet_parsing() {
        let ntp_payload = hex::decode("d9000afa000000000001029000000000000000000000000000000000000000000000000000000000c50204ecec42ee92").expect("Invalid hex string");

        match Application::try_from(ntp_payload.as_slice()) {
            Ok(parsed) => {
                println!("Parsed application protocol: {:?}", parsed);
                assert_eq!(parsed.application_protocol, "NTP");
            }
            Err(e) => {
                panic!("Failed to parse DNS packet: {:?}", e);
            }
        }
    }

    /// #164 : sans port, NTP passe par la sonde aveugle. Synthetique : la
    /// requete NTP du test precedent, precision portee a +5 (2^5 s).
    #[test]
    fn test_ntp_needs_the_blind_probe_without_a_port() {
        let mut coarse = hex::decode("d9000afa000000000001029000000000000000000000000000000000000000000000000000000000c50204ecec42ee92").expect("hex");
        coarse[3] = 5;
        let parsed = Application::try_from(coarse.as_slice()).expect("payload non vide");
        assert_ne!(parsed.application_protocol, "NTP");
    }

    #[test]
    fn test_postgresql_packet_detection_from_payload() {
        let query = b"select 1\0";
        let mut payload = Vec::new();
        payload.push(b'Q');
        payload.extend_from_slice(&(4 + query.len() as u32).to_be_bytes());
        payload.extend_from_slice(query);

        let parsed = Application::try_from(payload.as_slice()).unwrap();

        assert_eq!(parsed.application_protocol, "PostgreSQL");
    }

    #[test]
    fn test_postgresql_weak_shape_is_not_detected_from_payload() {
        let payload = [b'S', 0x00, 0x00, 0x00, 0x04];

        let parsed = Application::try_from(payload.as_slice()).unwrap();

        assert_ne!(parsed.application_protocol, "PostgreSQL");
    }

    #[test]
    fn test_detects_giop() {
        let mut packet = b"GIOP".to_vec();
        packet.extend_from_slice(&[1, 2, 0, 1]); // version 1.2, big-endian, Reply
        packet.extend_from_slice(&0u32.to_be_bytes()); // body vide

        let parsed = Application::try_from(packet.as_slice()).unwrap();
        assert_eq!(parsed.application_protocol, "GIOP");
    }

    #[test]
    fn test_detects_srvloc() {
        // SLP v2 header minimal, lang tag "en"
        let mut packet = vec![2u8, 8];
        packet.extend_from_slice(&[0, 0, 16]); // packet length u24
        packet.extend_from_slice(&[0x20, 0x00]); // flags
        packet.extend_from_slice(&[0, 0, 0]); // next ext offset
        packet.extend_from_slice(&[0x42, 0x42]); // xid
        packet.extend_from_slice(&[0, 2]); // lang tag len
        packet.extend_from_slice(b"en");

        let parsed = Application::try_from(packet.as_slice()).unwrap();
        assert_eq!(parsed.application_protocol, "SRVLOC");
    }

    /// Regression issue #3 : les trames DHCP reelles (Discover op=1 et
    /// Offer op=2) doivent sortir "DHCP", plus jamais "SRVLOC".
    #[test]
    fn test_detects_dhcp_not_srvloc() {
        use crate::parse::application::protocols::dhcp::tests_fixtures::{
            DHCP_DISCOVER_PAYLOAD, DHCP_OFFER_PAYLOAD,
        };

        let discover = Application::try_from(&DHCP_DISCOVER_PAYLOAD[..]).unwrap();
        assert_eq!(discover.application_protocol, "DHCP");

        let offer = Application::try_from(&DHCP_OFFER_PAYLOAD[..]).unwrap();
        assert_eq!(offer.application_protocol, "DHCP");
    }

    #[test]
    fn test_detects_quic() {
        let mut packet = vec![0xC0u8]; // Initial, PN len 1
        packet.extend_from_slice(&1u32.to_be_bytes());
        packet.push(0); // dcid len
        packet.push(0); // scid len
        packet.push(0); // token len
        packet.push(1); // length = PN seul
        packet.push(0); // PN

        let parsed = Application::try_from(packet.as_slice()).unwrap();
        assert_eq!(parsed.application_protocol, "QUIC");
    }

    #[test]
    fn test_detects_snmp() {
        // SNMPv2c GetRequest minimal : seq(version, community, pdu)
        let packet: &[u8] = &[
            0x30, 0x18, // SEQUENCE
            0x02, 0x01, 0x01, // version 2c
            0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', // community
            0xA0, 0x0B, // GetRequest
            0x02, 0x01, 0x01, // request id
            0x02, 0x01, 0x00, // error status
            0x02, 0x01, 0x00, // error index
            0x30, 0x00, // varbind list vide
        ];

        let parsed = Application::try_from(packet).unwrap();
        assert_eq!(parsed.application_protocol, "SNMP");
    }

    #[test]
    fn test_detects_postgresql() {
        let mut packet = vec![b'Q'];
        let query = b"select 1\0";
        packet.extend_from_slice(&((4 + query.len()) as u32).to_be_bytes());
        packet.extend_from_slice(query);

        let parsed = Application::try_from(packet.as_slice()).unwrap();
        assert_eq!(parsed.application_protocol, "PostgreSQL");
    }

    #[test]
    fn test_detects_http() {
        let packet = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";

        let parsed = Application::try_from(&packet[..]).unwrap();
        assert_eq!(parsed.application_protocol, "HTTP");
    }

    #[test]
    fn test_random_text_is_not_http() {
        let packet = b"BONJOUR tout le monde\r\n\r\n";

        let parsed = Application::try_from(&packet[..]).unwrap();
        assert_ne!(parsed.application_protocol, "HTTP");
    }

    #[test]
    fn test_detects_mqtt_connect() {
        let packet: &[u8] = &[
            0x10, 0x0E, // CONNECT, remaining length 14
            0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3C, // variable header
            0x00, 0x02, b'i', b'd', // client id
        ];

        let parsed = Application::try_from(packet).unwrap();
        assert_eq!(parsed.application_protocol, "MQTT");
    }

    /// pcaps_exemple/protocols/valmet_dna/valmet-dna-multicast-anon.pcap,
    /// trame 1 : un telegramme d'etat Valmet DNA, reconnu a l'aveugle ; la
    /// meme trame sous une famille inconnue ne l'est pas.
    #[test]
    fn test_detects_valmet_dna() {
        let mut status = hex::decode(concat!(
            "ab01801d00ff007c00000fff001003b00000048ace4818e03d0018803f000000",
            "000000000a0002010005000000000003010120200000000000001d00018a0052",
            "c59c00000001ef00ab0100000000000000000000000000000000000000000000",
            "00000000000000000000540f5bf154059702000000000000000009d609d6",
        ))
        .expect("hex");
        let parsed = Application::try_from(status.as_slice()).unwrap();
        assert_eq!(parsed.application_protocol, "Valmet DNA");

        status[11] = 0xFE;
        let parsed = Application::try_from(status.as_slice()).unwrap();
        assert_ne!(parsed.application_protocol, "Valmet DNA");
    }

    #[test]
    fn test_unknown_payload_falls_through() {
        let packet = [0xFFu8, 0xFE, 0xFD, 0xFC, 0xFB];
        let parsed = Application::try_from(&packet[..]).unwrap();
        assert_eq!(parsed.application_protocol, "Unknown");
    }

    #[test]
    fn test_empty_packet_is_an_error() {
        assert!(matches!(
            Application::try_from(&[][..]),
            Err(crate::errors::application::ApplicationError::EmptyPacket)
        ));
    }
}
