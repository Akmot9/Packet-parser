// Copyright (c) 2024 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

pub mod protocols;
use serde::Serialize;

use crate::{errors::application::ApplicationError, parse::dispatch::classify_blind};

/// The `Application` struct contains information about the layer 7 protocol and its parsed data.
///
/// [`fn@crate::parse`] fills it in [`crate::PacketFlow::application`]. For a
/// payload without its frame, [`crate::classify_payload`] gives the same
/// answer from the transport protocol and the ports. Both apply the whole
/// dispatch table: a valid-looking S7Comm payload carried over UDP is not
/// labelled S7Comm, and weak COTP signatures stay behind TCP port 102.
///
/// # `Application::try_from` will be removed in 12.0
///
/// [`Application::try_from`] only receives application bytes and therefore
/// cannot enforce transport or port constraints. It can give a TCP segment
/// the label of a protocol that only exists over UDP, and it never
/// recognizes a protocol that its port identifies. On the capture corpus of
/// this crate it disagrees with `parse` on 9,307 flows out of 254,107.
///
/// Use [`crate::classify_payload`] instead. The rewrite is described in
/// [`MIGRATION-12.md`](https://github.com/Akmot9/Packet-parser/blob/main/MIGRATION-12.md)
/// (issue #219).
#[derive(Debug, Clone, Serialize, Eq)]
#[non_exhaustive]
pub struct Application {
    pub application_protocol: &'static str,
}

/// Classification without transport or ports. **Will be removed in 12.0**
/// (issue #219): use [`crate::classify_payload`].
///
/// This implementation carries no `#[deprecated]` attribute because rustc
/// rejects it on a trait implementation: the compiler will not warn its
/// callers before the removal.
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
    use crate::parse::classify_payload;
    use crate::parse::transport::protocols::TransportProtocol::{self, Tcp, Udp};
    use std::convert::TryFrom;

    /// pcaps_exemple/protocols/valmet_dna/valmet-dna-multicast-anon.pcap,
    /// trame 1 : un telegramme d'etat Valmet DNA.
    const VALMET_DNA_STATUS: &str = concat!(
        "ab01801d00ff007c00000fff001003b00000048ace4818e03d0018803f000000",
        "000000000a0002010005000000000003010120200000000000001d00018a0052",
        "c59c00000001ef00ab0100000000000000000000000000000000000000000000",
        "00000000000000000000540f5bf154059702000000000000000009d609d6",
    );

    /// L'etiquette de la table pour `payload` sous ce transport, sans port :
    /// seules les sondes aveugles s'appliquent, chacune derriere sa garde de
    /// transport (#219).
    fn label(protocol: TransportProtocol, payload: &[u8]) -> &'static str {
        classify_payload(protocol, None, None, payload)
            .expect("payload non vide")
            .application_protocol
    }

    #[test]
    fn test_ntp_packet_parsing() {
        let ntp_payload = hex::decode("d9000afa000000000001029000000000000000000000000000000000000000000000000000000000c50204ecec42ee92").expect("Invalid hex string");

        assert_eq!(label(Udp, &ntp_payload), "NTP");
    }

    /// #164 : sans port, NTP passe par la sonde aveugle. Synthetique : la
    /// requete NTP du test precedent, precision portee a +5 (2^5 s).
    #[test]
    fn test_ntp_needs_the_blind_probe_without_a_port() {
        let mut coarse = hex::decode("d9000afa000000000001029000000000000000000000000000000000000000000000000000000000c50204ecec42ee92").expect("hex");
        coarse[3] = 5;

        assert_ne!(label(Udp, &coarse), "NTP");
    }

    #[test]
    fn test_postgresql_packet_detection_from_payload() {
        let query = b"select 1\0";
        let mut payload = Vec::new();
        payload.push(b'Q');
        payload.extend_from_slice(&(4 + query.len() as u32).to_be_bytes());
        payload.extend_from_slice(query);

        assert_eq!(label(Tcp, &payload), "PostgreSQL");
    }

    #[test]
    fn test_postgresql_weak_shape_is_not_detected_from_payload() {
        let payload = [b'S', 0x00, 0x00, 0x00, 0x04];

        assert_ne!(label(Tcp, &payload), "PostgreSQL");
    }

    #[test]
    fn test_detects_giop() {
        let mut packet = b"GIOP".to_vec();
        packet.extend_from_slice(&[1, 2, 0, 1]); // version 1.2, big-endian, Reply
        packet.extend_from_slice(&0u32.to_be_bytes()); // body vide

        assert_eq!(label(Tcp, &packet), "GIOP");
    }

    /// SRVLOC circule sur UDP comme sur TCP : sa regle n'a pas de garde.
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

        assert_eq!(label(Udp, &packet), "SRVLOC");
        assert_eq!(label(Tcp, &packet), "SRVLOC");
    }

    /// Regression issue #3 : les trames DHCP reelles (Discover op=1 et
    /// Offer op=2) doivent sortir "DHCP", plus jamais "SRVLOC".
    #[test]
    fn test_detects_dhcp_not_srvloc() {
        use crate::parse::application::protocols::dhcp::tests_fixtures::{
            DHCP_DISCOVER_PAYLOAD, DHCP_OFFER_PAYLOAD,
        };

        assert_eq!(label(Udp, &DHCP_DISCOVER_PAYLOAD[..]), "DHCP");
        assert_eq!(label(Udp, &DHCP_OFFER_PAYLOAD[..]), "DHCP");
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

        assert_eq!(label(Udp, &packet), "QUIC");
    }

    /// SNMP sur TCP existe (RFC 3430) : sa regle sans port n'a pas de garde.
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

        assert_eq!(label(Udp, packet), "SNMP");
        assert_eq!(label(Tcp, packet), "SNMP");
    }

    #[test]
    fn test_detects_postgresql() {
        let mut packet = vec![b'Q'];
        let query = b"select 1\0";
        packet.extend_from_slice(&((4 + query.len()) as u32).to_be_bytes());
        packet.extend_from_slice(query);

        assert_eq!(label(Tcp, &packet), "PostgreSQL");
    }

    #[test]
    fn test_detects_http() {
        let packet = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";

        assert_eq!(label(Tcp, &packet[..]), "HTTP");
    }

    #[test]
    fn test_random_text_is_not_http() {
        let packet = b"BONJOUR tout le monde\r\n\r\n";

        assert_ne!(label(Tcp, &packet[..]), "HTTP");
    }

    #[test]
    fn test_detects_mqtt_connect() {
        let packet: &[u8] = &[
            0x10, 0x0E, // CONNECT, remaining length 14
            0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3C, // variable header
            0x00, 0x02, b'i', b'd', // client id
        ];

        assert_eq!(label(Tcp, packet), "MQTT");
    }

    /// Le telegramme d'etat Valmet DNA reel est reconnu sans port ; la meme
    /// trame sous une famille inconnue ne l'est pas.
    #[test]
    fn test_detects_valmet_dna() {
        let mut status = hex::decode(VALMET_DNA_STATUS).expect("hex");
        assert_eq!(label(Udp, &status), "Valmet DNA");

        status[11] = 0xFE;
        assert_ne!(label(Udp, &status), "Valmet DNA");
    }

    #[test]
    fn test_unknown_payload_falls_through() {
        let packet = [0xFFu8, 0xFE, 0xFD, 0xFC, 0xFB];

        assert_eq!(label(Tcp, &packet), "Unknown");
        assert_eq!(label(Udp, &packet), "Unknown");
    }

    // `impl TryFrom<&[u8]> for Application` est conserve jusqu'a la 12.0
    // (#219). Les deux tests qui suivent partent avec lui.

    /// La cascade sans transport ni port repond encore.
    #[test]
    fn test_blind_try_from_still_answers() {
        let status = hex::decode(VALMET_DNA_STATUS).expect("hex");

        let parsed = Application::try_from(status.as_slice()).expect("payload non vide");

        assert_eq!(parsed.application_protocol, "Valmet DNA");
    }

    #[test]
    fn test_empty_packet_is_an_error() {
        assert!(matches!(
            Application::try_from(&[][..]),
            Err(crate::errors::application::ApplicationError::EmptyPacket)
        ));
    }
}
