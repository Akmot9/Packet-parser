// Copyright (c) 2024 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use std::convert::TryFrom;

pub mod protocols;

use protocols::{TransportProtocol, tcp::TcpPacket, udp::UdpPacket};
use serde::Serialize;

use crate::errors::transport::TransportError;

/// Represents a transport layer packet (UDP, TCP, etc.)
#[derive(Debug, Clone, Serialize, Eq)]
pub struct Transport<'a> {
    /// The transport layer protocol name
    pub protocol: TransportProtocol,
    /// Source port
    pub source_port: Option<u16>,
    /// Destination port
    pub destination_port: Option<u16>,
    /// The payload of the transport packet
    #[serde(skip_serializing)]
    pub payload: Option<&'a [u8]>,
}

impl<'a> Transport<'a> {
    pub fn transport_from_u8(protocol: &u8) -> TransportProtocol {
        TransportProtocol::from_u8(*protocol)
    }
}

impl<'a> TryFrom<&'a [u8]> for Transport<'a> {
    type Error = TransportError;

    fn try_from(packet: &'a [u8]) -> Result<Self, Self::Error> {
        // First try to parse as TCP (most common case)
        // tempo de 100ms
        // std::thread::sleep(std::time::Duration::from_nanos(1));

        if let Ok(tcp_packet) = TcpPacket::try_from(packet) {
            return Ok(Transport {
                protocol: TransportProtocol::Tcp,
                source_port: Some(tcp_packet.header.source_port),
                destination_port: Some(tcp_packet.header.destination_port),
                payload: Some(tcp_packet.payload),
            });
        }

        // TODO: Add other protocol parsers here (UDP, etc.)
        if let Ok(udp_packet) = UdpPacket::try_from(packet) {
            return Ok(Transport {
                protocol: TransportProtocol::Udp,
                source_port: Some(udp_packet.source_port),
                destination_port: Some(udp_packet.destination_port),
                payload: Some(udp_packet.payload),
            });
        }
        // If we get here, no parser could handle the packet
        Err(TransportError::UnsupportedProtocol)
    }
}

impl<'a> PartialEq for Transport<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.protocol == other.protocol
            && self.source_port == other.source_port
            && self.destination_port == other.destination_port
    }
}
use std::hash::{Hash, Hasher};

impl<'a> Hash for Transport<'a> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.protocol.hash(state);
        self.source_port.hash(state);
        self.destination_port.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    fn hash_value<T: Hash>(value: &T) -> u64 {
        let mut hasher = DefaultHasher::new();
        value.hash(&mut hasher);
        hasher.finish()
    }

    // fn valid_tcp_packet() -> Vec<u8> {
    //     vec![
    //         0x30, 0x39, // source port = 12345
    //         0x00, 0x50, // destination port = 80
    //         0x00, 0x00, 0x00, 0x01, // sequence number
    //         0x00, 0x00, 0x00, 0x00, // acknowledgement number
    //         0x50, 0x18, // data offset = 5, flags = PSH+ACK
    //         0x04, 0x00, // window size
    //         0x12, 0x34, // checksum
    //         0x00, 0x00, // urgent pointer
    //         0xDE, 0xAD, 0xBE, 0xEF, // payload
    //     ]
    // }

    fn valid_udp_packet() -> Vec<u8> {
        // UDP header minimal de 8 octets
        // source port = 12345 (0x3039)
        // destination port = 53 (0x0035)
        // length = 8
        vec![
            0x30, 0x39, // source port = 12345
            0x00, 0x35, // destination port = 53
            0x00, 0x08, // length = 8
            0x00, 0x00, // checksum
        ]
    }

    #[test]
    fn test_transport_from_u8_tcp() {
        let proto = Transport::transport_from_u8(&6);
        assert_eq!(proto, TransportProtocol::Tcp);
    }

    #[test]
    fn test_transport_from_u8_udp() {
        let proto = Transport::transport_from_u8(&17);
        assert_eq!(proto, TransportProtocol::Udp);
    }

    #[test]
    fn test_transport_try_from_tcp() {
        // Header TCP minimal de 20 octets + 4 octets de payload
        let packet = vec![
            0x30, 0x39, // source port = 12345
            0x00, 0x50, // destination port = 80
            0x00, 0x00, 0x00, 0x01, // sequence number
            0x00, 0x00, 0x00, 0x00, // acknowledgement number
            0x50, 0x18, // data offset = 5, flags = PSH+ACK
            0x04, 0x00, // window size
            0x12, 0x34, // checksum
            0x00, 0x00, // urgent pointer
            0xDE, 0xAD, 0xBE, 0xEF, // payload
        ];

        // Vérifie d'abord que le parser TCP natif accepte bien ce paquet
        let tcp_packet = TcpPacket::try_from(packet.as_slice())
            .expect("Le paquet de test doit être accepté par TcpPacket::try_from");

        assert_eq!(tcp_packet.header.source_port, 12345);
        assert_eq!(tcp_packet.header.destination_port, 80);
        assert_eq!(tcp_packet.payload, &packet[20..]);

        // Ensuite seulement on teste la conversion générique Transport
        let transport = Transport::try_from(packet.as_slice()).unwrap();

        assert_eq!(transport.protocol, TransportProtocol::Tcp);
        assert_eq!(transport.source_port, Some(12345));
        assert_eq!(transport.destination_port, Some(80));
        assert_eq!(transport.payload, Some(&packet[20..]));
    }

    #[test]
    fn test_transport_try_from_udp() {
        let packet = valid_udp_packet();

        let transport = Transport::try_from(packet.as_slice()).unwrap();

        assert_eq!(transport.protocol, TransportProtocol::Udp);
        assert_eq!(transport.source_port, Some(12345));
        assert_eq!(transport.destination_port, Some(53));
        assert_eq!(transport.payload, Some(&packet[8..]));
    }

    #[test]
    fn test_transport_try_from_unsupported_protocol() {
        let packet = [0x00, 0x01, 0x02, 0x03];

        let err = Transport::try_from(packet.as_slice()).unwrap_err();

        assert!(matches!(err, TransportError::UnsupportedProtocol));
    }

    #[test]
    fn test_transport_partial_eq_ignores_payload() {
        let payload1 = [0xAA, 0xBB];
        let payload2 = [0xCC, 0xDD, 0xEE];

        let left = Transport {
            protocol: TransportProtocol::Tcp,
            source_port: Some(1000),
            destination_port: Some(2000),
            payload: Some(&payload1),
        };

        let right = Transport {
            protocol: TransportProtocol::Tcp,
            source_port: Some(1000),
            destination_port: Some(2000),
            payload: Some(&payload2),
        };

        assert_eq!(left, right);
    }

    #[test]
    fn test_transport_partial_eq_detects_different_ports() {
        let payload = [0xAA];

        let left = Transport {
            protocol: TransportProtocol::Tcp,
            source_port: Some(1000),
            destination_port: Some(2000),
            payload: Some(&payload),
        };

        let right = Transport {
            protocol: TransportProtocol::Tcp,
            source_port: Some(1001),
            destination_port: Some(2000),
            payload: Some(&payload),
        };

        assert_ne!(left, right);
    }

    #[test]
    fn test_transport_hash_ignores_payload() {
        let payload1 = [0x01, 0x02];
        let payload2 = [0x03, 0x04, 0x05];

        let left = Transport {
            protocol: TransportProtocol::Udp,
            source_port: Some(1111),
            destination_port: Some(2222),
            payload: Some(&payload1),
        };

        let right = Transport {
            protocol: TransportProtocol::Udp,
            source_port: Some(1111),
            destination_port: Some(2222),
            payload: Some(&payload2),
        };

        assert_eq!(hash_value(&left), hash_value(&right));
    }

    #[test]
    fn test_transport_serialize_skips_payload() {
        let payload = [0xDE, 0xAD, 0xBE, 0xEF];

        let transport = Transport {
            protocol: TransportProtocol::Tcp,
            source_port: Some(12345),
            destination_port: Some(443),
            payload: Some(&payload),
        };

        let json = serde_json::to_string(&transport).unwrap();

        assert!(json.contains("protocol"));
        assert!(json.contains("\"source_port\":12345"));
        assert!(json.contains("\"destination_port\":443"));
        assert!(!json.contains("payload"));
    }

    #[test]
    fn test_transport_clone_and_eq() {
        let payload = [0x10, 0x20];

        let transport = Transport {
            protocol: TransportProtocol::Udp,
            source_port: Some(5000),
            destination_port: Some(6000),
            payload: Some(&payload),
        };

        let cloned = transport.clone();

        assert_eq!(transport, cloned);
    }
}