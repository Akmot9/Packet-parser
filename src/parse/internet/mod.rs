pub mod protocols;

use std::convert::TryFrom;
use std::net::IpAddr;

use crate::errors::internet::InternetError;
use crate::parse::internet::protocols::profinet;
use protocols::arp::ArpPacket;
use protocols::ipv4;
use protocols::ipv6;
use serde::Serialize;
pub mod ip_type;
use super::transport::Transport;
use ip_type::IpType;

#[derive(Debug, Clone, Serialize)]
pub struct Internet<'a> {
    pub source: Option<IpAddr>,
    pub source_type: Option<IpType>,
    pub destination: Option<IpAddr>,
    pub destination_type: Option<IpType>,
    pub protocol_name: String,
    pub payload_protocol: Option<Transport<'a>>,
    pub payload: &'a [u8],
}

impl<'a> TryFrom<&'a [u8]> for Internet<'a> {
    type Error = InternetError;

    fn try_from(packet: &'a [u8]) -> Result<Self, Self::Error> {
        if packet.is_empty() {
            return Err(InternetError::EmptyPacket);
        }

        // Try to parse as ARP first
        if let Ok(arp_packet) = ArpPacket::try_from(packet) {
            return Ok(Internet {
                source: Some(arp_packet.sender_protocol_addr),
                source_type: Some(IpType::from_ip(
                    &arp_packet.sender_protocol_addr.to_string(),
                )),
                destination: Some(arp_packet.target_protocol_addr),
                destination_type: Some(IpType::from_ip(
                    &arp_packet.target_protocol_addr.to_string(),
                )),
                protocol_name: "ARP".to_string(),
                payload_protocol: None,
                payload: &[],
            });
        }

        if let Ok(ipv4_packet) = ipv4::Ipv4Packet::try_from(packet) {
            return Ok(Internet {
                source: Some(IpAddr::V4(ipv4_packet.source_addr)),
                source_type: Some(IpType::from_ip(&ipv4_packet.source_addr.to_string())),
                destination: Some(IpAddr::V4(ipv4_packet.dest_addr)),
                destination_type: Some(IpType::from_ip(&ipv4_packet.dest_addr.to_string())),
                protocol_name: "IPv4".to_string(),
                payload_protocol: Some(Transport::transport_from_u8(&ipv4_packet.protocol)),
                payload: ipv4_packet.payload,
            });
        }

        if let Ok(ipv6_packet) = ipv6::Ipv6Packet::try_from(packet) {
            return Ok(Internet {
                source: Some(IpAddr::V6(ipv6_packet.source_addr)),
                source_type: Some(IpType::from_ip(&ipv6_packet.source_addr.to_string())),
                destination: Some(IpAddr::V6(ipv6_packet.dest_addr)),
                destination_type: Some(IpType::from_ip(&ipv6_packet.dest_addr.to_string())),
                protocol_name: "IPv6".to_string(),
                payload_protocol: Some(Transport::transport_from_u8(&ipv6_packet.next_header)),
                payload: ipv6_packet.payload,
            });
        }
        if profinet::ProfinetPacket::try_from(packet).is_ok() {
            return Ok(Internet {
                source: None,
                source_type: None,
                destination: None,
                destination_type: None,
                protocol_name: "Profinet".to_string(),
                payload_protocol: None,
                payload: &[],
            });
        }
        Err(InternetError::UnsupportedProtocol)
    }
}
