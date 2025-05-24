pub mod protocols;

use std::convert::TryFrom;
use std::net::IpAddr;

use crate::errors::internet::InternetError;
use protocols::arp::ArpPacket;
use protocols::ipv4;
use protocols::ipv6;

#[derive(Debug, Clone)]
pub struct Internet<'a> {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol_name: String,
    pub payload_protocol: Option<u8>,
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
                source: arp_packet.sender_protocol_addr,
                destination: arp_packet.target_protocol_addr,
                protocol_name: "ARP".to_string(),
                payload_protocol: None,
                payload: &[],
            });
        }

        if let Ok(ipv4_packet) = ipv4::Ipv4Packet::try_from(packet) {
            return Ok(Internet {
                source: IpAddr::V4(ipv4_packet.source_addr),
                destination: IpAddr::V4(ipv4_packet.dest_addr),
                protocol_name: "IPv4".to_string(),
                payload_protocol: Some(ipv4_packet.protocol),
                payload: &ipv4_packet.payload,
            });
        }

        if let Ok(ipv6_packet) = ipv6::Ipv6Packet::try_from(packet) {
            return Ok(Internet {
                source: IpAddr::V6(ipv6_packet.source_addr),
                destination: IpAddr::V6(ipv6_packet.dest_addr),
                protocol_name: "IPv6".to_string(),
                payload_protocol: Some(ipv6_packet.next_header),
                payload: &ipv6_packet.payload,
            });
        }

        Err(InternetError::UnsupportedProtocol(format!(
            "Unsupported protocol: {}",
            packet[0]
        )))
    }
}
