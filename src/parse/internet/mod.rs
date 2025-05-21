pub mod protocols;

use std::convert::TryFrom;
use std::net::IpAddr;

use crate::errors::internet::InternetError;
use protocols::arp::ArpPacket;

#[derive(Debug, Clone)]
pub struct InternetPacket<'a> {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol_name: String,
    pub payload: &'a [u8],
}

#[derive(Debug)]
pub enum InternetProtocolType {
    Arp,
    Ipv4,
    Ipv6,
    Unknown(u8),
}

impl<'a> TryFrom<&'a [u8]> for InternetPacket<'a> {
    type Error = InternetError;

    fn try_from(packet: &'a [u8]) -> Result<Self, Self::Error> {
        if packet.is_empty() {
            return Err(InternetError::EmptyPacket);
        }

        // Try to parse as ARP first
        if let Ok(arp_packet) = ArpPacket::try_from(packet) {
            return Ok(InternetPacket {
                source: arp_packet.sender_protocol_addr,
                destination: arp_packet.target_protocol_addr,
                protocol_name: "ARP".to_string(),
                payload: packet,
            });
        }

        // Try to determine protocol from the first byte (IPv4/IPv6 version field)
        let version = packet[0] >> 4;

        match version {
            4 => {
                // IPv4 packet
                if packet.len() < 20 {
                    return Err(InternetError::InvalidLength {
                        expected: 20,
                        actual: packet.len(),
                    });
                }

                let source = IpAddr::from([packet[12], packet[13], packet[14], packet[15]]);
                let dest = IpAddr::from([packet[16], packet[17], packet[18], packet[19]]);

                Ok(InternetPacket {
                    source,
                    destination: dest,
                    protocol_name: "IPv4".to_string(),
                    payload: packet,
                })
            }
            6 => {
                // IPv6 packet - basic parsing, just get addresses
                if packet.len() < 40 {
                    return Err(InternetError::InvalidLength {
                        expected: 40,
                        actual: packet.len(),
                    });
                }

                let mut source_bytes = [0u8; 16];
                source_bytes.copy_from_slice(&packet[8..24]);
                let source = IpAddr::from(source_bytes);

                let mut dest_bytes = [0u8; 16];
                dest_bytes.copy_from_slice(&packet[24..40]);
                let dest = IpAddr::from(dest_bytes);

                Ok(InternetPacket {
                    source,
                    destination: dest,
                    protocol_name: "IPv6".to_string(),
                    payload: packet,
                })
            }
            _ => Err(InternetError::UnsupportedProtocol(format!(
                "Unknown IP version: {}",
                version
            ))),
        }
    }
}
