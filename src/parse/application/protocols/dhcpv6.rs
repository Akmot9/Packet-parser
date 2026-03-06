//! Module for parsing DHCPv6 packets.

use crate::errors::application::dhcpv6::Dhcpv6PacketParseError;
use std::fmt;

/// The `Dhcpv6Packet` struct represents a parsed DHCPv6 packet.
#[derive(Debug, PartialEq)]
pub struct Dhcpv6Packet<'a> {
    pub message_type: u8,
    pub transaction_id: u32,
    pub options: &'a [u8],
}

impl<'a> fmt::Display for Dhcpv6Packet<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DHCPv6 Packet: message_type={}, transaction_id={:06X}, options={:02X?}",
            self.message_type, self.transaction_id, self.options
        )
    }
}

/// Parses a DHCPv6 packet from a given payload.
///
/// # Arguments
///
/// * `payload` - A byte slice representing the raw DHCPv6 packet data.
///
/// # Returns
///
/// * `Result<Dhcpv6Packet, Dhcpv6PacketParseError>` - Returns `Ok(Dhcpv6Packet)` if parsing is successful,
///   otherwise returns an error.
pub fn parse_dhcpv6_packet<'a>(
    payload: &'a [u8],
) -> Result<Dhcpv6Packet<'a>, Dhcpv6PacketParseError> {
    // The standard DHCPv6 Client/Server message is at least 4 bytes long.
    // (1 byte message type + 3 bytes transaction ID)
    if payload.len() < 4 {
        return Err(Dhcpv6PacketParseError::InvalidPacketLength);
    }

    let message_type = payload[0];

    // Relay agents use different message formats (types 12 and 13)
    if message_type == 12 || message_type == 13 {
        return Err(Dhcpv6PacketParseError::UnsupportedRelayType);
    }

    // Type 0 is not a valid message type in DHCPv6
    if message_type == 0 {
        return Err(Dhcpv6PacketParseError::InvalidMessageType { message_type });
    }

    // Transaction ID is 24 bits (3 bytes), so we pad it with a 0 to make a u32
    let transaction_id = u32::from_be_bytes([0, payload[1], payload[2], payload[3]]);

    // The rest are options (zero-copy slice)
    let options = &payload[4..];

    Ok(Dhcpv6Packet {
        message_type,
        transaction_id,
        options,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dhcpv6_packet() {
        // Example DHCPv6 Solicit (Type 1)
        let payload = vec![
            0x01, // msg-type: SOLICIT
            0x12, 0x34, 0x56, // transaction-id
            0x00, 0x01, 0x00, 0x0A, // options
            0x00, 0x03, 0x00, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        ];

        match parse_dhcpv6_packet(&payload) {
            Ok(packet) => {
                assert_eq!(packet.message_type, 1);
                assert_eq!(packet.transaction_id, 0x123456);
                assert_eq!(
                    packet.options,
                    &[
                        0x00, 0x01, 0x00, 0x0A, 0x00, 0x03, 0x00, 0x01, 0x00, 0x11, 0x22, 0x33,
                        0x44, 0x55
                    ]
                );
            }
            Err(_) => panic!("Expected valid DHCPv6 packet"),
        }
    }

    #[test]
    fn test_parse_dhcpv6_packet_short_payload() {
        let short_payload = vec![0x01, 0x12, 0x34]; // Only 3 bytes
        match parse_dhcpv6_packet(&short_payload) {
            Ok(_) => panic!("Expected invalid DHCPv6 packet due to short payload"),
            Err(e) => assert_eq!(e, Dhcpv6PacketParseError::InvalidPacketLength),
        }
    }

    #[test]
    fn test_parse_dhcpv6_packet_unsupported_relay() {
        // Relay-forward message (Type 12) - different structure
        let relay_payload = vec![
            0x0C, // msg-type: RELAY-FORW
            0x00, // hop-count
            0x00, 0x00, // Padding
            0x00, 0x00, 0x00, 0x00, // Link-address...
        ];
        match parse_dhcpv6_packet(&relay_payload) {
            Ok(_) => panic!("Expected invalid DHCPv6 packet due to unsupported relay type"),
            Err(e) => assert_eq!(e, Dhcpv6PacketParseError::UnsupportedRelayType),
        }
    }
}
