// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Module for parsing DHCPv6 packets.

use crate::{
    checks::application::dhcpv6::{
        DHCPV6_RELAY_HEADER_LEN, extract_relay_header, extract_transaction_id,
        is_relay_message_type, validate_dhcpv6_message_type, validate_dhcpv6_min_length,
    },
    errors::application::dhcpv6::Dhcpv6PacketParseError,
};
use std::fmt;
use std::net::Ipv6Addr;

/// DHCPv6 Packet
///
/// ```mermaid
/// ---
/// title: Dhcpv6Packet
/// ---
/// packet-beta
/// 0-7: "Message Type u8"
/// 8-31: "Transaction ID u24"
/// 32-95: "Options variable"
/// ```
///
/// The `Dhcpv6Packet` struct represents a parsed DHCPv6 packet.
///
/// Les messages de relais, Relay-Forward (12) et Relay-Reply (13), ont un
/// autre en-tete (RFC 8415 §9) : `msg-type`, `hop-count`, `link-address` et
/// `peer-address`, 34 octets, sans identifiant de transaction. Il est lu
/// dans [`Dhcpv6Packet::relay`] ; `transaction_id` y vaut 0.
#[derive(Debug, PartialEq)]
#[non_exhaustive]
pub struct Dhcpv6Packet<'a> {
    pub message_type: u8,
    /// Identifiant de transaction (24 bits). Absent des messages de relais,
    /// ou il vaut 0 : leur en-tete est dans [`Dhcpv6Packet::relay`].
    pub transaction_id: u32,
    /// En-tete d'un message de relais (types 12 et 13), `None` sinon.
    pub relay: Option<Dhcpv6Relay>,
    /// Les options, brutes : apres l'identifiant de transaction (octet 4), ou
    /// apres `peer-address` pour un relais (octet 34).
    pub options: &'a [u8],
}

/// En-tete d'un message de relais DHCPv6 (RFC 8415 §9).
///
/// ```mermaid
/// ---
/// title: Dhcpv6Relay
/// ---
/// packet-beta
/// 0-7: "Message Type u8"
/// 8-15: "Hop Count u8"
/// 16-143: "Link Address (16 bytes)"
/// 144-271: "Peer Address (16 bytes)"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Dhcpv6Relay {
    /// Nombre d'agents de relais deja traverses.
    pub hop_count: u8,
    /// Adresse qui designe au serveur le lien du client (peut etre `::`).
    pub link_address: Ipv6Addr,
    /// Adresse du client ou de l'agent de relais dont vient le message.
    pub peer_address: Ipv6Addr,
}

impl<'a> fmt::Display for Dhcpv6Packet<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.relay {
            Some(relay) => write!(
                f,
                "DHCPv6 Packet: message_type={}, hop_count={}, link_address={}, peer_address={}, options={:02X?}",
                self.message_type,
                relay.hop_count,
                relay.link_address,
                relay.peer_address,
                self.options
            ),
            None => write!(
                f,
                "DHCPv6 Packet: message_type={}, transaction_id={:06X}, options={:02X?}",
                self.message_type, self.transaction_id, self.options
            ),
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for Dhcpv6Packet<'a> {
    type Error = Dhcpv6PacketParseError;

    fn try_from(payload: &'a [u8]) -> Result<Self, Self::Error> {
        validate_dhcpv6_min_length(payload)?;

        let message_type = payload[0];
        validate_dhcpv6_message_type(message_type)?;

        if is_relay_message_type(message_type) {
            // RFC 8415 §9 : hop-count, link-address, peer-address, options.
            let (hop_count, link_address, peer_address) = extract_relay_header(payload)?;
            return Ok(Dhcpv6Packet {
                message_type,
                transaction_id: 0,
                relay: Some(Dhcpv6Relay {
                    hop_count,
                    link_address,
                    peer_address,
                }),
                options: &payload[DHCPV6_RELAY_HEADER_LEN..],
            });
        }

        // Transaction ID is 24 bits (3 bytes), zero-padded into a u32.
        let transaction_id = extract_transaction_id(&payload[1..4])?;

        // The rest are options (zero-copy slice)
        let options = &payload[4..];

        Ok(Dhcpv6Packet {
            message_type,
            transaction_id,
            relay: None,
            options,
        })
    }
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

        match Dhcpv6Packet::try_from(payload.as_slice()) {
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
        match Dhcpv6Packet::try_from(short_payload.as_slice()) {
            Ok(_) => panic!("Expected invalid DHCPv6 packet due to short payload"),
            Err(e) => assert_eq!(e, Dhcpv6PacketParseError::PacketLength),
        }
    }

    #[test]
    fn test_parse_dhcpv6_packet_invalid_type() {
        // Unknown message type 14 (0x0E)
        let invalid_payload = vec![
            0x0E, // msg-type: UNKNOWN
            0x12, 0x34, 0x56, // transaction-id
            0x00, 0x00, 0x00, 0x00, // Options
        ];
        match Dhcpv6Packet::try_from(invalid_payload.as_slice()) {
            Ok(_) => panic!("Expected invalid DHCPv6 packet due to invalid message type"),
            Err(e) => assert_eq!(e, Dhcpv6PacketParseError::MessageType { message_type: 14 }),
        }
    }

    /// `The-Ultimate-PCAP.pcapng`, trame 36781 (UDP 547 -> 547) : un
    /// Relay-Forward qui porte un Solicit dans son option 9 (Relay Message).
    /// tshark 4.6.9 : hop-count 0, link-address 2001:470:7250:69::1,
    /// peer-address fe80::20c:29ff:fe48:92fd, options 9 puis 14, 3, 39, 6,
    /// 1 et 8 dans le message relaye.
    const RELAY_FORWARD_HEX: &str = concat!(
        "0c0020010470725000690000000000000001fe80000000000000020c29fffe4892fd",
        "0009004e013603eb000e00000003000c9f6e852400000000000000000027000c010a",
        "766d33342d74657374330006000a001700180038001f000e0001000e00020000ab11",
        "5beb45c3fe63e62c000800020000"
    );

    #[test]
    fn a_captured_relay_forward_reads_its_relay_header() {
        let payload = hex::decode(RELAY_FORWARD_HEX).expect("invalid hex fixture");

        let packet = Dhcpv6Packet::try_from(payload.as_slice()).expect("Relay-Forward");

        assert_eq!(packet.message_type, 12);
        assert_eq!(packet.transaction_id, 0);
        assert_eq!(
            packet.relay,
            Some(Dhcpv6Relay {
                hop_count: 0,
                link_address: "2001:470:7250:69::1".parse().unwrap(),
                peer_address: "fe80::20c:29ff:fe48:92fd".parse().unwrap(),
            })
        );
        // Option 9 (Relay Message), 78 octets : le Solicit relaye.
        assert_eq!(&packet.options[..4], &[0x00, 0x09, 0x00, 0x4e]);
        assert_eq!(packet.options.len(), payload.len() - 34);
        let inner = Dhcpv6Packet::try_from(&packet.options[4..]).expect("relayed Solicit");
        assert_eq!(inner.message_type, 1);
        assert_eq!(inner.transaction_id, 0x3603eb);
        assert_eq!(inner.relay, None);
    }

    #[test]
    fn a_relay_reply_reads_the_same_header() {
        let mut payload = hex::decode(RELAY_FORWARD_HEX).expect("invalid hex fixture");
        payload[0] = 13;
        payload[1] = 2;

        let packet = Dhcpv6Packet::try_from(payload.as_slice()).expect("Relay-Reply");

        assert_eq!(packet.relay.map(|relay| relay.hop_count), Some(2));
        assert!(
            packet
                .to_string()
                .contains("peer_address=fe80::20c:29ff:fe48:92fd")
        );
    }

    /// Un relais tient en 34 octets au moins (RFC 8415 §9) : en dessous, il
    /// n'a pas son peer-address.
    #[test]
    fn a_relay_shorter_than_its_header_is_refused() {
        let payload = hex::decode(RELAY_FORWARD_HEX).expect("invalid hex fixture");

        for len in [4, 8, 33] {
            assert_eq!(
                Dhcpv6Packet::try_from(&payload[..len]),
                Err(Dhcpv6PacketParseError::RelayLength { actual: len })
            );
        }
        let header_only = Dhcpv6Packet::try_from(&payload[..34]).expect("header only");
        assert!(header_only.options.is_empty());
    }
}
