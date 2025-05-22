// Copyright (c) 2024 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use std::convert::TryFrom;
use thiserror::Error;

pub mod protocols;

use protocols::tcp::TcpPacket;

/// Represents a transport layer packet (UDP, TCP, etc.)
#[derive(Debug)]
pub struct Transport<'a> {
    /// The transport layer protocol name
    pub protocol: String,
    /// Source port
    pub source_port: u16,
    /// Destination port
    pub destination_port: u16,
    /// The payload of the transport packet
    pub payload: &'a [u8],
}

/// Errors that can occur when parsing transport layer packets
#[derive(Error, Debug)]
pub enum TransportError {
    #[error("Packet is too short to be a valid transport packet")]
    PacketTooShort,

    #[error("Invalid TCP packet: {0}")]
    InvalidTcpPacket(String),

    #[error("Unsupported transport protocol")]
    UnsupportedProtocol,
}

impl<'a> TryFrom<&'a [u8]> for Transport<'a> {
    type Error = TransportError;

    fn try_from(packet: &'a [u8]) -> Result<Self, Self::Error> {
        // First try to parse as TCP (most common case)
        if let Ok(tcp_packet) = TcpPacket::try_from(packet) {
            return Ok(Transport {
                protocol: "TCP".to_string(),
                source_port: tcp_packet.header.source_port,
                destination_port: tcp_packet.header.destination_port,
                payload: tcp_packet.payload,
            });
        }

        // TODO: Add other protocol parsers here (UDP, etc.)

        // If we get here, no parser could handle the packet
        Err(TransportError::UnsupportedProtocol)
    }
}
