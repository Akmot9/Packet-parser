// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

/// Error types for DHCPv6 packet parsing.
#[derive(Debug, Error, PartialEq)]

pub enum Dhcpv6PacketParseError {
    #[error("Invalid DHCPv6 packet length")]
    InvalidPacketLength,

    #[error("Invalid DHCPv6 transaction ID: {transaction_id}")]
    InvalidTransactionId { transaction_id: u32 },

    #[error("Invalid DHCPv6 message type: {message_type}")]
    InvalidMessageType { message_type: u8 },
}
