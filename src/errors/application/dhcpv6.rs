// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
#[non_exhaustive]
pub enum Dhcpv6PacketParseError {
    #[error("Invalid DHCPv6 packet length")]
    PacketLength,

    #[error("Invalid DHCPv6 message type: {message_type}")]
    MessageType { message_type: u8 },

    /// Un message de relais (type 12 ou 13) plus court que son en-tete de
    /// 34 octets (RFC 8415 §9).
    #[error("DHCPv6 relay message too short: expected at least 34 bytes, got {actual}")]
    RelayLength { actual: usize },
}
