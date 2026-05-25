// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use crate::errors::transport::tcp::TcpError;

const TCP_MIN_LENGTH: usize = 20;

pub fn validate_tcp_min_length(packet: &[u8]) -> Result<(), TcpError> {
    if packet.len() < TCP_MIN_LENGTH {
        return Err(TcpError::PacketTooShort);
    }
    Ok(())
}
