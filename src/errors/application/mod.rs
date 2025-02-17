// Copyright (c) 2024 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

pub mod ntp;

/// Errors related to parsing an `Application`
#[derive(Debug, thiserror::Error)]
pub enum ApplicationParseError {
    #[error("Packet is empty")]
    EmptyPacket,

    // #[error("Failed to parse Modbus packet")]
    // ModbusParseError,
    #[error("Failed to parse NTP packet")]
    NtpParseError,
}
