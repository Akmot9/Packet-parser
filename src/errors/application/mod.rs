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
