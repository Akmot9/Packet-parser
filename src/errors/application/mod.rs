pub mod bitcoin;
pub mod dns;
pub mod tls;

/// Errors related to parsing an `Application`
#[derive(Debug, thiserror::Error)]
pub enum ApplicationParseError {
    #[error("Packet is empty")]
    EmptyPacket,

    #[error("Failed to parse DNS packet")]
    DnsParseError,

    #[error("Failed to parse TLS packet")]
    TlsParseError,

    #[error("Failed to parse DHCP packet")]
    DhcpParseError,

    #[error("Failed to parse HTTP request")]
    HttpParseError,

    #[error("Failed to parse Modbus packet")]
    ModbusParseError,

    #[error("Failed to parse NTP packet")]
    NtpParseError,

    #[error("Failed to parse Bitcoin packet")]
    BitcoinParseError,
}