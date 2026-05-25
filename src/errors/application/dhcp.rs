use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DhcpParseError {
    #[error("DHCP packet too short: expected at least {expected} bytes, got {actual}")]
    PacketTooShort { expected: usize, actual: usize },

    #[error("Invalid DHCP operation code: {op}")]
    InvalidOperation { op: u8 },

    #[error("Unsupported DHCP hardware type: {htype}")]
    UnsupportedHardwareType { htype: u8 },

    #[error("Invalid DHCP hardware address length: {hlen}")]
    InvalidHardwareAddressLength { hlen: u8 },
}
