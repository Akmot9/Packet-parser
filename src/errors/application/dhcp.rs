use thiserror::Error;
/// Error types for DHCP packet parsing.
#[derive(Debug, Error)]
pub enum DhcpParseError {
    #[error("Packet too short")]
    ShortPacket,
    #[error("Invalid operation code")]
    InvalidOp,
    #[error("Invalid hardware type")]
    InvalidHType,
    #[error("Invalid hardware length")]
    InvalidHLen,
}
