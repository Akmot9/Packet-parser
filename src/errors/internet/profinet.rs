use thiserror::Error;

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum ProfinetPacketError {
    #[error("Packet too short: minimum length required is 16 bytes, found {0} bytes")]
    PacketTooShort(usize),

    #[error("Unknown Frame ID: {0:#06x}")]
    UnknownFrameId(u16),

    #[error("Invalid DCP block length: expected at least 4 bytes, found {0} bytes")]
    InvalidDcpBlockLength(usize),

    #[error("Invalid name of station encoding")]
    InvalidNameOfStation,
}
