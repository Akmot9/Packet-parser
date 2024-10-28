use thiserror::Error;

use super::data_link::DataLinkError;

#[derive(Error, Debug)]
pub enum ParsedPacketError {
    #[error("Packet too short: {0} bytes")]
    PacketTooShort(u8),
    #[error("Invalid DataLink segment")]
    InvalidDataLink,
}

// Implémente la conversion automatique
impl From<DataLinkError> for ParsedPacketError {
    fn from(_: DataLinkError) -> Self {
        ParsedPacketError::InvalidDataLink
    }
}