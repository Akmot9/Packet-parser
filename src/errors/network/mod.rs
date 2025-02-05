use thiserror::Error;
pub mod protocol;
use protocol::NetworkProtocolError;

#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Data link too short: {0} bytes")]
    NetworkTooShort(u8),

    #[error("error decoding protocol")]
    ProtocolError,
}

// Implémente la conversion automatique
impl From<NetworkProtocolError> for NetworkError {
    fn from(_: NetworkProtocolError) -> Self {
        NetworkError::ProtocolError
    }
}

#[derive(Debug, Error, PartialEq)]
pub enum MRPParseError {
    #[error("Insufficient data for parsing, required at least {required} bytes, found {found}")]
    InsufficientData { required: usize, found: usize },

    #[error("Invalid UUID in MRPCommon TLV")]
    InvalidUUID,

    #[error("Unknown TLV type: {tlv_type:#04x}")]
    UnknownTLVType { tlv_type: u8 },
}
