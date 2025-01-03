use thiserror::Error;

#[derive(Debug, Error)]
pub enum DataLinkProtocolError {
    #[error("Le paquet est trop court pour déterminer le protocole.")]
    PacketTooShort,

    #[error("Protocole inconnu.")]
    UnknownProtocol,
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
