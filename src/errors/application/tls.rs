use thiserror::Error;

#[derive(Error, Debug)]
pub enum TlsParseError {
    #[error("Payload too short to be a TLS packet")]
    TooShort,

    #[error("Unknown TLS content type: {0}")]
    UnknownContentType(u8),

    #[error("Invalid TLS version: {0}.{1}")]
    InvalidVersion(u8, u8),

    #[error("Payload length mismatch")]
    LengthMismatch,
}
