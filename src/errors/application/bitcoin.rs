use thiserror::Error;

#[derive(Error, Debug)]
pub enum BitcoinPacketError {
    #[error("Payload too short: {0} bytes (minimum required: 24)")]
    PayloadTooShort(usize),

    #[error("Invalid magic number: {0:#X}")]
    InvalidMagicNumber(u32),

    #[error("Invalid command: {0}")]
    InvalidCommand(String),

    #[error("Payload length mismatch: expected {expected}, found {found}")]
    LengthMismatch { expected: u32, found: usize },

    #[error("Failed UTF-8 conversion")]
    Utf8Error(#[from] std::string::FromUtf8Error),
}
