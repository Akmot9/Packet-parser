use thiserror::Error;

#[derive(Debug, Error)]
pub enum DnsQueryParseError {
    #[error("Insufficient data: required {required} more bytes at offset {offset}, but only {available} bytes available")]
    InsufficientData {
        required: usize,
        offset: usize,
        available: usize,
    },
    #[error("Out of bound parse")]
    OutOfBoundParse,
    #[error("UTF-8 parsing error: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),
}
