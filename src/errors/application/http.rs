use thiserror::Error;

/// Error types for HTTP request parsing.
#[derive(Debug, Error)]
pub enum HttpRequestParseError {
    #[error("Invalid request line")]
    InvalidRequestLine,
    #[error("Invalid header format")]
    InvalidHeader,
}
