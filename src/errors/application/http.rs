use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HttpParseError {
    #[error("Invalid UTF-8 in HTTP request")]
    InvalidUtf8,

    #[error("Missing HTTP request line")]
    MissingRequestLine,

    #[error("Missing HTTP method")]
    MissingMethod,

    #[error("Missing HTTP URI")]
    MissingUri,

    #[error("Missing HTTP version")]
    MissingVersion,

    #[error("Invalid HTTP header")]
    InvalidHeader,
}
