use dns_header::DnsHeaderError;
use dns_queries::DnsQueryParseError;
use thiserror::Error;
pub mod dns_queries;
pub mod dns_header;

#[derive(Debug, Error)]
pub enum DnsPacketError {
    #[error("Insufficient data: expected at least {expected} bytes, but got {actual}")]
    InsufficientData { expected: usize, actual: usize },
    #[error("DNS header parsing error: {0}")]
    HeaderError(#[from] DnsHeaderError),
    #[error("DNS Query parsing error: {0}")]
    QueryError(#[from] DnsQueryParseError),
}
