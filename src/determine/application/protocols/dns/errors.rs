use thiserror::Error;

use crate::determine::application::protocols::dns::dns_header::errors::DnsHeaderError;
use crate::determine::application::protocols::dns::dns_queries::errors::DnsQueryParseError;

#[derive(Debug, Error)]
pub enum DnsPacketError {
    #[error("Insufficient data: expected at least {expected} bytes, but got {actual}")]
    InsufficientData { expected: usize, actual: usize },
    #[error("DNS header parsing error: {0}")]
    HeaderError(#[from] DnsHeaderError),
    #[error("DNS Query parsing error: {0}")]
    QueryError(#[from] DnsQueryParseError),
}
