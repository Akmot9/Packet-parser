// dns_header/error.rs
use crate::parsed_packet::application::protocols::dns::dns_header::dns_flags::errors::DnsFlagsError;
use thiserror::Error;
#[derive(Debug, Error)]
pub enum DnsHeaderError {
    #[error("Packet too short to be a DNS packet")]
    PacketTooShort,
    #[error("Invalid DNS packet: non-zero resource record counts with zero questions")]
    InvalidCounts,
    #[error("DNS Flags parsing error: {0}")]
    FlagsError(#[from] DnsFlagsError),
}
