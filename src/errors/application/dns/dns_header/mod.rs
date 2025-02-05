// dns_header/error.rs
pub mod dns_flags;

use dns_flags::DnsFlagsError;
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
