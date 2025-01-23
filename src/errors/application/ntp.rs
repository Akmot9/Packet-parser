use thiserror::Error;

/// Error types for NTP packet parsing.
#[derive(Debug, Error)]
pub enum NtpPacketParseError {
    #[error("Invalid NTP packet length")]
    InvalidPacketLength,
    #[error("Invalid NTP version: {version}")]
    InvalidVersion { version: u8 },

    #[error("Invalid NTP mode: {mode}")]
    InvalidMode { mode: u8 },
    #[error("Invalid stratum")]
    InvalidStratum,
    #[error("Invalid poll interval")]
    InvalidPoll,
}
