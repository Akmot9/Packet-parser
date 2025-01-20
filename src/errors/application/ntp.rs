use thiserror::Error;

/// Error types for NTP packet parsing.
#[derive(Debug, Error)]
pub enum NtpPacketParseError {
    #[error("Invalid NTP packet length")] InvalidPacketLength,
    #[error("Invalid NTP version")] InvalidVersion,
    #[error("Invalid NTP mode")] InvalidMode,
    #[error("Invalid stratum")] InvalidStratum,
    #[error("Invalid poll interval")] InvalidPoll,
}
