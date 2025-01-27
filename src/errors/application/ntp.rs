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
    #[error("Failed to parse NTP timestamp")]
    InvalidTime,
    #[error("La taille du timestamp NTP est incorrecte. Attendu: 8 octets, Reçu: {received}")]
    InvalidTimestampSize { received: usize },
    #[error("Erreur lors de la conversion du timestamp NTP en `DateTime<Utc>`. Unix Seconds: {seconds}, Nanos: {nanos}")]
    TimestampConversionError { seconds: i64, nanos: u32 },
    #[error("NTP timestamps are not in ascending order: Originate ≤ Receive ≤ Transmit violated")]
    InconsistentTimestamps,
}
