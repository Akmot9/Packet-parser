use crate::{
    errors::application::tls::TlsParseError,
    parse::application::protocols::tls::{TlsContentType, TlsVersion},
};

/// Checks if the payload length is at least 5 bytes
pub fn check_minimum_length(payload: &[u8]) -> Result<(), TlsParseError> {
    if payload.len() < 5 {
        return Err(TlsParseError::TooShort);
    }
    Ok(())
}

/// Checks if the first byte matches any known TLS content type
pub fn check_content_type(payload: &[u8]) -> Result<TlsContentType, TlsParseError> {
    match payload[0] {
        20 => Ok(TlsContentType::ChangeCipherSpec),
        21 => Ok(TlsContentType::Alert),
        22 => Ok(TlsContentType::Handshake),
        23 => Ok(TlsContentType::ApplicationData),
        24 => Ok(TlsContentType::Heartbeat),
        _ => Err(TlsParseError::UnknownContentType(payload[0])),
    }
}

/// Checks if the second and third bytes match any valid TLS version
pub fn check_tls_version(payload: &[u8]) -> Result<TlsVersion, TlsParseError> {
    let version = TlsVersion {
        major: payload[1],
        minor: payload[2],
    };
    if VALID_TLS_VERSIONS.contains(&version) {
        Ok(version)
    } else {
        Err(TlsParseError::InvalidVersion(version.major, version.minor))
    }
}

// List of valid TLS versions
const VALID_TLS_VERSIONS: [TlsVersion; 4] = [
    TlsVersion { major: 3, minor: 1 }, // TLS 1.0
    TlsVersion { major: 3, minor: 2 }, // TLS 1.1
    TlsVersion { major: 3, minor: 3 }, // TLS 1.2
    TlsVersion { major: 3, minor: 4 }, // TLS 1.3
];

/// Extracts the length of the TLS payload from the fourth and fifth bytes
pub fn extract_length(payload: &[u8]) -> u16 {
    u16::from_be_bytes([payload[3], payload[4]])
}

/// Ensures the payload length is consistent with the actual data length
pub fn validate_payload_length(payload: &[u8], length: u16) -> Result<(), TlsParseError> {
    if payload.len() < (5 + length as usize) {
        Err(TlsParseError::LengthMismatch)
    } else {
        Ok(())
    }
}

/// Extracts the actual payload data
pub fn extract_payload(payload: &[u8], length: u16) -> Vec<u8> {
    payload[5..(5 + length as usize)].to_vec()
}
