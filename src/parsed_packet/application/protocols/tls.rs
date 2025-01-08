use std::fmt;

/// The `TlsPacket` struct represents a parsed TLS packet.
#[derive(Debug)]
pub struct TlsPacket {
    /// The content type of the TLS packet (e.g., Handshake, ApplicationData).
    pub content_type: TlsContentType,
    /// The TLS version of the packet.
    pub version: TlsVersion,
    /// The length of the payload.
    pub length: u16,
    /// The actual payload data.
    pub payload: Vec<u8>,
}

impl fmt::Display for TlsPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TLS Packet: content_type={}, version={}, length={}, payload={:02X?}",
            self.content_type, self.version, self.length, self.payload
        )
    }
}

/// The `TlsContentType` enum represents the possible content types of a TLS packet.
#[derive(Debug, PartialEq)]
pub enum TlsContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
    Heartbeat = 24,
}

impl fmt::Display for TlsContentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            TlsContentType::ChangeCipherSpec => "ChangeCipherSpec",
            TlsContentType::Alert => "Alert",
            TlsContentType::Handshake => "Handshake",
            TlsContentType::ApplicationData => "ApplicationData",
            TlsContentType::Heartbeat => "Heartbeat",
        };
        write!(f, "{}", s)
    }
}

/// The `TlsVersion` struct represents a TLS version with major and minor version numbers.
#[derive(Debug, PartialEq)]
pub struct TlsVersion {
    pub major: u8,
    pub minor: u8,
}

// List of valid TLS versions
const VALID_TLS_VERSIONS: [TlsVersion; 4] = [
    TlsVersion { major: 3, minor: 1 }, // TLS 1.0
    TlsVersion { major: 3, minor: 2 }, // TLS 1.1
    TlsVersion { major: 3, minor: 3 }, // TLS 1.2
    TlsVersion { major: 3, minor: 4 }, // TLS 1.3
];

impl fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let version = match (self.major, self.minor) {
            (3, 1) => "TLS 1.0",
            (3, 2) => "TLS 1.1",
            (3, 3) => "TLS 1.2",
            (3, 4) => "TLS 1.3",
            _ => return write!(f, "{}.{}", self.major, self.minor),
        };
        write!(f, "{}", version)
    }
}

/// Checks if the payload length is at least 5 bytes
fn check_minimum_length(payload: &[u8]) -> Result<(), bool> {
    if payload.len() < 5 {
        return Err(false);
    }
    Ok(())
}

/// Checks if the first byte matches any known TLS content type
fn check_content_type(payload: &[u8]) -> Result<TlsContentType, bool> {
    match payload[0] {
        20 => Ok(TlsContentType::ChangeCipherSpec),
        21 => Ok(TlsContentType::Alert),
        22 => Ok(TlsContentType::Handshake),
        23 => Ok(TlsContentType::ApplicationData),
        24 => Ok(TlsContentType::Heartbeat),
        _ => Err(false),
    }
}

/// Checks if the second and third bytes match any valid TLS version
fn check_tls_version(payload: &[u8]) -> Result<TlsVersion, bool> {
    let version = TlsVersion {
        major: payload[1],
        minor: payload[2],
    };
    if VALID_TLS_VERSIONS.contains(&version) {
        Ok(version)
    } else {
        Err(false)
    }
}

/// Extracts the length of the TLS payload from the fourth and fifth bytes
fn extract_length(payload: &[u8]) -> u16 {
    u16::from_be_bytes([payload[3], payload[4]])
}

/// Ensures the payload length is consistent with the actual data length
fn validate_payload_length(payload: &[u8], length: u16) -> Result<(), bool> {
    if payload.len() < (5 + length as usize) {
        return Err(false);
    }
    Ok(())
}

/// Extracts the actual payload data
fn extract_payload(payload: &[u8], length: u16) -> Vec<u8> {
    payload[5..(5 + length as usize)].to_vec()
}

/// Parses a TLS packet from a given payload.
///
/// # Arguments
///
/// * `payload` - A byte slice representing the raw TLS packet data.
///
/// # Returns
///
/// * `Result<TlsPacket, bool>` - Returns `Ok(TlsPacket)` if parsing is successful,
///   otherwise returns `Err(false)` indicating an invalid TLS packet.
pub fn parse_tls_packet(payload: &[u8]) -> Result<TlsPacket, bool> {
    check_minimum_length(payload)?;
    let content_type = check_content_type(payload)?;
    let version = check_tls_version(payload)?;
    let length = extract_length(payload);
    validate_payload_length(payload, length)?;
    let actual_payload = extract_payload(payload, length);

    Ok(TlsPacket {
        content_type,
        version,
        length,
        payload: actual_payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests for the `parse_tls_packet` function.
    #[test]
    fn test_parse_tls_packet() {
        // Test with a valid TLS packet
        let tls_payload = vec![22, 3, 3, 0, 5, 1, 2, 3, 4, 5]; // Handshake, TLS 1.2, length 5
        match parse_tls_packet(&tls_payload) {
            Ok(packet) => {
                assert_eq!(packet.content_type, TlsContentType::Handshake);
                assert_eq!(packet.version, TlsVersion { major: 3, minor: 3 });
                assert_eq!(packet.length, 5);
                assert_eq!(packet.payload, vec![1, 2, 3, 4, 5]);
            }
            Err(_) => panic!("Expected TLS packet"),
        }

        // Test with an invalid content type
        let invalid_content_type = vec![99, 3, 3, 0, 5, 1, 2, 3, 4, 5];
        match parse_tls_packet(&invalid_content_type) {
            Ok(_) => panic!("Expected non-TLS packet due to invalid content type"),
            Err(is_tls) => assert!(!is_tls),
        }

        // Test with an invalid TLS version
        let invalid_tls_version = vec![22, 3, 9, 0, 5, 1, 2, 3, 4, 5]; // Handshake, invalid TLS 1.3
        match parse_tls_packet(&invalid_tls_version) {
            Ok(_) => panic!("Expected non-TLS packet due to invalid TLS version"),
            Err(is_tls) => assert!(!is_tls),
        }

        // Test with an invalid length (inconsistent with payload length)
        let invalid_length = vec![22, 3, 3, 0, 6, 1, 2, 3, 4, 5]; // Handshake, TLS 1.2, length 6 (but only 5 bytes of actual data)
        match parse_tls_packet(&invalid_length) {
            Ok(_) => panic!("Expected non-TLS packet due to inconsistent length"),
            Err(is_tls) => assert!(!is_tls),
        }

        // Test with a payload length shorter than 5 bytes
        let short_payload = vec![22, 3, 3, 0]; // Only 4 bytes, should be at least 5
        match parse_tls_packet(&short_payload) {
            Ok(_) => panic!("Expected non-TLS packet due to short payload"),
            Err(is_tls) => assert!(!is_tls),
        }
    }

    #[test]
    fn test_check_minimum_length() {
        assert!(check_minimum_length(&vec![1, 2, 3, 4, 5]).is_ok());
        assert!(check_minimum_length(&vec![1, 2, 3, 4]).is_err());
    }

    #[test]
    fn test_check_content_type() {
        assert_eq!(
            check_content_type(&vec![22, 3, 3, 0, 5]).unwrap(),
            TlsContentType::Handshake
        );
        assert!(check_content_type(&vec![99, 3, 3, 0, 5]).is_err());
    }

    #[test]
    fn test_check_tls_version() {
        assert_eq!(
            check_tls_version(&vec![22, 3, 3, 0, 5]).unwrap(),
            TlsVersion { major: 3, minor: 3 }
        );
        assert!(check_tls_version(&vec![22, 3, 9, 0, 5]).is_err());
    }

    #[test]
    fn test_extract_length() {
        assert_eq!(extract_length(&vec![22, 3, 3, 0, 5]), 5);
    }

    #[test]
    fn test_validate_payload_length() {
        assert!(validate_payload_length(&vec![22, 3, 3, 0, 5, 1, 2, 3, 4, 5], 5).is_ok());
        assert!(validate_payload_length(&vec![22, 3, 3, 0, 6, 1, 2, 3, 4, 5], 6).is_err());
    }

    #[test]
    fn test_extract_payload() {
        assert_eq!(
            extract_payload(&vec![22, 3, 3, 0, 5, 1, 2, 3, 4, 5], 5),
            vec![1, 2, 3, 4, 5]
        );
    }
}
