use crate::{errors::application::tls::TlsParseError, protocols::application::tls::{
        check_content_type, check_minimum_length, check_tls_version, extract_length, extract_payload, validate_payload_length
    }};

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

/// The `TlsContentType` enum represents the possible content types of a TLS packet.
#[derive(Debug, PartialEq)]
pub enum TlsContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
    Heartbeat = 24,
}

/// The `TlsVersion` struct represents a TLS version with major and minor version numbers.
#[derive(Debug, PartialEq)]
pub struct TlsVersion {
    pub major: u8,
    pub minor: u8,
}


impl TryFrom<&[u8]> for TlsPacket {
    type Error = TlsParseError;
    
    fn try_from(payload: &[u8]) -> Result<Self, Self::Error> {
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
