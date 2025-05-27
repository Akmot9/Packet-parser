use std::fmt;

/// The `BitcoinPacket` struct represents a parsed Bitcoin packet.
#[derive(Debug)]
pub struct BitcoinPacket {
    pub magic: u32,
    pub command: String,
    pub length: u32,
    pub checksum: [u8; 4],
    pub payload: Vec<u8>,
}

impl fmt::Display for BitcoinPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Bitcoin Packet: magic={:02X?}, command={}, length={}, checksum={:02X?}, payload={:02X?}",
            self.magic, self.command, self.length, self.checksum, self.payload
        )
    }
}

/// List of valid magic numbers for different Bitcoin networks
const VALID_MAGIC_NUMBERS: [u32; 5] = [
    0xD9B4BEF9, // Mainnet
    0x0709110B, // Testnet
    0x0B110907, // Testnet3
    0xFABFB5DA, // Regtest
    0x40CF030A, // Signet
];

/// Checks if the payload length is at least 24 bytes (minimum length of a Bitcoin packet header)
fn check_minimum_length(payload: &[u8]) -> Result<(), bool> {
    if payload.len() < 24 {
        // println!("Payload too short: {}", payload.len());
        return Err(false);
    }
    Ok(())
}

/// Checks if the first 4 bytes match any known Bitcoin network magic number
fn check_magic_number(payload: &[u8]) -> Result<u32, bool> {
    let magic = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    if VALID_MAGIC_NUMBERS.contains(&magic) {
        Ok(magic)
    } else {
        // println!("Invalid magic number: {:02X?}", magic);
        Err(false)
    }
}

/// Checks if the command contains only valid ASCII characters (alphanumeric and null-padded)
fn is_valid_command(command: &str) -> bool {
    command
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '\0')
}

/// Extracts the command string from the payload (12 bytes, null-padded ASCII)
fn extract_command(payload: &[u8]) -> Result<String, bool> {
    let mut command = vec![0; 12];
    command.copy_from_slice(&payload[4..16]);
    let command_string = String::from_utf8(command).unwrap();
    let command_trimmed = command_string.trim_end_matches('\u{0}').to_string();

    if is_valid_command(&command_trimmed) {
        Ok(command_trimmed)
    } else {
        // println!("Invalid command: {}", command_trimmed);
        Err(false)
    }
}

/// Extracts the length of the payload from the header (4 bytes)
fn extract_length(payload: &[u8]) -> u32 {
    u32::from_le_bytes([payload[16], payload[17], payload[18], payload[19]])
}

/// Extracts the checksum from the header (4 bytes)
fn extract_checksum(payload: &[u8]) -> [u8; 4] {
    [payload[20], payload[21], payload[22], payload[23]]
}

/// Ensures the payload length is consistent with the actual data length
fn validate_actual_payload_length(payload: &[u8], length: u32) -> Result<(), bool> {
    if payload.len() != length as usize {
        // println!(
        //     "Payload length inconsistent: expected {}, got {}",
        //     length,
        //     payload.len()
        // );
        return Err(false);
    }
    Ok(())
}

/// Extracts the actual payload data
fn extract_payload(payload: &[u8]) -> Vec<u8> {
    payload[24..].to_vec()
}

/// Parses a Bitcoin packet from a given payload.
///
/// # Arguments
///
/// * `payload` - A byte slice representing the raw Bitcoin packet data.
///
/// # Returns
///
/// * `Result<BitcoinPacket, bool>` - Returns `Ok(BitcoinPacket)` if parsing is successful,
///   otherwise returns `Err(false)` indicating an invalid Bitcoin packet.
pub fn parse_bitcoin_packet(payload: &[u8]) -> Result<BitcoinPacket, bool> {
    check_minimum_length(payload)?;
    let magic = check_magic_number(payload)?;
    let command = extract_command(payload)?;
    let length = extract_length(payload);
    let checksum = extract_checksum(payload);

    let actual_payload = extract_payload(payload);
    validate_actual_payload_length(&actual_payload, length)?;

    Ok(BitcoinPacket {
        magic,
        command,
        length,
        checksum,
        payload: actual_payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_checksum() {
        // Test with a valid payload containing a known checksum
        let payload = vec![
            0xF9, 0xBE, 0xB4, 0xD9, // Magic number (mainnet)
            0x76, 0x65, 0x72, 0x61, 0x63, 0x6B, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // Command ("verack")
            0x00, 0x00, 0x00, 0x00, // Length (0)
            0x5D, 0xF6, 0xE0, 0xE2, // Checksum (example)
        ];
        let expected_checksum = [0x5D, 0xF6, 0xE0, 0xE2];
        let extracted_checksum = extract_checksum(&payload);
        assert_eq!(extracted_checksum, expected_checksum);
    }

    #[test]
    fn test_extract_checksum_incorrect_length() {
        // Test with a payload shorter than required length for checksum extraction
        let payload = vec![0xF9, 0xBE, 0xB4]; // Only 3 bytes, should fail
        let result = std::panic::catch_unwind(|| extract_checksum(&payload));
        assert!(
            result.is_err(),
            "Expected panic due to short payload length"
        );
    }

    /// Tests for the `parse_bitcoin_packet` function.

    #[test]
    fn test_valid_bitcoin_packet() {
        // Test with a valid Bitcoin packet (simplified example)
        let bitcoin_payload = vec![
            0xF9, 0xBE, 0xB4, 0xD9, // Magic number (mainnet)
            0x76, 0x65, 0x72, 0x61, 0x63, 0x6B, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // Command ("verack")
            0x00, 0x00, 0x00, 0x00, // Length (0)
            0x5D, 0xF6, 0xE0, 0xE2, // Checksum (example)
        ];
        match parse_bitcoin_packet(&bitcoin_payload) {
            Ok(packet) => {
                assert_eq!(packet.magic, 3652501241);
                assert_eq!(packet.command, "verack");
                assert_eq!(packet.length, 0);
                assert_eq!(packet.checksum, [0x5D, 0xF6, 0xE0, 0xE2]);
                assert_eq!(packet.payload.len(), 0);
            }
            Err(_) => panic!("Expected Bitcoin packet"),
        }
    }

    #[test]
    fn test_invalid_magic_number() {
        // Test with an invalid magic number
        let invalid_magic_number = vec![
            0x99, 0xBE, 0xB4, 0xD9, // Invalid magic number
            0x76, 0x65, 0x72, 0x61, 0x63, 0x6B, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // Command ("verack")
            0x00, 0x00, 0x00, 0x00, // Length (0)
            0x5D, 0xF6, 0xE0, 0xE2, // Checksum (example)
        ];
        match parse_bitcoin_packet(&invalid_magic_number) {
            Ok(_) => assert!(
                false,
                "Expected non-Bitcoin packet due to invalid magic number"
            ),
            Err(is_bitcoin) => assert!(!is_bitcoin),
        }
    }

    #[test]
    fn test_short_payload() {
        // Test with a payload length shorter than 24 bytes
        let short_payload = vec![0xF9, 0xBE, 0xB4]; // Only 3 bytes, should be at least 24
        match parse_bitcoin_packet(&short_payload) {
            Ok(_) => assert!(false, "Expected non-Bitcoin packet due to short payload"),
            Err(is_bitcoin) => assert!(!is_bitcoin),
        }
    }

    #[test]
    fn test_invalid_length() {
        // Test with an invalid length (inconsistent with payload length)
        let invalid_length = vec![
            0xF9, 0xBE, 0xB4, 0xD9, // Magic number (mainnet)
            0x76, 0x65, 0x72, 0x61, 0x63, 0x6B, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // Command ("verack")
            0x05, 0x00, 0x00, 0x00, // Length (5)
        ];
        match parse_bitcoin_packet(&invalid_length) {
            Ok(_) => assert!(false,"Expected non-Bitcoin packet due to inconsistent length => length of the tested packet: {}", invalid_length.len()),
            Err(is_bitcoin) => assert!(!is_bitcoin),
        }
    }

    #[test]
    fn test_check_minimum_length() {
        assert!(check_minimum_length(&vec![0; 24]).is_ok());
        assert!(check_minimum_length(&vec![0; 23]).is_err());
    }

    #[test]
    fn test_check_magic_number() {
        assert_eq!(
            check_magic_number(&vec![0xF9, 0xBE, 0xB4, 0xD9]).unwrap(),
            0xD9B4BEF9
        );
        assert!(check_magic_number(&vec![0x99, 0xBE, 0xB4, 0xD9]).is_err());
    }

    #[test]
    fn test_extract_command() {
        assert_eq!(
            extract_command(&vec![
                0xF9, 0xBE, 0xB4, 0xD9, 0x76, 0x65, 0x72, 0x61, 0x63, 0x6B, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00
            ])
            .unwrap(),
            "verack"
        );
    }

    #[test]
    fn test_extract_length() {
        assert_eq!(
            extract_length(&vec![
                0xF9, 0xBE, 0xB4, 0xD9, // Magic number (4 bytes)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, // Command (12 bytes)
                0x05, 0x00, 0x00, 0x00, // Length (4 bytes, little-endian, 5 in this case)
            ]),
            5
        );
    }

    #[test]
    fn test_extract_payload() {
        assert_eq!(
            extract_payload(&vec![
                0xF9, 0xBE, 0xB4, 0xD9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
                0x05
            ]),
            vec![0x01, 0x02, 0x03, 0x04, 0x05]
        );
    }
}
