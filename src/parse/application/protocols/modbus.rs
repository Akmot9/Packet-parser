use std::fmt;

/// The `ModbusPacket` struct represents a parsed Modbus packet.
#[derive(Debug)]
pub struct ModbusPacket {
    /// The transaction identifier of the Modbus packet.
    pub transaction_id: u16,
    /// The protocol identifier of the Modbus packet.
    pub protocol_id: u16,
    /// The length of the remaining bytes in the packet.
    pub length: u16,
    /// The unit identifier of the Modbus packet.
    pub unit_id: u8,
    /// The function code of the Modbus packet.
    pub function_code: u8,
    /// The actual data of the Modbus packet.
    pub data: Vec<u8>,
}

impl fmt::Display for ModbusPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Modbus Packet: transaction_id={}, protocol_id={}, length={}, unit_id={}, function_code={}, data={:02X?}",
            self.transaction_id, self.protocol_id, self.length, self.unit_id, self.function_code, self.data
        )
    }
}

/// Checks if the payload length is at least 8 bytes for a Modbus packet
fn check_minimum_length(payload: &[u8]) -> Result<(), bool> {
    if payload.len() < 8 {
        return Err(false);
    }
    Ok(())
}

/// Extracts the transaction ID from the payload
fn extract_transaction_id(payload: &[u8]) -> u16 {
    u16::from_be_bytes([payload[0], payload[1]])
}

/// Extracts the protocol ID from the payload
fn extract_protocol_id(payload: &[u8]) -> u16 {
    u16::from_be_bytes([payload[2], payload[3]])
}

/// Extracts the length of the Modbus payload from the payload
fn extract_length(payload: &[u8]) -> u16 {
    u16::from_be_bytes([payload[4], payload[5]])
}

/// Extracts the unit ID from the payload
fn extract_unit_id(payload: &[u8]) -> u8 {
    payload[6]
}

/// Extracts the function code from the payload
fn extract_function_code(payload: &[u8]) -> u8 {
    payload[7]
}

/// Extracts the actual payload data
fn extract_data(payload: &[u8]) -> Vec<u8> {
    payload[8..].to_vec()
}

/// Verifies if the protocol identifier is 0x0000
fn check_protocol_id(protocol_id: u16) -> Result<(), bool> {
    if protocol_id != 0x0000 {
        return Err(false);
    }
    Ok(())
}

/// Verifies if the function code is a valid Modbus function code
fn check_function_code(function_code: u8) -> Result<(), bool> {
    let valid_function_codes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0F, 0x10];
    if !valid_function_codes.contains(&function_code) {
        return Err(false);
    }
    Ok(())
}

/// Parses a Modbus packet from a given payload.
///
/// # Arguments
///
/// * `payload` - A byte slice representing the raw Modbus packet data.
///
/// # Returns
///
/// * `Result<ModbusPacket, bool>` - Returns `Ok(ModbusPacket)` if parsing is successful,
///   otherwise returns `Err(false)` indicating an invalid Modbus packet.
pub fn parse_modbus_packet(payload: &[u8]) -> Result<ModbusPacket, bool> {
    check_minimum_length(payload)?;
    let transaction_id = extract_transaction_id(payload);
    let protocol_id = extract_protocol_id(payload);
    check_protocol_id(protocol_id)?;
    let length = extract_length(payload);
    let unit_id = extract_unit_id(payload);
    let function_code = extract_function_code(payload);
    check_function_code(function_code)?;
    let data = extract_data(payload);

    Ok(ModbusPacket {
        transaction_id,
        protocol_id,
        length,
        unit_id,
        function_code,
        data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_modbus_packet() {
        // Test with a valid Modbus packet
        let modbus_payload = vec![
            0x5A, 0x3C, 0x00, 0x00, 0x00, 0x06, 0x11, 0x03, 0x02, 0x04, 0x00, 0x01,
        ];
        match parse_modbus_packet(&modbus_payload) {
            Ok(packet) => {
                assert_eq!(packet.transaction_id, 0x5A3C);
                assert_eq!(packet.protocol_id, 0x0000);
                assert_eq!(packet.length, 6);
                assert_eq!(packet.unit_id, 0x11);
                assert_eq!(packet.function_code, 0x03);
                assert_eq!(packet.data, vec![0x02, 0x04, 0x00, 0x01]);
            }
            Err(_) => panic!("Expected Modbus packet"),
        }

        // Test with an invalid Modbus packet (too short)
        let short_payload = vec![0x5A, 0x3C];
        match parse_modbus_packet(&short_payload) {
            Ok(_) => panic!("Expected non-Modbus packet due to short payload"),
            Err(is_modbus) => assert!(!is_modbus),
        }

        // Test with an invalid Modbus packet (incorrect protocol id)
        let invalid_protocol_id_payload = vec![
            0x5A, 0x3C, 0x00, 0x01, 0x00, 0x06, 0x11, 0x03, 0x02, 0x04, 0x00, 0x01,
        ];
        match parse_modbus_packet(&invalid_protocol_id_payload) {
            Ok(_) => panic!("Expected non-Modbus packet due to invalid protocol id"),
            Err(is_modbus) => assert!(!is_modbus),
        }

        // Test with an invalid Modbus packet (invalid function code)
        let invalid_function_code_payload = vec![
            0x5A, 0x3C, 0x00, 0x00, 0x00, 0x06, 0x11, 0xFF, 0x02, 0x04, 0x00, 0x01,
        ];
        match parse_modbus_packet(&invalid_function_code_payload) {
            Ok(_) => panic!("Expected non-Modbus packet due to invalid function code"),
            Err(is_modbus) => assert!(!is_modbus),
        }
    }

    #[test]
    fn test_check_minimum_length() {
        assert!(check_minimum_length(&vec![1, 2, 3, 4, 5, 6, 7, 8]).is_ok());
        assert!(check_minimum_length(&vec![1, 2, 3, 4, 5, 6, 7]).is_err());
    }

    #[test]
    fn test_extract_transaction_id() {
        assert_eq!(
            extract_transaction_id(&vec![0x5A, 0x3C, 0x00, 0x00, 0x00, 0x06, 0x11, 0x03]),
            0x5A3C
        );
    }

    #[test]
    fn test_extract_protocol_id() {
        assert_eq!(
            extract_protocol_id(&vec![0x5A, 0x3C, 0x00, 0x00, 0x00, 0x06, 0x11, 0x03]),
            0x0000
        );
    }

    #[test]
    fn test_extract_length() {
        assert_eq!(
            extract_length(&vec![0x5A, 0x3C, 0x00, 0x00, 0x00, 0x06, 0x11, 0x03]),
            6
        );
    }

    #[test]
    fn test_extract_unit_id() {
        assert_eq!(
            extract_unit_id(&vec![0x5A, 0x3C, 0x00, 0x00, 0x00, 0x06, 0x11, 0x03]),
            0x11
        );
    }

    #[test]
    fn test_extract_function_code() {
        assert_eq!(
            extract_function_code(&vec![0x5A, 0x3C, 0x00, 0x00, 0x00, 0x06, 0x11, 0x03]),
            0x03
        );
    }

    #[test]
    fn test_extract_data() {
        assert_eq!(
            extract_data(&vec![
                0x5A, 0x3C, 0x00, 0x00, 0x00, 0x06, 0x11, 0x03, 0x02, 0x04, 0x00, 0x01
            ]),
            vec![0x02, 0x04, 0x00, 0x01]
        );
    }
}
