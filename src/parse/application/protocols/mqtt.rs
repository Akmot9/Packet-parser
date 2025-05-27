use std::fmt;

/// The `MqttPacket` struct represents a parsed MQTT packet.
#[derive(Debug)]
pub struct MqttPacket {
    /// The fixed header of the MQTT packet.
    pub fixed_header: MqttFixedHeader,
    /// The variable header of the MQTT packet.
    pub variable_header: Vec<u8>,
    /// The payload of the MQTT packet.
    pub payload: Vec<u8>,
}

impl fmt::Display for MqttPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MQTT Packet: fixed_header={}, variable_header={:02X?}, payload={:02X?}",
            self.fixed_header, self.variable_header, self.payload
        )
    }
}

/// The `MqttFixedHeader` struct represents the fixed header of an MQTT packet.
#[derive(Debug, PartialEq)]
pub struct MqttFixedHeader {
    pub packet_type: MqttPacketType,
    pub remaining_length: u32,
}

impl fmt::Display for MqttFixedHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "packet_type={}, remaining_length={}",
            self.packet_type, self.remaining_length
        )
    }
}

/// The `MqttPacketType` enum represents the possible types of an MQTT packet.
#[derive(Debug, PartialEq)]
pub enum MqttPacketType {
    Connect = 1,
    Connack,
    Publish,
    Puback,
    Pubrec,
    Pubrel,
    Pubcomp,
    Subscribe,
    Suback,
    Unsubscribe,
    Unsuback,
    Pingreq,
    Pingresp,
    Disconnect,
}

impl fmt::Display for MqttPacketType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            MqttPacketType::Connect => "CONNECT",
            MqttPacketType::Connack => "CONNACK",
            MqttPacketType::Publish => "PUBLISH",
            MqttPacketType::Puback => "PUBACK",
            MqttPacketType::Pubrec => "PUBREC",
            MqttPacketType::Pubrel => "PUBREL",
            MqttPacketType::Pubcomp => "PUBCOMP",
            MqttPacketType::Subscribe => "SUBSCRIBE",
            MqttPacketType::Suback => "SUBACK",
            MqttPacketType::Unsubscribe => "UNSUBSCRIBE",
            MqttPacketType::Unsuback => "UNSUBACK",
            MqttPacketType::Pingreq => "PINGREQ",
            MqttPacketType::Pingresp => "PINGRESP",
            MqttPacketType::Disconnect => "DISCONNECT",
        };
        write!(f, "{}", s)
    }
}

/// Checks if the payload length is at least 2 bytes (minimum size for fixed header)
fn check_minimum_length(payload: &[u8]) -> Result<(), bool> {
    if payload.len() < 2 {
        return Err(false);
    }
    Ok(())
}

/// Checks if the first byte matches any known MQTT packet type
fn check_packet_type(payload: &[u8]) -> Result<MqttPacketType, bool> {
    match payload[0] >> 4 {
        1 => Ok(MqttPacketType::Connect),
        2 => Ok(MqttPacketType::Connack),
        3 => Ok(MqttPacketType::Publish),
        4 => Ok(MqttPacketType::Puback),
        5 => Ok(MqttPacketType::Pubrec),
        6 => Ok(MqttPacketType::Pubrel),
        7 => Ok(MqttPacketType::Pubcomp),
        8 => Ok(MqttPacketType::Subscribe),
        9 => Ok(MqttPacketType::Suback),
        10 => Ok(MqttPacketType::Unsubscribe),
        11 => Ok(MqttPacketType::Unsuback),
        12 => Ok(MqttPacketType::Pingreq),
        13 => Ok(MqttPacketType::Pingresp),
        14 => Ok(MqttPacketType::Disconnect),
        _ => Err(false),
    }
}

/// Extracts the remaining length from the fixed header
fn extract_remaining_length(payload: &[u8]) -> Result<(u32, usize), bool> {
    let mut multiplier = 1;
    let mut value = 0;
    let mut bytes_used = 0;

    for (i, &byte) in payload[1..].iter().enumerate() {
        value += ((byte & 127) as u32) * multiplier;
        multiplier *= 128;
        bytes_used = i + 1;
        if byte & 128 == 0 {
            break;
        }
    }

    if bytes_used == 0 {
        return Err(false);
    }

    Ok((value, bytes_used + 1))
}

/// Extracts the variable header and payload
fn extract_variable_and_payload(payload: &[u8], remaining_length: u32, header_len: usize) -> Result<(Vec<u8>, Vec<u8>), bool> {
    if payload.len() < header_len + remaining_length as usize {
        return Err(false);
    }

    let variable_header = payload[header_len..(header_len + remaining_length as usize)].to_vec();
    let payload_data = payload[(header_len + remaining_length as usize)..].to_vec();

    Ok((variable_header, payload_data))
}

/// Parses an MQTT packet from a given payload.
///
/// # Arguments
///
/// * `payload` - A byte slice representing the raw MQTT packet data.
///
/// # Returns
///
/// * `Result<MqttPacket, bool>` - Returns `Ok(MqttPacket)` if parsing is successful,
///   otherwise returns `Err(false)` indicating an invalid MQTT packet.
pub fn parse_mqtt_packet(payload: &[u8]) -> Result<MqttPacket, bool> {
    check_minimum_length(payload)?;
    let packet_type = check_packet_type(payload)?;
    let (remaining_length, header_len) = extract_remaining_length(payload)?;
    let (variable_header, payload_data) = extract_variable_and_payload(payload, remaining_length, header_len)?;

    Ok(MqttPacket {
        fixed_header: MqttFixedHeader {
            packet_type,
            remaining_length,
        },
        variable_header,
        payload: payload_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mqtt_packet() {
        // Test with a valid MQTT packet (CONNECT)
        let mqtt_payload = vec![0x10, 0x0C, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3C];
        match parse_mqtt_packet(&mqtt_payload) {
            Ok(packet) => {
                assert_eq!(packet.fixed_header.packet_type, MqttPacketType::Connect);
                assert_eq!(packet.fixed_header.remaining_length, 12);
                assert_eq!(packet.variable_header, vec![0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3C]);
                assert_eq!(packet.payload, vec![]);
            }
            Err(_) => panic!("Expected MQTT packet"),
        }

        // Test with an invalid packet type
        let invalid_packet_type = vec![0xF0, 0x00];
        match parse_mqtt_packet(&invalid_packet_type) {
            Ok(_) => panic!("Expected non-MQTT packet due to invalid packet type"),
            Err(is_mqtt) => assert!(!is_mqtt),
        }

        // Test with an invalid remaining length
        let invalid_remaining_length = vec![0x10, 0xFF, 0xFF, 0xFF, 0xFF]; // Incorrect remaining length encoding
        match parse_mqtt_packet(&invalid_remaining_length) {
            Ok(_) => panic!("Expected non-MQTT packet due to invalid remaining length"),
            Err(is_mqtt) => assert!(!is_mqtt),
        }

        // Test with a payload length shorter than required
        let short_payload = vec![0x10]; // Only 1 byte, should be at least 2
        match parse_mqtt_packet(&short_payload) {
            Ok(_) => panic!("Expected non-MQTT packet due to short payload"),
            Err(is_mqtt) => assert!(!is_mqtt),
        }
    }

    #[test]
    fn test_check_minimum_length() {
        assert!(check_minimum_length(&vec![0x10, 0x00]).is_ok());
        assert!(check_minimum_length(&vec![0x10]).is_err());
    }

    #[test]
    fn test_check_packet_type() {
        assert_eq!(check_packet_type(&vec![0x10, 0x00]).unwrap(), MqttPacketType::Connect);
        assert!(check_packet_type(&vec![0xF0, 0x00]).is_err());
    }

    #[test]
    fn test_extract_remaining_length() {
        assert_eq!(extract_remaining_length(&vec![0x10, 0x00]).unwrap(), (0, 2));
        assert_eq!(extract_remaining_length(&vec![0x10, 0x7F]).unwrap(), (127, 2));
        assert_eq!(extract_remaining_length(&vec![0x10, 0x80, 0x01]).unwrap(), (128, 3));
        assert_eq!(extract_remaining_length(&vec![0x10, 0xFF, 0x7F]).unwrap(), (16383, 3));
    }

    #[test]
    fn test_extract_variable_and_payload() {
        let payload = vec![0x10, 0x0C, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3C];
        let (variable_header, payload_data) = extract_variable_and_payload(&payload, 12, 2).unwrap();
        assert_eq!(variable_header, vec![0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3C]);
        assert_eq!(payload_data, vec![]);
    }
}
