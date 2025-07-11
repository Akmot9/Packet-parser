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
        write!(f, "{s}")
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
    let mut bytes_used = 0; // Start at 1 to account for the first byte (packet type)

    // We need at least 2 bytes (packet type + at least 1 length byte)
    if payload.len() < 2 {
        return Err(false);
    }

    // Skip the first byte (packet type)
    for &byte in &payload[1..] {
        value += ((byte & 127) as u32) * multiplier;
        multiplier *= 128;
        bytes_used += 1;

        if byte & 128 == 0 {
            break;
        }

        // Prevent integer overflow and malformed packets
        if bytes_used > 4 {
            return Err(false);
        }

        // Make sure we don't go past the end of the payload
        if bytes_used >= payload.len() {
            return Err(false);
        }
    }

    // The header length is the packet type (1) + the number of bytes used for remaining length
    // But since bytes_used already includes the packet type, we can just use it as is
    Ok((value, bytes_used))
}

/// Extracts the variable header and payload
/// Extracts the variable header and payload based on the remaining_length and header_len
fn extract_variable_and_payload(
    payload: &[u8],
    remaining_length: u32,
    header_len: usize,
    packet_type: &MqttPacketType,
) -> Result<(Vec<u8>, Vec<u8>), bool> {
    println!(
        "extract_variable_and_payload - payload len: {}, remaining_length: {}, header_len: {}",
        payload.len(),
        remaining_length,
        header_len
    );

    if payload.len() < header_len {
        println!("Error: Payload too short for header_len ({header_len})");
        return Err(false);
    }

    let actual_remaining = payload.len() - header_len;
    if actual_remaining < remaining_length as usize {
        println!(
            "Error: actual remaining length ({actual_remaining}) is less than expected remaining_length ({remaining_length})",
        );
        return Err(false);
    }

    let variable_and_payload = &payload[header_len..header_len + remaining_length as usize];
    let variable_header_len = get_variable_header_length(packet_type, variable_and_payload);

    if variable_header_len > variable_and_payload.len() {
        println!(
            "Error: variable_header_len ({}) > variable_and_payload.len() ({})",
            variable_header_len,
            variable_and_payload.len()
        );
        return Err(false);
    }

    let (variable_header, payload_data) = variable_and_payload.split_at(variable_header_len);

    println!(
        "Extracted variable header ({} bytes): {:?}",
        variable_header.len(),
        variable_header
    );
    println!(
        "Extracted payload data ({} bytes): {:?}",
        payload_data.len(),
        payload_data
    );

    Ok((variable_header.to_vec(), payload_data.to_vec()))
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
    println!("Parsing MQTT packet. Payload length: {}", payload.len());
    println!("Payload: {payload:?}");

    check_minimum_length(payload)?;
    println!("Passed minimum length check");

    let packet_type = check_packet_type(payload)?;
    println!("Packet type: {packet_type:?}");

    let (remaining_length, remaining_length_bytes) = extract_remaining_length(payload)?;
    println!(
        "Remaining length: {remaining_length}, remaining_length_bytes: {remaining_length_bytes}"
    );

    let header_len = 1 + remaining_length_bytes;

    let (variable_header, payload_data) =
        extract_variable_and_payload(payload, remaining_length, header_len, &packet_type)?;
    println!("Successfully extracted variable header and payload");
    println!("Variable header: {variable_header:?}");
    println!("Payload data: {payload_data:?}");

    Ok(MqttPacket {
        fixed_header: MqttFixedHeader {
            packet_type,
            remaining_length,
        },
        variable_header,
        payload: payload_data,
    })
}

fn get_variable_header_length(packet_type: &MqttPacketType, data: &[u8]) -> usize {
    match packet_type {
        MqttPacketType::Connect => 10,
        MqttPacketType::Connack => 2,
        MqttPacketType::Publish => {
            if data.len() < 4 {
                return 0;
            }
            let topic_len = u16::from_be_bytes([data[0], data[1]]) as usize;
            2 + topic_len
        }
        MqttPacketType::Disconnect => 0,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mqtt_packet() {
        // Test with a valid MQTT packet (CONNECT)
        let mqtt_payload = vec![
            0x10, 0x0A, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3C,
        ];

        println!("Testing with MQTT CONNECT packet");
        match parse_mqtt_packet(&mqtt_payload) {
            Ok(packet) => {
                println!("Successfully parsed MQTT packet: {:?}", packet);
                assert_eq!(packet.fixed_header.packet_type, MqttPacketType::Connect);
                assert_eq!(packet.fixed_header.remaining_length, 10);
                assert_eq!(
                    packet.variable_header,
                    vec![0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3C]
                );
                assert_eq!(packet.payload, Vec::<u8>::new());
            }
            Err(e) => {
                println!("Failed to parse MQTT packet. Error: {}", e);
                panic!("Expected MQTT packet");
            }
        }

        // Test with an invalid packet type
        let invalid_packet_type = vec![0xF0, 0x00];
        match parse_mqtt_packet(&invalid_packet_type) {
            Ok(_) => panic!("Expected non-MQTT packet due to invalid packet type"),
            Err(is_mqtt) => assert!(!is_mqtt),
        }

        // Test with an invalid remaining length (malformed)
        let invalid_remaining_length = vec![0x10, 0xFF, 0xFF, 0xFF, 0xFF]; // Malformed remaining length
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
        assert_eq!(
            check_packet_type(&vec![0x10, 0x00]).unwrap(),
            MqttPacketType::Connect
        );
        assert!(check_packet_type(&vec![0xF0, 0x00]).is_err());
    }

    #[test]
    fn test_extract_remaining_length() {
        assert_eq!(extract_remaining_length(&vec![0x10, 0x00]).unwrap(), (0, 1));
        assert_eq!(
            extract_remaining_length(&vec![0x10, 0x7F]).unwrap(),
            (127, 1)
        );
        assert_eq!(
            extract_remaining_length(&vec![0x10, 0x80, 0x01]).unwrap(),
            (128, 2)
        );
        assert_eq!(
            extract_remaining_length(&vec![0x10, 0xFF, 0x7F]).unwrap(),
            (16383, 2)
        );
    }

    #[test]
    fn test_extract_variable_and_payload() {
        let payload = vec![
            0x10, 0x0A, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3C,
        ];

        // On doit appeler la fonction avec le bon type MQTT
        let packet_type = MqttPacketType::Connect;
        let (variable_header, payload_data) =
            extract_variable_and_payload(&payload, 10, 2, &packet_type).unwrap();

        assert_eq!(
            variable_header,
            vec![0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3C]
        );
        assert_eq!(payload_data, Vec::<u8>::new());
    }

    #[test]
    fn test_parse_mqtt_connect() {
        let payload = vec![
            0x10, 0x0C, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3C, 0x00, 0x00,
        ];
        let packet = parse_mqtt_packet(&payload).expect("Failed to parse CONNECT packet");
        assert_eq!(packet.fixed_header.packet_type, MqttPacketType::Connect);
        assert_eq!(packet.fixed_header.remaining_length, 12);
        assert_eq!(
            packet.variable_header,
            vec![0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3C]
        );
        assert_eq!(packet.payload, vec![0x00, 0x00]);
    }

    #[test]
    fn test_parse_mqtt_connack() {
        let payload = vec![0x20, 0x02, 0x00, 0x00];
        let packet = parse_mqtt_packet(&payload).expect("Failed to parse CONNACK packet");
        assert_eq!(packet.fixed_header.packet_type, MqttPacketType::Connack);
        assert_eq!(packet.fixed_header.remaining_length, 2);
        assert_eq!(packet.variable_header, vec![0x00, 0x00]);
    }

    #[test]
    fn test_parse_mqtt_publish() {
        let payload = vec![
            0x30, 0x1D, 0x00, 0x0B, b's', b'e', b'n', b's', b'o', b'r', b'/', b'd', b'a', b't',
            b'a', b'{', b'"', b's', b't', b'a', b't', b'u', b's', b'"', b':', b' ', b'"', b'O',
            b'K', b'"', b'}',
        ];
        let packet = parse_mqtt_packet(&payload).expect("Failed to parse PUBLISH packet");
        assert_eq!(packet.fixed_header.packet_type, MqttPacketType::Publish);
        assert_eq!(packet.fixed_header.remaining_length, 29);
        assert_eq!(
            packet.variable_header,
            vec![
                0x00, 0x0B, b's', b'e', b'n', b's', b'o', b'r', b'/', b'd', b'a', b't', b'a'
            ]
        );
        assert_eq!(
            packet.payload,
            vec![
                b'{', b'"', b's', b't', b'a', b't', b'u', b's', b'"', b':', b' ', b'"', b'O', b'K',
                b'"', b'}'
            ]
        );
    }

    #[test]
    fn test_parse_mqtt_disconnect() {
        let payload = vec![0xE0, 0x00];
        let packet = parse_mqtt_packet(&payload).expect("Failed to parse DISCONNECT packet");
        assert_eq!(packet.fixed_header.packet_type, MqttPacketType::Disconnect);
        assert_eq!(packet.fixed_header.remaining_length, 0);
        assert_eq!(packet.variable_header, Vec::<u8>::new());
        assert_eq!(packet.payload, Vec::<u8>::new());
    }
}
