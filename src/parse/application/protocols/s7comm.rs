// Copyright (c) 2025 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use std::fmt;

/// Represents an S7Comm packet
#[derive(Debug)]
pub struct S7CommPacket<'a> {
    /// TPKT Header (RFC 1006)
    pub tpkt: TpktHeader,

    /// COTP Header (ISO 8073 / X.224)
    pub cotp: CotpHeader,

    /// S7 Communication Header (S7Comm)
    pub s7_header: S7Header,

    /// S7 Parameter (ex: Read Var, Write Var, etc.)
    pub parameter: S7Parameter<'a>,

    /// Données supplémentaires (optionnel)
    pub payload: Option<&'a [u8]>,
}

/// TPKT Header (4 octets)
#[derive(Debug)]
pub struct TpktHeader {
    pub version: u8,  // Devrait être 3
    pub reserved: u8, // Devrait être 0
    pub length: u16,  // Taille totale du TPKT
}

/// COTP Header (au minimum 3 octets pour Data TPDU)
#[derive(Debug)]
pub struct CotpHeader {
    pub length: u8,                 // Longueur du header (ex: 2)
    pub pdu_type: u8,               // 0xF0 = Data TPDU
    pub destination_reference: u16, // Destination Reference (0x0000)
    pub source_reference: u16,      // Source Reference (0x0000)
    pub last_data_unit: bool,       // Dernier paquet (bit 0x01)
}

/// S7 Header (S7Comm PDU)
#[derive(Debug)]
pub struct S7Header {
    pub protocol_id: u8,         // 0x32
    pub rosctr: u8,              // Type de message (0x01 = Job, 0x03 = Ack, etc.)
    pub reserved: u16,           // 0x0000
    pub pduref: u16,             // PDU Reference ID
    pub parameter_length: u16,   // Taille de la section Parameter
    pub data_length: u16,        // Taille de la section Data (optionnel)
    pub error_class: Option<u8>, // Pour ACK/Error uniquement
    pub error_code: Option<u8>,  // Pour ACK/Error uniquement
}

/// Paramètres S7 (Read Var, Write Var, etc.)
#[derive(Debug)]
pub struct S7Parameter<'a> {
    pub function: u8, // Exemple: 0x04 = Read Var
    pub items: Vec<S7ParameterItem<'a>>,
}

/// Item dans les paramètres S7 (Read Var, Write Var)
#[derive(Debug)]
pub struct S7ParameterItem<'a> {
    pub spec_type: u8,         // 0x12 = Variable Specification
    pub length: u8,            // Longueur de la spec (ex: 0x0A)
    pub syntax_id: u8,         // 0x10 = S7ANY
    pub transport_size: u8,    // 0x02 = BYTE
    pub db_number: u16,        // Numéro du bloc de données (DB)
    pub area: u8,              // Zone mémoire (0x83 = DB)
    pub address: u32,          // Adresse (calculée sur 3 octets)
    pub raw: Option<&'a [u8]>, // Données brutes si nécessaire
}

impl<'a> S7CommPacket<'a> {
    /// Minimum required size for an S7Comm packet (TPKT + COTP + S7 Header)
    const MIN_SIZES: usize = 4 + 3 + 10;

    /// Try to parse a byte slice into an S7CommPacket
    pub fn try_from(packet: &'a [u8]) -> Result<Self, &'static str> {
        println!("S7CommPacket::try_from: packet len: {:?}", packet);
        if packet.len() < Self::MIN_SIZES {
            return Err("Packet too short for S7Comm header");
        }

        // Parse TPKT Header (4 bytes)
        if packet[0] != 0x03 {
            return Err("Invalid TPKT version, expected 0x03");
        }

        let tpkt = TpktHeader {
            version: packet[0],
            reserved: packet[1],
            length: u16::from_be_bytes([packet[2], packet[3]]),
        };

        // Parse COTP Header (starts at offset 4)
        let cotp_len = packet[4] as usize;
        if 4 + cotp_len + 1 > packet.len() {
            return Err("Invalid COTP header length");
        }

        let cotp = CotpHeader {
            length: packet[4],
            pdu_type: packet[5],
            destination_reference: u16::from_be_bytes([packet[6], packet[7]]),
            source_reference: u16::from_be_bytes([packet[8], packet[9]]),
            last_data_unit: (packet[10] & 0x80) != 0,
        };

        // S7 Header starts after TPKT + COTP
        let s7_start = 4 + cotp.length as usize + 1; // +1 for the length byte itself
        println!("S7 header start: {}", s7_start);

        if s7_start + 10 > packet.len() {
            println!(
                "Packet too short for S7 header: need {} bytes, have {}",
                s7_start + 10,
                packet.len()
            );
            return Err("Packet too short for S7 header");
        }

        // First create the header without error fields
        let mut s7_header = S7Header {
            protocol_id: packet[s7_start],
            rosctr: packet[s7_start + 1],
            reserved: u16::from_be_bytes([packet[s7_start + 2], packet[s7_start + 3]]),
            pduref: u16::from_be_bytes([packet[s7_start + 4], packet[s7_start + 5]]),
            parameter_length: u16::from_be_bytes([packet[s7_start + 6], packet[s7_start + 7]]),
            data_length: u16::from_be_bytes([packet[s7_start + 8], packet[s7_start + 9]]),
            error_class: None,
            error_code: None,
        };

        // Update error fields if this is an ACK/Error message
        if s7_header.rosctr == 0x03 && s7_start + 11 < packet.len() {
            s7_header.error_class = Some(packet[s7_start + 10]);
            s7_header.error_code = Some(packet[s7_start + 11]);
        }

        println!("S7 Header: {:?}", s7_header);

        // Print packet structure for debugging - only print up to the packet length
        println!("Packet structure:");
        println!(
            "  TPKT: {:02x} {:02x} {:02x}{:02x}",
            packet[0], packet[1], packet[2], packet[3]
        );
        println!(
            "  COTP: {:02x} {:02x} {:02x}",
            packet[4], packet[5], packet[6]
        );

        // Only print S7 header bytes that exist in the packet
        let s7_header_end = std::cmp::min(s7_start + 12, packet.len());
        print!("  S7 Header: ");
        for byte in packet.iter().take(s7_header_end).skip(s7_start) {
            print!("{:02x} ", byte);
        }
        println!();

        // The parameter section starts right after the S7 header (10 bytes for header + 2 for error class/code if present)
        let s7_header_length = if s7_header.rosctr == 0x03 { 12 } else { 10 };
        let param_start = s7_start + s7_header_length;

        println!("Parameter section start: {}", param_start);

        // If there's no parameter data, return an empty parameter section
        let parameter = if s7_header.parameter_length > 0 {
            let param_end = param_start + s7_header.parameter_length as usize;

            if param_end > packet.len() {
                println!(
                    "Invalid parameter length: param_end={}, packet_len={}",
                    param_end,
                    packet.len()
                );
                println!("  TPKT length: {}", tpkt.length);
                println!("  COTP length: {}", cotp.length);
                println!("  S7 parameter_length: {}", s7_header.parameter_length);
                println!("  S7 data_length: {}", s7_header.data_length);
                return Err("Invalid parameter length");
            }

            Self::parse_parameter(&packet[param_start..param_end])?
        } else {
            // Return empty parameter section
            S7Parameter {
                function: 0,
                items: Vec::new(),
            }
        };

        // Parse payload if present
        let payload = if s7_header.data_length > 0 {
            let data_start = param_start + s7_header.parameter_length as usize;
            let data_end = data_start + s7_header.data_length as usize;
            if data_end > packet.len() {
                return Err("Invalid data length");
            }
            Some(&packet[data_start..data_end])
        } else {
            None
        };

        Ok(S7CommPacket {
            tpkt,
            cotp,
            s7_header,
            parameter,
            payload,
        })
    }

    /// Helper function to parse S7 parameter section
    fn parse_parameter(data: &'a [u8]) -> Result<S7Parameter<'a>, &'static str> {
        if data.is_empty() {
            return Err("Empty parameter data");
        }

        println!("Parameter data ({} bytes): {:?}", data.len(), data);
        let function = data[0];
        let item_count = data[1] as usize;
        let mut items = Vec::with_capacity(item_count);
        let mut offset = 2; // Skip function code and item count

        for i in 0..item_count {
            if offset + 2 > data.len() {
                return Err("Invalid parameter item header");
            }

            let spec_type = data[offset];
            let length = data[offset + 1] as usize;

            println!(
                "  Item {}: spec_type={:02x}, length={}",
                i, spec_type, length
            );

            if offset + 2 + length > data.len() {
                println!(
                    "  Invalid item: offset={}, length={}, data_len={}",
                    offset,
                    length,
                    data.len()
                );
                return Err("Invalid parameter item length");
            }

            if spec_type == 0x12 && length >= 0x0A {
                // S7ANY parameter item
                if offset + 12 > data.len() {
                    return Err("S7ANY parameter too short");
                }

                let syntax_id = data[offset + 2];
                let transport_size = data[offset + 3];
                let db_number = u16::from_be_bytes([data[offset + 5], data[offset + 6]]);
                let area = data[offset + 7];
                let address = ((data[offset + 8] as u32) << 16)
                    | ((data[offset + 9] as u32) << 8)
                    | (data[offset + 10] as u32);

                println!("  S7ANY: syntax_id={:02x}, transport_size={}, db_number={}, area={:02x}, address={:06x}",
                        syntax_id, transport_size, db_number, area, address);

                items.push(S7ParameterItem {
                    spec_type,
                    length: length as u8,
                    syntax_id,
                    transport_size,
                    db_number,
                    area,
                    address,
                    raw: Some(&data[offset..offset + 2 + length]),
                });

                offset += 2 + length;
            } else {
                // For other item types, just store the raw data
                println!("  Generic parameter item");
                items.push(S7ParameterItem {
                    spec_type,
                    length: length as u8,
                    syntax_id: 0,
                    transport_size: 0,
                    db_number: 0,
                    area: 0,
                    address: 0,
                    raw: Some(&data[offset..offset + 2 + length]),
                });
                offset += 2 + length;
            }
        }

        if items.is_empty() {
            return Err("No parameter items found");
        }

        Ok(S7Parameter { function, items })
    }
}

impl<'a> fmt::Display for S7CommPacket<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "S7Comm Protocol ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_s7comm_try_from() {
        // The provided hex string
        let hex_str = "0300001f02f080320100000013000e00000401120a10020001000083000000";

        // Convert hex string to bytes
        let bytes = hex::decode(hex_str).expect("Failed to decode hex string");

        // Try to parse as S7Comm packet
        let result = S7CommPacket::try_from(&bytes[..]);

        // Check if parsing succeeded
        assert!(
            result.is_ok(),
            "Failed to parse S7Comm packet: {:?}",
            result.err().unwrap()
        );

        // Add more assertions based on the expected values from your packet
    }
}
