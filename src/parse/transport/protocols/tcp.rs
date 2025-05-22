use std::convert::TryFrom;
use thiserror::Error;

/// Represents a TCP header
#[derive(Debug, PartialEq)]
pub struct TcpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub data_offset: u8,      // 4 bits
    pub reserved: u8,          // 3 bits
    pub ns: bool,              // 1 bit
    pub cwr: bool,             // 1 bit
    pub ece: bool,             // 1 bit
    pub urg: bool,             // 1 bit
    pub ack: bool,             // 1 bit
    pub psh: bool,             // 1 bit
    pub rst: bool,             // 1 bit
    pub syn: bool,             // 1 bit
    pub fin: bool,             // 1 bit
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub options: Vec<u8>,
}

/// Represents a TCP packet
#[derive(Debug)]
pub struct TcpPacket<'a> {
    pub header: TcpHeader,
    pub payload: &'a [u8],
}

#[derive(Error, Debug)]
pub enum TcpError {
    #[error("Packet too short to be a valid TCP header")]
    PacketTooShort,
    
    #[error("Invalid data offset: {0}")]
    InvalidDataOffset(u8),
    
    #[error("Invalid TCP header length")]
    InvalidHeaderLength,
}

impl<'a> TryFrom<&'a [u8]> for TcpPacket<'a> {
    type Error = TcpError;

    fn try_from(packet: &'a [u8]) -> Result<Self, Self::Error> {
        // Minimum TCP header size is 20 bytes
        if packet.len() < 20 {
            return Err(TcpError::PacketTooShort);
        }

        let data_offset = (packet[12] >> 4) * 4;
        
        // Validate data offset (must be at least 20 and at most 60 bytes)
        if data_offset < 20 || data_offset > 60 {
            return Err(TcpError::InvalidDataOffset(data_offset));
        }
        
        // Ensure packet is long enough for the header
        if packet.len() < data_offset as usize {
            return Err(TcpError::PacketTooShort);
        }

        let header = TcpHeader {
            source_port: u16::from_be_bytes([packet[0], packet[1]]),
            destination_port: u16::from_be_bytes([packet[2], packet[3]]),
            sequence_number: u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]),
            acknowledgment_number: u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]),
            data_offset: packet[12] >> 4,
            reserved: (packet[12] >> 1) & 0x07,
            ns: (packet[12] & 0x01) != 0,
            cwr: (packet[13] & 0x80) != 0,
            ece: (packet[13] & 0x40) != 0,
            urg: (packet[13] & 0x20) != 0,
            ack: (packet[13] & 0x10) != 0,
            psh: (packet[13] & 0x08) != 0,
            rst: (packet[13] & 0x04) != 0,
            syn: (packet[13] & 0x02) != 0,
            fin: (packet[13] & 0x01) != 0,
            window_size: u16::from_be_bytes([packet[14], packet[15]]),
            checksum: u16::from_be_bytes([packet[16], packet[17]]),
            urgent_pointer: u16::from_be_bytes([packet[18], packet[19]]),
            options: if data_offset > 20 {
                packet[20..data_offset as usize].to_vec()
            } else {
                Vec::new()
            },
        };

        let payload = &packet[data_offset as usize..];
        
        Ok(TcpPacket { header, payload })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_packet_parsing() {
        // A simple TCP packet with no options
        let tcp_packet = [
            // Source port (1234)
            0x04, 0xD2,
            // Destination port (80)
            0x00, 0x50,
            // Sequence number (1)
            0x00, 0x00, 0x00, 0x01,
            // Acknowledgment number (0)
            0x00, 0x00, 0x00, 0x00,
            // Data offset (5 * 4 = 20 bytes), Reserved, NS=0, CWR=0, ECE=0, URG=0, ACK=1, PSH=0, RST=0, SYN=1, FIN=0
            0x50, 0x12,
            // Window size (8192)
            0x20, 0x00,
            // Checksum (0 for test)
            0x00, 0x00,
            // Urgent pointer (0)
            0x00, 0x00,
            // Payload (4 bytes)
            0x01, 0x02, 0x03, 0x04,
        ];

        let tcp = TcpPacket::try_from(&tcp_packet[..]).unwrap();
        
        assert_eq!(tcp.header.source_port, 1234);
        assert_eq!(tcp.header.destination_port, 80);
        assert_eq!(tcp.header.sequence_number, 1);
        assert_eq!(tcp.header.acknowledgment_number, 0);
        assert_eq!(tcp.header.data_offset, 5);
        assert!(tcp.header.ack);
        assert!(tcp.header.syn);
        assert!(!tcp.header.fin);
        assert_eq!(tcp.header.window_size, 8192);
        assert_eq!(tcp.header.checksum, 0);
        assert_eq!(tcp.header.urgent_pointer, 0);
        assert!(tcp.header.options.is_empty());
        assert_eq!(tcp.payload, &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_tcp_packet_too_short() {
        // Only 19 bytes (minimum is 20)
        let short_packet = [0u8; 19];
        let result = TcpPacket::try_from(&short_packet[..]);
        assert!(matches!(result, Err(TcpError::PacketTooShort)));
    }

    #[test]
    fn test_tcp_invalid_data_offset() {
        // Create a packet with invalid data offset (1 * 4 = 4 bytes, which is less than minimum 20)
        let mut packet = [0u8; 20];
        packet[12] = 0x10; // Data offset = 1 (4 bytes)
        let result = TcpPacket::try_from(&packet[..]);
        assert!(matches!(result, Err(TcpError::InvalidDataOffset(1))));
    }
}