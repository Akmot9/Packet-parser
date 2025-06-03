use serde::Serialize;
use std::convert::TryFrom;
use thiserror::Error;
// use std::fmt;

#[repr(u16)]
#[derive(Debug, Serialize, Clone, Eq, PartialEq, Hash, Default)]
pub enum FrameId {
    #[default]
    Unicast = 0xC000,
    Multicast = 0xF800,
    GetReqSetReqGetRespSetResp = 0xFEFD,
    IdentifyReq = 0xFEFE,
    IdentifyResp = 0xFEFF,
}

impl FrameId {
    fn from_u16(value: u16) -> Option<FrameId> {
        match value {
            0xC000..=0xF7FF => Some(FrameId::Unicast),
            0xF800..=0xFBFF => Some(FrameId::Multicast),
            0xFEFD => Some(FrameId::GetReqSetReqGetRespSetResp),
            0xFEFE => Some(FrameId::IdentifyReq),
            0xFEFF => Some(FrameId::IdentifyResp),
            _ => None,
        }
    }
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum ProfinetPacketError {
    #[error("Packet too short: minimum length required is 16 bytes, found {0} bytes")]
    PacketTooShort(usize),
    #[error("Unknown Frame ID: {0:#06x}")]
    UnknownFrameId(u16),
    #[error("Invalid DCP block length: expected at least 4 bytes, found {0} bytes")]
    InvalidDcpBlockLength(usize),
    #[error("Invalid name of station encoding")]
    InvalidNameOfStation,
}

#[derive(Debug, Default, Serialize, Clone, Eq, PartialEq, Hash)]
pub struct ProfinetPacket<'a> {
    pub frame_id: FrameId,
    pub service_id: u8,
    pub service_type: u8,
    pub xid: u32,
    pub response_delay: u16,
    pub dcp_data_length: u16,
    pub option: u8,
    pub suboption: u8,
    pub dcp_block_length: u16,
    pub name_of_station: &'a str,
}

impl<'a> TryFrom<&'a [u8]> for ProfinetPacket<'a> {
    type Error = ProfinetPacketError;

    fn try_from(data: &'a [u8]) -> Result<Self, Self::Error> {
        validate_packet_length(data)?;
        let frame_id = validate_frame_id(data)?;
        validate_dcp_block(data)?;

        let service_id = data[2];
        let service_type = data[3];
        let xid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let response_delay = u16::from_be_bytes([data[8], data[9]]);
        let dcp_data_length = u16::from_be_bytes([data[10], data[11]]);

        let option = data[12];
        let suboption = data[13];
        let dcp_block_length = u16::from_be_bytes([data[14], data[15]]);

        let name_of_station = extract_name_of_station(data)?;

        Ok(ProfinetPacket {
            frame_id,
            service_id,
            service_type,
            xid,
            response_delay,
            dcp_data_length,
            option,
            suboption,
            dcp_block_length,
            name_of_station,
        })
    }
}

/// Validate the length of the packet.
fn validate_packet_length(data: &[u8]) -> Result<(), ProfinetPacketError> {
    if data.len() < 16 {
        Err(ProfinetPacketError::PacketTooShort(data.len()))
    } else {
        Ok(())
    }
}

/// Validate and extract the Frame ID.
fn validate_frame_id(data: &[u8]) -> Result<FrameId, ProfinetPacketError> {
    let frame_id_value = u16::from_be_bytes([data[0], data[1]]);
    FrameId::from_u16(frame_id_value).ok_or(ProfinetPacketError::UnknownFrameId(frame_id_value))
}

/// Validate the DCP block length.
fn validate_dcp_block(data: &[u8]) -> Result<(), ProfinetPacketError> {
    if data.len() < 16 {
        return Err(ProfinetPacketError::PacketTooShort(data.len()));
    }
    let block = &data[12..];
    if block.len() < 4 {
        return Err(ProfinetPacketError::InvalidDcpBlockLength(block.len()));
    }
    Ok(())
}

/// Extract the name of station from the DCP block.
fn extract_name_of_station<'a>(data: &'a [u8]) -> Result<&'a str, ProfinetPacketError> {
    let block = &data[12..];
    let dcp_block_length = u16::from_be_bytes([block[2], block[3]]) as usize;

    if block.len() < (4 + dcp_block_length) {
        return Err(ProfinetPacketError::InvalidDcpBlockLength(block.len()));
    }

    std::str::from_utf8(&block[4..4 + dcp_block_length])
        .map_err(|_| ProfinetPacketError::InvalidNameOfStation)
}

// impl fmt::Display for ProfinetPacket {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         writeln!(f, "Frame ID: {:?}", self.frame_id)?;
//         writeln!(f, "Service ID: {}", self.service_id)?;
//         writeln!(f, "Service Type: {}", self.service_type)?;
//         writeln!(f, "XID: {:#010x}", self.xid)?;
//         writeln!(f, "Response Delay: {}", self.response_delay)?;
//         writeln!(f, "DCP Data Length: {}", self.dcp_data_length)?;
//         writeln!(f, "Option: {}", self.option)?;
//         writeln!(f, "Suboption: {}", self.suboption)?;
//         writeln!(f, "DCP Block Length: {}", self.dcp_block_length)?;
//         writeln!(f, "Name Of Station: {}", self.name_of_station)?;
//         Ok(())
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_id_from_u16() {
        assert_eq!(FrameId::from_u16(0xC000), Some(FrameId::Unicast));
        assert_eq!(FrameId::from_u16(0xF800), Some(FrameId::Multicast));
        assert_eq!(
            FrameId::from_u16(0xFEFD),
            Some(FrameId::GetReqSetReqGetRespSetResp)
        );
        assert_eq!(FrameId::from_u16(0xFEFE), Some(FrameId::IdentifyReq));
        assert_eq!(FrameId::from_u16(0xFEFF), Some(FrameId::IdentifyResp));
        assert_eq!(FrameId::from_u16(0x0000), None);
    }

    // #[test]
    // fn test_profinet_packet_new() {
    //     let data: Vec<u8> = vec![
    //         0xFE, 0xFE, // Frame ID
    //         0x01, 0x02, // Service ID and Service Type
    //         0x00, 0x00, 0x00, 0x01, // XID
    //         0x00, 0x10, // Response Delay
    //         0x00, 0x0C, // DCP Data Length
    //         0x02, // Option
    //         0x03, // Suboption
    //         0x00, 0x04, // DCP Block Length
    //         b'T', b'E', b'S', b'T' // Name Of Station
    //     ];

    //     let packet = ProfinetPacket::try_from(&data).expect("Failed to parse packet");

    //     assert_eq!(packet.frame_id, FrameId::IdentifyReq);
    //     assert_eq!(packet.service_id, 0x01);
    //     assert_eq!(packet.service_type, 0x02);
    //     assert_eq!(packet.xid, 0x00000001);
    //     assert_eq!(packet.response_delay, 0x0010);
    //     assert_eq!(packet.dcp_data_length, 0x000C);
    //     assert_eq!(packet.option, 0x02);
    //     assert_eq!(packet.suboption, 0x03);
    //     assert_eq!(packet.dcp_block_length, 0x0004);
    //     assert_eq!(packet.name_of_station, "TEST");
    // }

    // #[test]
    // fn test_profinet_packet_new_with_real_data() {
    //     let data: Vec<u8> = vec![
    //         0xFE, 0xFE, // Frame ID
    //         0x05, 0x00, // Service ID and Service Type
    //         0x03, 0x00, 0x01, 0x44, // XID
    //         0x00, 0x01, // Response Delay
    //         0x00, 0x0E, // DCP Data Length
    //         0x02, // Option
    //         0x02, // Suboption
    //         0x00, 0x09, // DCP Block Length
    //         b's', b'c', b'a', b'l', b'a', b'n', b'c', b'e', b'h', // Name Of Station
    //         b'e', b'm', b'e', b'n', b's', b',', b' ', b'S', b'I', b'M', b'A' // Continuation of the Name Of Station
    //     ];

    //     let packet = ProfinetPacket::new(&data);

    //     assert!(packet.is_some());
    //     let packet = packet.unwrap();
    //     assert_eq!(packet.frame_id, FrameId::IdentifyReq);
    //     assert_eq!(packet.service_id, 0x05);
    //     assert_eq!(packet.service_type, 0x00);
    //     assert_eq!(packet.xid, 0x03000144);
    //     assert_eq!(packet.response_delay, 0x0001);
    //     assert_eq!(packet.dcp_data_length, 0x000E);
    //     assert_eq!(packet.option, 0x02);
    //     assert_eq!(packet.suboption, 0x02);
    //     assert_eq!(packet.dcp_block_length, 0x0009);
    //     assert_eq!(packet.name_of_station, "scalanceh");
    // }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use pnet::packet::ethernet::MutableEthernetPacket;
    use pnet::packet::MutablePacket;

    use pnet::packet::Packet;

    #[test]
    fn test_handle_profinet_packet() {
        // Constructing a mock Ethernet packet with Profinet payload.
        let mut ethernet_data = vec![0u8; 64];
        let mut eth_packet = MutableEthernetPacket::new(&mut ethernet_data).unwrap();

        // Setting Ethernet type to indicate Profinet packet.
        eth_packet.set_ethertype(pnet::packet::ethernet::EtherType(0x8892));

        // Adding a Profinet payload (mocked data).
        let profinet_payload = [
            0xFE, 0xFE, // Frame ID for IdentifyReq
            0x01, 0x02, // Service ID and Type
            0x00, 0x00, 0x00, 0x01, // XID
            0x00, 0x10, // Response Delay
            0x00, 0x0C, // DCP Data Length
            0x02, // Option
            0x03, // Suboption
            0x00, 0x04, // DCP Block Length
            b'T', b'E', b'S', b'T', // Name Of Station
        ];
        eth_packet.payload_mut()[..profinet_payload.len()].copy_from_slice(&profinet_payload);

        // Attempt to parse the Profinet packet from the Ethernet payload.
        let payload = eth_packet.payload();
        match ProfinetPacket::try_from(payload) {
            Ok(packet) => {
                // Assert the parsed values to ensure correctness.
                assert_eq!(packet.frame_id, FrameId::IdentifyReq);
                assert_eq!(packet.service_id, 0x01);
                assert_eq!(packet.service_type, 0x02);
                assert_eq!(packet.xid, 0x00000001);
                assert_eq!(packet.response_delay, 0x0010);
                assert_eq!(packet.dcp_data_length, 0x000C);
                assert_eq!(packet.option, 0x02);
                assert_eq!(packet.suboption, 0x03);
                assert_eq!(packet.dcp_block_length, 0x0004);
                assert_eq!(packet.name_of_station, "TEST");
            }
            Err(e) => panic!("Failed to parse Profinet packet: {:?}", e),
        }
    }
}
