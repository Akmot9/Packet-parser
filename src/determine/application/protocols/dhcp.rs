//! Module for parsing DHCP packets.

use crate::{checks::application::dhcp::*, errors::application::dhcp::DhcpParseError};

/// The `DhcpPacket` struct represents a parsed DHCP packet.
#[derive(Debug)]
pub struct DhcpPacket {
    pub op: u8,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: [u8; 4],
    pub yiaddr: [u8; 4],
    pub siaddr: [u8; 4],
    pub giaddr: [u8; 4],
    pub chaddr: [u8; 16],
    pub sname: [u8; 64],
    pub file: [u8; 128],
    pub options: Vec<u8>,
}
impl TryFrom<&[u8]> for DhcpPacket {
    type Error = DhcpParseError;

    fn try_from(payload: &[u8]) -> Result<Self, Self::Error> {
        validate_packet_length(payload)?;

        let op = validate_op(payload)?;
        let htype = validate_htype(payload)?;
        let hlen = validate_hlen(payload)?;
        let hops = payload[3];
        let xid = extract_xid(payload)?;
        let secs = extract_secs(payload)?;
        let flags = extract_flags(payload)?;
        let ciaddr = extract_ciaddr(payload)?;
        let yiaddr = extract_yiaddr(payload)?;
        let siaddr = extract_siaddr(payload)?;
        let giaddr = extract_giaddr(payload)?;
        let chaddr = extract_chaddr(payload)?;
        let sname = extract_sname(payload)?;
        let file = extract_file(payload)?;
        let options = extract_options(payload)?;

        Ok(DhcpPacket {
            op,
            htype,
            hlen,
            hops,
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr,
            sname,
            file,
            options,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        determine::application::protocols::dhcp::DhcpPacket,
        errors::application::dhcp::DhcpParseError,
    };

    #[test]
    fn test_parse_dhcp_packet() {
        let dhcp_payload = &[
            0x01, 0x01, 0x06, 0x00, // op, htype, hlen, hops
            0x39, 0x03, 0xF3, 0x26, // xid
            0x00, 0x00, // secs
            0x00, 0x00, // flags
            0x00, 0x00, 0x00, 0x00, // ciaddr
            0x00, 0x00, 0x00, 0x00, // yiaddr
            0x00, 0x00, 0x00, 0x00, // siaddr
            0x00, 0x00, 0x00, 0x00, // giaddr
            0x00, 0x0C, 0x29, 0x36, 0x57, 0xD2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, // chaddr
        ]
        .iter()
        .cloned()
        .chain([0x00; 64].iter().cloned())
        .chain([0x00; 128].iter().cloned())
        .chain(
            [
                0x63, 0x82, 0x53, 0x63, // Magic cookie
                0x35, 0x01, 0x05, // DHCP message type
                0xFF, // End option
            ]
            .iter()
            .cloned(),
        )
        .collect::<Vec<u8>>();

        let result = DhcpPacket::try_from(dhcp_payload.as_slice());
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_dhcp_packet_short_payload() {
        let short_payload = [0x01, 0x01, 0x06, 0x00, 0x39, 0x03, 0xF3, 0x26];
        let result = DhcpPacket::try_from(short_payload.as_slice());
        assert!(matches!(result, Err(DhcpParseError::InvalidOp)));
    }

    #[test]
    fn test_parse_dhcp_packet_invalid_op() {
        let invalid_op_payload = vec![
            0x03, 0x01, 0x06, 0x00, 0x39, 0x03, 0xF3, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x0C, 0x29, 0x36, 0x57, 0xD2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ]
        .iter()
        .cloned()
        .chain([0x00; 64].iter().cloned())
        .chain([0x00; 128].iter().cloned())
        .chain(
            [0x63, 0x82, 0x53, 0x63, 0x35, 0x01, 0x05, 0xFF]
                .iter()
                .cloned(),
        )
        .collect::<Vec<u8>>();

        let result = DhcpPacket::try_from(invalid_op_payload.as_slice());
        assert!(matches!(result, Err(DhcpParseError::ShortPacket)));
    }
}
