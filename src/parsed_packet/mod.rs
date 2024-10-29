mod data_link;
use std::convert::TryFrom;

use data_link::DataLink;

use crate::{errors::parse::ParsedPacketError, validations::parse::validate_packet_length};

#[derive(Debug)]
pub struct ParsedPacket {
    data_link: DataLink,
    size: usize,
}

impl TryFrom<&[u8]> for ParsedPacket {
    type Error = ParsedPacketError;
    
    fn try_from(packets: &[u8]) -> Result<Self, Self::Error> {
        validate_packet_length(packets)?;
        
        let data_link: DataLink = DataLink::try_from(&packets[0..])?;
        Ok(ParsedPacket {
            data_link,
            size: packets.len(),
        })
    }
}

use std::fmt;

impl fmt::Display for ParsedPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ParsedPacket {{\n  Data Link Layer: {},\n  Packet Size: {}\n}}",
            self.data_link,
            self.size
        )
    }
}

