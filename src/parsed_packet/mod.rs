mod data_link;
use std::convert::TryFrom;

use data_link::{DataLink, DataLinkError};

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

fn validate_packet_length(packets: &[u8]) -> Result<(), ParsedPacketError> {
    if packets.len() < 14 {
        return Err(ParsedPacketError::PacketTooShort(packets.len() as u8));
    }
    Ok(())
}

use thiserror::Error;
#[derive(Error, Debug)]
pub enum ParsedPacketError {
    #[error("Packet too short: {0} bytes")]
    PacketTooShort(u8),
    #[error("Invalid DataLink segment")]
    InvalidDataLink,
}

// Implémente la conversion automatique
impl From<DataLinkError> for ParsedPacketError {
    fn from(_: DataLinkError) -> Self {
        ParsedPacketError::InvalidDataLink
    }
}

use std::fmt;

impl fmt::Display for ParsedPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ParsedPacket {{\n  Data Link Layer: {},\n  Packet Size: {}\n}}",
            self.data_link, self.size
        )
    }
}
