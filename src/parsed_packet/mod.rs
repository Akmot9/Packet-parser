mod data_link;
mod network;
mod transport;
mod application;

use std::convert::TryFrom;

use application::Application;
use data_link::{DataLink, DataLinkError};

#[derive(Debug)]
pub struct ParsedPacket<'a> {
    data_link: DataLink<'a>, // Ajoutez la durée de vie ici
    network: Option<Network<'a>>,
    _transport: Option<Transport<'a>>,
    _application: Option<Application>,
    size: usize,
}

impl<'a> TryFrom<&'a [u8]> for ParsedPacket<'a> {
    type Error = ParsedPacketError;

    fn try_from(packets: &'a [u8]) -> Result<Self, Self::Error> {
        validate_packet_length(packets)?;

        let data_link = DataLink::try_from(packets)?; // Utilisation cohérente de la durée de vie
        let _network = Network::try_from(data_link.payload);
        Ok(ParsedPacket {
            data_link,
            size: packets.len(),
            network: None,
            _transport: None,
            _application: None,
        })
    }
}

fn validate_packet_length(packets: &[u8]) -> Result<(), ParsedPacketError> {
    if packets.len() < 14 {
        return Err(ParsedPacketError::PacketTooShort(packets.len() as u8));
    }
    Ok(())
}

use network::Network;
use thiserror::Error;
use transport::Transport;
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

impl<'a> fmt::Display for ParsedPacket<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ParsedPacket {{\n  Data Link Layer: {},\n  Packet Size: {}\n}}",
            self.data_link, self.size
        )
    }
}
