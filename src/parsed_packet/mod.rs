mod application;
pub(crate) mod data_link;
mod network;
mod transport;

use std::convert::TryFrom;

use application::Application;
use data_link::DataLink;
use network::Network;
use transport::Transport;

use crate::{errors::ParsedPacketError, valildations::validate_packet_length};

#[derive(Debug)]
pub(crate) struct ParsedPacket<'a> {
    pub data_link: DataLink<'a>,
    _network: Option<Network<'a>>,
    _transport: Option<Transport<'a>>,
    _application: Option<Application>,
    pub size: usize,
}

impl<'a> TryFrom<&'a [u8]> for ParsedPacket<'a> {
    type Error = ParsedPacketError;

    fn try_from(packets: &'a [u8]) -> Result<Self, Self::Error> {
        validate_packet_length(packets)?;

        let data_link = DataLink::try_from(packets)?;
        // let _network = Network::try_from(data_link.payload);
        // let _transport = Network::try_from(network.payload);
        // let _application = Network::try_from(transport.payload);

        Ok(ParsedPacket {
            data_link,
            size: packets.len(),
            _network: None,
            _transport: None,
            _application: None,
        })
    }
}
