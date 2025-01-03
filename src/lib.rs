pub mod displays;
pub mod errors;
pub mod parsed_packet;
pub mod valildations;

use std::convert::TryFrom;

use parsed_packet::{
    application::Application, 
    data_link::DataLink, 
    network::Network, 
    transport::Transport
};

use crate::{
    errors::ParsedPacketError, 
    valildations::validate_packet_length
};

#[derive(Debug)]
pub struct ParsedPacket<'a> {
    data_link: DataLink<'a>,
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
