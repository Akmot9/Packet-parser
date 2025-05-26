// Copyright (c) 2025 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use application::Application;
use internet::Internet;
use transport::Transport;

use crate::{errors::{transport::TransportError, ParsedPacketError}, DataLink};

pub mod application;
pub mod data_link;
pub mod internet;
pub mod transport;
// You can determine either a full raw packet that will return a PacketParsed struct composed of data link network transportand application layers.
// Or if you need to, you can put your payload in a determine application try from. detemines function are not dependants.

pub struct PacketFlux<'a> {
    pub data_link: DataLink<'a>,
    pub internet: Internet<'a>,
    pub transport: Option<Transport<'a>>,
    pub application: Option<Application<'a>>,
}

impl<'a> TryFrom<&'a [u8]> for PacketFlux<'a> {
    type Error = ParsedPacketError;

    fn try_from(packets: &'a [u8]) -> Result<Self, Self::Error> {
        let data_link = DataLink::try_from(packets)?;
        let internet = Internet::try_from(data_link.payload)?;

        // Étape 4 : Transport
        // met None si pas de transport et pas de internet. ou le transport si il y a un transport. ou internet.protocol_name
        let transport = match Transport::try_from(internet.payload) {
            Ok(transport) => Some(transport),
            Err(TransportError::UnsupportedProtocol) => {
                Some(internet.payload_protocol.clone())
            }
            Err(e) => return Err(e.into()), // Pour les autres erreurs, on propage
        };
        // Étape 5 : Application
        // handle when transport is None then application is None   
        let application = match &transport {
            Some(t) => match t.payload {
                Some(p) => Application::try_from(p).ok(),
                None => None,
            },
            None => None,
        };

        Ok(PacketFlux {
            data_link,
            internet,
            transport,
            application,
        })
    }
}
