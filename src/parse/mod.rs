// Copyright (c) 2025 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use application::Application;
use internet::Internet;
use transport::Transport;

use crate::{errors::ParsedPacketError, DataLink};

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
        let transport = None;

        // Étape 5 : Application
        let application = None;

        Ok(PacketFlux {
            data_link,
            internet,
            transport,
            application,
        })
    }
}

