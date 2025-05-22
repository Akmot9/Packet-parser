// Copyright (c) 2024 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use std::fmt::{self, Display, Formatter};

use crate::parse::PacketPath;

pub(crate) mod data_link;
pub(crate) mod internet;
pub(crate) mod transport;
pub(crate) mod application;

impl Display for PacketPath<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "ParsedPacket :")?;
        writeln!(f, "  Data Link Layer: {}", self.data_link)?;
        match &self.internet {
            Some(ip) => writeln!(f, "  Internet Layer: {}", ip)?,
            None => {},
        }
        match &self.transport {
            Some(trans) => writeln!(f, "  Transport Layer: {}", trans)?,
            None => {},
        }
        match &self.application {
            Some(app) => writeln!(f, "  Application Layer: {}", app)?,
            None => {},
        }
        write!(f, "")
    }
}
