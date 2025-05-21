// Copyright (c) 2024 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use std::fmt::{self, Display, Formatter};

use crate::parse::ParsedPacketPath;

pub(crate) mod data_link;
pub(crate) mod internet;

impl Display for ParsedPacketPath<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "ParsedPacket :")?;
        writeln!(f, "  Data Link Layer: {}", self.data_link)?;
        match &self.internet {
            Some(ip) => writeln!(f, "  Internet Layer: {}", ip)?,
            None => writeln!(f, "  Internet Layer: [non parsée]")?,
        }
        write!(f, "")
    }
}
