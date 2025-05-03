// Copyright (c) 2024 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use std::fmt::{self, Display};

use crate::parse::ParsedPacket;

pub(crate) mod data_link;

impl<'a> Display for ParsedPacket<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ParsedPacket {{\n  Data Link Layer: {}}}",
            self.data_link
        )
    }
}
