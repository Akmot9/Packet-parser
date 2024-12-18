use std::fmt;

use crate::ParsedPacket;
mod data_link;

impl<'a> fmt::Display for ParsedPacket<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ParsedPacket {{\n  Data Link Layer: {},\n  Packet Size: {}\n}}",
            self.data_link, self.size
        )
    }
}
