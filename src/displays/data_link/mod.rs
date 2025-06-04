use std::fmt;
pub mod ethertype;
pub mod mac_addres;
pub mod oui;
use crate::parse::data_link::DataLink;

impl fmt::Display for DataLink<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "\n    Destination MAC: {},\n    Source MAC: {},\n    Ethertype: {},\n    Payload Length: {}\n",
            self.destination_mac,
            self.source_mac,
            self.ethertype,
            self.payload.len()
        )
    }
}
