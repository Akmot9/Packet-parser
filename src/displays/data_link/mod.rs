use std::fmt;
pub mod mac_addres;
pub mod ethertype;
use crate::parse::data_link::DataLink;

impl<'a> fmt::Display for DataLink<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "\n    DataLink {{\n       Destination MAC: {},\n       Source MAC: {},\n       Ethertype: {},\n       Payload Length: {}\n    }}",
            self.destination_mac.display_with_oui(),
            self.source_mac.display_with_oui(),
            self.ethertype,
            self.payload.len()
        )
    }
}
