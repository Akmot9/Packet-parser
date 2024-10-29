use crate::{errors::data_link::DataLinkError, validations::data_link::validate_data_link_length};
mod mac_addres;
use mac_addres::MacAddress;

#[derive(Debug)]
pub struct DataLink {
    destination_mac: MacAddress,
    source_mac: MacAddress,
    ethertype: u16,
    payload: Option<Vec<u8>>,
}

impl TryFrom<&[u8]> for DataLink {
    type Error = DataLinkError;
    
    fn try_from(packets: &[u8]) -> Result<Self, Self::Error> {
        validate_data_link_length(packets)?;

        Ok(DataLink {
            destination_mac: MacAddress::try_from(&packets[0..6]).unwrap(),
            source_mac: MacAddress::try_from(&packets[6..12]).unwrap(),
            ethertype: u16::from_be_bytes([packets[12], packets[13]]),
            payload: None
        })
    }
}

use std::fmt;

impl fmt::Display for DataLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "\n    DataLink {{\n       Destination MAC: {},\n       Source MAC: {},\n       Ethertype: 0x{:04X},\n       Payload Length: {}\n    }}",
            self.destination_mac.display_with_oui(),
            self.source_mac.display_with_oui(),
            self.ethertype,
            self.payload.as_ref().map_or(0, |p| p.len())
        )
    }
}

