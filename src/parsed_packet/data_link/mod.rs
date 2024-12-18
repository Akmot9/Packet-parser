// parsed_packet/data_link/mod.rs

mod mac_addres;
use mac_addres::MacAddress;

mod ethertype;
use ethertype::Ethertype;
use crate::errors::data_link::DataLinkError;

#[derive(Debug)]
pub struct DataLink<'a> {
    destination_mac: MacAddress,
    source_mac: MacAddress,
    ethertype: Ethertype,
    pub payload: &'a [u8],
}

impl<'a> TryFrom<&'a [u8]> for DataLink<'a> {
    type Error = DataLinkError;

    fn try_from(packets: &'a [u8]) -> Result<Self, Self::Error> {
        validate_data_link_length(packets)?;

        Ok(DataLink {
            destination_mac: MacAddress::try_from(&packets[0..6]).unwrap(),
            source_mac: MacAddress::try_from(&packets[6..12]).unwrap(),
            ethertype: Ethertype::from(u16::from_be_bytes([packets[12], packets[13]])),
            payload: &packets[14..],
        })
    }
}

const DATALINK_HEADER_LEN: usize = 14;

pub fn validate_data_link_length(packets: &[u8]) -> Result<(), DataLinkError> {
    if packets.len() < DATALINK_HEADER_LEN {
        return Err(DataLinkError::DataLinkTooShort(packets.len() as u8));
    }
    Ok(())
}


use std::fmt;

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

