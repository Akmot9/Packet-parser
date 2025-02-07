// parsed_packet/data_link/mod.rs

pub mod mac_addres;
use mac_addres::MacAddress;

pub mod ethertype;
use crate::{
    errors::data_link::DataLinkError, 
    checks::data_link::validate_data_link_length
};

use ethertype::Ethertype;

#[derive(Debug)]
pub struct DataLink<'a> {
    pub destination_mac: MacAddress,
    pub source_mac: MacAddress,
    pub ethertype: Ethertype,
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