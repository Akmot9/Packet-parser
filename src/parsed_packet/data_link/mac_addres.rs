use crate::{errors::data_link::MacAddressError, validations::data_link::validate_mac_length};

#[derive(Debug)]
pub struct MacAddress {
    bytes: [u8; 6],
}

impl TryFrom<&[u8]> for MacAddress {
    type Error = MacAddressError;
    
    fn try_from(packets: &[u8]) -> Result<Self, Self::Error> {
        validate_mac_length(packets)?;

        Ok(MacAddress {
            bytes: [packets[0], packets[1], packets[2], packets[3], packets[4], packets[5]]
        })
    }
}