use crate::errors::data_link::{DataLinkError, MacAddressError};

pub fn validate_data_link_length(packets: &[u8]) -> Result<(), DataLinkError> {
    if packets.len() < 14 {
        return Err(DataLinkError::DataLinkTooShort(packets.len() as u8));
    }
    Ok(())
}

pub fn validate_mac_length(packets: &[u8]) -> Result<(), MacAddressError> {
    if packets.len() < 6 {
        return Err(MacAddressError::MacAddressTooShort(packets.len() as u8));
    }
    Ok(())
}