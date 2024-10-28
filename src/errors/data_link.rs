use thiserror::Error;

#[derive(Error, Debug)]
pub enum DataLinkError {
    #[error("Data link too short: {0} bytes")]
    DataLinkTooShort(u8),
}

#[derive(Error, Debug)]
pub enum MacAddressError {
    #[error("Data link too short: {0} bytes")]
    MacAddressTooShort(u8),
}