use thiserror::Error;
pub mod mac_addres;
use mac_addres::MacParseError;

#[derive(Error, Debug)]
pub enum DataLinkError {
    #[error("Data link too short: {0} bytes")]
    DataLinkTooShort(u8),
    #[error("MAC address parsing error: {0}")]
    MacParseError(#[from] MacParseError),
}
