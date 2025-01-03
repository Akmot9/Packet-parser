use thiserror::Error;
pub mod mac_addres;
mod protocol;
use protocol::DataLinkProtocolError;

#[derive(Error, Debug)]
pub enum DataLinkError {
    #[error("Data link too short: {0} bytes")]
    DataLinkTooShort(u8),

    #[error("error decoding protocol")]
    ProtocolError,
}

// Implémente la conversion automatique
impl From<DataLinkProtocolError> for DataLinkError {
    fn from(_: DataLinkProtocolError) -> Self {
        DataLinkError::ProtocolError
    }
}
