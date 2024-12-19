use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Data link too short: {0} bytes")]
    NetworkTooShort(u8),
}
