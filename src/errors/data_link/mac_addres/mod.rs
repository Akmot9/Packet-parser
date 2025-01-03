use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq, Clone, Copy)]
pub enum MacParseError {
    #[error("Invalid MAC address length: expected 6 bytes, found {actual} bytes")]
    InvalidLength { actual: usize },
}
