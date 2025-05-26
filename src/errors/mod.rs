// Copyright (c) 2024 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

// errors/mod.rs

pub(crate) mod application;
pub(crate) mod data_link;
pub(crate) mod internet;
pub(crate) mod transport;

use application::ApplicationError;
use data_link::DataLinkError;
use internet::InternetError;
use thiserror::Error;
use transport::TransportError;



#[derive(Error, Debug)]
pub enum ParsedPacketError {
    #[error("Packet too short: {0} bytes")]
    PacketTooShort(u8),
    #[error("Invalid DataLink segment")]
    InvalidDataLink,
    #[error("Invalid Internet segment")]
    InvalidInternet,
    #[error("Transport layer error: {0}")]
    Transport(#[from] TransportError),
    #[error("Application layer error: {0}")]
    Application(#[from] ApplicationError),
}

// Implémente la conversion automatique
impl From<DataLinkError> for ParsedPacketError {
    fn from(_: DataLinkError) -> Self {
        ParsedPacketError::InvalidDataLink
    }
}
impl From<InternetError> for ParsedPacketError {
    fn from(_: InternetError) -> Self {
        ParsedPacketError::InvalidInternet
    }
}
