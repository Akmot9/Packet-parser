
// Copyright (c) 2024 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

// errors/mod.rs

pub(crate) mod application;
pub(crate) mod data_link;

use data_link::DataLinkError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParsedPacketError {
    #[error("Packet too short: {0} bytes")]
    PacketTooShort(u8),
    #[error("Invalid DataLink segment")]
    InvalidDataLink,
}

// Implémente la conversion automatique
impl From<DataLinkError> for ParsedPacketError {
    fn from(_: DataLinkError) -> Self {
        ParsedPacketError::InvalidDataLink
    }
}
