// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

use crate::errors::application::modbus_tcp::ModbusTcpError;

#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum UmasError {
    /// L'enveloppe Modbus/TCP est elle-meme invalide.
    #[error("Invalid Modbus/TCP envelope: {0}")]
    InvalidEnvelope(#[from] ModbusTcpError),

    /// Le code fonction Modbus n'est pas 0x5A : ce n'est pas de l'UMAS.
    #[error("Not a UMAS PDU: Modbus function code {got:#04x}, expected 0x5a")]
    NotUmas { got: u8 },

    /// Le PDU UMAS doit porter au moins l'identifiant de session et le code
    /// fonction.
    #[error("UMAS PDU too small: needed {needed} bytes, got {actual}")]
    PduTooSmall { needed: usize, actual: usize },
}
