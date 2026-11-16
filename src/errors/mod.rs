// Copyright (c) 2024 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

// errors/mod.rs

//! # Dependency direction
//!
//! The decoders in [`mod@crate::parse`] depend on this module, not the other
//! way round. Two enums are the deliberate exception:
//! [`SnmpError`](crate::errors::application::snmp::SnmpError) carries an
//! [`SnmpVersion`](crate::parse::application::protocols::snmp::SnmpVersion) and
//! [`MqttError`](crate::errors::application::mqtt::MqttError) an
//! [`MqttPacketType`](crate::parse::application::protocols::mqtt::MqttPacketType),
//! both defined by their decoder. An error names what it rejects with the
//! decoder's own type, not with a copy of it kept in step by hand.

// Publics : le doc-comment de `lib.rs` promet aux consommateurs de pouvoir
// nommer et matcher les types d'erreur par couche. Tant que ces modules
// étaient `pub(crate)`, la promesse ne compilait pas (E0603) et les 120
// `validate_*` publics de `checks/` renvoyaient des types innommables.
pub mod application;
pub mod data_link;
pub mod internet;
mod link_layer;
pub mod transport;

use internet::InternetError;
pub use link_layer::LinkLayerError;
use thiserror::Error;
use transport::TransportError;

use crate::LinkType;

/// Error returned by the top-level packet parsing APIs.
///
/// Every link-layer failure, Ethernet included, is reported through
/// [`ParseError::InvalidLinkLayer`]: handling a link error no longer depends
/// on the LINKTYPE of the capture.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum ParseError {
    #[error("Unsupported link type: {0}")]
    UnsupportedLinkType(LinkType),

    #[error("Invalid link layer: {0}")]
    InvalidLinkLayer(#[from] LinkLayerError),

    #[error("Invalid Internet segment: {0}")]
    InvalidInternet(#[from] InternetError),

    #[error("Transport layer error: {0}")]
    Transport(#[from] TransportError),
}
