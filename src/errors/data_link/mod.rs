// Copyright (c) 2024 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;
pub mod mac_address;

/// Ancien nom de [`mac_address`], garde pour les appelants de la 11.8 et retire en
/// 12.0 (#220, `MIGRATION-12.md`). Le compilateur ne previent pas : rustc ne
/// propage pas `#[deprecated]` a travers un `pub use`.
pub use mac_address as mac_addres;
pub mod stp;
use mac_address::MacParseError;

#[derive(Error, Debug, PartialEq)]
#[non_exhaustive]
pub enum DataLinkError {
    /// La trame (ou le tag VLAN) est plus courte que ce que son en-tete
    /// exige. `required` compte les tags VLAN deja rencontres.
    #[error("Data link too short: required bytes {required}, actual bytes {actual}")]
    DataLinkTooShort { required: usize, actual: usize },
    #[error("MAC address parsing error: {0}")]
    MacParseError(#[from] MacParseError),
}
