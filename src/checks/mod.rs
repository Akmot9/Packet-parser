// Copyright (c) 2024 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Regles de validation et d'extraction des parseurs, par couche.
//!
//! Module interne depuis la 11.0.0 : ses ~120 `validate_*` / `extract_*`
//! etaient publics sans etre une API assumee, et figeaient par SemVer le
//! moindre refactor de validation. La seule brique destinee aux
//! consommateurs, la verification opt-in des checksums, vit dans
//! [`crate::checksum`].

pub mod application;
pub mod data_link;
pub mod internet;
pub mod transport;
