// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum HttpParseError {
    /// La tete du message (ligne de depart et en-tetes) n'est pas de l'UTF-8
    /// valide. Le corps n'est pas valide : il peut etre binaire (#176).
    #[error("Invalid UTF-8 in HTTP message head")]
    InvalidUtf8,

    #[error("Missing HTTP method")]
    MissingMethod,

    #[error("Unknown HTTP method: {0}")]
    InvalidMethod(String),

    #[error("Missing HTTP URI")]
    MissingUri,

    #[error("Missing HTTP version")]
    MissingVersion,

    #[error("Invalid HTTP version: {0}")]
    InvalidVersion(String),

    #[error("Invalid HTTP header")]
    InvalidHeader,

    /// Ligne de statut d'une reponse sans code (RFC 9112 §4). En fin d'enum :
    /// ajoutee apres la 11.6.0.
    #[error("Missing HTTP status code")]
    MissingStatusCode,

    /// Le code de statut n'est pas fait de trois chiffres. En fin d'enum :
    /// ajoutee apres la 11.6.0.
    #[error("Invalid HTTP status code: {0}")]
    InvalidStatusCode(String),
}
