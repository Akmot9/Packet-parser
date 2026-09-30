// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use thiserror::Error;

/// Erreurs du decodeur ASTERIX. Chaque variante nomme ce qui a ete refuse :
/// la sonde de detection s'appuie sur ce decodeur, et une trame qui ne
/// s'explique pas entierement par un UAP connu n'est jamais etiquetee.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum AsterixError {
    /// Moins d'octets que l'en-tete de data block (CAT + LEN) n'en exige.
    #[error("ASTERIX payload too small: needed {needed} bytes, got {actual}")]
    Truncated { needed: usize, actual: usize },

    /// La longueur declaree ne peut pas contenir un en-tete et un record,
    /// ou depasse les octets restants.
    #[error(
        "ASTERIX data block of category {category} declares {declared} bytes, {available} available"
    )]
    InvalidBlockLength {
        category: u8,
        declared: u16,
        available: usize,
    },

    /// Aucun UAP n'est connu pour cette categorie : ses records ne peuvent
    /// pas etre decoupes, donc le datagramme n'est pas reconnu.
    #[error("ASTERIX category {0} is not supported")]
    UnsupportedCategory(u8),

    /// Un record dont le FSPEC n'annonce aucun data item.
    #[error("ASTERIX record of category {category} carries no data item")]
    EmptyRecord { category: u8 },

    /// Le FSPEC continue (bit FX) au-dela des octets que l'UAP definit.
    #[error("ASTERIX FSPEC of category {category} extends beyond its UAP")]
    FspecOverflow { category: u8 },

    /// Un bit du FSPEC designe un FRN de reserve, ou hors de l'UAP.
    #[error("ASTERIX FRN {frn} is not defined in the UAP of category {category}")]
    UnknownFrn { category: u8, frn: u8 },

    /// Un bit du primary subfield d'un item compose designe un sous-champ
    /// de reserve, ou hors de la definition de l'item.
    #[error("ASTERIX item {item} sets undefined subfield #{subfield}")]
    UnknownSubfield { item: &'static str, subfield: u8 },

    /// Un champ explicite (SP, RE) declare une longueur nulle : le LEN se
    /// compte lui-meme, sa valeur minimale est 1.
    #[error("ASTERIX item {item} declares a zero explicit length")]
    InvalidExplicitLength { item: &'static str },

    /// Le data item deborde du record.
    #[error("ASTERIX item {item} is truncated: needed {needed} bytes, got {actual}")]
    TruncatedItem {
        item: &'static str,
        needed: usize,
        actual: usize,
    },

    /// Les records n'atteignent pas exactement la fin du data block.
    #[error("ASTERIX data block of category {category} is not exactly filled by its records")]
    BlockNotConsumed { category: u8 },
}
