// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! User Application Profiles : pour chaque categorie supportee, l'ordre des
//! data items dans le FSPEC (Field Reference Number, FRN) et le format
//! structurel de chacun. C'est tout ce qu'il faut pour decouper un record
//! sans en interpreter le contenu — et c'est ce que le probing exige : un
//! record qui ne se decoupe pas exactement selon son UAP n'est pas de
//! l'ASTERIX de cette categorie.
//!
//! Sources : EUROCONTROL-SPEC-0149, Part 4 (CAT 048, ed. 1.32), Part 2b
//! (CAT 034, ed. 1.29) et Part 12 (CAT 021, ed. 2.6). Les UAP y sont
//! stables depuis les editions 1.x de CAT 034/048 et 2.1 de CAT 021 ; les
//! editions 0.2x de CAT 021, d'ordre entierement different, ne sont pas
//! decrites — rien dans les octets ne permet de les distinguer.

/// Format structurel d'un data item (Part 1, §5.2.5 a §5.2.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ItemFormat {
    /// Longueur fixe, en octets.
    Fixed(usize),
    /// Extensible : le bit 1 (FX) de chaque octet annonce un octet de plus.
    Variable,
    /// Un octet REP, puis REP fois `n` octets.
    Repetitive(usize),
    /// Un primary subfield extensible dont chaque bit annonce un sous-champ,
    /// dans l'ordre de la liste (7 par octet, le bit 1 restant le FX).
    Compound(&'static [Subfield]),
    /// Un octet LEN (lui compris) puis les donnees : SP et RE.
    Explicit,
}

/// Format d'un sous-champ d'item compose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Subfield {
    Fixed(usize),
    Variable,
    Repetitive(usize),
    /// Bit reserve du primary subfield : un record qui le pose n'est pas
    /// decodable.
    Spare,
}

/// Un data item de l'UAP : son identifiant (`I048/010`) et son format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ItemSpec {
    pub id: &'static str,
    pub format: ItemFormat,
}

/// UAP d'une categorie : `items[frn - 1]`, `None` pour un FRN de reserve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Uap {
    pub category: u8,
    pub items: &'static [Option<ItemSpec>],
}

impl Uap {
    /// Nombre maximal d'octets de FSPEC : sept FRN par octet.
    pub const fn max_fspec_octets(&self) -> usize {
        self.items.len().div_ceil(7)
    }

    pub fn item(&self, frn: u8) -> Option<&'static ItemSpec> {
        let index = usize::from(frn).checked_sub(1)?;
        self.items.get(index)?.as_ref()
    }
}

const fn item(id: &'static str, format: ItemFormat) -> Option<ItemSpec> {
    Some(ItemSpec { id, format })
}

const fn fixed(id: &'static str, len: usize) -> Option<ItemSpec> {
    item(id, ItemFormat::Fixed(len))
}

/// CAT 048 — Monoradar Target Reports (Part 4, ed. 1.32, §4.3).
static CAT048_ITEMS: [Option<ItemSpec>; 28] = [
    fixed("I048/010", 2),
    fixed("I048/140", 3),
    item("I048/020", ItemFormat::Variable),
    fixed("I048/040", 4),
    fixed("I048/070", 2),
    fixed("I048/090", 2),
    // Radar Plot Characteristics : SRL, SRR, SAM, PRL, PAM, RPD, APD.
    item(
        "I048/130",
        ItemFormat::Compound(&[
            Subfield::Fixed(1),
            Subfield::Fixed(1),
            Subfield::Fixed(1),
            Subfield::Fixed(1),
            Subfield::Fixed(1),
            Subfield::Fixed(1),
            Subfield::Fixed(1),
        ]),
    ),
    fixed("I048/220", 3),
    fixed("I048/240", 6),
    item("I048/250", ItemFormat::Repetitive(8)),
    fixed("I048/161", 2),
    fixed("I048/042", 4),
    fixed("I048/200", 4),
    item("I048/170", ItemFormat::Variable),
    fixed("I048/210", 4),
    item("I048/030", ItemFormat::Variable),
    fixed("I048/080", 2),
    fixed("I048/100", 4),
    fixed("I048/110", 2),
    // Radial Doppler Speed : CAL (2 octets), RDS (repetitif, 6 octets).
    item(
        "I048/120",
        ItemFormat::Compound(&[Subfield::Fixed(2), Subfield::Repetitive(6)]),
    ),
    fixed("I048/230", 2),
    fixed("I048/260", 7),
    fixed("I048/055", 1),
    fixed("I048/050", 2),
    fixed("I048/065", 1),
    fixed("I048/060", 2),
    item("I048/SP", ItemFormat::Explicit),
    item("I048/RE", ItemFormat::Explicit),
];

/// CAT 034 — Monoradar Service Messages (Part 2b, ed. 1.29, §4.3).
static CAT034_ITEMS: [Option<ItemSpec>; 14] = [
    fixed("I034/010", 2),
    fixed("I034/000", 1),
    fixed("I034/030", 3),
    fixed("I034/020", 1),
    fixed("I034/041", 2),
    // System Configuration and Status : COM, deux reserves, PSR, SSR, MDS.
    item(
        "I034/050",
        ItemFormat::Compound(&[
            Subfield::Fixed(1),
            Subfield::Spare,
            Subfield::Spare,
            Subfield::Fixed(1),
            Subfield::Fixed(1),
            Subfield::Fixed(2),
        ]),
    ),
    // System Processing Mode : meme decoupage, MDS sur un octet.
    item(
        "I034/060",
        ItemFormat::Compound(&[
            Subfield::Fixed(1),
            Subfield::Spare,
            Subfield::Spare,
            Subfield::Fixed(1),
            Subfield::Fixed(1),
            Subfield::Fixed(1),
        ]),
    ),
    item("I034/070", ItemFormat::Repetitive(2)),
    fixed("I034/100", 8),
    fixed("I034/110", 1),
    fixed("I034/120", 8),
    fixed("I034/090", 2),
    item("I034/RE", ItemFormat::Explicit),
    item("I034/SP", ItemFormat::Explicit),
];

/// Data Ages (I021/295) : 23 sous-champs d'un octet, dans l'ordre du
/// primary subfield (AOS, TRD, M3A, QI, TI, MAM, GH ; FL, ISA, FSA, AS, TAS,
/// MH, BVR ; GVR, GV, TAR, TI, TS, MET, ROA ; ARA, SCC).
static CAT021_DATA_AGES: [Subfield; 23] = [Subfield::Fixed(1); 23];

/// CAT 021 — ADS-B Target Reports (Part 12, ed. 2.6, §4.3).
static CAT021_ITEMS: [Option<ItemSpec>; 49] = [
    fixed("I021/010", 2),
    item("I021/040", ItemFormat::Variable),
    fixed("I021/161", 2),
    fixed("I021/015", 1),
    fixed("I021/071", 3),
    fixed("I021/130", 6),
    fixed("I021/131", 8),
    fixed("I021/072", 3),
    fixed("I021/150", 2),
    fixed("I021/151", 2),
    fixed("I021/080", 3),
    fixed("I021/073", 3),
    fixed("I021/074", 4),
    fixed("I021/075", 3),
    fixed("I021/076", 4),
    fixed("I021/140", 2),
    item("I021/090", ItemFormat::Variable),
    fixed("I021/210", 1),
    fixed("I021/070", 2),
    fixed("I021/230", 2),
    fixed("I021/145", 2),
    fixed("I021/152", 2),
    fixed("I021/200", 1),
    fixed("I021/155", 2),
    fixed("I021/157", 2),
    fixed("I021/160", 4),
    fixed("I021/165", 2),
    fixed("I021/077", 3),
    fixed("I021/170", 6),
    fixed("I021/020", 1),
    // Met Information : WS, WD, TMP (2 octets), TRB (1 octet).
    item(
        "I021/220",
        ItemFormat::Compound(&[
            Subfield::Fixed(2),
            Subfield::Fixed(2),
            Subfield::Fixed(2),
            Subfield::Fixed(1),
        ]),
    ),
    fixed("I021/146", 2),
    fixed("I021/148", 2),
    // Trajectory Intent : TIS (extensible), TID (repetitif, 15 octets).
    item(
        "I021/110",
        ItemFormat::Compound(&[Subfield::Variable, Subfield::Repetitive(15)]),
    ),
    fixed("I021/016", 1),
    fixed("I021/008", 1),
    item("I021/271", ItemFormat::Variable),
    fixed("I021/132", 1),
    item("I021/250", ItemFormat::Repetitive(8)),
    fixed("I021/260", 7),
    fixed("I021/400", 1),
    item("I021/295", ItemFormat::Compound(&CAT021_DATA_AGES)),
    None,
    None,
    None,
    None,
    None,
    item("I021/RE", ItemFormat::Explicit),
    item("I021/SP", ItemFormat::Explicit),
];

pub static CAT021: Uap = Uap {
    category: 21,
    items: &CAT021_ITEMS,
};

pub static CAT034: Uap = Uap {
    category: 34,
    items: &CAT034_ITEMS,
};

pub static CAT048: Uap = Uap {
    category: 48,
    items: &CAT048_ITEMS,
};

/// Categories dont l'UAP est connu, donc decodables.
pub static SUPPORTED_CATEGORIES: [u8; 3] = [21, 34, 48];

/// L'UAP d'une categorie, `None` si elle n'est pas supportee.
pub fn uap_for(category: u8) -> Option<&'static Uap> {
    match category {
        21 => Some(&CAT021),
        34 => Some(&CAT034),
        48 => Some(&CAT048),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_every_supported_category_has_a_uap_and_vice_versa() {
        for category in SUPPORTED_CATEGORIES {
            let uap = uap_for(category).expect("categorie supportee sans UAP");
            assert_eq!(uap.category, category);
        }
        for category in (0..=255u8).filter(|c| !SUPPORTED_CATEGORIES.contains(c)) {
            assert!(uap_for(category).is_none(), "CAT {category}");
        }
    }

    #[test]
    fn test_item_lookup_follows_the_frn_numbering() {
        assert_eq!(CAT048.item(1).map(|i| i.id), Some("I048/010"));
        assert_eq!(CAT048.item(28).map(|i| i.id), Some("I048/RE"));
        assert_eq!(CAT048.item(0), None);
        assert_eq!(CAT048.item(29), None);
        // FRN 43 a 47 de CAT 021 sont reserves.
        assert_eq!(CAT021.item(42).map(|i| i.id), Some("I021/295"));
        assert_eq!(CAT021.item(43), None);
        assert_eq!(CAT021.item(48).map(|i| i.id), Some("I021/RE"));
        assert_eq!(CAT021.item(49).map(|i| i.id), Some("I021/SP"));
    }

    #[test]
    fn test_fspec_sizes() {
        assert_eq!(CAT048.max_fspec_octets(), 4);
        assert_eq!(CAT034.max_fspec_octets(), 2);
        assert_eq!(CAT021.max_fspec_octets(), 7);
    }

    #[test]
    fn test_item_ids_carry_their_category() {
        for uap in [&CAT021, &CAT034, &CAT048] {
            let prefix = format!("I{:03}/", uap.category);
            for spec in uap.items.iter().flatten() {
                assert!(spec.id.starts_with(&prefix), "{}", spec.id);
            }
        }
    }
}
