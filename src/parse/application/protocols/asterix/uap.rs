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
//! Sources : EUROCONTROL-SPEC-0149, dans l'edition que tshark 4.6.6 retient
//! par defaut — Part 2a (CAT 001, ed. 1.4), Part 2b (CAT 002, ed. 1.2, et
//! CAT 034, ed. 1.29), Part 3 (CAT 008, ed. 1.3), Part 4 (CAT 048, ed.
//! 1.32), Part 9 (CAT 062, ed. 1.21), Part 10 (CAT 063, ed. 1.7), Part 15
//! (CAT 065, ed. 1.6), Part 12 (CAT 021, ed. 2.7), Part 16 (CAT 023, ed.
//! 1.3) et Part 17 (CAT 247, ed. 1.3). Les tables des categories ajoutees
//! par #119 ont ete derivees des definitions lisibles par machine de
//! `zoranbosnjak/asterix-specs` (BSD-3), puis recoupees avec tshark sur le
//! corpus. Les UAP sont stables entre editions : seul le nombre d'extents
//! de quelques items extensibles grandit (I021/090, I062/080), et la table
//! retient l'edition la plus recente, qui accepte les precedentes. Les
//! editions 0.2x de CAT 021, d'ordre entierement different, ne sont pas
//! decrites — rien dans les octets ne permet de les distinguer.

/// Format structurel d'un data item (Part 1, ed. 3.1, §5.2.5.1.1 a
/// §5.2.5.1.5 ; SP et RE, §5.2.5.4 et §5.2.5.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ItemFormat {
    /// Longueur fixe, en octets.
    Fixed(usize),
    /// Extensible a extents d'un octet, en nombre non borne : le bit 1 (FX)
    /// de chaque octet annonce un octet de plus. C'est la forme `repetitive
    /// fx` d'elements de sept bits (I048/030, I001/130, I002/050…), soit
    /// [`ItemFormat::RepetitiveFx`]`(1)`.
    Variable,
    /// Un octet REP, puis REP fois `n` octets.
    Repetitive(usize),
    /// Un primary subfield extensible dont chaque bit annonce un sous-champ,
    /// dans l'ordre de la liste (7 par octet, le bit 1 restant le FX).
    Compound(&'static [Subfield]),
    /// Un octet LEN (lui compris) puis les donnees : SP et RE.
    Explicit,
    /// Extensible borne (`extended` de la specification) : les extents, de
    /// tailles connues en octets, chacun termine par son bit FX ; le FX du
    /// dernier extent defini doit etre a zero — un record qui le pose
    /// annonce plus que l'UAP ne definit (I048/020, I062/080, I023/101 a
    /// premier extent de deux octets…).
    Extended(&'static [usize]),
    /// Extents de `n` octets, FX en bit 1 du dernier octet de chacun, en
    /// nombre non borne (`repetitive fx` d'elements de plus de sept bits :
    /// I062/510, trois octets par unite).
    RepetitiveFx(usize),
    /// Random Field Sequencing (Part 1, ed. 1.0 de novembre 1997, §4.3.5.3 ;
    /// retire de la Part 1 des le brouillon 1.1 d'aout 1998) : un octet N,
    /// puis N data items introduits chacun par leur FRN sur un octet, dans un
    /// ordre quelconque. CAT 001, 002 et 008 le reservent en fin d'UAP.
    Rfs,
}

/// Format d'un sous-champ d'item compose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Subfield {
    Fixed(usize),
    /// Extents d'un octet, non borne : voir [`ItemFormat::Variable`].
    Variable,
    Repetitive(usize),
    /// Bit reserve du primary subfield : un record qui le pose n'est pas
    /// decodable.
    Spare,
    /// Extensible borne : voir [`ItemFormat::Extended`].
    Extended(&'static [usize]),
    /// Extents de `n` octets, non borne : voir [`ItemFormat::RepetitiveFx`].
    RepetitiveFx(usize),
}

/// Un data item de l'UAP : son identifiant (`I048/010`) et son format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ItemSpec {
    pub id: &'static str,
    pub format: ItemFormat,
}

/// Regle de choix entre plusieurs UAP d'une meme categorie, lue dans le
/// record lui-meme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UapSelector {
    /// CAT 001 : le bit TYP (bit 8 du premier octet de I001/020) choisit
    /// l'UAP des plots (0) ou des pistes (1) ; sans I001/020, celui des
    /// plots — comme tshark.
    Cat001TargetType,
}

/// UAP d'une categorie : `items[frn - 1]`, `None` pour un FRN de reserve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Uap {
    pub category: u8,
    pub items: &'static [Option<ItemSpec>],
    /// Quand la categorie a plusieurs UAP, la regle qui designe celui du
    /// record ; `None` pour une categorie a UAP unique ou pour une variante
    /// deja choisie.
    pub selector: Option<UapSelector>,
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

    /// La specification d'un item par son identifiant (`"I001/040"`), dans
    /// cet UAP.
    pub fn item_by_id(&self, id: &str) -> Option<&'static ItemSpec> {
        self.items.iter().flatten().find(|spec| spec.id == id)
    }
}

const fn item(id: &'static str, format: ItemFormat) -> Option<ItemSpec> {
    Some(ItemSpec { id, format })
}

const fn fixed(id: &'static str, len: usize) -> Option<ItemSpec> {
    item(id, ItemFormat::Fixed(len))
}

/// CAT 001 — Monoradar Target Reports (Part 2a, ed. 1.4, §4.3), UAP des
/// plots : TYP = 0 dans I001/020, ou I001/020 absent.
static CAT001_PLOT_ITEMS: [Option<ItemSpec>; 21] = [
    fixed("I001/010", 2),
    item("I001/020", ItemFormat::Extended(&[1, 1])),
    fixed("I001/040", 4),
    fixed("I001/070", 2),
    fixed("I001/090", 2),
    item("I001/130", ItemFormat::Variable),
    fixed("I001/141", 2),
    fixed("I001/050", 2),
    fixed("I001/120", 1),
    fixed("I001/131", 1),
    fixed("I001/080", 2),
    fixed("I001/100", 4),
    fixed("I001/060", 2),
    item("I001/030", ItemFormat::Variable),
    fixed("I001/150", 1),
    None,
    None,
    None,
    None,
    item("I001/SP", ItemFormat::Explicit),
    item("I001/RFS", ItemFormat::Rfs),
];

/// CAT 001, UAP des pistes : TYP = 1 dans I001/020. I001/150 y suit le RFS.
static CAT001_TRACK_ITEMS: [Option<ItemSpec>; 22] = [
    fixed("I001/010", 2),
    item("I001/020", ItemFormat::Extended(&[1, 1])),
    fixed("I001/161", 2),
    fixed("I001/040", 4),
    fixed("I001/042", 4),
    fixed("I001/200", 4),
    fixed("I001/070", 2),
    fixed("I001/090", 2),
    fixed("I001/141", 2),
    item("I001/130", ItemFormat::Variable),
    fixed("I001/131", 1),
    fixed("I001/120", 1),
    item("I001/170", ItemFormat::Extended(&[1, 1])),
    item("I001/210", ItemFormat::Variable),
    fixed("I001/050", 2),
    fixed("I001/080", 2),
    fixed("I001/100", 4),
    fixed("I001/060", 2),
    item("I001/030", ItemFormat::Variable),
    item("I001/SP", ItemFormat::Explicit),
    item("I001/RFS", ItemFormat::Rfs),
    fixed("I001/150", 1),
];

/// CAT 002 — Monoradar Service Messages (Part 2b, ed. 1.2, §4.3).
static CAT002_ITEMS: [Option<ItemSpec>; 14] = [
    fixed("I002/010", 2),
    fixed("I002/000", 1),
    fixed("I002/020", 1),
    fixed("I002/030", 3),
    fixed("I002/041", 2),
    item("I002/050", ItemFormat::Variable),
    item("I002/060", ItemFormat::Variable),
    item("I002/070", ItemFormat::Repetitive(2)),
    fixed("I002/100", 8),
    fixed("I002/090", 2),
    item("I002/080", ItemFormat::Variable),
    None,
    item("I002/SP", ItemFormat::Explicit),
    item("I002/RFS", ItemFormat::Rfs),
];

/// CAT 008 — Monoradar Derived Weather Information (Part 3, ed. 1.3, §4.3).
static CAT008_ITEMS: [Option<ItemSpec>; 14] = [
    fixed("I008/010", 2),
    fixed("I008/000", 1),
    item("I008/020", ItemFormat::Extended(&[1, 1])),
    item("I008/036", ItemFormat::Repetitive(3)),
    item("I008/034", ItemFormat::Repetitive(4)),
    fixed("I008/040", 2),
    item("I008/050", ItemFormat::Repetitive(2)),
    fixed("I008/090", 3),
    // Processing Status : un seul extent, de trois octets.
    item("I008/100", ItemFormat::Extended(&[3])),
    item("I008/110", ItemFormat::Variable),
    fixed("I008/120", 2),
    item("I008/038", ItemFormat::Repetitive(4)),
    item("I008/SP", ItemFormat::Explicit),
    item("I008/RFS", ItemFormat::Rfs),
];

/// CAT 021 — ADS-B Target Reports (Part 12, ed. 2.7, §4.3).
///
/// Data Ages (I021/295) : 23 sous-champs d'un octet, dans l'ordre du
/// primary subfield (AOS, TRD, M3A, QI, TI, MAM, GH ; FL, ISA, FSA, AS, TAS,
/// MH, BVR ; GVR, GV, TAR, TI, TS, MET, ROA ; ARA, SCC).
static CAT021_DATA_AGES: [Subfield; 23] = [Subfield::Fixed(1); 23];

static CAT021_ITEMS: [Option<ItemSpec>; 49] = [
    fixed("I021/010", 2),
    item("I021/040", ItemFormat::Extended(&[1, 1, 1, 1, 1])),
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
    // Quality Indicators : neuf extents en ed. 2.7 (quatre en 2.6).
    item("I021/090", ItemFormat::Extended(&[1; 9])),
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
    // Trajectory Intent : TIS (un extent), TID (repetitif, 15 octets).
    item(
        "I021/110",
        ItemFormat::Compound(&[Subfield::Extended(&[1]), Subfield::Repetitive(15)]),
    ),
    fixed("I021/016", 1),
    fixed("I021/008", 1),
    item("I021/271", ItemFormat::Extended(&[1, 1])),
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

/// CAT 023 — CNS/ATM Ground Station and Service Status Reports (Part 16,
/// ed. 1.3, §4.3).
static CAT023_ITEMS: [Option<ItemSpec>; 14] = [
    fixed("I023/010", 2),
    fixed("I023/000", 1),
    fixed("I023/015", 1),
    fixed("I023/070", 3),
    item("I023/100", ItemFormat::Extended(&[1, 1])),
    // Service Configuration : premier extent de deux octets.
    item("I023/101", ItemFormat::Extended(&[2, 1])),
    fixed("I023/200", 1),
    item("I023/110", ItemFormat::Extended(&[1])),
    item("I023/120", ItemFormat::Repetitive(6)),
    None,
    None,
    None,
    item("I023/RE", ItemFormat::Explicit),
    item("I023/SP", ItemFormat::Explicit),
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

/// CAT 048 — Monoradar Target Reports (Part 4, ed. 1.32, §4.3).
static CAT048_ITEMS: [Option<ItemSpec>; 28] = [
    fixed("I048/010", 2),
    fixed("I048/140", 3),
    item("I048/020", ItemFormat::Extended(&[1, 1, 1, 1, 1, 1])),
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
    item("I048/170", ItemFormat::Extended(&[1, 1])),
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

/// CAT 062 — SDPS Track Messages (Part 9, ed. 1.21, §4.3).
///
/// Aircraft Derived Data (I062/380), dans l'ordre du primary subfield : ADR,
/// ID, MHG, IAS, TAS, SAL, FSS, TIS (un extent), TID (repetitif, 15 octets),
/// COM, SAB, ACS, BVR, GVR, RAN, TAR, TAN, GS, VUN, MET, EMC, POS, GAL, PUN,
/// MB (repetitif, 8 octets), IAR, MAC, BPS.
static CAT062_AIRCRAFT_DERIVED_DATA: [Subfield; 28] = [
    Subfield::Fixed(3),
    Subfield::Fixed(6),
    Subfield::Fixed(2),
    Subfield::Fixed(2),
    Subfield::Fixed(2),
    Subfield::Fixed(2),
    Subfield::Fixed(2),
    Subfield::Extended(&[1]),
    Subfield::Repetitive(15),
    Subfield::Fixed(2),
    Subfield::Fixed(2),
    Subfield::Fixed(7),
    Subfield::Fixed(2),
    Subfield::Fixed(2),
    Subfield::Fixed(2),
    Subfield::Fixed(2),
    Subfield::Fixed(2),
    Subfield::Fixed(2),
    Subfield::Fixed(1),
    Subfield::Fixed(8),
    Subfield::Fixed(1),
    Subfield::Fixed(6),
    Subfield::Fixed(2),
    Subfield::Fixed(1),
    Subfield::Repetitive(8),
    Subfield::Fixed(2),
    Subfield::Fixed(2),
    Subfield::Fixed(2),
];

/// Track Data Ages (I062/295) : 31 sous-champs d'un octet (MFL, MD1, MD2,
/// MDA, MD4, MD5, MHG ; IAS, TAS, SAL, FSS, TID, COM, SAB ; ACS, BVR, GVR,
/// RAN, TAR, TAN, GSP ; VUN, MET, EMC, POS, GAL, PUN, MB ; IAR, MAC, BPS).
static CAT062_TRACK_DATA_AGES: [Subfield; 31] = [Subfield::Fixed(1); 31];

/// Flight Plan Related Data (I062/390) : TAG, CSN, IFI, FCT, TAC, WTC, DEP,
/// DST, RDS, CFL, CTL, TOD (repetitif, 4 octets), AST, STS, STD, STA, PEM,
/// PEC.
static CAT062_FLIGHT_PLAN_DATA: [Subfield; 18] = [
    Subfield::Fixed(2),
    Subfield::Fixed(7),
    Subfield::Fixed(4),
    Subfield::Fixed(1),
    Subfield::Fixed(4),
    Subfield::Fixed(1),
    Subfield::Fixed(4),
    Subfield::Fixed(4),
    Subfield::Fixed(3),
    Subfield::Fixed(2),
    Subfield::Fixed(2),
    Subfield::Repetitive(4),
    Subfield::Fixed(6),
    Subfield::Fixed(1),
    Subfield::Fixed(7),
    Subfield::Fixed(7),
    Subfield::Fixed(2),
    Subfield::Fixed(7),
];

static CAT062_ITEMS: [Option<ItemSpec>; 35] = [
    fixed("I062/010", 2),
    None,
    fixed("I062/015", 1),
    fixed("I062/070", 3),
    fixed("I062/105", 8),
    fixed("I062/100", 6),
    fixed("I062/185", 4),
    fixed("I062/210", 2),
    fixed("I062/060", 2),
    fixed("I062/245", 7),
    item(
        "I062/380",
        ItemFormat::Compound(&CAT062_AIRCRAFT_DERIVED_DATA),
    ),
    fixed("I062/040", 2),
    // Track Status : sept extents en ed. 1.21 (six en 1.20).
    item("I062/080", ItemFormat::Extended(&[1; 7])),
    // System Track Update Ages : TRK, PSR, SSR, MDS, ADS (2 octets), ES,
    // VDL, UAT, LOP, MLT.
    item(
        "I062/290",
        ItemFormat::Compound(&[
            Subfield::Fixed(1),
            Subfield::Fixed(1),
            Subfield::Fixed(1),
            Subfield::Fixed(1),
            Subfield::Fixed(2),
            Subfield::Fixed(1),
            Subfield::Fixed(1),
            Subfield::Fixed(1),
            Subfield::Fixed(1),
            Subfield::Fixed(1),
        ]),
    ),
    fixed("I062/200", 1),
    item("I062/295", ItemFormat::Compound(&CAT062_TRACK_DATA_AGES)),
    fixed("I062/136", 2),
    fixed("I062/130", 2),
    fixed("I062/135", 2),
    fixed("I062/220", 2),
    item("I062/390", ItemFormat::Compound(&CAT062_FLIGHT_PLAN_DATA)),
    item("I062/270", ItemFormat::Extended(&[1, 1, 1])),
    fixed("I062/300", 1),
    // Mode 5 Data Reports and Extended Mode 1 Code : SUM, PMN, POS, GA, EM1,
    // TOS, XP.
    item(
        "I062/110",
        ItemFormat::Compound(&[
            Subfield::Fixed(1),
            Subfield::Fixed(4),
            Subfield::Fixed(6),
            Subfield::Fixed(2),
            Subfield::Fixed(2),
            Subfield::Fixed(1),
            Subfield::Fixed(1),
        ]),
    ),
    fixed("I062/120", 2),
    // Composed Track Number : unites de trois octets (IDENT, TRACK, FX).
    item("I062/510", ItemFormat::RepetitiveFx(3)),
    // Estimated Accuracies : APC, COV, APW, AGA, ABA, ATV, AAS, ARC.
    item(
        "I062/500",
        ItemFormat::Compound(&[
            Subfield::Fixed(4),
            Subfield::Fixed(2),
            Subfield::Fixed(4),
            Subfield::Fixed(1),
            Subfield::Fixed(1),
            Subfield::Fixed(2),
            Subfield::Fixed(2),
            Subfield::Fixed(1),
        ]),
    ),
    // Measured Information : SID, POS, HEI, MDC, MDA, TYP.
    item(
        "I062/340",
        ItemFormat::Compound(&[
            Subfield::Fixed(2),
            Subfield::Fixed(4),
            Subfield::Fixed(2),
            Subfield::Fixed(2),
            Subfield::Fixed(2),
            Subfield::Fixed(1),
        ]),
    ),
    None,
    None,
    None,
    None,
    None,
    item("I062/RE", ItemFormat::Explicit),
    item("I062/SP", ItemFormat::Explicit),
];

/// CAT 063 — Sensor Status Messages (Part 10, ed. 1.7, §4.3).
static CAT063_ITEMS: [Option<ItemSpec>; 14] = [
    fixed("I063/010", 2),
    fixed("I063/015", 1),
    fixed("I063/030", 3),
    fixed("I063/050", 2),
    item("I063/060", ItemFormat::Extended(&[1, 1, 1])),
    fixed("I063/070", 2),
    fixed("I063/080", 4),
    fixed("I063/081", 2),
    fixed("I063/090", 4),
    fixed("I063/091", 2),
    fixed("I063/092", 2),
    None,
    item("I063/RE", ItemFormat::Explicit),
    item("I063/SP", ItemFormat::Explicit),
];

/// CAT 065 — SDPS Service Status Messages (Part 15, ed. 1.6, §4.3).
static CAT065_ITEMS: [Option<ItemSpec>; 14] = [
    fixed("I065/010", 2),
    fixed("I065/000", 1),
    fixed("I065/015", 1),
    fixed("I065/030", 3),
    fixed("I065/020", 1),
    fixed("I065/040", 1),
    fixed("I065/050", 1),
    None,
    None,
    None,
    None,
    None,
    item("I065/RE", ItemFormat::Explicit),
    item("I065/SP", ItemFormat::Explicit),
];

/// CAT 247 — Version Number Exchange (Part 17, ed. 1.3, §4.3).
static CAT247_ITEMS: [Option<ItemSpec>; 7] = [
    fixed("I247/010", 2),
    fixed("I247/015", 1),
    fixed("I247/140", 3),
    item("I247/550", ItemFormat::Repetitive(3)),
    None,
    item("I247/SP", ItemFormat::Explicit),
    item("I247/RE", ItemFormat::Explicit),
];

/// CAT 001, entree de la categorie : l'UAP des plots, dont le selecteur
/// bascule vers [`CAT001_TRACK`] quand I001/020 annonce une piste.
pub static CAT001: Uap = Uap {
    category: 1,
    items: &CAT001_PLOT_ITEMS,
    selector: Some(UapSelector::Cat001TargetType),
};

pub static CAT001_TRACK: Uap = Uap {
    category: 1,
    items: &CAT001_TRACK_ITEMS,
    selector: None,
};

pub static CAT002: Uap = Uap {
    category: 2,
    items: &CAT002_ITEMS,
    selector: None,
};

pub static CAT008: Uap = Uap {
    category: 8,
    items: &CAT008_ITEMS,
    selector: None,
};

pub static CAT021: Uap = Uap {
    category: 21,
    items: &CAT021_ITEMS,
    selector: None,
};

pub static CAT023: Uap = Uap {
    category: 23,
    items: &CAT023_ITEMS,
    selector: None,
};

pub static CAT034: Uap = Uap {
    category: 34,
    items: &CAT034_ITEMS,
    selector: None,
};

pub static CAT048: Uap = Uap {
    category: 48,
    items: &CAT048_ITEMS,
    selector: None,
};

pub static CAT062: Uap = Uap {
    category: 62,
    items: &CAT062_ITEMS,
    selector: None,
};

pub static CAT063: Uap = Uap {
    category: 63,
    items: &CAT063_ITEMS,
    selector: None,
};

pub static CAT065: Uap = Uap {
    category: 65,
    items: &CAT065_ITEMS,
    selector: None,
};

pub static CAT247: Uap = Uap {
    category: 247,
    items: &CAT247_ITEMS,
    selector: None,
};

/// Categories dont l'UAP est connu, donc decodables.
pub static SUPPORTED_CATEGORIES: [u8; 11] = [1, 2, 8, 21, 23, 34, 48, 62, 63, 65, 247];

/// L'UAP d'une categorie, `None` si elle n'est pas supportee. Pour CAT 001,
/// l'UAP des plots, dont le [`Uap::selector`] designe celui des pistes.
pub fn uap_for(category: u8) -> Option<&'static Uap> {
    match category {
        1 => Some(&CAT001),
        2 => Some(&CAT002),
        8 => Some(&CAT008),
        21 => Some(&CAT021),
        23 => Some(&CAT023),
        34 => Some(&CAT034),
        48 => Some(&CAT048),
        62 => Some(&CAT062),
        63 => Some(&CAT063),
        65 => Some(&CAT065),
        247 => Some(&CAT247),
        _ => None,
    }
}

/// Toutes les variantes d'UAP d'une categorie, pour retrouver un item par
/// son identifiant quel que soit l'UAP qui l'a porte.
pub(crate) fn uaps_for(category: u8) -> impl Iterator<Item = &'static Uap> {
    uap_for(category)
        .into_iter()
        .chain((category == 1).then_some(&CAT001_TRACK))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_every_supported_category_has_a_uap_and_vice_versa() {
        for category in SUPPORTED_CATEGORIES {
            let uap = uap_for(category).expect("categorie supportee sans UAP");
            assert_eq!(uap.category, category);
            assert_eq!(
                uaps_for(category).count(),
                if category == 1 { 2 } else { 1 }
            );
        }
        for category in (0..=255u8).filter(|c| !SUPPORTED_CATEGORIES.contains(c)) {
            assert!(uap_for(category).is_none(), "CAT {category}");
            assert_eq!(uaps_for(category).count(), 0, "CAT {category}");
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
        // CAT 001 : I001/150 est le FRN 15 des plots et le FRN 22 des pistes.
        assert_eq!(CAT001.item(15).map(|i| i.id), Some("I001/150"));
        assert_eq!(CAT001_TRACK.item(22).map(|i| i.id), Some("I001/150"));
        assert_eq!(CAT001_TRACK.item(3).map(|i| i.id), Some("I001/161"));
        assert_eq!(CAT001.item_by_id("I001/161"), None);
        assert_eq!(
            CAT001_TRACK.item_by_id("I001/161").map(|i| i.format),
            Some(ItemFormat::Fixed(2))
        );
        // CAT 062 : FRN 2 et 29 a 33 reserves.
        assert_eq!(CAT062.item(2), None);
        assert_eq!(CAT062.item(28).map(|i| i.id), Some("I062/340"));
        assert_eq!(CAT062.item(34).map(|i| i.id), Some("I062/RE"));
    }

    #[test]
    fn test_fspec_sizes() {
        assert_eq!(CAT001.max_fspec_octets(), 3);
        assert_eq!(CAT001_TRACK.max_fspec_octets(), 4);
        assert_eq!(CAT002.max_fspec_octets(), 2);
        assert_eq!(CAT008.max_fspec_octets(), 2);
        assert_eq!(CAT021.max_fspec_octets(), 7);
        assert_eq!(CAT023.max_fspec_octets(), 2);
        assert_eq!(CAT034.max_fspec_octets(), 2);
        assert_eq!(CAT048.max_fspec_octets(), 4);
        assert_eq!(CAT062.max_fspec_octets(), 5);
        assert_eq!(CAT063.max_fspec_octets(), 2);
        assert_eq!(CAT065.max_fspec_octets(), 2);
        assert_eq!(CAT247.max_fspec_octets(), 1);
    }

    #[test]
    fn test_item_ids_carry_their_category() {
        for category in SUPPORTED_CATEGORIES {
            let prefix = format!("I{category:03}/");
            for uap in uaps_for(category) {
                assert_eq!(uap.category, category);
                for spec in uap.items.iter().flatten() {
                    assert!(spec.id.starts_with(&prefix), "{}", spec.id);
                }
            }
        }
    }

    #[test]
    fn test_only_cat001_selects_its_uap_and_rfs_is_reserved_to_three_categories() {
        for category in SUPPORTED_CATEGORIES {
            let uap = uap_for(category).unwrap();
            assert_eq!(uap.selector.is_some(), category == 1, "CAT {category}");
            let has_rfs = uap
                .items
                .iter()
                .flatten()
                .any(|spec| spec.format == ItemFormat::Rfs);
            assert_eq!(has_rfs, matches!(category, 1 | 2 | 8), "CAT {category}");
        }
        assert_eq!(CAT001_TRACK.selector, None);
    }

    #[test]
    fn test_extended_items_have_at_least_one_extent() {
        for category in SUPPORTED_CATEGORIES {
            for uap in uaps_for(category) {
                for spec in uap.items.iter().flatten() {
                    match spec.format {
                        ItemFormat::Extended(extents) => {
                            assert!(!extents.is_empty(), "{}", spec.id);
                            assert!(extents.iter().all(|&size| size > 0), "{}", spec.id);
                        }
                        ItemFormat::RepetitiveFx(size)
                        | ItemFormat::Repetitive(size)
                        | ItemFormat::Fixed(size) => assert!(size > 0, "{}", spec.id),
                        ItemFormat::Compound(subfields) => {
                            for subfield in subfields {
                                match subfield {
                                    Subfield::Extended(extents) => {
                                        assert!(!extents.is_empty(), "{}", spec.id);
                                    }
                                    Subfield::Fixed(size)
                                    | Subfield::Repetitive(size)
                                    | Subfield::RepetitiveFx(size) => {
                                        assert!(*size > 0, "{}", spec.id);
                                    }
                                    Subfield::Variable | Subfield::Spare => {}
                                }
                            }
                        }
                        ItemFormat::Variable | ItemFormat::Explicit | ItemFormat::Rfs => {}
                    }
                }
            }
        }
    }
}
