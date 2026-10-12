// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! ASTERIX (All Purpose STructured EUROCONTROL SuRveillance Information
//! EXchange), le format d'echange des donnees de surveillance du controle
//! aerien : plots et pistes radar, rapports ADS-B, pistes systeme, messages
//! de service.
//!
//! Un datagramme porte un ou plusieurs **data blocks** — un octet de
//! categorie (CAT), deux octets de longueur (LEN, en-tete compris), puis
//! des **records**. Chaque record commence par un FSPEC, suite d'octets dont
//! chaque bit annonce la presence d'un data item ; le bit de poids faible
//! (FX) annonce un octet de FSPEC de plus. L'ordre des bits et le format de
//! chaque item sont fixes par l'UAP de la categorie (voir [`uap`]).
//!
//! Ce module decoupe les records de onze categories et expose chaque item
//! en zero-copie : **CAT 048** (plots et pistes monoradar), **CAT 034** (ses
//! messages de service), **CAT 001** et **CAT 002** (leurs equivalents de
//! premiere generation : plots, pistes et messages de service), **CAT 008**
//! (meteo derivee du radar), **CAT 021** (ADS-B), **CAT 023** (etat des
//! stations sol CNS/ATM), **CAT 062** (pistes systeme du SDPS), **CAT 063**
//! (etat des capteurs), **CAT 065** (etat du service SDPS) et **CAT 247**
//! (numeros de version). Les items les plus courants sont decodes en valeurs
//! typees par les modules `catNNN`.
//!
//! ## Politique de reconnaissance
//!
//! ASTERIX n'a ni magic ni port IANA : sa signature, c'est sa structure.
//! Un datagramme n'est reconnu que si **tous** ses data blocks sont d'une
//! categorie supportee et que leurs records se decoupent exactement selon
//! l'UAP, jusqu'au dernier octet. Un bloc d'une autre categorie fait
//! echouer le decodage entier plutot que d'etiqueter a moitie : la
//! structure d'un bloc inconnu n'est pas verifiable, et `CAT + LEN` seuls
//! matchent trop de choses.
//!
//! CAT 001 a deux UAP, plots et pistes, que le bit TYP de I001/020 departage
//! ([`uap::UapSelector`]) ; CAT 001, 002 et 008 reservent un FRN au Random
//! Field Sequencing, decoupe selon la Part 1 et expose comme un item
//! `Ixxx/RFS` dont [`AsterixRecord::rfs_items`] rend le contenu.

pub mod cat001;
pub mod cat002;
pub mod cat008;
pub mod cat021;
pub mod cat023;
pub mod cat034;
pub mod cat048;
pub mod cat062;
pub mod cat063;
pub mod cat065;
pub mod cat247;
pub mod fields;
pub mod uap;

use crate::{
    checks::application::asterix::{ASTERIX_BLOCK_HEADER_LEN, fx_extent, read_block_header},
    errors::application::asterix::AsterixError,
};
use uap::{ItemFormat, ItemSpec, Subfield, Uap, UapSelector, uap_for, uaps_for};

/// Un datagramme ASTERIX : ses data blocks, dans l'ordre du wire.
///
/// ```mermaid
/// ---
/// title: AsterixPacket
/// ---
/// packet-beta
/// 0-7: "CAT u8"
/// 8-23: "LEN u16 (en-tete compris)"
/// 24-31: "FSPEC (extensible par FX)"
/// 32-63: "Data items, dans l'ordre du FSPEC"
/// 64-95: "... records suivants, puis data block suivant"
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AsterixPacket<'a> {
    pub blocks: Vec<AsterixDataBlock<'a>>,
}

/// Un data block : une categorie, et les records qu'il porte.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AsterixDataBlock<'a> {
    pub category: u8,
    /// Longueur declaree, en-tete compris.
    pub length: u16,
    pub records: Vec<AsterixRecord<'a>>,
}

/// Un record : son FSPEC et ses data items, dans l'ordre des FRN.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AsterixRecord<'a> {
    pub category: u8,
    pub fspec: &'a [u8],
    pub items: Vec<AsterixItem<'a>>,
}

/// Un data item, tel qu'il est sur le wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct AsterixItem<'a> {
    /// Field Reference Number : sa position dans l'UAP, a partir de 1.
    pub frn: u8,
    /// Identifiant de l'item, `I048/010` par exemple ; `I048/SP` et
    /// `I048/RE` pour les champs explicites, `I001/RFS` pour un champ
    /// Random Field Sequencing.
    pub id: &'static str,
    /// Les octets de l'item (zero-copie), en-tete REP ou LEN compris.
    pub data: &'a [u8],
}

impl<'a> AsterixRecord<'a> {
    /// Les octets d'un item, par identifiant (`"I048/240"`) — parmi les
    /// items du FSPEC, puis parmi ceux qu'un champ RFS porte.
    pub fn item(&self, id: &str) -> Option<&'a [u8]> {
        self.items
            .iter()
            .find(|item| item.id == id)
            .map(|item| item.data)
            .or_else(|| {
                self.rfs_items()
                    .into_iter()
                    .find(|item| item.id == id)
                    .map(|item| item.data)
            })
    }

    pub fn has(&self, id: &str) -> bool {
        self.item(id).is_some()
    }

    /// L'UAP qui a decoupe ce record : celui de sa categorie, ou, pour
    /// CAT 001, la variante que le bit TYP de I001/020 designe.
    pub fn uap(&self) -> Option<&'static Uap> {
        let uap = uap_for(self.category)?;
        Some(match uap.selector {
            Some(UapSelector::Cat001TargetType) => {
                // I001/020 est le FRN 2 des deux UAP ; absent, c'est un plot.
                let track = self
                    .items
                    .iter()
                    .find(|item| item.frn == 2)
                    .and_then(|item| item.data.first())
                    .is_some_and(|first| first & 0x80 != 0);
                if track { &uap::CAT001_TRACK } else { uap }
            }
            None => uap,
        })
    }

    /// Les data items portes par les champs Random Field Sequencing du
    /// record, dans l'ordre du wire ; vide pour les categories sans RFS.
    /// Ils ont deja ete valides au decoupage du record.
    pub fn rfs_items(&self) -> Vec<AsterixItem<'a>> {
        let Some(uap) = self.uap() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for container in self.items.iter().filter(|item| {
            uap.item(item.frn)
                .is_some_and(|spec| spec.format == ItemFormat::Rfs)
        }) {
            let buf = container.data;
            let Some(&count) = buf.first() else {
                continue;
            };
            let mut pos = 1;
            for _ in 0..count {
                let Some(&frn) = buf.get(pos) else {
                    break;
                };
                let Some(spec) = uap.item(frn) else {
                    break;
                };
                let Ok(len) = item_len(uap, spec, &buf[pos + 1..]) else {
                    break;
                };
                out.push(AsterixItem {
                    frn,
                    id: spec.id,
                    data: &buf[pos + 1..pos + 1 + len],
                });
                pos += 1 + len;
            }
        }
        out
    }

    /// Les octets du sous-champ `number` (a partir de 1, numerotation de la
    /// specification) d'un item compose, `None` si l'item est absent, n'est
    /// pas compose, ou ne porte pas ce sous-champ.
    pub fn subfield(&self, id: &str, number: usize) -> Option<&'a [u8]> {
        let data = self.item(id)?;
        let spec = uaps_for(self.category).find_map(|uap| uap.item_by_id(id))?;
        let ItemFormat::Compound(subfields) = spec.format else {
            return None;
        };
        let mut found = None;
        walk_compound(data, subfields, spec.id, |index, bytes| {
            if index + 1 == number {
                found = Some(bytes);
            }
        })
        .ok()?;
        found
    }
}

impl<'a> TryFrom<&'a [u8]> for AsterixPacket<'a> {
    type Error = AsterixError;

    fn try_from(payload: &'a [u8]) -> Result<Self, Self::Error> {
        let mut blocks = Vec::new();
        let mut rest = payload;
        // Un buffer vide n'est pas un datagramme : au moins un bloc.
        loop {
            let (category, length) = read_block_header(rest)?;
            let uap = uap_for(category).ok_or(AsterixError::UnsupportedCategory(category))?;
            let body = &rest[ASTERIX_BLOCK_HEADER_LEN..length];
            let records = parse_records(uap, body)?;
            blocks.push(AsterixDataBlock {
                category,
                // `read_block_header` borne `length` par un u16.
                length: length as u16,
                records,
            });
            rest = &rest[length..];
            if rest.is_empty() {
                break;
            }
        }
        Ok(AsterixPacket { blocks })
    }
}

/// Decoupe les records d'un data block jusqu'a son dernier octet.
fn parse_records<'a>(
    uap: &'static Uap,
    body: &'a [u8],
) -> Result<Vec<AsterixRecord<'a>>, AsterixError> {
    let mut records = Vec::new();
    let mut rest = body;
    while !rest.is_empty() {
        let (record, consumed) = parse_record(uap, rest)?;
        records.push(record);
        rest = &rest[consumed..];
    }
    if records.is_empty() {
        // Inatteignable : `read_block_header` exige un corps non vide. Garde
        // le sens du type d'erreur si cette borne bouge.
        return Err(AsterixError::BlockNotConsumed {
            category: uap.category,
        });
    }
    Ok(records)
}

/// Decoupe un record : son FSPEC, puis chaque item annonce, dans l'ordre
/// des FRN. Rend le record et le nombre d'octets consommes.
fn parse_record<'a>(
    uap: &'static Uap,
    buf: &'a [u8],
) -> Result<(AsterixRecord<'a>, usize), AsterixError> {
    let category = uap.category;
    let fspec_len = fx_extent(buf).ok_or(AsterixError::FspecOverflow { category })?;
    let fspec = &buf[..fspec_len];
    let uap = select_uap(uap, fspec, &buf[fspec_len..]);
    if fspec_len > uap.max_fspec_octets() {
        return Err(AsterixError::FspecOverflow { category });
    }
    let mut items = Vec::new();
    let mut pos = fspec_len;
    for (octet_index, octet) in fspec.iter().enumerate() {
        for bit in 0..7u8 {
            if octet & (0x80 >> bit) == 0 {
                continue;
            }
            // Sept FRN par octet ; `octet_index` < 7 et `bit` < 7, donc
            // le FRN tient dans un u8.
            let frn = (octet_index * 7) as u8 + bit + 1;
            let spec = uap
                .item(frn)
                .ok_or(AsterixError::UnknownFrn { category, frn })?;
            let len = match spec.format {
                ItemFormat::Rfs => rfs_len(uap, spec, fspec, &buf[pos..])?,
                _ => item_len(uap, spec, &buf[pos..])?,
            };
            items.push(AsterixItem {
                frn,
                id: spec.id,
                data: &buf[pos..pos + len],
            });
            pos += len;
        }
    }
    if items.is_empty() {
        return Err(AsterixError::EmptyRecord { category });
    }
    Ok((
        AsterixRecord {
            category,
            fspec,
            items,
        },
        pos,
    ))
}

/// L'UAP du record quand la categorie en a plusieurs : CAT 001 lit le bit
/// TYP de I001/020 (FRN 2), place apres I001/010 (FRN 1, deux octets) s'il
/// est present — comme tshark. Sans I001/020, ou sans l'octet, l'UAP des
/// plots ; le decoupage signale ensuite toute troncature.
fn select_uap(uap: &'static Uap, fspec: &[u8], body: &[u8]) -> &'static Uap {
    match uap.selector {
        None => uap,
        Some(UapSelector::Cat001TargetType) => {
            let first = fspec.first().copied().unwrap_or(0);
            if first & 0x40 == 0 {
                return uap;
            }
            let offset = if first & 0x80 != 0 { 2 } else { 0 };
            match body.get(offset) {
                Some(typ) if typ & 0x80 != 0 => &uap::CAT001_TRACK,
                _ => uap,
            }
        }
    }
}

/// Longueur d'un item selon son format, sans en interpreter le contenu.
/// `uap` ne sert qu'au Random Field Sequencing, dont les items sont
/// designes par leur FRN.
fn item_len(uap: &'static Uap, spec: &'static ItemSpec, buf: &[u8]) -> Result<usize, AsterixError> {
    let item = spec.id;
    let truncated = |needed: usize| AsterixError::TruncatedItem {
        item,
        needed,
        actual: buf.len(),
    };
    match spec.format {
        ItemFormat::Fixed(len) => ensure(buf, len, truncated),
        ItemFormat::Variable => fx_extent(buf).ok_or_else(|| truncated(buf.len() + 1)),
        ItemFormat::Repetitive(each) => repetitive_len(buf, each, truncated),
        ItemFormat::Explicit => {
            let declared = usize::from(*buf.first().ok_or_else(|| truncated(1))?);
            if declared == 0 {
                return Err(AsterixError::InvalidExplicitLength { item });
            }
            ensure(buf, declared, truncated)
        }
        ItemFormat::Compound(subfields) => walk_compound(buf, subfields, item, |_, _| {}),
        ItemFormat::Extended(extents) => extended_len(buf, extents, item),
        ItemFormat::RepetitiveFx(each) => repetitive_fx_len(buf, each, item),
        // Hors d'un record (un RFS ne peut pas en porter un autre) : seule la
        // double occurrence interne est verifiee.
        ItemFormat::Rfs => rfs_len(uap, spec, &[], buf),
    }
}

/// Parcourt un item compose : son primary subfield, puis chaque sous-champ
/// annonce, remis a `visit` avec son index (a partir de 0). Rend la
/// longueur totale de l'item.
fn walk_compound<'a>(
    buf: &'a [u8],
    subfields: &'static [Subfield],
    item: &'static str,
    mut visit: impl FnMut(usize, &'a [u8]),
) -> Result<usize, AsterixError> {
    let truncated = |needed: usize| AsterixError::TruncatedItem {
        item,
        needed,
        actual: buf.len(),
    };
    let primary_len = fx_extent(buf).ok_or_else(|| truncated(buf.len() + 1))?;
    let primary = &buf[..primary_len];
    let mut pos = primary_len;
    for (octet_index, octet) in primary.iter().enumerate() {
        for bit in 0..7u8 {
            if octet & (0x80 >> bit) == 0 {
                continue;
            }
            let index = octet_index * 7 + usize::from(bit);
            let unknown = AsterixError::UnknownSubfield {
                item,
                // Numerotation a partir de 1, comme la specification ;
                // `index` est borne par la longueur du primary subfield.
                subfield: (index + 1).min(255) as u8,
            };
            let rest = &buf[pos..];
            let sub_truncated = |needed: usize| AsterixError::TruncatedItem {
                item,
                needed: pos + needed,
                actual: buf.len(),
            };
            // Les erreurs des formes extensibles comptent depuis le debut du
            // sous-champ : les ramener au debut de l'item.
            let rebase = |error: AsterixError| match error {
                AsterixError::TruncatedItem { item, needed, .. } => AsterixError::TruncatedItem {
                    item,
                    needed: pos + needed,
                    actual: buf.len(),
                },
                other => other,
            };
            let len = match subfields.get(index).ok_or(unknown.clone())? {
                Subfield::Spare => return Err(unknown),
                Subfield::Fixed(len) => ensure(rest, *len, sub_truncated)?,
                Subfield::Variable => {
                    fx_extent(rest).ok_or_else(|| sub_truncated(rest.len() + 1))?
                }
                Subfield::Repetitive(each) => repetitive_len(rest, *each, sub_truncated)?,
                Subfield::Extended(extents) => extended_len(rest, extents, item).map_err(rebase)?,
                Subfield::RepetitiveFx(each) => {
                    repetitive_fx_len(rest, *each, item).map_err(rebase)?
                }
            };
            visit(index, &rest[..len]);
            pos += len;
        }
    }
    Ok(pos)
}

fn ensure(
    buf: &[u8],
    needed: usize,
    truncated: impl FnOnce(usize) -> AsterixError,
) -> Result<usize, AsterixError> {
    if buf.len() < needed {
        return Err(truncated(needed));
    }
    Ok(needed)
}

/// Un octet REP puis REP elements de `each` octets. REP peut valoir zero :
/// la specification ne l'interdit pas et tshark l'accepte.
fn repetitive_len(
    buf: &[u8],
    each: usize,
    truncated: impl FnOnce(usize) -> AsterixError,
) -> Result<usize, AsterixError> {
    // `each` <= 15 et `rep` <= 255 : pas de debordement possible.
    let needed = buf.first().map_or(1, |rep| 1 + usize::from(*rep) * each);
    if buf.len() < needed {
        return Err(truncated(needed));
    }
    Ok(needed)
}

/// Extents de tailles connues, chacun termine par son bit FX ; le FX du
/// dernier extent defini doit etre a zero.
fn extended_len(buf: &[u8], extents: &[usize], item: &'static str) -> Result<usize, AsterixError> {
    let mut pos = 0;
    for (index, &size) in extents.iter().enumerate() {
        let end = pos + size.max(1);
        if buf.len() < end {
            return Err(AsterixError::TruncatedItem {
                item,
                needed: end,
                actual: buf.len(),
            });
        }
        pos = end;
        if buf[end - 1] & 0x01 == 0 {
            return Ok(pos);
        }
        if index + 1 == extents.len() {
            return Err(AsterixError::ExtentOverflow { item });
        }
    }
    Err(AsterixError::ExtentOverflow { item })
}

/// Extents de `each` octets, FX en bit 1 du dernier octet de chacun, en
/// nombre non borne.
fn repetitive_fx_len(buf: &[u8], each: usize, item: &'static str) -> Result<usize, AsterixError> {
    let each = each.max(1);
    let mut pos = 0;
    loop {
        let end = pos + each;
        if buf.len() < end {
            return Err(AsterixError::TruncatedItem {
                item,
                needed: end,
                actual: buf.len(),
            });
        }
        pos = end;
        if buf[end - 1] & 0x01 == 0 {
            return Ok(pos);
        }
    }
}

/// Random Field Sequencing : un octet N, puis N items introduits chacun par
/// leur FRN. Un FRN inconnu, de reserve, designant le RFS lui-meme, deja
/// annonce par le FSPEC ou deja porte par le RFS est refuse : un record ne
/// porte chaque data item qu'une fois.
fn rfs_len(
    uap: &'static Uap,
    spec: &'static ItemSpec,
    fspec: &[u8],
    buf: &[u8],
) -> Result<usize, AsterixError> {
    let category = uap.category;
    let truncated = |needed: usize| AsterixError::TruncatedItem {
        item: spec.id,
        needed,
        actual: buf.len(),
    };
    let count = *buf.first().ok_or_else(|| truncated(1))?;
    if count == 0 {
        return Err(AsterixError::EmptyRfs { category });
    }
    // Les FRN deja presents : ceux du FSPEC (sept par octet, au plus 49
    // pour les UAP connus), puis ceux que le RFS a deja portes.
    let mut seen: u64 = 0;
    for (octet_index, octet) in fspec.iter().enumerate() {
        for bit in 0..7u8 {
            if octet & (0x80 >> bit) != 0 {
                let frn = (octet_index * 7) as u32 + u32::from(bit) + 1;
                seen |= 1u64 << frn.min(63);
            }
        }
    }
    let mut pos = 1;
    for _ in 0..count {
        let frn = *buf.get(pos).ok_or_else(|| truncated(pos + 1))?;
        let inner = uap
            .item(frn)
            .filter(|inner| inner.format != ItemFormat::Rfs)
            .ok_or(AsterixError::InvalidRfsFrn { category, frn })?;
        let bit = 1u64 << u32::from(frn).min(63);
        if seen & bit != 0 {
            return Err(AsterixError::DuplicateRfsFrn { category, frn });
        }
        seen |= bit;
        let len = item_len(uap, inner, &buf[pos + 1..])?;
        pos += 1 + len;
    }
    Ok(pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Record CAT 048 minimal : FSPEC 1 octet, I048/010 seul.
    const MINIMAL_048: [u8; 6] = [0x30, 0x00, 0x06, 0x80, 0x19, 0xc9];

    #[test]
    fn test_parse_a_minimal_record() {
        let packet = AsterixPacket::try_from(&MINIMAL_048[..]).expect("bloc minimal");
        assert_eq!(packet.blocks.len(), 1);
        let block = &packet.blocks[0];
        assert_eq!((block.category, block.length), (48, 6));
        assert_eq!(block.records.len(), 1);
        let record = &block.records[0];
        assert_eq!(record.category, 48);
        assert_eq!(record.fspec, &[0x80]);
        assert_eq!(record.items.len(), 1);
        assert_eq!(record.items[0].frn, 1);
        assert_eq!(record.items[0].id, "I048/010");
        assert_eq!(record.item("I048/010"), Some(&[0x19, 0xc9][..]));
        assert!(!record.has("I048/140"));
        assert_eq!(record.uap(), Some(&uap::CAT048));
        assert!(record.rfs_items().is_empty());
    }

    #[test]
    fn test_items_borrow_the_input() {
        let packet = AsterixPacket::try_from(&MINIMAL_048[..]).unwrap();
        let data = packet.blocks[0].records[0].items[0].data;
        assert!(MINIMAL_048.as_ptr_range().contains(&data.as_ptr()));
    }

    #[test]
    fn test_several_records_and_blocks_tile_the_datagram() {
        let mut datagram = Vec::new();
        // Bloc 034 de dix octets : un record (010), puis un record (010 et
        // 000 — FSPEC 0xc0, les items suivent l'ordre des FRN).
        datagram.extend_from_slice(&[0x22, 0x00, 0x0a]);
        datagram.extend_from_slice(&[0x80, 0x00, 0x01]);
        datagram.extend_from_slice(&[0xc0, 0x00, 0x01, 0x01]);
        // Puis un bloc 048 minimal.
        datagram.extend_from_slice(&MINIMAL_048);
        assert_eq!(datagram.len(), 3 + 3 + 4 + 6);

        let packet = AsterixPacket::try_from(datagram.as_slice()).expect("deux blocs");
        assert_eq!(packet.blocks.len(), 2);
        assert_eq!(packet.blocks[0].category, 34);
        assert_eq!(packet.blocks[0].records.len(), 2);
        let ids: Vec<&str> = packet.blocks[0].records[1]
            .items
            .iter()
            .map(|item| item.id)
            .collect();
        assert_eq!(ids, ["I034/010", "I034/000"]);
        assert_eq!(packet.blocks[1].category, 48);
    }

    #[test]
    fn test_reject_unsupported_category_even_after_a_valid_block() {
        let mut datagram = MINIMAL_048.to_vec();
        datagram.extend_from_slice(&[0x0a, 0x00, 0x05, 0x80, 0x00]); // CAT 010
        assert_eq!(
            AsterixPacket::try_from(datagram.as_slice()),
            Err(AsterixError::UnsupportedCategory(10))
        );
    }

    #[test]
    fn test_reject_trailing_and_missing_bytes() {
        let mut long = MINIMAL_048.to_vec();
        long.push(0x00);
        // L'octet en trop est lu comme l'en-tete d'un bloc suivant, tronque.
        assert!(matches!(
            AsterixPacket::try_from(long.as_slice()),
            Err(AsterixError::Truncated {
                needed: 3,
                actual: 1
            })
        ));
        assert!(matches!(
            AsterixPacket::try_from(&MINIMAL_048[..5]),
            Err(AsterixError::InvalidBlockLength { declared: 6, .. })
        ));
        assert!(matches!(
            AsterixPacket::try_from(&[][..]),
            Err(AsterixError::Truncated { .. })
        ));
    }

    #[test]
    fn test_reject_a_record_that_overflows_its_block() {
        // LEN 6 mais le FSPEC annonce 010 (2) et 140 (3).
        let datagram = [0x30, 0x00, 0x06, 0xc0, 0x19, 0xc9];
        assert_eq!(
            AsterixPacket::try_from(&datagram[..]),
            Err(AsterixError::TruncatedItem {
                item: "I048/140",
                needed: 3,
                actual: 0
            })
        );
    }

    #[test]
    fn test_reject_an_empty_fspec() {
        let datagram = [0x30, 0x00, 0x05, 0x00, 0x00];
        assert_eq!(
            AsterixPacket::try_from(&datagram[..]),
            Err(AsterixError::EmptyRecord { category: 48 })
        );
    }

    #[test]
    fn test_reject_fspec_beyond_the_uap() {
        // CAT 034 : deux octets de FSPEC au plus.
        let datagram = [0x22, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x00];
        assert_eq!(
            AsterixPacket::try_from(&datagram[..]),
            Err(AsterixError::FspecOverflow { category: 34 })
        );
        // FSPEC qui ne se termine jamais.
        let datagram = [0x22, 0x00, 0x05, 0x01, 0x01];
        assert_eq!(
            AsterixPacket::try_from(&datagram[..]),
            Err(AsterixError::FspecOverflow { category: 34 })
        );
    }

    #[test]
    fn test_reject_spare_frn() {
        // CAT 021, FRN 43 (reserve) : 7e octet de FSPEC, bit 8.
        let datagram = [
            0x15, 0x00, 0x0b, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x80, 0x00,
        ];
        assert_eq!(
            AsterixPacket::try_from(&datagram[..]),
            Err(AsterixError::UnknownFrn {
                category: 21,
                frn: 43
            })
        );
    }

    #[test]
    fn test_compound_item_walks_its_subfields() {
        // FSPEC 0x02 : FRN 7 seul. I048/130 avec SRL (bit 8) et APD
        // (bit 2) : primary 0x82, puis un octet par sous-champ.
        let datagram = [0x30, 0x00, 0x07, 0x02, 0x82, 0xaa, 0xbb];
        let packet = AsterixPacket::try_from(&datagram[..]).expect("compose valide");
        let record = &packet.blocks[0].records[0];
        assert_eq!(record.item("I048/130"), Some(&[0x82, 0xaa, 0xbb][..]));
        // Sous-champs par leur numero de la specification : SRL #1, APD #7.
        assert_eq!(record.subfield("I048/130", 1), Some(&[0xaa][..]));
        assert_eq!(record.subfield("I048/130", 7), Some(&[0xbb][..]));
        assert_eq!(record.subfield("I048/130", 2), None);
        assert_eq!(record.subfield("I048/010", 1), None);
        assert_eq!(record.subfield("I048/140", 1), None);
    }

    #[test]
    fn test_compound_rejects_spare_and_undefined_subfields() {
        // I034/050 : bit 7 du primary est reserve.
        let datagram = [0x22, 0x00, 0x06, 0x04, 0x40, 0x00];
        assert_eq!(
            AsterixPacket::try_from(&datagram[..]),
            Err(AsterixError::UnknownSubfield {
                item: "I034/050",
                subfield: 2
            })
        );
        // I048/120 (FRN 20 : troisieme octet de FSPEC, bit 4) : deux
        // sous-champs definis, le bit 6 du primary ne l'est pas.
        let datagram = [0x30, 0x00, 0x07, 0x01, 0x01, 0x04, 0x20];
        assert_eq!(
            AsterixPacket::try_from(&datagram[..]),
            Err(AsterixError::UnknownSubfield {
                item: "I048/120",
                subfield: 3
            })
        );
    }

    #[test]
    fn test_repetitive_and_explicit_items() {
        // I048/250 (FRN 10) avec REP 2 (17 octets), puis I048/SP (FRN 27)
        // de longueur 3.
        let mut datagram = vec![0x30, 0x00, 0x00, 0x01, 0x21, 0x01, 0x04];
        datagram.push(2);
        datagram.extend_from_slice(&[0x11; 16]);
        datagram.extend_from_slice(&[0x03, 0xde, 0xad]);
        datagram[2] = datagram.len() as u8;
        let packet = AsterixPacket::try_from(datagram.as_slice()).expect("repetitif + explicite");
        let record = &packet.blocks[0].records[0];
        assert_eq!(record.item("I048/250").map(<[u8]>::len), Some(17));
        assert_eq!(record.item("I048/SP"), Some(&[0x03, 0xde, 0xad][..]));

        // LEN explicite nul.
        let datagram = [0x30, 0x00, 0x08, 0x01, 0x01, 0x01, 0x04, 0x00];
        assert_eq!(
            AsterixPacket::try_from(&datagram[..]),
            Err(AsterixError::InvalidExplicitLength { item: "I048/SP" })
        );
        // REP au-dela du bloc.
        let datagram = [0x30, 0x00, 0x06, 0x01, 0x20, 0x03];
        assert_eq!(
            AsterixPacket::try_from(&datagram[..]),
            Err(AsterixError::TruncatedItem {
                item: "I048/250",
                needed: 25,
                actual: 1
            })
        );
    }

    /// Octets synthetiques : I048/020 (FRN 3) definit six extents d'un
    /// octet ; un septieme n'est plus de l'ASTERIX de cette edition.
    #[test]
    fn test_bounded_extended_item_rejects_an_extent_beyond_its_uap() {
        let mut datagram = vec![0x30, 0x00, 0x00, 0x20];
        datagram.extend_from_slice(&[0x01, 0x01, 0x01, 0x01, 0x01, 0x00]);
        datagram[2] = datagram.len() as u8;
        let packet = AsterixPacket::try_from(datagram.as_slice()).expect("six extents");
        assert_eq!(
            packet.blocks[0].records[0]
                .item("I048/020")
                .map(<[u8]>::len),
            Some(6)
        );

        let mut datagram = vec![0x30, 0x00, 0x00, 0x20];
        datagram.extend_from_slice(&[0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00]);
        datagram[2] = datagram.len() as u8;
        assert_eq!(
            AsterixPacket::try_from(datagram.as_slice()),
            Err(AsterixError::ExtentOverflow { item: "I048/020" })
        );
        // Tronque au milieu du troisieme extent.
        let datagram = [0x30, 0x00, 0x06, 0x20, 0x01, 0x01];
        assert_eq!(
            AsterixPacket::try_from(&datagram[..]),
            Err(AsterixError::TruncatedItem {
                item: "I048/020",
                needed: 3,
                actual: 2
            })
        );
    }

    /// Octets synthetiques : I062/510 (FRN 26, 4e octet de FSPEC, bit 4)
    /// est une suite non bornee d'unites de trois octets.
    #[test]
    fn test_repetitive_fx_item_chains_units_of_three_octets() {
        let mut datagram = vec![0x3e, 0x00, 0x00, 0x01, 0x01, 0x01, 0x08];
        datagram.extend_from_slice(&[0x0b, 0x03, 0x81, 0x0c, 0x00, 0x01, 0x0d, 0x00, 0x02]);
        datagram[2] = datagram.len() as u8;
        let packet = AsterixPacket::try_from(datagram.as_slice()).expect("trois unites");
        assert_eq!(
            packet.blocks[0].records[0]
                .item("I062/510")
                .map(<[u8]>::len),
            Some(9)
        );
        // Derniere unite tronquee.
        let datagram = [
            0x3e, 0x00, 0x0c, 0x01, 0x01, 0x01, 0x08, 0x0b, 0x03, 0x81, 0x0c, 0x00,
        ];
        assert_eq!(
            AsterixPacket::try_from(&datagram[..]),
            Err(AsterixError::TruncatedItem {
                item: "I062/510",
                needed: 6,
                actual: 5
            })
        );
    }

    /// Octets synthetiques, aucune capture du corpus ne portant de RFS :
    /// CAT 002, FRN 14 (RFS, 2e octet de FSPEC, bit 2) avec deux items,
    /// I002/020 (FRN 3) puis I002/000 (FRN 2), dans cet ordre.
    #[test]
    fn test_rfs_field_carries_items_in_any_order() {
        let datagram = [
            0x02, 0x00, 0x0c, 0x81, 0x02, 0x00, 0x01, 0x02, 0x03, 0x07, 0x02, 0x01,
        ];
        let packet = AsterixPacket::try_from(&datagram[..]).expect("RFS valide");
        let record = &packet.blocks[0].records[0];
        let ids: Vec<&str> = record.items.iter().map(|item| item.id).collect();
        assert_eq!(ids, ["I002/010", "I002/RFS"]);
        assert_eq!(
            record.item("I002/RFS"),
            Some(&[0x02, 0x03, 0x07, 0x02, 0x01][..])
        );
        let inner: Vec<(u8, &str, &[u8])> = record
            .rfs_items()
            .iter()
            .map(|item| (item.frn, item.id, item.data))
            .collect();
        assert_eq!(
            inner,
            [(3, "I002/020", &[0x07][..]), (2, "I002/000", &[0x01][..])]
        );
        // `item` voit a travers le RFS.
        assert_eq!(record.item("I002/000"), Some(&[0x01][..]));
        assert!(record.has("I002/020"));

        // Un FRN deja annonce par le FSPEC (1 : I002/010), ou deux fois dans
        // le RFS (3 : I002/020), est refuse : chaque item une fois au plus.
        // Trouve par le fuzz (parse_asterix, 402 509 executions).
        for (bytes, frn) in [
            (
                &[
                    0x02, 0x00, 0x0b, 0x81, 0x02, 0x00, 0x01, 0x01, 0x01, 0x00, 0x01,
                ][..],
                1,
            ),
            (
                &[
                    0x02, 0x00, 0x0c, 0x81, 0x02, 0x00, 0x01, 0x02, 0x03, 0x07, 0x03, 0x08,
                ][..],
                3,
            ),
        ] {
            assert_eq!(
                AsterixPacket::try_from(bytes),
                Err(AsterixError::DuplicateRfsFrn { category: 2, frn }),
                "{bytes:02x?}"
            );
        }

        // N nul, FRN de reserve (12), FRN du RFS lui-meme (14), item tronque.
        for (bytes, expected) in [
            (
                &[0x02, 0x00, 0x08, 0x81, 0x02, 0x00, 0x01, 0x00][..],
                AsterixError::EmptyRfs { category: 2 },
            ),
            (
                &[0x02, 0x00, 0x0a, 0x81, 0x02, 0x00, 0x01, 0x01, 0x0c, 0x00][..],
                AsterixError::InvalidRfsFrn {
                    category: 2,
                    frn: 12,
                },
            ),
            (
                &[0x02, 0x00, 0x0a, 0x81, 0x02, 0x00, 0x01, 0x01, 0x0e, 0x01][..],
                AsterixError::InvalidRfsFrn {
                    category: 2,
                    frn: 14,
                },
            ),
            (
                &[0x02, 0x00, 0x09, 0x81, 0x02, 0x00, 0x01, 0x01, 0x04][..],
                AsterixError::TruncatedItem {
                    item: "I002/030",
                    needed: 3,
                    actual: 0,
                },
            ),
        ] {
            assert_eq!(
                AsterixPacket::try_from(bytes),
                Err(expected),
                "{bytes:02x?}"
            );
        }
    }

    /// Octets synthetiques : CAT 001, le bit TYP de I001/020 choisit l'UAP.
    /// FSPEC 0xe0 : 010, 020, puis FRN 3 — I001/040 (quatre octets) pour un
    /// plot, I001/161 (deux octets) pour une piste.
    #[test]
    fn test_cat001_uap_follows_the_target_type() {
        let plot = [
            0x01, 0x00, 0x0b, 0xe0, 0x00, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44,
        ];
        let packet = AsterixPacket::try_from(&plot[..]).expect("plot");
        let record = &packet.blocks[0].records[0];
        assert_eq!(record.uap(), Some(&uap::CAT001));
        assert_eq!(record.item("I001/040"), Some(&[0x11, 0x22, 0x33, 0x44][..]));
        assert_eq!(record.item("I001/161"), None);

        let track = [0x01, 0x00, 0x09, 0xe0, 0x00, 0x01, 0x80, 0x0f, 0xff];
        let packet = AsterixPacket::try_from(&track[..]).expect("piste");
        let record = &packet.blocks[0].records[0];
        assert_eq!(record.uap(), Some(&uap::CAT001_TRACK));
        assert_eq!(record.item("I001/161"), Some(&[0x0f, 0xff][..]));
        assert_eq!(record.item("I001/040"), None);

        // Sans I001/010, TYP se lit au premier octet du corps.
        let track = [0x01, 0x00, 0x07, 0x60, 0x80, 0x0f, 0xff];
        let packet = AsterixPacket::try_from(&track[..]).expect("piste sans 010");
        assert_eq!(packet.blocks[0].records[0].uap(), Some(&uap::CAT001_TRACK));

        // Sans I001/020 : plot, et le FRN 15 (troisieme octet de FSPEC,
        // bit 8) est I001/150, qui n'existe qu'au FRN 22 des pistes.
        let plot = [0x01, 0x00, 0x09, 0x81, 0x01, 0x80, 0x00, 0x01, 0xaa];
        let packet = AsterixPacket::try_from(&plot[..]).expect("plot sans 020");
        let record = &packet.blocks[0].records[0];
        assert_eq!(record.uap(), Some(&uap::CAT001));
        assert_eq!(record.item("I001/150"), Some(&[0xaa][..]));
    }
}
