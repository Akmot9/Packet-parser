// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! ASTERIX (All Purpose STructured EUROCONTROL SuRveillance Information
//! EXchange), le format d'echange des donnees de surveillance du controle
//! aerien : plots et pistes radar, rapports ADS-B, messages de service.
//!
//! Un datagramme porte un ou plusieurs **data blocks** — un octet de
//! categorie (CAT), deux octets de longueur (LEN, en-tete compris), puis
//! des **records**. Chaque record commence par un FSPEC, suite d'octets dont
//! chaque bit annonce la presence d'un data item ; le bit de poids faible
//! (FX) annonce un octet de FSPEC de plus. L'ordre des bits et le format de
//! chaque item sont fixes par l'UAP de la categorie (voir [`uap`]).
//!
//! Ce module decoupe les records de trois categories — **CAT 048** (plots
//! et pistes monoradar), **CAT 034** (messages de service du meme radar :
//! top nord, franchissement de secteur) et **CAT 021** (ADS-B) — et expose
//! chaque item en zero-copie. Les items les plus courants sont decodes en
//! valeurs typees par [`cat048`], [`cat034`] et [`cat021`].
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

pub mod cat021;
pub mod cat034;
pub mod cat048;
pub mod fields;
pub mod uap;

use crate::{
    checks::application::asterix::{ASTERIX_BLOCK_HEADER_LEN, fx_extent, read_block_header},
    errors::application::asterix::AsterixError,
};
use uap::{ItemFormat, ItemSpec, Subfield, Uap, uap_for};

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
    /// `I048/RE` pour les champs explicites.
    pub id: &'static str,
    /// Les octets de l'item (zero-copie), en-tete REP ou LEN compris.
    pub data: &'a [u8],
}

impl<'a> AsterixRecord<'a> {
    /// Les octets d'un item, par identifiant (`"I048/240"`).
    pub fn item(&self, id: &str) -> Option<&'a [u8]> {
        self.items
            .iter()
            .find(|item| item.id == id)
            .map(|item| item.data)
    }

    pub fn has(&self, id: &str) -> bool {
        self.items.iter().any(|item| item.id == id)
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
    if fspec_len > uap.max_fspec_octets() {
        return Err(AsterixError::FspecOverflow { category });
    }
    let fspec = &buf[..fspec_len];
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
            let len = item_len(spec, &buf[pos..])?;
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

/// Longueur d'un item selon son format, sans en interpreter le contenu.
fn item_len(spec: &'static ItemSpec, buf: &[u8]) -> Result<usize, AsterixError> {
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
        ItemFormat::Compound(subfields) => {
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
                    let len = match subfields.get(index).ok_or(unknown.clone())? {
                        Subfield::Spare => return Err(unknown),
                        Subfield::Fixed(len) => ensure(rest, *len, sub_truncated)?,
                        Subfield::Variable => {
                            fx_extent(rest).ok_or_else(|| sub_truncated(rest.len() + 1))?
                        }
                        Subfield::Repetitive(each) => repetitive_len(rest, *each, sub_truncated)?,
                    };
                    pos += len;
                }
            }
            Ok(pos)
        }
    }
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
        datagram.extend_from_slice(&[0x3e, 0x00, 0x05, 0x80, 0x00]); // CAT 062
        assert_eq!(
            AsterixPacket::try_from(datagram.as_slice()),
            Err(AsterixError::UnsupportedCategory(62))
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
}
