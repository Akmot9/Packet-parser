// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

// src/parse/data_link/vlan_tag.rs (par ex.)

use serde::Serialize;

use crate::checks::data_link::validate_vlan_tag_length;

use super::ethertype::Ethertype; // adapte le chemin si besoin

/// TPID IEEE 802.1Q : tag client (C-tag), le cas courant.
pub const TPID_8021Q: u16 = 0x8100;
/// TPID IEEE 802.1ad : tag fournisseur (S-tag) du provider bridging / QinQ.
pub const TPID_8021AD: u16 = 0x88A8;
/// TPID QinQ historique, anterieur a 802.1ad, encore emis par certains
/// equipements (Cisco, Juniper) pour le tag externe.
pub const TPID_QINQ_LEGACY: u16 = 0x9100;

/// IEEE 802.1Q VLAN Tag
///
/// ```mermaid
/// ---
/// title: VlanTag
/// ---
/// packet-beta
/// 0-2: "PCP u3"
/// 3-3: "DEI u1"
/// 4-15: "VLAN ID u12"
/// 16-31: "Inner EtherType u16"
/// ```
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash)]
pub struct VlanTag {
    /// VLAN ID sur 12 bits (0–4095)
    pub id: u16,
    /// Priority Code Point (0–7)
    pub pcp: u8,
    /// Drop Eligible Indicator
    pub dei: bool,
    /// EtherType interne (couche L3 réelle)
    #[serde(skip_serializing)]
    pub inner_ethertype: Ethertype,
}

impl VlanTag {
    /// Vrai si `ethertype` est un TPID, c'est-a-dire annonce un tag VLAN de
    /// 4 octets (TCI + EtherType suivant) plutot qu'une charge utile.
    pub fn is_tpid(ethertype: u16) -> bool {
        matches!(ethertype, TPID_8021Q | TPID_8021AD | TPID_QINQ_LEGACY)
    }

    /// Nom lisible de l'EtherType interne (IPv4, IPv6, etc.)
    pub fn inner_ethertype_name(&self) -> String {
        self.inner_ethertype.name()
    }
}

/// Pile complete des tags VLAN d'une trame, du tag externe au tag interne
/// (802.1ad / QinQ : S-tag puis C-tag ; ou deux 802.1Q empiles).
///
/// Vue zero-copie sur les octets de tags de la trame, deja valides par le
/// parseur : aucune allocation sur le chemin chaud, quelle que soit la
/// profondeur de la pile (bornee par la seule longueur de la trame).
/// Vide pour une trame sans tag ; un seul element pour du 802.1Q simple.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct VlanStack<'a> {
    // Suite de blocs de 4 octets : TCI puis EtherType suivant.
    tags: &'a [u8],
}

impl<'a> VlanStack<'a> {
    const TAG_LEN: usize = 4;

    /// `tags` : les octets de la trame entre le premier TPID (exclu) et
    /// l'EtherType de couche 3 (inclus), soit 4 octets par tag.
    pub(crate) fn new(tags: &'a [u8]) -> Self {
        debug_assert!(tags.len().is_multiple_of(Self::TAG_LEN));
        Self { tags }
    }

    /// Nombre de tags empiles.
    pub fn len(&self) -> usize {
        self.tags.len() / Self::TAG_LEN
    }

    pub fn is_empty(&self) -> bool {
        self.tags.is_empty()
    }

    /// Les tags, du plus externe (S-tag) au plus interne (C-tag).
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = VlanTag> + ExactSizeIterator + 'a {
        self.tags
            .chunks_exact(Self::TAG_LEN)
            .map(|tag| VlanTag::from_tag_bytes([tag[0], tag[1], tag[2], tag[3]]))
    }

    /// Tag externe : le S-VLAN (reseau du fournisseur) d'une pile QinQ.
    pub fn outer(&self) -> Option<VlanTag> {
        self.iter().next()
    }

    /// Tag interne : le C-VLAN (reseau du client), celui que porte aussi
    /// `DataLink::vlan`.
    pub fn inner(&self) -> Option<VlanTag> {
        self.iter().next_back()
    }

    /// Vrai pour une pile d'au moins deux tags : en dessous, `vlan` dit deja
    /// tout et la pile n'est pas serialisee.
    pub(crate) fn is_not_stacked(&self) -> bool {
        self.len() < 2
    }
}

impl Serialize for VlanStack<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.iter())
    }
}

impl TryFrom<&[u8]> for VlanTag {
    type Error = crate::errors::data_link::DataLinkError; // adapte si tu as un VlanError

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        validate_vlan_tag_length(bytes)?;
        Ok(Self::from_tag_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
        ]))
    }
}

impl VlanTag {
    /// Decode les 4 octets d'un tag (TCI puis EtherType suivant). Infaillible :
    /// toute valeur de TCI est un tag valide.
    fn from_tag_bytes(bytes: [u8; 4]) -> Self {
        let tci = u16::from_be_bytes([bytes[0], bytes[1]]);
        let pcp = ((tci & 0b1110_0000_0000_0000) >> 13) as u8;
        let dei = ((tci & 0b0001_0000_0000_0000) >> 12) != 0;
        let id = tci & 0x0FFF;

        Self {
            id,
            pcp,
            dei,
            inner_ethertype: Ethertype::from(u16::from_be_bytes([bytes[2], bytes[3]])),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_vlan_tag_try_from_valid_ipv4() {
        // TCI :
        // PCP = 5  -> 101
        // DEI = 1  -> 1
        // VID = 100 -> 0x064
        //
        // tci = (5 << 13) | (1 << 12) | 100
        let tci: u16 = (5 << 13) | (1 << 12) | 100;
        let tci_bytes = tci.to_be_bytes();

        // EtherType interne IPv4 = 0x0800
        let bytes = [tci_bytes[0], tci_bytes[1], 0x08, 0x00];

        let vlan = VlanTag::try_from(bytes.as_slice()).unwrap();

        assert_eq!(vlan.id, 100);
        assert_eq!(vlan.pcp, 5);
        assert!(vlan.dei);
        assert_eq!(vlan.inner_ethertype, Ethertype::from(0x0800));
    }

    #[test]
    fn test_vlan_tag_try_from_valid_ipv6() {
        // PCP = 0, DEI = 0, VID = 4095
        let tci: u16 = 0x0FFF;
        let tci_bytes = tci.to_be_bytes();

        // EtherType interne IPv6 = 0x86DD
        let bytes = [tci_bytes[0], tci_bytes[1], 0x86, 0xDD];

        let vlan = VlanTag::try_from(bytes.as_slice()).unwrap();

        assert_eq!(vlan.id, 4095);
        assert_eq!(vlan.pcp, 0);
        assert!(!vlan.dei);
        assert_eq!(vlan.inner_ethertype, Ethertype::from(0x86DD));
    }

    #[test]
    fn test_vlan_tag_try_from_valid_zero_vid() {
        // PCP = 3, DEI = 0, VID = 0
        let tci: u16 = 3 << 13;
        let tci_bytes = tci.to_be_bytes();

        let bytes = [tci_bytes[0], tci_bytes[1], 0x08, 0x00];

        let vlan = VlanTag::try_from(bytes.as_slice()).unwrap();

        assert_eq!(vlan.id, 0);
        assert_eq!(vlan.pcp, 3);
        assert!(!vlan.dei);
        assert_eq!(vlan.inner_ethertype, Ethertype::from(0x0800));
    }

    #[test]
    fn test_vlan_tag_try_from_too_short_empty() {
        let err = VlanTag::try_from(&[][..]).unwrap_err();
        assert_eq!(
            err,
            crate::errors::data_link::DataLinkError::DataLinkTooShort {
                required: 4,
                actual: 0
            }
        );
    }

    #[test]
    fn test_vlan_tag_try_from_too_short_three_bytes() {
        let err = VlanTag::try_from(&[0x00, 0x01, 0x08][..]).unwrap_err();
        assert_eq!(
            err,
            crate::errors::data_link::DataLinkError::DataLinkTooShort {
                required: 4,
                actual: 3
            }
        );
    }

    #[test]
    fn test_inner_ethertype_name() {
        let vlan = VlanTag {
            id: 10,
            pcp: 1,
            dei: false,
            inner_ethertype: Ethertype::from(0x0800),
        };

        assert_eq!(vlan.inner_ethertype_name(), vlan.inner_ethertype.name());
    }

    #[test]
    fn test_serialize_skips_inner_ethertype() {
        let vlan = VlanTag {
            id: 42,
            pcp: 6,
            dei: true,
            inner_ethertype: Ethertype::from(0x0800),
        };

        let json = serde_json::to_string(&vlan).unwrap();

        assert!(json.contains("\"id\":42"));
        assert!(json.contains("\"pcp\":6"));
        assert!(json.contains("\"dei\":true"));
        assert!(!json.contains("inner_ethertype"));
    }

    #[test]
    fn test_clone_and_eq() {
        let vlan1 = VlanTag {
            id: 123,
            pcp: 4,
            dei: true,
            inner_ethertype: Ethertype::from(0x86DD),
        };

        let vlan2 = vlan1.clone();

        assert_eq!(vlan1, vlan2);
    }
}
