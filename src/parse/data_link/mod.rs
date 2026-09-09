// Copyright (c) 2024 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

// parsed_packet/data_link/mod.rs

//! The `DataLink` module provides functionality to parse and analyze data link layer packets,
//! specifically Ethernet frames. It extracts MAC addresses, Ethertype, and the payload from
//! a raw byte slice.
//!
//! # Overview
//!
//! The `DataLink` structure represents an Ethernet frame with the following fields:
//! - `destination_mac`: The destination MAC address of the packet.
//! - `source_mac`: The source MAC address of the packet.
//! - `ethertype`: The Ethertype value, which indicates the protocol used in the payload.
//! - `payload`: The remaining packet data after the Ethernet header.
//!
//! This module includes:
//! - A `TryFrom<&[u8]>` implementation to parse an Ethernet frame from a raw byte slice.
//! - A validation step to ensure the packet length is sufficient before parsing.
//!
//! # Example
//!
//! ```rust
//! use packet_parser::parse::data_link::DataLink;
//!
//! let raw_packet: [u8; 18] = [
//!     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Destination MAC
//!     0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, // Source MAC
//!     0x08, 0x00, // Ethertype (IPv4)
//!     0x45, 0x00, 0x00, 0x54, // Payload (IPv4 Header fragment)
//! ];
//!
//! let datalink = DataLink::try_from(raw_packet.as_ref()).expect("Failed to parse valid packet");
//! println!("{:?}", datalink);
//! ```
//!
//! # Errors
//!
//! The `TryFrom<&[u8]>` implementation can return a `DataLinkError` if:
//! - The packet is too short to contain a valid Ethernet frame.
//! - The MAC addresses or Ethertype are invalid.
//!
//! # See Also
//! - [`MacAddress`]
//! - [`Ethertype`]

pub mod mac_addres;
use mac_addres::MacAddress;
use serde::Serialize;

pub mod ethertype;
pub mod stp;
pub mod vlan_tag;

use crate::{
    checks::data_link::{validate_data_link_length, validate_data_link_vlan_stack_length},
    errors::data_link::DataLinkError,
    parse::data_link::vlan_tag::VlanTag,
};

use ethertype::Ethertype;

/// En-tete Ethernet II : deux MAC et un EtherType.
const DATALINK_HEADER_LEN: usize = 14;
/// Un tag VLAN : TCI (2 octets) et EtherType suivant (2 octets).
const VLAN_TAG_LEN: usize = 4;

/// Ethernet Frame
///
/// ```mermaid
/// ---
/// title: DataLink
/// ---
/// packet-beta
/// 0-47: "Destination MAC u48"
/// 48-95: "Source MAC u48"
/// 96-111: "EtherType / VLAN TPID u16"
/// 112-127: "VLAN TCI u16 if present"
/// 128-143: "Inner EtherType u16 if VLAN (may be another TPID)"
/// 144-191: "Payload variable"
/// ```
///
/// Represents a parsed Ethernet frame, containing source and destination MAC addresses,
/// an Ethertype, an optional VLAN tag, and the payload.
///
/// Stacked tags (IEEE 802.1ad / QinQ: an S-tag `0x88a8` or legacy `0x9100`
/// followed by a C-tag `0x8100`, or two `0x8100`) are consumed entirely so
/// that `ethertype` and `payload` always describe the real layer 3. `vlan`
/// then holds the **innermost** tag (the C-VLAN, i.e. the customer network),
/// the only one whose `inner_ethertype` is that real layer 3. Exposing the
/// whole stack needs a new field and waits for the next major (#82, #76).
#[derive(Debug, Clone, Serialize, Eq)]
pub struct DataLink<'a> {
    /// The destination MAC address (serialized as a string).
    pub destination_mac: MacAddress,
    /// The source MAC address (serialized as a string).
    pub source_mac: MacAddress,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vlan: Option<VlanTag>,
    /// The Ethertype of the packet, indicating the protocol in the payload
    /// (serialized as its name, e.g. "IPv4").
    #[serde(serialize_with = "ethertype::serialize_name")]
    pub ethertype: Ethertype,
    /// The payload of the Ethernet frame.
    #[serde(skip_serializing)]
    pub payload: &'a [u8],
}

/// Parses `packets` as an **Ethernet II** frame.
///
/// Low-level entry point, kept for compatibility. It only checks that the
/// buffer is long enough — it never verifies that the bytes *are* Ethernet, so
/// a capture in another LINKTYPE yields a successful parse holding fabricated
/// MAC addresses. Prefer [`fn@crate::parse`], which dispatches on the LINKTYPE
/// declared by the capture and refuses the ones it does not support.
impl<'a> TryFrom<&'a [u8]> for DataLink<'a> {
    type Error = DataLinkError;

    fn try_from(packets: &'a [u8]) -> Result<Self, Self::Error> {
        validate_data_link_length(packets)?;

        let destination_mac = MacAddress::try_from(&packets[0..6])?;
        let source_mac = MacAddress::try_from(&packets[6..12])?;

        // EtherType brut : couche 3, ou TPID d'un tag VLAN.
        let raw_ethertype = u16::from_be_bytes([packets[12], packets[13]]);

        // Pile de tags VLAN. Chaque tag fait 4 octets (TCI + EtherType
        // suivant) et cet EtherType peut lui-meme etre un TPID : 802.1ad met
        // un S-tag 0x88a8 (ou 0x9100 historique) devant le C-tag 0x8100, et
        // certains equipements empilent deux 0x8100. On consomme toute la
        // pile pour atteindre la vraie couche 3 ; `vlan` garde le tag
        // interne, le seul dont `inner_ethertype` est cette couche 3.
        let mut vlan: Option<VlanTag> = None;
        let mut next_ethertype = raw_ethertype;
        let mut offset = DATALINK_HEADER_LEN;
        let mut tags = 0;
        while VlanTag::is_tpid(next_ethertype) {
            tags += 1;
            validate_data_link_vlan_stack_length(packets, tags)?;
            let tag = VlanTag::try_from(&packets[offset..offset + VLAN_TAG_LEN])?;
            next_ethertype = tag.inner_ethertype.0;
            offset += VLAN_TAG_LEN;
            vlan = Some(tag);
        }

        let ethertype = Ethertype::from(next_ethertype);
        let payload: &'a [u8] = &packets[offset..];

        Ok(DataLink {
            destination_mac,
            source_mac,
            vlan,
            ethertype,
            payload,
        })
    }
}

impl<'a> PartialEq for DataLink<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.destination_mac == other.destination_mac
            && self.source_mac == other.source_mac
            && self.vlan == other.vlan
            && self.ethertype == other.ethertype
    }
}

use std::hash::{Hash, Hasher};

impl<'a> Hash for DataLink<'a> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.destination_mac.hash(state);
        self.source_mac.hash(state);
        self.vlan.hash(state);
        self.ethertype.hash(state);
    }
}

#[cfg(test)]
mod tests {

    use crate::errors::data_link::DataLinkError;
    use crate::parse::data_link::DataLink;
    use crate::parse::data_link::mac_addres::MacAddress;

    #[test]
    fn test_datalink_try_from_valid_packet() {
        let raw_packet: [u8; 18] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Destination MAC
            0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, // Source MAC
            0x08, 0x00, // Ethertype (IPv4)
            0x45, 0x00, 0x00, 0x54, // Payload (IPv4 Header fragment)
        ];

        let datalink =
            DataLink::try_from(raw_packet.as_ref()).expect("Failed to parse valid packet");

        assert_eq!(
            datalink.destination_mac,
            MacAddress::try_from(&raw_packet[0..6]).unwrap()
        );
        assert_eq!(
            datalink.source_mac,
            MacAddress::try_from(&raw_packet[6..12]).unwrap()
        );
        assert_eq!(datalink.ethertype.name(), "IPv4"); // IPv4 Ethertype
    }

    #[test]
    fn test_datalink_try_from_invalid_length() {
        let short_packet: [u8; 10] = [0x00; 10];

        let result = DataLink::try_from(short_packet.as_ref());
        assert!(matches!(result, Err(DataLinkError::DataLinkTooShort(_))));
    }

    #[test]
    fn test_datalink_try_from_ethertype_parsing() {
        let raw_packet: [u8; 18] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Destination MAC
            0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, // Source MAC
            0x86, 0xDD, // Ethertype (IPv6)
            0x60, 0x00, 0x00, 0x00, // IPv6 Header fragment
        ];

        let datalink = DataLink::try_from(raw_packet.as_ref()).unwrap();
        assert_eq!(datalink.ethertype.name(), "IPv6"); // IPv6 Ethertype
    }

    #[test]
    fn test_datalink_try_from_ethertype_unknown() {
        let raw_packet: [u8; 18] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Destination MAC
            0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, // Source MAC
            0xAB, 0xCD, // Inconnu Ethertype
            0x12, 0x34, 0x56, 0x78, // Payload quelconque
        ];

        let datalink = DataLink::try_from(raw_packet.as_ref()).unwrap();
        assert_eq!(datalink.ethertype.name(), "Unknown (0xABCD)"); // Ethertype inconnu, mais accepté
    }
    #[test]
    fn test_datalink_try_from_empty_payload() {
        let raw_packet: [u8; 14] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Destination MAC
            0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, // Source MAC
            0xAB, 0xCD, // Inconnu Ethertype
        ];

        let datalink = DataLink::try_from(raw_packet.as_ref()).unwrap();
        assert_eq!(datalink.ethertype.name(), "Unknown (0xABCD)"); // Ethertype inconnu, mais accepté
    }

    #[test]
    fn test_datalink_try_from_vlan_tagged() {
        // Dest MAC, Src MAC, TPID=0x8100, TCI (PCP=0, DEI=0, VLAN 10), inner EtherType=0x0800 (IPv4)
        let raw_packet: [u8; 22] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Dest
            0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, // Src
            0x81, 0x00, // TPID 802.1Q
            0x00, 0x0A, // TCI : VLAN 10
            0x08, 0x00, // Inner EtherType : IPv4
            0x45, 0x00, 0x00, 0x54, // Début header IPv4
        ];

        let datalink = DataLink::try_from(raw_packet.as_ref()).unwrap();

        assert_eq!(datalink.ethertype.name(), "IPv4");
        assert!(datalink.vlan.is_some());
        let vlan = datalink.vlan.unwrap();
        assert_eq!(vlan.id, 10);
        assert_eq!(datalink.payload, &raw_packet[18..]);
    }

    /// 802.1ad / QinQ : S-tag 0x88a8 (VID 200) puis C-tag 0x8100 (VID 104,
    /// PCP 3, DEI 1) devant de l'IPv4. `vlan` retient le tag interne avec
    /// ses bits de priorite, `ethertype` la vraie couche 3, et la charge
    /// utile commence apres les deux tags (octet 22).
    #[test]
    fn test_datalink_try_from_qinq_8021ad_keeps_inner_tag_and_reaches_l3() {
        let raw_packet: [u8; 26] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Dest
            0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, // Src
            0x88, 0xA8, 0x00, 0xC8, // S-tag : TPID 802.1ad, VID 200
            0x81, 0x00, 0x70, 0x68, // C-tag : TPID 802.1Q, PCP 3, DEI 1, VID 104
            0x08, 0x00, // EtherType reel : IPv4
            0x45, 0x00, 0x00, 0x54, // Debut header IPv4
        ];

        let datalink = DataLink::try_from(raw_packet.as_ref()).unwrap();

        let vlan = datalink.vlan.expect("tag interne conserve");
        assert_eq!(vlan.id, 104);
        assert_eq!(vlan.pcp, 3);
        assert!(vlan.dei);
        assert_eq!(vlan.inner_ethertype.name(), "IPv4");
        assert_eq!(datalink.ethertype.name(), "IPv4");
        assert_eq!(datalink.payload, &raw_packet[22..]);
    }

    /// Double 0x8100 (empilement non standard mais courant) : meme
    /// resultat, le tag externe (VID 300) n'est plus pris pour le seul.
    #[test]
    fn test_datalink_try_from_double_8021q_keeps_inner_tag() {
        let raw_packet: [u8; 26] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Dest
            0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, // Src
            0x81, 0x00, 0x01, 0x2C, // Tag externe : VID 300
            0x81, 0x00, 0x00, 0x6A, // Tag interne : VID 106
            0x86, 0xDD, // EtherType reel : IPv6
            0x60, 0x00, 0x00, 0x00, // Debut header IPv6
        ];

        let datalink = DataLink::try_from(raw_packet.as_ref()).unwrap();

        assert_eq!(datalink.vlan.as_ref().map(|v| v.id), Some(106));
        assert_eq!(datalink.ethertype.name(), "IPv6");
        assert_eq!(datalink.payload, &raw_packet[22..]);
    }

    /// TPID QinQ historique 0x9100 en tag externe.
    #[test]
    fn test_datalink_try_from_qinq_legacy_9100() {
        let raw_packet: [u8; 26] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Dest
            0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, // Src
            0x91, 0x00, 0x00, 0x0A, // Tag externe historique : VID 10
            0x81, 0x00, 0x00, 0x14, // Tag interne : VID 20
            0x08, 0x06, // EtherType reel : ARP
            0x00, 0x01, 0x08, 0x00, // Debut ARP
        ];

        let datalink = DataLink::try_from(raw_packet.as_ref()).unwrap();

        assert_eq!(datalink.vlan.as_ref().map(|v| v.id), Some(20));
        assert_eq!(datalink.ethertype.name(), "ARP");
    }

    /// Trame coupee au milieu du second tag : erreur explicite, pas d'acces
    /// hors borne. 21 octets = 12 MAC + 4 (S-tag) + 5 (C-tag sans son dernier octet).
    #[test]
    fn test_datalink_try_from_qinq_truncated_inside_second_tag() {
        let raw_packet: [u8; 21] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Dest
            0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, // Src
            0x88, 0xA8, 0x00, 0xC8, // S-tag : TPID + TCI
            0x81, 0x00, 0x00, 0x68, 0x08, // C-tag : TPID + TCI, EtherType ampute
        ];

        let result = DataLink::try_from(raw_packet.as_ref());
        assert!(matches!(result, Err(DataLinkError::DataLinkTooShort(21))));

        // Et un tag exactement complet mais sans un seul octet de charge
        // utile reste accepte : charge utile vide, comme en Ethernet nu.
        let exact: [u8; 22] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0x88, 0xA8,
            0x00, 0xC8, 0x81, 0x00, 0x00, 0x68, 0x08, 0x00,
        ];
        let datalink = DataLink::try_from(exact.as_ref()).unwrap();
        assert_eq!(datalink.vlan.as_ref().map(|v| v.id), Some(104));
        assert!(datalink.payload.is_empty());
    }
}
