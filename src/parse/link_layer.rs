// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use serde::Serialize;
use std::{
    fmt,
    hash::{Hash, Hasher},
};

use super::data_link::{DataLink, ethertype, ethertype::Ethertype, mac_addres::MacAddress};
use crate::LinkType;

/// Protocol carried immediately after the link-layer header.
///
/// This is deliberately independent from Ethernet: RAW IP can announce IPv4
/// or IPv6 without fabricating an EtherType, while Ethernet and Linux cooked
/// captures can map their protocol field to the same semantic value.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Hash)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum NetworkProtocol {
    Ipv4,
    Ipv6,
    Arp,
    Profinet,
    Other(u16),
}

/// Effective addresses and LLC/SNAP payload of a decoded IEEE 802.11 frame.
///
/// The addresses have already been resolved according to the ToDS/FromDS bits.
/// `snap_protocol` is the real protocol value carried by the LLC/SNAP header;
/// no Ethernet frame is fabricated.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Eq)]
pub struct Ieee80211Link<'a> {
    pub destination_mac: MacAddress,
    pub source_mac: MacAddress,
    #[serde(serialize_with = "ethertype::serialize_name")]
    pub snap_protocol: Ethertype,
    #[serde(skip_serializing)]
    pub payload: &'a [u8],
}

impl<'a> Ieee80211Link<'a> {
    /// Builds the semantic IEEE 802.11 view exposed after LLC/SNAP decoding.
    pub const fn new(
        destination_mac: MacAddress,
        source_mac: MacAddress,
        snap_protocol: Ethertype,
        payload: &'a [u8],
    ) -> Self {
        Self {
            destination_mac,
            source_mac,
            snap_protocol,
            payload,
        }
    }
}

impl PartialEq for Ieee80211Link<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.destination_mac == other.destination_mac
            && self.source_mac == other.source_mac
            && self.snap_protocol == other.snap_protocol
    }
}

impl Hash for Ieee80211Link<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.destination_mac.hash(state);
        self.source_mac.hash(state);
        self.snap_protocol.hash(state);
    }
}

impl From<Ethertype> for NetworkProtocol {
    fn from(ethertype: Ethertype) -> Self {
        match ethertype.0 {
            0x0800 => Self::Ipv4,
            0x86dd => Self::Ipv6,
            0x0806 => Self::Arp,
            0x8892 => Self::Profinet,
            other => Self::Other(other),
        }
    }
}

/// Format-specific link-layer information.
///
/// New variants can be added without changing the common L3/L4/L7 pipeline.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash)]
#[serde(tag = "link_kind", content = "link_details", rename_all = "snake_case")]
pub enum LinkLayerKind<'a> {
    Ethernet(DataLink<'a>),
    Ieee80211(Ieee80211Link<'a>),
}

/// Parsed link layer together with its canonical LINKTYPE.
///
/// Construction goes through format-specific constructors so `link_type`,
/// `network_protocol` and `kind` cannot disagree.
#[derive(Debug, Clone, Serialize)]
pub struct LinkLayer<'a> {
    link_type: LinkType,
    network_protocol: NetworkProtocol,
    #[serde(skip_serializing)]
    network_payload: &'a [u8],
    #[serde(flatten)]
    kind: LinkLayerKind<'a>,
}

impl PartialEq for LinkLayer<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.link_type == other.link_type
            && self.network_protocol == other.network_protocol
            && self.kind == other.kind
    }
}

impl Eq for LinkLayer<'_> {}

impl Hash for LinkLayer<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.link_type.hash(state);
        self.network_protocol.hash(state);
        self.kind.hash(state);
    }
}

impl<'a> LinkLayer<'a> {
    /// Wraps an Ethernet II / 802.1Q frame in the generic link-layer model.
    pub fn ethernet(frame: DataLink<'a>) -> Self {
        Self {
            link_type: LinkType::ETHERNET,
            network_protocol: frame.ethertype.into(),
            network_payload: frame.payload,
            kind: LinkLayerKind::Ethernet(frame),
        }
    }

    /// Wraps a decoded native IEEE 802.11 frame without inventing Ethernet.
    pub fn ieee80211(frame: Ieee80211Link<'a>) -> Self {
        Self {
            link_type: LinkType::IEEE802_11,
            network_protocol: frame.snap_protocol.into(),
            network_payload: frame.payload,
            kind: LinkLayerKind::Ieee80211(frame),
        }
    }

    /// Canonical LINKTYPE used to decode this packet.
    pub const fn link_type(&self) -> LinkType {
        self.link_type
    }

    /// Protocol carried by the link-layer payload.
    pub const fn network_protocol(&self) -> NetworkProtocol {
        self.network_protocol
    }

    /// Format-specific link-layer fields.
    pub const fn kind(&self) -> &LinkLayerKind<'a> {
        &self.kind
    }

    /// Ethernet view when this packet was decoded as LINKTYPE_ETHERNET.
    pub const fn as_ethernet(&self) -> Option<&DataLink<'a>> {
        match &self.kind {
            LinkLayerKind::Ethernet(frame) => Some(frame),
            LinkLayerKind::Ieee80211(_) => None,
        }
    }

    /// IEEE 802.11 view when the link layer was decoded from a wireless frame.
    pub const fn as_ieee80211(&self) -> Option<&Ieee80211Link<'a>> {
        match &self.kind {
            LinkLayerKind::Ethernet(_) => None,
            LinkLayerKind::Ieee80211(frame) => Some(frame),
        }
    }

    /// Zero-copy payload passed to the network-layer parser.
    pub const fn network_payload(&self) -> &'a [u8] {
        self.network_payload
    }
}

impl<'a> From<DataLink<'a>> for LinkLayer<'a> {
    fn from(frame: DataLink<'a>) -> Self {
        Self::ethernet(frame)
    }
}

impl fmt::Display for LinkLayer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            LinkLayerKind::Ethernet(frame) => frame.fmt(f),
            LinkLayerKind::Ieee80211(frame) => write!(
                f,
                "\n    IEEE 802.11 Destination MAC: {},\n    Source MAC: {},\n    SNAP Protocol: {},\n    Payload Length: {}\n",
                frame.destination_mac,
                frame.source_mac,
                frame.snap_protocol.name(),
                frame.payload.len()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::data_link::mac_addres::MacAddress;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    fn ethernet<'a>(payload: &'a [u8]) -> LinkLayer<'a> {
        LinkLayer::ethernet(DataLink {
            destination_mac: MacAddress([0, 1, 2, 3, 4, 5]),
            source_mac: MacAddress([6, 7, 8, 9, 10, 11]),
            vlan: None,
            ethertype: Ethertype(0x0800),
            payload,
        })
    }

    fn hash_of<T: Hash>(value: &T) -> u64 {
        let mut hasher = DefaultHasher::new();
        value.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn ethernet_exposes_common_and_specific_views() {
        let payload = [0x45, 0, 0, 20];
        let layer = ethernet(&payload);

        assert_eq!(layer.link_type(), LinkType::ETHERNET);
        assert_eq!(layer.network_protocol(), NetworkProtocol::Ipv4);
        assert_eq!(layer.network_payload().as_ptr(), payload.as_ptr());
        assert_eq!(layer.as_ethernet().unwrap().ethertype, Ethertype(0x0800));
    }

    #[test]
    fn serialization_is_explicitly_tagged() {
        let payload = [0x45, 0, 0, 20];
        let value = serde_json::to_value(ethernet(&payload)).unwrap();

        assert_eq!(value["link_type"], 1);
        assert_eq!(value["network_protocol"]["kind"], "ipv4");
        assert_eq!(value["link_kind"], "ethernet");
        assert_eq!(value["link_details"]["ethertype"], "IPv4");
        assert!(value["link_details"].get("payload").is_none());
    }

    #[test]
    fn equality_and_hash_ignore_network_payload_bytes() {
        let first = ethernet(&[1, 2, 3]);
        let second = ethernet(&[9, 8, 7, 6]);

        assert_eq!(first, second);
        assert_eq!(hash_of(&first), hash_of(&second));
    }

    #[test]
    fn unknown_protocol_keeps_its_wire_value_in_json() {
        let layer = LinkLayer::ethernet(DataLink {
            destination_mac: MacAddress([0, 1, 2, 3, 4, 5]),
            source_mac: MacAddress([6, 7, 8, 9, 10, 11]),
            vlan: None,
            ethertype: Ethertype(0xabcd),
            payload: &[],
        });
        let value = serde_json::to_value(layer).unwrap();

        assert_eq!(value["network_protocol"]["kind"], "other");
        assert_eq!(value["network_protocol"]["value"], 0xabcd);
        assert_eq!(value["link_details"]["ethertype"], "Unknown (0xABCD)");
    }
}
