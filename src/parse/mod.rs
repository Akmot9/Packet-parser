// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! PacketFlow – Unified network packet parsing abstraction
//!
//! This module provides the [`PacketFlow`] structure, which represents a
//! fully parsed network packet across multiple layers:
//!
//! - Data Link (L2)
//! - Internet (L3)
//! - Transport (L4)
//! - Application (L7, best-effort)
//!
//! The parsing model is **layered and progressive**: each layer is parsed
//! from the payload of the previous one. Unsupported protocols do **not**
//! cause a hard failure and are represented as `None`, allowing partial
//! decoding of real-world traffic.
//!
//! ## Design goals
//!
//! - Deterministic, zero-copy parsing of the L2/L3/L4 layers using `&[u8]`
//!   references. Some application-layer parsers (e.g. DNS, HTTP, SNMP) and
//!   tunnel recursion do allocate (`Vec`, `Box`).
//! - Clear separation between protocol layers
//! - Robust handling of unknown or unsupported protocols
//! - Suitable for network auditing, traffic analysis and post-capture inspection
//!
//! This module does **not** perform stream reassembly or session tracking.
//! It expects a complete packet buffer (e.g. from PCAP capture).

use application::Application;
use application::protocols::copt::{CotpHeader, CotpNumberFormat, CotpParameter, CotpPduType};
use internet::Internet;
use serde::Serialize;
use transport::Transport;

use crate::{LinkLayer, LinkType, ParseError, owned::PacketFlowOwned};

pub mod application;
pub mod data_link;
mod dispatch;
mod engine;
pub use dispatch::DecodeAsProtocol;
pub mod internet;
mod link;
pub mod link_layer;
pub mod transport;
pub(crate) mod tunnel;

/// Returns whether this build has a decoder for the canonical link type.
///
/// This can be used to reject an unsupported capture interface before reading
/// or mutating packet-derived state.
#[inline(always)]
pub const fn is_supported(link_type: LinkType) -> bool {
    link::is_supported(link_type)
}

/// Parses one packet using the decoder selected by its explicit link type.
///
/// [`LinkType`] uses canonical `LINKTYPE_*` values. The caller is responsible
/// for mapping its capture source to that namespace and passing only packet
/// bytes, without a PCAP or PCAPNG record header.
#[inline(always)]
pub fn parse(link_type: LinkType, bytes: &[u8]) -> Result<PacketFlow<'_>, ParseError> {
    PacketFlow::parse_decoded(link::decode(link_type, bytes)?, 0)
}

/// Comme [`fn@parse`], avec une configuration de l'appelant : « mon FTP
/// tourne sur 2121 » se declare via [`ParseConfig::decode_as`] (issue #65).
/// Les ports declares etendent les gardes de port de la table de dispatch
/// sans les remplacer — le contenu doit toujours confirmer le port, et le
/// comportement par defaut est strictement celui de [`fn@parse`].
pub fn parse_with<'a>(
    link_type: LinkType,
    bytes: &'a [u8],
    config: &ParseConfig,
) -> Result<PacketFlow<'a>, ParseError> {
    PacketFlow::parse_decoded_with(link::decode(link_type, bytes)?, 0, &config.decode_as)
}

/// Configuration de parsing cote appelant (« Decode As »). Construite en
/// builder ; vide par defaut, auquel cas [`parse_with`] est identique a
/// [`fn@parse`].
#[derive(Debug, Clone, Default)]
pub struct ParseConfig {
    decode_as: Vec<(u16, DecodeAsProtocol)>,
}

impl ParseConfig {
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare qu'un port supplementaire porte ce protocole. Le port ne
    /// remplace jamais la validation de contenu : il donne seulement sa
    /// chance a la sonde avant le reste de la table.
    #[must_use]
    pub fn decode_as(mut self, port: u16, protocol: DecodeAsProtocol) -> Self {
        self.decode_as.push((port, protocol));
        self
    }
}

/// Timed counterpart of [`fn@parse`]: the exact same pipeline, reporting the
/// time spent in each layer.
///
/// Always available. Without the `parse_timing` feature nothing is measured
/// and `timing` comes back zeroed, so enabling the feature anywhere in the
/// dependency graph never changes this signature (issue #26).
#[inline(always)]
pub fn parse_timed<'a>(
    link_type: LinkType,
    bytes: &'a [u8],
    timing: &mut crate::timing::ParseTiming,
) -> Result<PacketFlow<'a>, ParseError> {
    timing.time_total(|timing| {
        let decoded = link::decode_into(link_type, bytes, timing)?;
        PacketFlow::parse_decoded_into(decoded, 0, &[], timing)
    })
}

/// Layer at which recognized-but-invalid bytes stopped the parsing.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CorruptedLayerKind {
    /// The EtherType announced a known L3 protocol but its bytes are invalid.
    Internet,
    /// The internet layer announced a known L4 protocol but its bytes are
    /// invalid.
    Transport,
}

/// A layer that was **recognized** (by the EtherType or the IP protocol
/// field) but whose bytes are invalid.
///
/// Parsing degrades gracefully instead of failing: every layer *below* the
/// reported one (closer to the wire) stays filled, and the problem is
/// reported here. Two cases:
///
/// - **structural corruption** — the bytes cannot be read as this protocol
///   (truncated header, impossible length): the reported layer and
///   everything above it are `None`;
/// - **semantic anomaly** — the header reads fine but says something no
///   conforming stack emits (TCP SYN+FIN, non-zero reserved bits): the
///   reported layer is **kept**, so its ports remain available for flow
///   correlation, and only the layers above it are `None`.
///
/// To tell them apart, check whether the layer named by `layer` is `Some`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash)]
pub struct CorruptedLayer {
    /// Which layer had invalid bytes.
    pub layer: CorruptedLayerKind,
    /// Human-readable description of the parse error.
    pub error: String,
}

/// A fully or partially parsed network packet flow.
///
/// `PacketFlow` represents a packet parsed across protocol layers.
/// Each layer is optional except for the data link layer, which is mandatory.
///
/// Unsupported or unrecognized protocols do **not** fail parsing and instead
/// result in `None` for the corresponding layer. A **recognized but corrupt**
/// layer does not fail parsing either: the layers below it are kept and the
/// problem is reported in [`PacketFlow::corrupted`]. Parsing only returns an
/// error when the data-link layer itself cannot be read.
///
/// The structure borrows from the original packet buffer (`&[u8]`) and is
/// therefore zero-copy.
///
/// ## Equality and hashing
///
/// `PartialEq`, `Eq` and `Hash` compare the **flow identity** (addresses,
/// protocols, ports…), not the raw bytes: layer payloads are deliberately
/// ignored. Two packets of the same conversation carrying different data
/// therefore compare equal and hash identically.
#[derive(Debug, Clone, Serialize, Eq)]
#[non_exhaustive]
pub struct PacketFlow<'a> {
    /// Link layer (mandatory), tagged with its canonical LINKTYPE.
    pub data_link: LinkLayer<'a>,

    /// Internet layer (optional).
    #[serde(flatten)]
    pub internet: Option<Internet<'a>>,

    /// Transport layer (optional).
    #[serde(flatten)]
    pub transport: Option<Transport<'a>>,

    /// Application layer (optional, best-effort).
    #[serde(flatten)]
    pub application: Option<Application>,

    /// Encapsulated packet (optional). When this flow is a tunnel (e.g. CAPWAP,
    /// carried as the application protocol), `inner` holds the packet parsed
    /// from inside the tunnel — recursively, from the outermost to the
    /// innermost. See [`PacketFlow::flatten`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inner: Option<Box<PacketFlow<'a>>>,

    /// Present when a recognized layer carried invalid bytes: the layers
    /// below it stay filled, that layer and the ones above are `None` —
    /// except after a semantic anomaly (TCP SYN+FIN, reserved bits), where
    /// the reported layer is kept (see [`CorruptedLayer`]). `None` on
    /// healthy packets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub corrupted: Option<CorruptedLayer>,
}

/// Parses `bytes` **assuming [`LinkType::ETHERNET`]**.
///
/// Kept for compatibility; prefer [`fn@parse`], which takes the LINKTYPE the
/// capture actually declares. This impl will be removed in a future major
/// release.
///
/// # This does not fail on a non-Ethernet capture — it fabricates data
///
/// There is no plausibility check: any buffer of at least 14 bytes is read as
/// an Ethernet header. Given a `LINKTYPE_LINUX_SLL` frame — what a capture on
/// the Linux `any` interface produces — the 16 cooked-header bytes are
/// reinterpreted as MAC addresses and an EtherType. The call returns `Ok` with
/// invented MAC addresses, `internet: None` and `corrupted: None`. **Nothing
/// signals the mistake**, and a flow matrix built from it fills up with
/// addresses that never existed on the wire.
///
/// Reach for this only when the capture is known to be Ethernet.
impl<'a> TryFrom<&'a [u8]> for PacketFlow<'a> {
    type Error = ParseError;

    #[inline(always)]
    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        parse(LinkType::ETHERNET, bytes)
    }
}

impl<'a> PartialEq for PacketFlow<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.data_link == other.data_link
            && self.internet == other.internet
            && self.transport == other.transport
            && self.application == other.application
            && self.inner == other.inner
            && self.corrupted == other.corrupted
    }
}

use std::hash::{Hash, Hasher};

impl<'a> Hash for PacketFlow<'a> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.data_link.hash(state);
        self.internet.hash(state);
        self.transport.hash(state);
        self.application.hash(state);
        self.inner.hash(state);
        self.corrupted.hash(state);
    }
}

impl<'a> PacketFlow<'a> {
    /// Converts this borrowed [`PacketFlow`] into a [`PacketFlowOwned`].
    ///
    /// This performs the necessary allocations to detach from the original
    /// packet buffer and is suitable for storage, serialization or cross-thread
    /// usage. The conversion is **lossy**: the owned form drops the payloads
    /// and the per-layer `details`.
    ///
    /// Named `to_owned_flow` rather than `to_owned` on purpose: `to_owned`
    /// shadowed [`ToOwned::to_owned`], so `flow.to_owned()` read as a clone
    /// while returning a different, amputated type (issue #27). To clone a
    /// flow, use [`Clone::clone`].
    pub fn to_owned_flow(&self) -> PacketFlowOwned {
        PacketFlowOwned::from(self)
    }

    /// Returns this flow and every encapsulated flow, from the outermost to the
    /// innermost. A non-tunneled packet yields a single entry; a tunneled one
    /// yields several (outer tunnel + inner conversation(s)).
    pub fn flatten(&self) -> Vec<&PacketFlow<'a>> {
        let mut out = Vec::new();
        let mut current = self;
        loop {
            out.push(current);
            match current.inner.as_deref() {
                Some(next) => current = next,
                None => break,
            }
        }
        out
    }

    /// Parses an Ethernet frame into a [`PacketFlow`] and fills timing data.
    /// See [`parse_timed`]: the timing stays zeroed without the
    /// `parse_timing` feature.
    #[inline(always)]
    pub fn try_from_timed(
        bytes: &'a [u8],
        timing: &mut crate::timing::ParseTiming,
    ) -> Result<Self, ParseError> {
        parse_timed(LinkType::ETHERNET, bytes, timing)
    }
}

/// Decode the first RFC 1006 TPKT frame and its COTP header.
///
/// A TCP segment may contain bytes after the first TPKT (including another
/// complete frame), so the declared TPKT boundary is used instead of requiring
/// equality with the whole transport payload. LI delimits only the COTP
/// header: CR/CC/DR, DT and ED may carry user data after it, while other TPDU
/// types may be concatenated and are checked one by one.
fn cotp_from_tpkt(payload: &[u8]) -> Option<CotpHeader<'_>> {
    const TPKT_HEADER_LEN: usize = 4;
    const TPKT_MIN_LEN: usize = 7;

    if payload.len() < TPKT_MIN_LEN || payload[0] != 3 || payload[1] != 0 {
        return None;
    }

    let tpkt_len = usize::from(u16::from_be_bytes([payload[2], payload[3]]));
    if !(TPKT_MIN_LEN..=payload.len()).contains(&tpkt_len) {
        return None;
    }

    let cotp_bytes = &payload[TPKT_HEADER_LEN..tpkt_len];
    let (header, mut consumed) = CotpHeader::from_bytes(cotp_bytes).ok()?;
    if !is_strict_cotp_header(&header) {
        return None;
    }

    if cotp_may_consume_user_data(header.pdu_type) {
        return Some(header);
    }

    while consumed < cotp_bytes.len() {
        let (next, next_consumed) = CotpHeader::from_bytes(&cotp_bytes[consumed..]).ok()?;
        if !is_strict_cotp_header(&next) || next_consumed == 0 {
            return None;
        }
        consumed = consumed.checked_add(next_consumed)?;
        if cotp_may_consume_user_data(next.pdu_type) {
            return Some(header);
        }
    }

    (consumed == cotp_bytes.len()).then_some(header)
}

fn cotp_may_consume_user_data(pdu_type: CotpPduType) -> bool {
    matches!(
        pdu_type,
        CotpPduType::Data
            | CotpPduType::ExpeditedData
            | CotpPduType::ConnectionRequest
            | CotpPduType::ConnectionConfirm
            | CotpPduType::DisconnectRequest
    )
}

fn is_strict_cotp_header(header: &CotpHeader<'_>) -> bool {
    match header.pdu_type {
        CotpPduType::Data => match header.number_format {
            Some(CotpNumberFormat::Class01Normal) => header
                .parameters
                .iter()
                .any(|parameter| matches!(parameter, CotpParameter::TpduNumber(0))),
            Some(CotpNumberFormat::Normal | CotpNumberFormat::Extended) => true,
            None | Some(CotpNumberFormat::Undetermined) => false,
        },
        CotpPduType::ExpeditedData
        | CotpPduType::ExpeditedDataAcknowledgement
        | CotpPduType::DataAcknowledgement
        | CotpPduType::Reject => !matches!(
            header.number_format,
            None | Some(CotpNumberFormat::Undetermined)
        ),
        CotpPduType::ConnectionRequest | CotpPduType::ConnectionConfirm => {
            is_strict_connection_header(header)
        }
        CotpPduType::DisconnectRequest
        | CotpPduType::DisconnectConfirm
        | CotpPduType::TpduError => true,
        CotpPduType::Other(_) => false,
    }
}

fn is_strict_connection_header(header: &CotpHeader<'_>) -> bool {
    for parameter in &header.parameters {
        if let CotpParameter::Other(code, _) = parameter {
            // The tolerant CR decoder preserves unknown parameters as RFC 905
            // permits. A detector cannot use that tolerance as evidence: only
            // the defined connection parameters remain valid fingerprints.
            if !matches!(
                code,
                0x85..=0x89 | 0x8B | 0xC1 | 0xC2 | 0xC4..=0xC7 | 0xF0 | 0xF2
            ) {
                return false;
            }
        }

        if header.class == 0
            && matches!(
                parameter,
                CotpParameter::TpduSize(0x0C | 0x0D)
                    | CotpParameter::Checksum(_)
                    | CotpParameter::AtnExtendedChecksum16(_)
                    | CotpParameter::AtnExtendedChecksum32(_)
                    | CotpParameter::Other(
                        0x85..=0x89 | 0x8B | 0xC4..=0xC7 | 0xF0 | 0xF2,
                        _
                    )
            )
        {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests;
