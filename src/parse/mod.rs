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
use internet::Internet;
use serde::{Serialize, Serializer};
use transport::Transport;
use transport::protocols::TransportProtocol;

use crate::errors::{internet::InternetError, transport::TransportError};
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

/// Like [`fn@parse`], with a configuration supplied by the caller: "my FTP
/// runs on port 2121" is declared with [`ParseConfig::decode_as`] (issue #65).
/// Declared ports extend the port guards of the dispatch table without
/// replacing them: the content must still confirm the port, and the default
/// behaviour is exactly that of [`fn@parse`].
pub fn parse_with<'a>(
    link_type: LinkType,
    bytes: &'a [u8],
    config: &ParseConfig,
) -> Result<PacketFlow<'a>, ParseError> {
    PacketFlow::parse_decoded_with(link::decode(link_type, bytes)?, 0, &config.decode_as)
}

/// Caller-side parsing configuration ("Decode As"). Built as a builder;
/// empty by default, in which case [`parse_with`] behaves exactly like
/// [`fn@parse`].
#[derive(Debug, Clone, Default)]
pub struct ParseConfig {
    decode_as: Vec<(u16, DecodeAsProtocol)>,
}

impl ParseConfig {
    pub fn new() -> Self {
        Self::default()
    }

    /// Declares that an additional port carries this protocol. The port
    /// never replaces content validation: it only gives the probe its turn
    /// before the rest of the table.
    #[must_use]
    pub fn decode_as(mut self, port: u16, protocol: DecodeAsProtocol) -> Self {
        self.decode_as.push((port, protocol));
        self
    }
}

/// Classifies the payload of one TCP segment or UDP datagram when the caller
/// knows its transport protocol and its ports but no longer has the frame: a
/// stream it reassembled, a datagram it defragmented, a payload stored
/// without its headers.
///
/// The answer is the one [`fn@parse`] puts in [`PacketFlow::application`] for
/// the outermost flow of a frame with this transport, these ports and this
/// payload. It goes through the same dispatch table, with its transport
/// guards and its port guards, and through the same tunnel detection: the
/// label of a VXLAN, Geneve, GTP-U or CAPWAP datagram is the name of the
/// tunnel.
///
/// # Return value
///
/// - `None` when there is nothing to classify: an empty payload, a protocol
///   other than TCP or UDP, or a UDP port reserved for mDNS (5353) or LLMNR
///   (5355) that carries something else;
/// - `Some` with the label `"Unknown"` for a payload that was probed and not
///   recognized;
/// - `Some` with the label of the protocol otherwise.
///
/// Only TCP and UDP payloads are classified. `parse` probes nothing above
/// ICMP, ESP or a protocol this crate does not decode, and neither does this
/// function, whatever bytes and ports it is given.
///
/// # Ports
///
/// Pass `None` for a port you do not know. The rules that need a port then do
/// not apply; the signatures strong enough to stand without one remain, each
/// behind its transport guard. Many protocols are only recognized on their
/// port (COTP, FTP replies, IEC 104, PTP...): give the ports whenever you have
/// them.
///
/// # Differences with `parse`
///
/// This function receives a payload, not a frame. Three answers of `parse`
/// depend on what it does not see:
///
/// - **TCP flags.** `parse` leaves the application layer empty for a segment
///   whose flags no conforming stack emits (SYN+FIN, reserved bits: see
///   [`CorruptedLayer`]). This function classifies its payload like any
///   other.
/// - **IP-level tunnels.** `parse` names GRE and IP-in-IP from the IP header.
///   They carry no transport payload, and this function returns `None` for
///   their protocols, as for any protocol other than TCP and UDP.
/// - **Tunnel nesting.** `parse` keeps at most four levels of flows and does
///   not look for a tunnel in the last one: a tunnel datagram found there is
///   labelled by the table alone. This function has no depth. It always
///   answers as for an outermost flow, and names the tunnel.
///
/// # Example
///
/// ```
/// use packet_parser::{TransportProtocol, classify_payload};
///
/// // An MMS error PDU under TPKT and COTP, captured on TCP port 102.
/// let payload =
///     hex::decode("0300002202f0800100010061153013020103a00ea20c800304a273a205a003870102")?;
/// let label = |source_port, destination_port| {
///     classify_payload(TransportProtocol::Tcp, source_port, destination_port, &payload)
///         .map(|application| application.protocol.label())
/// };
///
/// // The port confirms a signature too weak to stand alone.
/// assert_eq!(label(Some(102), Some(1345)), Some("COTP"));
/// // Without it, the payload is probed and not recognized.
/// assert_eq!(label(None, None), Some("Unknown"));
/// # Ok::<(), hex::FromHexError>(())
/// ```
pub fn classify_payload(
    protocol: TransportProtocol,
    source_port: Option<u16>,
    destination_port: Option<u16>,
    payload: &[u8],
) -> Option<Application> {
    classify_transport_payload(protocol, source_port, destination_port, payload, &[])
}

/// Like [`classify_payload`], with the caller's configuration: the answer is
/// the one [`parse_with`] gives with the same [`ParseConfig`].
///
/// A port declared with [`ParseConfig::decode_as`] gives its protocol a chance
/// before the rest of the table. The content must still confirm the port, and
/// the transport guard of the protocol still applies.
///
/// ```
/// use packet_parser::{
///     DecodeAsProtocol, ParseConfig, TransportProtocol, classify_payload, classify_payload_with,
/// };
///
/// // The greeting of an FTP server that listens on port 2121.
/// let greeting = b"220 Chris Sanders FTP Server\r\n";
/// let label = |application: Option<packet_parser::Application>| {
///     application.map(|application| application.protocol.label())
/// };
///
/// // An FTP reply has the shape of an SMTP or NNTP reply: only its port tells.
/// let by_default = classify_payload(TransportProtocol::Tcp, Some(2121), Some(1137), greeting);
/// assert_eq!(label(by_default), Some("Unknown"));
///
/// let config = ParseConfig::new().decode_as(2121, DecodeAsProtocol::Ftp);
/// let declared =
///     classify_payload_with(TransportProtocol::Tcp, Some(2121), Some(1137), greeting, &config);
/// assert_eq!(label(declared), Some("FTP"));
/// ```
pub fn classify_payload_with(
    protocol: TransportProtocol,
    source_port: Option<u16>,
    destination_port: Option<u16>,
    payload: &[u8],
    config: &ParseConfig,
) -> Option<Application> {
    classify_transport_payload(
        protocol,
        source_port,
        destination_port,
        payload,
        &config.decode_as,
    )
}

fn classify_transport_payload(
    protocol: TransportProtocol,
    source_port: Option<u16>,
    destination_port: Option<u16>,
    payload: &[u8],
    decode_as: &[(u16, DecodeAsProtocol)],
) -> Option<Application> {
    if !matches!(protocol, TransportProtocol::Tcp | TransportProtocol::Udp) {
        return None;
    }
    let transport = Transport {
        source_port,
        destination_port,
        protocol,
        payload: Some(payload),
        details: None,
    };
    // Profondeur 0 : la fonction repond comme pour le flux externe d'une
    // trame. Le flux interne d'un tunnel est decode puis jete : c'est lui
    // qui prouve le tunnel, comme dans `parse`.
    PacketFlow::application_and_inner(&transport, 0, decode_as).0
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
///
/// The parser builds this value. To build one yourself, in a test fixture
/// for instance, convert the error: `layer` follows from its kind.
///
/// ```
/// use packet_parser::errors::internet::InternetError;
/// use packet_parser::{CorruptedLayer, CorruptedLayerKind};
///
/// let corrupted = CorruptedLayer::from(InternetError::EmptyPacket);
/// assert_eq!(corrupted.layer, CorruptedLayerKind::Internet);
/// assert_eq!(corrupted.error.to_string(), "Empty packet");
/// ```
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct CorruptedLayer {
    /// Which layer had invalid bytes.
    pub layer: CorruptedLayerKind,
    /// Why: the error of the decoder that refused the bytes. Match on it to
    /// tell a truncated header from an impossible length or a TCP anomaly.
    /// Its `Display` is the human-readable description, and the text of the
    /// JSON key `error`.
    pub error: CorruptedLayerError,
}

impl From<InternetError> for CorruptedLayer {
    fn from(error: InternetError) -> Self {
        Self {
            layer: CorruptedLayerKind::Internet,
            error: CorruptedLayerError::Internet(error),
        }
    }
}

impl From<TransportError> for CorruptedLayer {
    fn from(error: TransportError) -> Self {
        Self {
            layer: CorruptedLayerKind::Transport,
            error: CorruptedLayerError::Transport(error),
        }
    }
}

/// The typed cause of a [`CorruptedLayer`]: the error of the layer whose
/// bytes are invalid.
///
/// ```
/// use packet_parser::errors::transport::{TransportError, tcp::TcpError};
/// use packet_parser::{CorruptedLayerError, LinkType, parse};
///
/// // Ethernet, IPv4, and a TCP header with both SYN and FIN set.
/// let frame = hex::decode(concat!(
///     "020000000001020000000002", "0800",
///     "450000280001400040060000c0000201c0000202",
///     "9c409c410000000100000000500300000000ffff",
/// ))
/// .unwrap();
/// let flow = parse(LinkType::ETHERNET, &frame).unwrap();
///
/// let corrupted = flow.corrupted.expect("the anomaly is reported");
/// assert!(matches!(
///     corrupted.error,
///     CorruptedLayerError::Transport(TransportError::TcpError(TcpError::InvalidFlags {
///         flags: 0x03
///     }))
/// ));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum CorruptedLayerError {
    /// The internet layer was recognized by its EtherType, but its bytes are
    /// invalid.
    #[error(transparent)]
    Internet(#[from] InternetError),
    /// The transport layer was recognized by the IP protocol field, but its
    /// bytes are invalid, or its header carries a semantic anomaly.
    #[error(transparent)]
    Transport(#[from] TransportError),
}

/// Serialized as its text, the same string the `error` key always carried.
impl Serialize for CorruptedLayerError {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
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
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash)]
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

#[cfg(test)]
mod tests;
