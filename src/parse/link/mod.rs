// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

mod ethernet;
mod ieee802_3br;
mod linux_sll;
mod linux_sll2;
pub(crate) mod raw_ip;

use crate::{LinkLayer, LinkType, NetworkProtocol, ParseError};

use ethernet::EthernetDecoder;
use ieee802_3br::Ieee8023brDecoder;
use linux_sll::LinuxSllDecoder;
use linux_sll2::LinuxSll2Decoder;
pub(crate) use raw_ip::RawIpDecoder;

#[derive(Clone, Copy)]
enum DecoderKind {
    Ethernet,
    /// Carries the link type it was selected for: RAW, IPV4 and IPV6 share the
    /// same decoder but must each be reported back as declared by the capture.
    RawIp(LinkType),
    LinuxSll,
    LinuxSll2,
    Ieee8023br,
}

/// Format-neutral output consumed by the shared L3/L4/L7 pipeline.
pub(crate) struct DecodedLink<'a> {
    layer: LinkLayer<'a>,
    network_protocol: NetworkProtocol,
    network_payload: &'a [u8],
}

impl<'a> DecodedLink<'a> {
    pub(crate) fn new(layer: LinkLayer<'a>) -> Self {
        Self {
            network_protocol: layer.network_protocol(),
            network_payload: layer.network_payload(),
            layer,
        }
    }

    pub(crate) fn into_parts(self) -> (LinkLayer<'a>, NetworkProtocol, &'a [u8]) {
        (self.layer, self.network_protocol, self.network_payload)
    }
}

/// Single source of truth for the link types backed by a decoder.
#[inline(always)]
const fn decoder_for(link_type: LinkType) -> Option<DecoderKind> {
    match link_type {
        LinkType::ETHERNET => Some(DecoderKind::Ethernet),
        // RAW, IPV4 et IPV6 partagent la meme forme : les octets commencent
        // directement a l'en-tete IP. RawIpDecoder lit la version au premier
        // quartet, ce qui couvre les trois sans decodeur dedie.
        LinkType::RAW => Some(DecoderKind::RawIp(LinkType::RAW)),
        LinkType::IPV4 => Some(DecoderKind::RawIp(LinkType::IPV4)),
        LinkType::IPV6 => Some(DecoderKind::RawIp(LinkType::IPV6)),
        LinkType::LINUX_SLL => Some(DecoderKind::LinuxSll),
        LinkType::LINUX_SLL2 => Some(DecoderKind::LinuxSll2),
        LinkType::IEEE802_3BR => Some(DecoderKind::Ieee8023br),
        _ => None,
    }
}

/// Returns whether a decoder is currently available for this link type.
#[inline(always)]
pub(crate) const fn is_supported(link_type: LinkType) -> bool {
    decoder_for(link_type).is_some()
}

/// Internal contract implemented by each supported link-layer decoder.
pub(crate) trait LinkDecoder {
    fn decode<'a>(bytes: &'a [u8]) -> Result<DecodedLink<'a>, ParseError>;
}

#[inline(always)]
fn decode_with<'a>(kind: DecoderKind, bytes: &'a [u8]) -> Result<DecodedLink<'a>, ParseError> {
    match kind {
        DecoderKind::Ethernet => EthernetDecoder::decode(bytes),
        DecoderKind::RawIp(link_type) => RawIpDecoder::decode_as(link_type, bytes),
        DecoderKind::LinuxSll => LinuxSllDecoder::decode(bytes),
        DecoderKind::LinuxSll2 => LinuxSll2Decoder::decode(bytes),
        DecoderKind::Ieee8023br => Ieee8023brDecoder::decode(bytes),
    }
}

/// Selects a link decoder from the numeric link type.
#[inline(always)]
pub(crate) fn decode(link_type: LinkType, bytes: &[u8]) -> Result<DecodedLink<'_>, ParseError> {
    match decoder_for(link_type) {
        Some(kind) => decode_with(kind, bytes),
        None => Err(ParseError::UnsupportedLinkType(link_type)),
    }
}

#[cfg(feature = "parse_timing")]
#[inline(always)]
pub(crate) fn decode_timed<'a>(
    link_type: LinkType,
    bytes: &'a [u8],
    timing: &mut crate::timing::ParseTiming,
) -> Result<DecodedLink<'a>, ParseError> {
    let kind = decoder_for(link_type).ok_or(ParseError::UnsupportedLinkType(link_type))?;
    let t0 = crate::timing::now();
    let result = decode_with(kind, bytes);
    timing.l2_ns = crate::timing::elapsed_ns(t0);
    result
}
