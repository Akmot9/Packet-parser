// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

mod ethernet;

use crate::{LinkType, PacketFlow, ParseError};

use ethernet::EthernetDecoder;

#[derive(Clone, Copy)]
enum DecoderKind {
    Ethernet,
}

/// Single source of truth for the link types backed by a decoder.
#[inline(always)]
const fn decoder_for(link_type: LinkType) -> Option<DecoderKind> {
    match link_type {
        LinkType::ETHERNET => Some(DecoderKind::Ethernet),
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
    fn decode<'a>(bytes: &'a [u8]) -> Result<PacketFlow<'a>, ParseError>;

    #[cfg(feature = "parse_timing")]
    fn decode_timed<'a>(
        bytes: &'a [u8],
        timing: &mut crate::timing::ParseTiming,
    ) -> Result<PacketFlow<'a>, ParseError>;
}

/// Selects a decoder from the numeric link type.
#[inline(always)]
pub(crate) fn decode(link_type: LinkType, bytes: &[u8]) -> Result<PacketFlow<'_>, ParseError> {
    match decoder_for(link_type) {
        Some(DecoderKind::Ethernet) => EthernetDecoder::decode(bytes),
        None => Err(ParseError::UnsupportedLinkType(link_type)),
    }
}

#[cfg(feature = "parse_timing")]
#[inline(always)]
pub(crate) fn decode_timed<'a>(
    link_type: LinkType,
    bytes: &'a [u8],
    timing: &mut crate::timing::ParseTiming,
) -> Result<PacketFlow<'a>, ParseError> {
    use crate::timing::{elapsed_ns, now};

    *timing = crate::timing::ParseTiming::default();
    let total_t0 = now();

    let result = match decoder_for(link_type) {
        Some(DecoderKind::Ethernet) => EthernetDecoder::decode_timed(bytes, timing),
        None => Err(ParseError::UnsupportedLinkType(link_type)),
    };

    timing.total_ns = elapsed_ns(total_t0);
    result
}
