// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use super::{DecodedLink, LinkDecoder, decode_ethernet_frame};
use crate::{LinkLayer, LinkType, ParseError};

/// Decoder for Ethernet II frames, including the stacked VLAN tags path.
pub(super) struct EthernetDecoder;

impl LinkDecoder for EthernetDecoder {
    #[inline(always)]
    fn decode<'a>(bytes: &'a [u8]) -> Result<DecodedLink<'a>, ParseError> {
        // Meme contrat d'erreur que RAW, SLL et SLL2 : `Truncated` porte le
        // LINKTYPE, la taille requise (tags VLAN deja rencontres compris) et
        // la taille reelle.
        let frame = decode_ethernet_frame(LinkType::ETHERNET, bytes, 0)?;
        Ok(DecodedLink::new(LinkLayer::ethernet(frame)))
    }
}
