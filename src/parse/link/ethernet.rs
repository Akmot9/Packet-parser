// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use super::LinkDecoder;
use crate::{DataLink, PacketFlow, ParseError};

/// Decoder for Ethernet II frames, including the existing 802.1Q VLAN path.
pub(super) struct EthernetDecoder;

impl LinkDecoder for EthernetDecoder {
    #[inline(always)]
    fn decode<'a>(bytes: &'a [u8]) -> Result<PacketFlow<'a>, ParseError> {
        let data_link = DataLink::try_from(bytes)?;
        PacketFlow::parse_layers(data_link, 0)
    }

    #[cfg(feature = "parse_timing")]
    #[inline(always)]
    fn decode_timed<'a>(
        bytes: &'a [u8],
        timing: &mut crate::timing::ParseTiming,
    ) -> Result<PacketFlow<'a>, ParseError> {
        use crate::timing::{elapsed_ns, now};

        let t0 = now();
        let data_link = match DataLink::try_from(bytes) {
            Ok(data_link) => data_link,
            Err(error) => {
                timing.l2_ns = elapsed_ns(t0);
                return Err(error.into());
            }
        };
        timing.l2_ns = elapsed_ns(t0);

        PacketFlow::parse_layers_timed(data_link, timing)
    }
}
