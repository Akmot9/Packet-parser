// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Les renommages de la 12.0 (#220) : en 11.x, l'ancien nom et le nouveau
//! designent la meme chose, et les discriminants ne bougent pas.

#![allow(deprecated)]

use packet_parser::errors::application::{copt as old_cotp_errors, cotp as cotp_errors};
use packet_parser::errors::data_link::{mac_addres as old_mac_errors, mac_address as mac_errors};
use packet_parser::parse::application::protocols::{copt, cotp};
use packet_parser::parse::data_link::{mac_addres, mac_address};

/// Les quatre anciens chemins de modules restent, en alias des nouveaux :
/// un appelant de la 11.8 compile sans changement, constructeur du tuple
/// struct compris.
#[test]
fn old_module_paths_still_resolve() {
    let pdu: cotp::CotpPduType = copt::CotpPduType::from(0xf0);
    assert_eq!(pdu, cotp::CotpPduType::from(0xf0));

    let header: Result<copt::CotpHeader<'_>, old_cotp_errors::CotpParseError> =
        cotp::CotpHeader::try_from(&[][..]);
    let same: Result<cotp::CotpHeader<'_>, cotp_errors::CotpParseError> = header;
    assert!(same.is_err());

    let mac: mac_address::MacAddress = mac_addres::MacAddress([0xff; mac_addres::MAC_LEN]);
    assert!(mac.is_broadcast());
    assert_eq!(mac, packet_parser::MacAddress([0xff; mac_address::MAC_LEN]));

    let oui: mac_address::oui::Oui = mac_addres::oui::Oui::from_bytes(&[0, 0, 0]);
    assert_eq!(oui, mac_address::oui::Oui::from_bytes(&[0, 0, 0]));

    let error: Result<mac_address::MacAddress, old_mac_errors::MacParseError> =
        mac_addres::MacAddress::try_from(&[0u8; 2][..]);
    let same: Result<mac_addres::MacAddress, mac_errors::MacParseError> = error;
    assert!(same.is_err());
}
