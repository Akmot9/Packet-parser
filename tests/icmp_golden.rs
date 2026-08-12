// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests ICMPv4 au niveau `PacketFlow`, sur trames Ethernet completes.
//!
//! Captures : `pcaps_exemple/protocols/icmp/`, issues du depot public de
//! Chris Sanders (voir le `SOURCE.md` du dossier). METHODE_AJOUT_PROTOCOLE.md
//! exige au moins un test de ce niveau pour tout protocole ajoute.

use packet_parser::parse::transport::TransportDetails;
use packet_parser::parse::transport::protocols::TransportProtocol;
use packet_parser::parse::transport::protocols::icmp::IcmpBody;
use packet_parser::parse::transport::protocols::icmpv6::Icmpv6Body;
use packet_parser::{LinkType, parse};
use std::net::Ipv6Addr;

/// Trame 1 : Echo request (ping) 192.168.100.138 -> 192.168.100.1
/// (pcaps_exemple/protocols/icmp/icmp_echo.pcapng).
const ECHO_REQUEST_FRAME_HEX: &str = concat!(
    "0012804bc07f0016d4b859b108004500003cfefd00008001f1e6c0a8648ac0a8",
    "64010800145c050034006162636465666768696a6b6c6d6e6f70717273747576",
    "77616263646566676869"
);

/// Trame 2 : Time-to-live exceeded in transit, emis par 192.168.100.1
/// (pcaps_exemple/protocols/icmp/icmp_traceroute.pcapng).
const TIME_EXCEEDED_FRAME_HEX: &str = concat!(
    "0016d4b859b10012804bc07f080045c00038491a0000ff01280ec0a86401c0a8",
    "648a0b00f4ff000000004500005cff51000001018f1ac0a8648a040202010800",
    "baff05003800"
);

fn frame(hex_fixture: &str, expected_len: usize) -> Vec<u8> {
    let bytes = hex::decode(hex_fixture).expect("invalid test hex fixture");
    assert_eq!(
        bytes.len(),
        expected_len,
        "fixture length must match capture"
    );
    bytes
}

#[test]
fn packet_flow_decodes_icmp_echo_request() {
    let bytes = frame(ECHO_REQUEST_FRAME_HEX, 74);
    let flow = parse(LinkType::ETHERNET, bytes.as_slice()).expect("captured frame decodes");

    let transport = flow
        .transport
        .expect("ICMP is reported at the transport slot");
    assert_eq!(transport.protocol, TransportProtocol::Icmp);

    let Some(TransportDetails::Icmp(icmp)) = transport.details else {
        panic!("ICMP details are now decoded, not left empty");
    };
    assert_eq!(icmp.message_type, 8);
    assert_eq!(icmp.code, 0);

    let IcmpBody::Echo(echo) = icmp.body else {
        panic!("echo request must expose an echo body");
    };
    assert_eq!(echo.identifier, 0x0500);
    assert_eq!(echo.sequence_number, 0x3400);
    assert_eq!(echo.data.len(), 32);
}

#[test]
fn packet_flow_decodes_icmp_time_exceeded_with_original_datagram() {
    let bytes = frame(TIME_EXCEEDED_FRAME_HEX, 70);
    let flow = parse(LinkType::ETHERNET, bytes.as_slice()).expect("captured frame decodes");

    let transport = flow
        .transport
        .expect("ICMP is reported at the transport slot");
    let Some(TransportDetails::Icmp(icmp)) = transport.details else {
        panic!("ICMP details are now decoded, not left empty");
    };
    assert_eq!(icmp.message_type, 11);
    assert_eq!(icmp.code, 0);

    let IcmpBody::Error(report) = icmp.body else {
        panic!("time exceeded must expose an error body");
    };
    assert_eq!(report.rest_of_header, 0);
    // Le routeur cite le datagramme fautif : en-tete IPv4 (0x45) puis les
    // 8 premiers octets de donnees, ici le debut de l'echo request d'origine.
    assert_eq!(report.original_datagram[0], 0x45);
    assert_eq!(report.original_datagram.len(), 28);
}

/// ICMP n'a pas de couche applicative : exposer son contenu au probing
/// generique produirait des etiquettes fantaisistes. `payload` doit rester
/// None et aucune application ne doit etre detectee.
#[test]
fn icmp_is_never_handed_to_application_probing() {
    for (hex_fixture, len) in [(ECHO_REQUEST_FRAME_HEX, 74), (TIME_EXCEEDED_FRAME_HEX, 70)] {
        let bytes = frame(hex_fixture, len);
        let flow = parse(LinkType::ETHERNET, bytes.as_slice()).expect("captured frame decodes");

        let transport = flow.transport.expect("transport layer is present");
        assert!(transport.payload.is_none());
        assert!(flow.application.is_none());
    }
}

// ---------------------------------------------------------------------------
// ICMPv6 (pcaps_exemple/protocols/icmp/icmpv6_neighbor_solicitation.pcapng)
// ---------------------------------------------------------------------------

/// Trame 1 : Neighbor Solicitation pour 2001:db8:1:2::1000, emise vers
/// l'adresse multicast sollicitee ff02::1:ff00:1000.
const NEIGHBOR_SOLICITATION_FRAME_HEX: &str = concat!(
    "3333ff001000000c292f803186dd6000000000203aff20010db8000100020000",
    "000000001003ff0200000000000000000001ff001000870044b7000000002001",
    "0db80001000200000000000010000101000c292f8031"
);

/// Trame 2 : Neighbor Advertisement en reponse, flags solicited + override.
const NEIGHBOR_ADVERTISEMENT_FRAME_HEX: &str = concat!(
    "000c292f8031000c291fa75586dd6000000000203aff20010db8000100020000",
    "00000000100020010db800010002000000000000100388008beb600000002001",
    "0db80001000200000000000010000201000c291fa755"
);

#[test]
fn packet_flow_decodes_icmpv6_neighbor_solicitation() {
    let bytes = frame(NEIGHBOR_SOLICITATION_FRAME_HEX, 86);
    let flow = parse(LinkType::ETHERNET, bytes.as_slice()).expect("captured frame decodes");

    let transport = flow
        .transport
        .expect("ICMPv6 is reported at the transport slot");
    assert_eq!(transport.protocol, TransportProtocol::Ipv6Icmp);

    let Some(TransportDetails::Icmpv6(icmpv6)) = transport.details else {
        panic!("ICMPv6 details are now decoded, not left empty");
    };
    assert_eq!(icmpv6.message_type, 135);

    let Icmpv6Body::NeighborSolicitation(solicitation) = icmpv6.body else {
        panic!("neighbor solicitation must expose its dedicated body");
    };
    assert_eq!(
        solicitation.target_address,
        "2001:db8:1:2::1000".parse::<Ipv6Addr>().unwrap()
    );
}

#[test]
fn packet_flow_decodes_icmpv6_neighbor_advertisement_flags() {
    let bytes = frame(NEIGHBOR_ADVERTISEMENT_FRAME_HEX, 86);
    let flow = parse(LinkType::ETHERNET, bytes.as_slice()).expect("captured frame decodes");

    let Some(TransportDetails::Icmpv6(icmpv6)) = flow
        .transport
        .expect("ICMPv6 is reported at the transport slot")
        .details
    else {
        panic!("ICMPv6 details are now decoded, not left empty");
    };

    let Icmpv6Body::NeighborAdvertisement(advertisement) = icmpv6.body else {
        panic!("neighbor advertisement must expose its dedicated body");
    };
    assert!(!advertisement.router);
    assert!(advertisement.solicited);
    assert!(advertisement.overrides);
}

/// Meme regle qu'en v4 : ICMPv6 ne porte pas de couche applicative.
#[test]
fn icmpv6_is_never_handed_to_application_probing() {
    let bytes = frame(NEIGHBOR_SOLICITATION_FRAME_HEX, 86);
    let flow = parse(LinkType::ETHERNET, bytes.as_slice()).expect("captured frame decodes");

    let transport = flow.transport.expect("transport layer is present");
    assert!(transport.payload.is_none());
    assert!(flow.application.is_none());
}
