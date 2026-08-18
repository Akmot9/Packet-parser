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

// ---------------------------------------------------------------------------
// Messages d'erreur (pcaps_exemple/protocols/icmp/icmp_destination_unreachable.pcapng)
// ---------------------------------------------------------------------------

/// Trame 1 : ICMPv4 Destination Unreachable, code 3 (port unreachable),
/// emis par la pile locale apres un envoi UDP vers 127.0.0.1:9999.
const ICMPV4_PORT_UNREACHABLE_FRAME_HEX: &str = concat!(
    "000000000000000000000000080045c000399e5000004001ddb17f0000017f00",
    "00010303c9a3000000004500001dfd41400040113f8c7f0000017f0000019623",
    "270f0009fe1c78"
);

/// Trame 2 : ICMPv6 Destination Unreachable, code 4 (port unreachable),
/// apres un envoi UDP vers [::1]:9999.
const ICMPV6_PORT_UNREACHABLE_FRAME_HEX: &str = concat!(
    "00000000000000000000000086dd600245dc00393a4000000000000000000000",
    "000000000001000000000000000000000000000000010104956a00000000600e",
    "cab8000911400000000000000000000000000000000100000000000000000000",
    "0000000000018dd5270f0009001c78"
);

#[test]
fn packet_flow_decodes_icmpv4_destination_unreachable() {
    let bytes = frame(ICMPV4_PORT_UNREACHABLE_FRAME_HEX, 71);
    let flow = parse(LinkType::ETHERNET, bytes.as_slice()).expect("captured frame decodes");

    let Some(TransportDetails::Icmp(icmp)) = flow
        .transport
        .expect("ICMP is reported at the transport slot")
        .details
    else {
        panic!("ICMP details are decoded");
    };
    assert_eq!(icmp.message_type, 3);
    assert_eq!(icmp.code, 3);

    let IcmpBody::Error(report) = icmp.body else {
        panic!("destination unreachable must expose an error body");
    };
    // Code 3 n'utilise pas les quatre octets qui suivent le checksum ; ils
    // porteraient le MTU pour le code 4 (fragmentation needed).
    assert_eq!(report.rest_of_header, 0);
    // Le datagramme cite est l'IPv4 + UDP qui a provoque l'erreur.
    assert_eq!(report.original_datagram[0], 0x45);
    // Protocole 17 (UDP) a l'offset 9 de l'en-tete IPv4 original.
    assert_eq!(report.original_datagram[9], 17);
}

#[test]
fn packet_flow_decodes_icmpv6_destination_unreachable() {
    let bytes = frame(ICMPV6_PORT_UNREACHABLE_FRAME_HEX, 111);
    let flow = parse(LinkType::ETHERNET, bytes.as_slice()).expect("captured frame decodes");

    let Some(TransportDetails::Icmpv6(icmpv6)) = flow
        .transport
        .expect("ICMPv6 is reported at the transport slot")
        .details
    else {
        panic!("ICMPv6 details are decoded");
    };
    assert_eq!(icmpv6.message_type, 1);
    assert_eq!(icmpv6.code, 4);

    let Icmpv6Body::Error(report) = icmpv6.body else {
        panic!("destination unreachable must expose an error body");
    };
    assert_eq!(report.rest_of_header, 0);
    // Le paquet invoquant commence par un en-tete IPv6 (version 6).
    assert_eq!(report.invoking_packet[0] >> 4, 6);
    // Next header 17 (UDP) a l'offset 6 de l'en-tete IPv6.
    assert_eq!(report.invoking_packet[6], 17);
}

// ---------------------------------------------------------------------------
// MTU du lien suivant (pcaps_exemple/protocols/icmp/icmp_mtu_exceeded.pcapng)
//
// Seuls ces deux messages portent une valeur non nulle dans `rest_of_header`.
// Les trames font 590 et 1294 octets : trop pour des constantes hex, on lit
// donc la capture, comme `s7comm_regression`.
// ---------------------------------------------------------------------------

const MTU_CAPTURE: &str = "pcaps_exemple/protocols/icmp/icmp_mtu_exceeded.pcapng";

/// Renvoie la n-ieme trame de la capture (numerotation Wireshark, 1-based).
/// Lecture via `pcap-file` (Rust pur) : aucune dependance systeme, le test
/// tourne aussi sur les runners Windows/macOS de la CI.
fn frame_from_capture(path: &str, frame_number: usize) -> Vec<u8> {
    use pcap_file::pcapng::{Block, PcapNgReader};

    let file = std::fs::File::open(path).expect("capture is readable");
    let mut reader = PcapNgReader::new(file).expect("valid pcapng");
    let mut seen = 0;
    while let Some(block) = reader.next_block() {
        if let Block::EnhancedPacket(epb) = block.expect("readable block") {
            seen += 1;
            if seen == frame_number {
                return epb.data.into_owned();
            }
        }
    }
    panic!("frame {frame_number} not found in {path}");
}

#[test]
fn packet_flow_decodes_icmpv4_fragmentation_needed_with_next_hop_mtu() {
    let bytes = frame_from_capture(MTU_CAPTURE, 2);
    let flow = parse(LinkType::ETHERNET, bytes.as_slice()).expect("captured frame decodes");

    let Some(TransportDetails::Icmp(icmp)) = flow
        .transport
        .expect("ICMP is reported at the transport slot")
        .details
    else {
        panic!("ICMP details are decoded");
    };
    assert_eq!(icmp.message_type, 3);
    assert_eq!(icmp.code, 4);

    let IcmpBody::Error(report) = icmp.body else {
        panic!("fragmentation needed must expose an error body");
    };
    // RFC 1191 : deux octets inutilises, puis le MTU du saut suivant. C'est le
    // seul cas ICMPv4 ou `rest_of_header` n'est pas nul.
    assert_eq!(report.rest_of_header & 0xffff, 1280);
    assert_eq!(report.rest_of_header >> 16, 0);
    assert_eq!(report.original_datagram[0], 0x45);
}

#[test]
fn packet_flow_decodes_icmpv6_packet_too_big_with_mtu() {
    let bytes = frame_from_capture(MTU_CAPTURE, 5);
    let flow = parse(LinkType::ETHERNET, bytes.as_slice()).expect("captured frame decodes");

    let Some(TransportDetails::Icmpv6(icmpv6)) = flow
        .transport
        .expect("ICMPv6 is reported at the transport slot")
        .details
    else {
        panic!("ICMPv6 details are decoded");
    };
    assert_eq!(icmpv6.message_type, 2);
    assert_eq!(icmpv6.code, 0);

    let Icmpv6Body::Error(report) = icmpv6.body else {
        panic!("packet too big must expose an error body");
    };
    // RFC 4443 §3.2 : les quatre octets portent le MTU en entier, pas seulement
    // les deux derniers comme en IPv4.
    assert_eq!(report.rest_of_header, 1280);
    assert_eq!(report.invoking_packet[0] >> 4, 6);
}

/// La capture NDP existante n'a qu'une annonce non-routeur. Celle-ci vient
/// d'un vrai routeur (flags « rtr, sol » selon tshark) : sans elle, le bit
/// Router ne serait jamais teste dans l'etat vrai.
#[test]
fn packet_flow_decodes_neighbor_advertisement_with_router_flag() {
    let bytes = frame_from_capture(MTU_CAPTURE, 13);
    let flow = parse(LinkType::ETHERNET, bytes.as_slice()).expect("captured frame decodes");

    let Some(TransportDetails::Icmpv6(icmpv6)) = flow
        .transport
        .expect("ICMPv6 is reported at the transport slot")
        .details
    else {
        panic!("ICMPv6 details are decoded");
    };

    let Icmpv6Body::NeighborAdvertisement(advertisement) = icmpv6.body else {
        panic!("neighbor advertisement must expose its dedicated body");
    };
    assert!(advertisement.router);
    assert!(advertisement.solicited);
    assert!(!advertisement.overrides);
}

// ---------------------------------------------------------------------------
// Decouverte de routeurs (pcaps_exemple/The-Ultimate-PCAP.pcapng)
// ---------------------------------------------------------------------------

/// Trame 1600 : Router Solicitation portant une option Source Link-Layer
/// Address, emise vers le multicast all-routers ff02::2.
const ROUTER_SOLICITATION_FRAME_HEX: &str = concat!(
    "33330000000200216a2d3b8e86dd6000000000103afffe800000000000000221",
    "6afffe2d3b8eff02000000000000000000000000000285002f75000000000101",
    "00216a2d3b8e"
);

/// Trame 1604 : Router Advertisement vers le multicast all-nodes ff02::1,
/// drapeau O pose, options Prefix Information et MTU.
const ROUTER_ADVERTISEMENT_FRAME_HEX: &str = concat!(
    "333300000001d42122765b7886dd6000000000383afffe800000000000000000",
    "000000000001ff02000000000000000000000000000186001553ff4807080000",
    "7530000003e8030440c000093a80000151800000000020030050aa1042430000",
    "00000000000005010000000005d4"
);

#[test]
fn packet_flow_decodes_icmpv6_router_solicitation() {
    let bytes = frame(ROUTER_SOLICITATION_FRAME_HEX, 70);
    let flow = parse(LinkType::ETHERNET, bytes.as_slice()).expect("captured frame decodes");

    let Some(TransportDetails::Icmpv6(icmpv6)) = flow
        .transport
        .expect("ICMPv6 is reported at the transport slot")
        .details
    else {
        panic!("ICMPv6 details are decoded");
    };
    assert_eq!(icmpv6.message_type, 133);

    let Icmpv6Body::RouterSolicitation(solicitation) = icmpv6.body else {
        panic!("router solicitation must expose its dedicated body");
    };
    assert_eq!(solicitation.options[0], 1);
}

#[test]
fn packet_flow_decodes_icmpv6_router_advertisement() {
    let bytes = frame(ROUTER_ADVERTISEMENT_FRAME_HEX, 110);
    let flow = parse(LinkType::ETHERNET, bytes.as_slice()).expect("captured frame decodes");

    let Some(TransportDetails::Icmpv6(icmpv6)) = flow
        .transport
        .expect("ICMPv6 is reported at the transport slot")
        .details
    else {
        panic!("ICMPv6 details are decoded");
    };

    let Icmpv6Body::RouterAdvertisement(advertisement) = icmpv6.body else {
        panic!("router advertisement must expose its dedicated body");
    };
    assert_eq!(advertisement.current_hop_limit, 255);
    assert!(!advertisement.managed_address_configuration);
    assert!(advertisement.other_configuration);
    assert_eq!(advertisement.router_lifetime, 1800);
    assert_eq!(advertisement.reachable_time, 30_000);
    assert_eq!(advertisement.retransmit_timer, 1000);
    // Prefix Information (3) puis MTU (5).
    assert_eq!(advertisement.options[0], 3);
}
