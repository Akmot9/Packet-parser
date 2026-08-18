// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests IEEE 802.3br (LINKTYPE 274) au niveau `PacketFlow`, sur des
//! mPackets express reels.
//!
//! Captures : `pcaps_exemple/The-Ultimate-PCAP.pcapng` (numeros de trame
//! notes sur chaque fixture). Toutes les trames LINKTYPE 274 du corpus sont
//! SMD-E : preambule de 0x55 (7 octets, ou 6 — la norme autorise le PHY a le
//! raccourcir et le corpus contient les deux), SMD 0xd5, trame Ethernet
//! complete, puis 4 octets de CRC. Le decodeur retire l'enveloppe et delegue
//! a Ethernet ; ces tests verrouillent le decoupage sur des protocoles
//! varies.

use packet_parser::parse::transport::TransportDetails;
use packet_parser::parse::transport::protocols::TransportProtocol;
use packet_parser::parse::transport::protocols::icmp::IcmpBody;
use packet_parser::parse::transport::protocols::icmpv6::Icmpv6Body;
use packet_parser::{LinkType, parse};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Trame 26175 : echo request ICMP 192.168.42.11 -> 5.35.226.136.
const ICMP_ECHO_MPACKET_HEX: &str = concat!(
    "55555555555555d50007b4002a02b827ebc9163708004500005433f240004001",
    "3458c0a82a0b0523e2880800f50404550001aa89be5fa1b8090008090a0b0c0d",
    "0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d",
    "2e2f30313233343536377757589e"
);

/// Trame 21593 : neighbor solicitation ICMPv6 pour fe80::3a63:bbff:fe02:5a4d.
const ICMPV6_NS_MPACKET_HEX: &str = concat!(
    "55555555555555d53333ff025a4dd4a33d97606d86dd6000000000203afffe80",
    "0000000000000ca4b90c5dade86bff0200000000000000000001ff025a4d8700",
    "552800000000fe800000000000003a63bbfffe025a4d0101d4a33d97606d989a",
    "1332"
);

/// Trame 28153 : annonce VRRP (IP protocole 112) de 192.168.42.5 vers
/// l'adresse multicast dediee 224.0.0.18.
const VRRP_MPACKET_HEX: &str = concat!(
    "55555555555555d501005e00001200005e000101080045c0004600000000ff70",
    "efc7c0a82a05e000001221016401fe01e76ec0a82a010000000000000000fe1c",
    "01000000c0a82a0500000000c010264f5ec8561d45c7a086694bd638f6d720e6"
);

/// Trame 48891 : router advertisement ICMPv6 dans un tag 802.1Q (VLAN 131).
const VLAN_RA_MPACKET_HEX: &str = concat!(
    "55555555555555d53333000000013cfa300491148100008386dd600000000018",
    "3afffe800000000000003efa30fffe049114ff02000000000000000000000000",
    "0001860036f940000708000000000000000001013cfa3004911421952647"
);

/// Trame 48910 : BFD sur UDP dans un tag 802.1Q (VLAN 131), avec un
/// preambule raccourci a 6 octets — le cas reel qui interdit un offset fixe.
const SHORT_PREAMBLE_BFD_MPACKET_HEX: &str = concat!(
    "555555555555d53cfa300491140014699e11408100008386dd60000000002011",
    "fffe80000000000000021469fffe9e1140fe800000000000003efa30fffe0491",
    "14c0000ec800209a9a20800318000000037710fef9000f4240000f4240000000",
    "005c3112fd"
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
fn express_mpacket_decodes_icmp_echo_request() {
    let bytes = frame(ICMP_ECHO_MPACKET_HEX, 110);
    let flow = parse(LinkType::IEEE802_3BR, bytes.as_slice()).expect("captured mPacket decodes");

    // Le LINKTYPE declare par la capture est conserve, mais la vue Ethernet
    // est bien celle de la trame encapsulee.
    assert_eq!(flow.data_link.link_type(), LinkType::IEEE802_3BR);
    let ethernet = flow.data_link.as_ethernet().expect("Ethernet view");
    assert_eq!(ethernet.source_mac.0, [0xb8, 0x27, 0xeb, 0xc9, 0x16, 0x37]);
    assert_eq!(
        ethernet.destination_mac.0,
        [0x00, 0x07, 0xb4, 0x00, 0x2a, 0x02]
    );

    let internet = flow.internet.expect("IPv4 layer");
    assert_eq!(
        internet.source,
        Some(IpAddr::V4(Ipv4Addr::new(192, 168, 42, 11)))
    );
    assert_eq!(
        internet.destination,
        Some(IpAddr::V4(Ipv4Addr::new(5, 35, 226, 136)))
    );

    let transport = flow.transport.expect("ICMP at the transport slot");
    assert_eq!(transport.protocol, TransportProtocol::Icmp);
    let Some(TransportDetails::Icmp(icmp)) = transport.details else {
        panic!("ICMP details are decoded");
    };
    assert_eq!(icmp.message_type, 8);
    assert_eq!(icmp.code, 0);
    let IcmpBody::Echo(echo) = icmp.body else {
        panic!("echo request exposes an echo body");
    };
    assert_eq!(echo.identifier, 0x0455);
    assert_eq!(echo.sequence_number, 0x0001);
    // 84 octets IP - 20 (en-tete IP) - 8 (en-tete ICMP) : le CRC de queue du
    // mPacket ne fuit pas dans les donnees echo.
    assert_eq!(echo.data.len(), 56);
}

#[test]
fn express_mpacket_decodes_icmpv6_neighbor_solicitation() {
    let bytes = frame(ICMPV6_NS_MPACKET_HEX, 98);
    let flow = parse(LinkType::IEEE802_3BR, bytes.as_slice()).expect("captured mPacket decodes");

    let transport = flow.transport.expect("ICMPv6 at the transport slot");
    assert_eq!(transport.protocol, TransportProtocol::Ipv6Icmp);
    let Some(TransportDetails::Icmpv6(icmpv6)) = transport.details else {
        panic!("ICMPv6 details are decoded");
    };
    assert_eq!(icmpv6.message_type, 135);
    let Icmpv6Body::NeighborSolicitation(solicitation) = icmpv6.body else {
        panic!("neighbor solicitation exposes its body");
    };
    assert_eq!(
        solicitation.target_address,
        "fe80::3a63:bbff:fe02:5a4d".parse::<Ipv6Addr>().unwrap()
    );
}

#[test]
fn express_mpacket_decodes_vrrp_announcement() {
    let bytes = frame(VRRP_MPACKET_HEX, 96);
    let flow = parse(LinkType::IEEE802_3BR, bytes.as_slice()).expect("captured mPacket decodes");

    let internet = flow.internet.expect("IPv4 layer");
    assert_eq!(
        internet.source,
        Some(IpAddr::V4(Ipv4Addr::new(192, 168, 42, 5)))
    );
    assert_eq!(
        internet.destination,
        Some(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 18)))
    );

    let transport = flow.transport.expect("VRRP at the transport slot");
    assert_eq!(transport.protocol, TransportProtocol::Vrrp);
}

#[test]
fn express_mpacket_preserves_the_8021q_tag_of_the_inner_frame() {
    let bytes = frame(VLAN_RA_MPACKET_HEX, 94);
    let flow = parse(LinkType::IEEE802_3BR, bytes.as_slice()).expect("captured mPacket decodes");

    let ethernet = flow.data_link.as_ethernet().expect("Ethernet view");
    let vlan = ethernet.vlan.as_ref().expect("802.1Q tag is preserved");
    assert_eq!(vlan.id, 131);

    let transport = flow.transport.expect("ICMPv6 at the transport slot");
    let Some(TransportDetails::Icmpv6(icmpv6)) = transport.details else {
        panic!("ICMPv6 details are decoded");
    };
    // Type 134 : router advertisement.
    assert_eq!(icmpv6.message_type, 134);
}

#[test]
fn express_mpacket_with_shortened_preamble_decodes() {
    let bytes = frame(SHORT_PREAMBLE_BFD_MPACKET_HEX, 101);
    let flow = parse(LinkType::IEEE802_3BR, bytes.as_slice()).expect("captured mPacket decodes");

    assert_eq!(flow.data_link.link_type(), LinkType::IEEE802_3BR);
    let ethernet = flow.data_link.as_ethernet().expect("Ethernet view");
    assert_eq!(ethernet.source_mac.0, [0x00, 0x14, 0x69, 0x9e, 0x11, 0x40]);
    assert_eq!(ethernet.vlan.as_ref().expect("802.1Q tag").id, 131);

    let transport = flow.transport.expect("UDP at the transport slot");
    assert_eq!(transport.protocol, TransportProtocol::Udp);
    assert_eq!(transport.source_port, Some(49152));
    // 3784 : BFD control.
    assert_eq!(transport.destination_port, Some(3784));
}
