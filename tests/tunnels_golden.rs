// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests des tunnels GRE et IP-in-IP (issue #15) sur trames reelles
//! de `pcaps_exemple/The-Ultimate-PCAP.pcapng` (numeros de trame notes sur
//! chaque fixture). VXLAN, GTP-U et Geneve attendent des captures reelles —
//! regle du depot — et restent portes par l'issue.

use packet_parser::parse::transport::protocols::TransportProtocol;
use packet_parser::{LinkType, parse};

/// Trame 20749 : GRE v0 sans option (proto 0x0800) portant un ping ICMP
/// 172.23.11.56 -> 192.168.42.11.
const GRE_IPV4_ICMP_HEX: &str = concat!(
    "0025456017c1001e7a793f1008004500005411fb0000ff2ff6c3ac101702c0a8",
    "2f01000008004500003c6c5b00007f012d63ac170b38c0a82a0b08004cf80001",
    "00636162636465666768696a6b6c6d6e6f70717273747576776162636465666768",
    "69"
);

/// Trame 20949 : GRE v0 (proto 0x86dd) portant un MLDv2 ICMPv6.
const GRE_IPV6_MLD_HEX: &str = concat!(
    "001e7a793f100025456017c1080045e0006430d00000fe2fd7fec0a82f01ac10",
    "1702000086dd6e0000000024000100000000000000000000000000000000ff02",
    "00000000000000000000000000163a000502000001008f006e8a000000010400",
    "0000ff020000000000000000000000000002"
);

/// Trame 20741 : GRE dans GRE — le tunnel externe (proto 0x0800) porte un
/// IPv4 dont le protocole est de nouveau 47, keepalive GRE (proto 0x0000).
const GRE_IN_GRE_KEEPALIVE_HEX: &str = concat!(
    "0025456017c1001e7a793f10080045c0003011f80000ff2ff62aac101702c0a8",
    "2f010000080045c0001811f70000ff2ff643c0a82f01ac10170200000000"
);

/// Trame 49553 : ERSPAN Type III (gre.proto 0x22eb, flags sequence) — hors
/// perimetre du peeling, refus propre attendu.
const GRE_ERSPAN_HEX: &str = concat!(
    "1c697a0fcc5e3cecef8b490086dd600ea6cf007a2f402a006020ad0b83000000",
    "0000d06104432a006020ad0b8300000000000c010022100022eb000000002000",
    "000027d87468000000051400000169a1a8840200000103013cfa3003121086dd",
    "6000000000283a7f2a006020ad0b8321f88779fa455ba8582a01023902c29900",
    "00000000000000018000cbb8000126be6162636465666768696a6b6c6d6e6f70",
    "71727374757677616263646566676869"
);

/// Trame 11830 : IPv6-in-IPv4 (protocole IP 41, 6in4) portant une reponse
/// DNS sur UDP.
const IPV6_IN_IPV4_DNS_HEX: &str = concat!(
    "0014699e11400010dbff10000800450000a9a86f4000fb290a36d842501ec118",
    "e30c60000000006d113b2620017100f800f0000000000000000720010470765b",
    "000000000000d031005328790035006d6fd63610001000010000000000010132",
    "0132013001300135013101620130013001300130013001300130013001300130",
    "0130013001300162013501360137013001370134013001310130013001320369",
    "7036046172706100000c00010000291000000080000000"
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
fn gre_ipv4_tunnel_exposes_the_inner_icmp_flow() {
    let bytes = frame(GRE_IPV4_ICMP_HEX, 98);
    let flow = parse(LinkType::ETHERNET, bytes.as_slice()).expect("captured frame decodes");

    assert_eq!(
        flow.application
            .as_ref()
            .map(|application| application.application_protocol),
        Some("GRE")
    );
    let flows = flow.flatten();
    assert_eq!(flows.len(), 2, "tunnel externe + conversation interne");

    let inner = flows[1];
    let internet = inner.internet.as_ref().expect("IPv4 interne");
    assert_eq!(internet.protocol_name, "IPv4");
    let transport = inner.transport.as_ref().expect("ICMP interne");
    assert_eq!(transport.protocol, TransportProtocol::Icmp);
}

#[test]
fn gre_ipv6_tunnel_exposes_the_inner_icmpv6_flow() {
    let bytes = frame(GRE_IPV6_MLD_HEX, 114);
    let flow = parse(LinkType::ETHERNET, bytes.as_slice()).expect("captured frame decodes");

    assert_eq!(
        flow.application
            .as_ref()
            .map(|application| application.application_protocol),
        Some("GRE")
    );
    let inner = flow.inner.as_ref().expect("flux interne");
    let transport = inner.transport.as_ref().expect("ICMPv6 interne");
    assert_eq!(transport.protocol, TransportProtocol::Ipv6Icmp);
}

#[test]
fn gre_in_gre_recurses_and_refuses_the_keepalive_leaf() {
    let bytes = frame(GRE_IN_GRE_KEEPALIVE_HEX, 62);
    let flow = parse(LinkType::ETHERNET, bytes.as_slice()).expect("captured frame decodes");

    let flows = flow.flatten();
    // Externe (GRE) + interne IPv4 dont le protocole est encore GRE ; le
    // keepalive (gre.proto 0x0000) n'est pas pele, la recursion s'arrete
    // proprement.
    assert_eq!(flows.len(), 2);
    assert_eq!(
        flows[0]
            .application
            .as_ref()
            .map(|application| application.application_protocol),
        Some("GRE")
    );
    let inner = flows[1];
    assert_eq!(
        inner.transport.as_ref().map(|transport| transport.protocol),
        Some(TransportProtocol::Gre)
    );
    assert!(inner.inner.is_none(), "le keepalive n'est pas pele");
    assert!(inner.application.is_none());
}

#[test]
fn erspan_is_refused_not_guessed() {
    let bytes = frame(GRE_ERSPAN_HEX, 176);
    let flow = parse(LinkType::ETHERNET, bytes.as_slice()).expect("captured frame decodes");

    // gre.proto 0x22eb (ERSPAN III) : pas de peeling, pas d'etiquette GRE,
    // le transport identifie le protocole 47 et rien d'autre n'est invente.
    assert!(flow.inner.is_none());
    assert!(flow.application.is_none());
    assert_eq!(
        flow.transport.as_ref().map(|transport| transport.protocol),
        Some(TransportProtocol::Gre)
    );
}

#[test]
fn ipv6_in_ipv4_exposes_the_inner_dns_flow() {
    let bytes = frame(IPV6_IN_IPV4_DNS_HEX, 183);
    let flow = parse(LinkType::ETHERNET, bytes.as_slice()).expect("captured frame decodes");

    assert_eq!(
        flow.application
            .as_ref()
            .map(|application| application.application_protocol),
        Some("IP-in-IP")
    );
    let inner = flow.inner.as_ref().expect("flux interne IPv6");
    let internet = inner.internet.as_ref().expect("IPv6 interne");
    assert_eq!(internet.protocol_name, "IPv6");
    assert_eq!(
        inner
            .application
            .as_ref()
            .map(|application| application.application_protocol),
        Some("DNS"),
        "la reponse DNS du flux interne est classifiee"
    );
}
