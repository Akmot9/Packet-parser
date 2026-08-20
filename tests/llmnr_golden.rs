// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests LLMNR (RFC 4795) sur des payloads UDP reels.
//!
//! Captures : `pcaps_exemple/The-Ultimate-PCAP.pcapng` (numeros de trame
//! notes sur chaque fixture). Le corpus contient 18 trames LLMNR, toutes des
//! requetes ANY pour le nom `Johannes-Dell`, emises en double sur IPv4
//! (224.0.0.252) et IPv6 (ff02::1:3), port UDP 5355.
//!
//! Les tests appellent directement `DnsPacket::try_from_llmnr` sur le
//! payload UDP : le cablage dans la table de dispatch est fait separement.
//! Une requete DNS classique du meme corpus est aussi verifiee : les deux
//! formats se recouvrent octet pour octet (le bit RD de DNS occupe la
//! position du bit T de LLMNR), seul le port UDP (53 vs 5355) tranche —
//! c'est la table de dispatch qui applique cette garde.

use packet_parser::parse::application::protocols::dns::DnsPacket;

/// Trame 38162 : requete LLMNR ANY `Johannes-Dell`,
/// fe80::30fa:6749:aa4f:7852 -> ff02::1:3, UDP 62625 -> 5355.
const LLMNR_QUERY_IPV6_HEX: &str = "374c000000010000000000000d4a6f68616e6e65732d44656c6c0000ff0001";

/// Trame 38163 : la meme requete (transaction id 0x374c) emise sur IPv4,
/// 169.254.140.132 -> 224.0.0.252, UDP 62625 -> 5355.
const LLMNR_QUERY_IPV4_HEX: &str = "374c000000010000000000000d4a6f68616e6e65732d44656c6c0000ff0001";

/// Trame 38198 : requete LLMNR ANY `Johannes-Dell` depuis un reseau route,
/// 10.0.1.97 -> 224.0.0.252, UDP 49664 -> 5355 (transaction id 0xdf7a).
const LLMNR_QUERY_ROUTED_HEX: &str =
    "df7a000000010000000000000d4a6f68616e6e65732d44656c6c0000ff0001";

/// Trame 1625 : requete DNS classique `heise.de` A,
/// 192.168.2.102 -> 192.168.2.1, UDP 56606 -> 53 (flags 0x0100, RD=1).
const DNS_QUERY_HEX: &str = "b89f010000010000000000000568656973650264650000010001";

fn payload(hex_fixture: &str) -> Vec<u8> {
    hex::decode(hex_fixture).expect("invalid test hex fixture")
}

fn assert_llmnr_any_query(bytes: &[u8], transaction_id: u16) {
    let packet = DnsPacket::try_from_llmnr(bytes).expect("captured LLMNR query decodes");

    assert_eq!(packet.header.transaction_id, transaction_id);
    // Requete standard : QR=0, opcode 0, C/TC/T a zero, rcode 0.
    assert_eq!(packet.header.flags, 0x0000);
    assert_eq!(packet.header.counts, [1, 0, 0, 0]);

    assert_eq!(packet.queries.queries.len(), 1);
    assert_eq!(packet.queries.queries[0].name, "Johannes-Dell");
    assert_eq!(packet.queries.queries[0].qtype.0, 255); // ANY
    assert_eq!(packet.queries.queries[0].qclass.0, 1); // IN

    assert!(packet.answers.is_none());
    assert!(packet.authorities.is_none());
    assert!(packet.additionals.is_none());
}

#[test]
fn llmnr_query_over_ipv6_decodes() {
    assert_llmnr_any_query(&payload(LLMNR_QUERY_IPV6_HEX), 0x374c);
}

#[test]
fn llmnr_query_over_ipv4_decodes() {
    assert_llmnr_any_query(&payload(LLMNR_QUERY_IPV4_HEX), 0x374c);
}

#[test]
fn llmnr_query_from_routed_network_decodes() {
    assert_llmnr_any_query(&payload(LLMNR_QUERY_ROUTED_HEX), 0xdf7a);
}

/// Les formats DNS et LLMNR se recouvrent : une requete DNS classique avec
/// RD=1 (trame 1625) est aussi un en-tete LLMNR valide, le bit RD occupant
/// la position du bit T (tentative). Symetriquement, une requete LLMNR a
/// flags nuls est un en-tete DNS valide. Aucun validateur d'octets ne peut
/// les distinguer — seul le port UDP (53 vs 5355) tranche, et cette garde
/// vit dans la table de dispatch, pas ici.
#[test]
fn classic_dns_query_overlaps_with_llmnr_format() {
    let dns_bytes = payload(DNS_QUERY_HEX);

    // La requete DNS est structurellement acceptee comme LLMNR...
    let as_llmnr = DnsPacket::try_from_llmnr(&dns_bytes).expect("DNS query overlaps LLMNR format");
    assert_eq!(as_llmnr.queries.queries[0].name, "heise.de");
    // ... et le parseur ne reinterprete pas les octets differemment du
    // parseur DNS strict : memes flags bruts, memes compteurs.
    let as_dns = DnsPacket::try_from(dns_bytes.as_slice()).expect("classic DNS query decodes");
    assert_eq!(as_llmnr.header.flags, as_dns.header.flags);
    assert_eq!(as_llmnr.header.counts, as_dns.header.counts);

    // Recouvrement inverse : la requete LLMNR reelle est aussi un DNS valide.
    let llmnr_bytes = payload(LLMNR_QUERY_IPV6_HEX);
    assert!(DnsPacket::try_from(llmnr_bytes.as_slice()).is_ok());
}

/// Une reponse DNS recursive (flags 0x8180 : RD+RA) est refusee par le
/// validateur LLMNR : RA occupe un bit Z de LLMNR, qui doit etre nul.
/// Fixture synthetique minimale (en-tete + question racine) : le corpus ne
/// contient pas de reponse LLMNR.
#[test]
fn recursive_dns_response_flags_are_rejected_by_llmnr() {
    let mut bytes = vec![
        0x00, 0x2b, // transaction id
        0x81, 0x80, // flags : reponse recursive RD+RA
        0x00, 0x01, // 1 question
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // aucune section
    ];
    bytes.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]); // racine, A, IN

    assert!(DnsPacket::try_from_llmnr(&bytes).is_err());
    assert!(DnsPacket::try_from(bytes.as_slice()).is_ok());
}
