// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests QUIC sur trames reellement capturees (issue #59).
//!
//! Toutes les fixtures proviennent de `pcaps_exemple/sll.pcap`, capture
//! LINKTYPE_LINUX_SLL versionnee dans le depot, et sont rattachees a leur
//! numero de trame. Aucun octet synthetique : la regle du projet veut que les
//! goldens ne verrouillent que ce qu'un vrai reseau a produit.
//!
//! La session capturee est un echange QUIC v1 sur IPv6, entre le client
//! `[2001:8613:fc79:b00b:3bdf:be98:149a:d1d2]:45403` et le serveur
//! `[2a00:1450:4006:818::200a]:443`.

use packet_parser::{LinkType, parse};

/// Trame 1716 : Initial serveur -> client (443 -> 45403), long header de type
/// 0, PKN 1, une frame ACK. Detecte sans garde de port : le long header porte
/// version et longueurs explicites, assez discriminants pour le probing.
const QUIC_INITIAL_LONG_HEADER_HEX: &str = concat!(
    "00000001000644152420a5646c7086dd600000000030113c2a0014504006081800",
    "0000000000200a200108613fc79b00b3bdfbe98149ad1d01bbb15b00308aa5c300",
    "0000010008eccce3b8d2b5d6130040162a7e7bc89cdad64e82b496e7478822a7b8",
    "1c09a27f96"
);

/// Trame 1730 : Handshake client -> serveur (45403 -> 443), long header de
/// type 2, DCID `eccce3b8d2b5d613`.
const QUIC_HANDSHAKE_LONG_HEADER_HEX: &str = concat!(
    "000400010006e0d55e289bd4e6aa86dd60092d4e00661140200108613fc79b00b3",
    "bdfbe98149ad1d2a00145040060818000000000000200ab15b01bb00668828eb00",
    "00000108eccce3b8d2b5d61300404dace5186c449048b79d3f515202ddc43cf5e1",
    "317aa13f1ef8966496f2d94997f60c5c02ba77a7efe8ce0c2aa01579c3d5ec67c9",
    "8602b027e4c6d45753918df15e2b74659013f8b2bb9e0afac417"
);

/// Trame 1731 : Short header (1-RTT, « Protected Payload KP0 ») client ->
/// serveur (45403 -> 443). RFC 9000 §17.3 rend cet en-tete volontairement
/// opaque : pas de version, pas de longueur de DCID. La detection passe donc
/// par la garde de port UDP 443, pas par le probing aveugle.
const QUIC_SHORT_HEADER_HEX: &str = concat!(
    "000400010006e0d55e289bd4148e86dd60092d4e00271140200108613fc79b00b3",
    "bdfbe98149ad1d2a00145040060818000000000000200ab15b01bb002787e940ec",
    "cce3b8d2b5d613e028d05e07a070c4dcb42970ea50f459fd07a251b0ef"
);

fn frame(hex_fixture: &str, expected_len: usize) -> Vec<u8> {
    let bytes = hex::decode(hex_fixture).expect("invalid test hex fixture");
    assert_eq!(
        bytes.len(),
        expected_len,
        "the fixture must match the frame length reported by tshark"
    );
    bytes
}

fn assert_quic(bytes: &[u8]) {
    let flow = parse(LinkType::LINUX_SLL, bytes).expect("captured frame decodes");
    let application = flow.application.expect("an application layer is detected");

    assert_eq!(application.application_protocol, "QUIC");
}

#[test]
fn quic_initial_long_header_is_detected() {
    assert_quic(&frame(QUIC_INITIAL_LONG_HEADER_HEX, 104));
}

#[test]
fn quic_handshake_long_header_is_detected() {
    assert_quic(&frame(QUIC_HANDSHAKE_LONG_HEADER_HEX, 158));
}

#[test]
fn quic_short_header_on_port_443_is_detected() {
    assert_quic(&frame(QUIC_SHORT_HEADER_HEX, 95));
}
