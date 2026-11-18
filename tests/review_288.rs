// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Les critères d'acceptation des constats de la relecture ligne à ligne
//! (#288), vérifiés par l'API publique : l'étiquette qu'une charge reçoit
//! sur son port. Les octets sont construits d'après la spécification citée
//! par chaque issue.

use packet_parser::{TransportProtocol, classify_payload};

/// L'étiquette d'une charge envoyée de 40000 vers `port`.
fn label(transport: TransportProtocol, port: u16, payload: &[u8]) -> &'static str {
    classify_payload(transport, Some(40_000), Some(port), payload)
        .map_or("Unknown", |application| application.protocol.label())
}

fn tcp(port: u16, payload: &[u8]) -> &'static str {
    label(TransportProtocol::Tcp, port, payload)
}

fn udp(port: u16, payload: &[u8]) -> &'static str {
    label(TransportProtocol::Udp, port, payload)
}

/// #300 : RFC 5246, annexe E.1. Un ClientHello TLS 1.2 dans un record 3.0
/// est du TLS, comme le même dans un record 3.1.
#[test]
fn issue_300_a_client_hello_in_a_version_3_0_record_is_tls() {
    let client_hello = |record_minor: u8| {
        let mut record = vec![0x16, 0x03, record_minor, 0x00, 0x2d];
        record.extend_from_slice(&[0x01, 0x00, 0x00, 0x29, 0x03, 0x03]);
        record.extend_from_slice(&[0x42; 32]);
        record.extend_from_slice(&[0x00, 0x00, 0x02, 0xc0, 0x2f, 0x01, 0x00]);
        record
    };
    assert_eq!(tcp(443, &client_hello(0x00)), "TLS");
    assert_eq!(tcp(443, &client_hello(0x01)), "TLS");
}

/// #301 : `pchMessageStart` de Bitcoin Core. Un `verack` de chaque réseau
/// est reconnu d'après ses octets sur le fil ; les deux valeurs retournées
/// que la table portait avant ne sont aucun réseau.
#[test]
fn issue_301_every_bitcoin_network_is_recognized_from_its_wire_bytes() {
    let verack = |magic: [u8; 4]| {
        let mut message = magic.to_vec();
        message.extend_from_slice(b"verack\0\0\0\0\0\0");
        message.extend_from_slice(&[0, 0, 0, 0]); // longueur nulle
        message.extend_from_slice(&[0x5d, 0xf6, 0xe0, 0xe2]); // sha256d("")
        message
    };
    for magic in [
        [0xf9, 0xbe, 0xb4, 0xd9], // mainnet
        [0x0b, 0x11, 0x09, 0x07], // testnet3
        [0x1c, 0x16, 0x3f, 0x28], // testnet4
        [0xfa, 0xbf, 0xb5, 0xda], // regtest
        [0x0a, 0x03, 0xcf, 0x40], // signet
    ] {
        assert_eq!(tcp(8333, &verack(magic)), "Bitcoin", "{magic:02x?}");
    }
    for reversed in [[0xda, 0xb5, 0xbf, 0xfa], [0x07, 0x09, 0x11, 0x0b]] {
        assert_ne!(tcp(8333, &verack(reversed)), "Bitcoin", "{reversed:02x?}");
    }
}

/// #304 : RFC 2578 §7.1.10, X.690 §8.3. Un Counter64 de 2^63 ou plus prend
/// 9 octets, dont un zéro de tête ; un 9e octet non nul reste refusé.
#[test]
fn issue_304_a_counter64_of_2_pow_63_or_more_is_snmp() {
    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut encoded = vec![tag, u8::try_from(value.len()).expect("court")];
        encoded.extend_from_slice(value);
        encoded
    }
    let response = |counter: &[u8]| {
        let mut varbind = tlv(0x06, &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00]);
        varbind.extend_from_slice(&tlv(0x46, counter));
        let mut pdu = tlv(0x02, &[0x01]); // request-id
        pdu.extend_from_slice(&tlv(0x02, &[0x00])); // error-status
        pdu.extend_from_slice(&tlv(0x02, &[0x00])); // error-index
        pdu.extend_from_slice(&tlv(0x30, &tlv(0x30, &varbind)));
        let mut message = tlv(0x02, &[0x01]); // v2c
        message.extend_from_slice(&tlv(0x04, b"public"));
        message.extend_from_slice(&tlv(0xa2, &pdu));
        tlv(0x30, &message)
    };
    let below = [0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    let top = [0x00, 0x80, 0, 0, 0, 0, 0, 0, 0];
    let max = [0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    let wide = [0x01, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(udp(161, &response(&below)), "SNMP");
    assert_eq!(udp(161, &response(&top)), "SNMP");
    assert_eq!(udp(161, &response(&max)), "SNMP");
    assert_ne!(udp(161, &response(&wide)), "SNMP");
}
