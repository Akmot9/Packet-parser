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

/// #305 : TCP coupe où il veut. Un segment FTP, SMTP ou NNTP coupé entre
/// le CR et le LF d'une ligne vaut le même segment coupé avant son CR ; un
/// CR suivi d'autre chose qu'un LF reste refusé.
#[test]
fn issue_305_a_segment_cut_between_cr_and_lf_keeps_its_label() {
    assert_eq!(tcp(21, b"150 Opening\r\n226 Done\r"), "FTP");
    let mail = b"MAIL FROM:<a@b.example>\r\nRCPT TO:<c@d.example>\r";
    assert_eq!(tcp(25, mail), "SMTP");
    assert_eq!(tcp(25, &mail[..mail.len() - 1]), "SMTP");
    // RFC 3977 §6.2.1.3, l'article de l'exemple, coupé dans sa 3e ligne.
    let article = b"220 3000234 <45223423@example.com>\r\n\
        Path: pathost!demo!whitehouse!not-for-mail\r\n\
        From: \"Demo User\" <nobody@example.net>\r";
    assert_eq!(tcp(119, article), "NNTP");
    assert_ne!(tcp(21, b"150 Opening\r\n226 Done\r\r"), "FTP");
}

/// #306 : les verbes standard absents des listes, sur leur port.
#[test]
fn issue_306_standard_verbs_are_labelled_on_their_port() {
    for command in [&b"XPWD\r\n"[..], b"LPSV\r\n", b"XMKD dir\r\n", b"CCC\r\n"] {
        assert_eq!(
            tcp(21, command),
            "FTP",
            "{:?}",
            String::from_utf8_lossy(command)
        );
    }
    for command in [
        &b"STARTTLS\r\n"[..],
        b"CHECK <a@b>\r\n",
        b"TAKETHIS <a@b>\r\n",
        b"CAPABILITIES AUTOUPDATE\r\n",
    ] {
        assert_eq!(
            tcp(119, command),
            "NNTP",
            "{:?}",
            String::from_utf8_lossy(command)
        );
    }
}

/// #307 : RFC 4253 §4.2, « The server MAY send other lines of data before
/// sending the version string ». Un texte sans ligne `SSH-` reste refusé.
#[test]
fn issue_307_lines_before_the_ssh_banner_keep_the_label() {
    let welcome = b"Welcome\r\nSSH-2.0-OpenSSH_9.6\r\n";
    assert_eq!(tcp(22, welcome), "SSH");
    assert_eq!(tcp(40_001, welcome), "SSH");
    assert_eq!(tcp(22, b"SSH-2.0-OpenSSH_9.6\r\n"), "SSH");
    assert_ne!(tcp(22, b"Welcome\r\nno banner here\r\n"), "SSH");
}

/// #307 : une réponse HTTP dont le corps cite une bannière SSH reste HTTP.
/// La bannière après des lignes de préambule n'est essayée qu'après HTTP.
#[test]
fn issue_307_an_http_body_quoting_a_banner_stays_http() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\
        Content-Length: 21\r\n\r\nSSH-2.0-OpenSSH_9.6\r\n";
    assert_eq!(tcp(8080, response), "HTTP");
}

/// #295 : la sonde UMAS exige des MBAP qui pavent le segment, comme
/// Modbus/TCP. Un MBAP UMAS suivi de texte, ou plus court que le segment,
/// n'est plus de l'UMAS ; un UMAS réel le reste.
#[test]
fn issue_295_umas_mbaps_must_tile_the_segment() {
    let read_id = [0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x5a, 0x00, 0x02];
    assert_eq!(tcp(502, &read_id), "UMAS");
    assert_eq!(tcp(40_001, &read_id), "UMAS");

    let mut with_text = read_id.to_vec();
    with_text.extend_from_slice(b"some text after the MBAP.");
    assert_ne!(tcp(40_001, &with_text), "UMAS");
    assert_ne!(tcp(502, &with_text), "UMAS");

    let mut longer = vec![0xbe, 0xef, 0x00, 0x00, 0x00, 0x10, 0x01, 0x5a, 0x59, 0x58];
    longer.extend_from_slice(&[0x41; 28]); // 32 octets apres la longueur, 16 declares
    assert_ne!(tcp(40_001, &longer), "UMAS");

    // Deux MBAP UMAS qui pavent le segment restent de l'UMAS.
    let mut two = read_id.to_vec();
    two.extend_from_slice(&read_id);
    assert_eq!(tcp(40_001, &two), "UMAS");
}

/// #296 : à l'aveugle, des chunks OPC UA qui pavent le segment, ou un
/// partiel de taille plausible ; sur le port, un chunk complet suivi de 1 à
/// 7 octets du suivant reste de l'OPC UA.
#[test]
fn issue_296_opcua_is_strict_off_port_and_tolerates_a_cut_header_on_port() {
    assert_ne!(tcp(40_001, b"CLOCK 12:00:00\r\n"), "OPC UA");
    assert_ne!(tcp(40_001, b"MSGCOUNT 3\r\n"), "OPC UA");

    let ack = [
        0x41, 0x43, 0x4b, 0x46, 0x1c, 0x00, 0x00, 0x00, // ACKF, 28 octets
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let next = [0x4d, 0x53, 0x47, 0x46, 0x18, 0x00, 0x00, 0x00]; // MSGF, 24 octets
    assert_eq!(tcp(4840, &ack), "OPC UA");
    for cut in 1..=8 {
        let mut segment = ack.to_vec();
        segment.extend_from_slice(&next[..cut]);
        assert_eq!(
            tcp(4840, &segment),
            "OPC UA",
            "{cut} octets du chunk suivant"
        );
    }
    // Un reste dont le type de message n'existe pas reste refusé.
    let mut wrong = ack.to_vec();
    wrong.extend_from_slice(b"XYZF");
    assert_ne!(tcp(4840, &wrong), "OPC UA");

    // Hors port, l'ACK complet reste de l'OPC UA, et un MSG partiel de taille
    // plausible aussi ; l'ACK suivi d'un reste ne l'est pas.
    assert_eq!(tcp(40_001, &ack), "OPC UA");
    let mut partial = next.to_vec();
    partial.extend_from_slice(&[0x00; 8]);
    assert_eq!(tcp(40_001, &partial), "OPC UA");
    let mut cut = ack.to_vec();
    cut.extend_from_slice(&next[..4]);
    assert_ne!(tcp(40_001, &cut), "OPC UA");
}

/// #298 : le CR réel de la trame 107 de
/// `pcaps_exemple/protocols/goose/iti_Sample_File_MMS_and_GOOSE.pcap`,
/// classe 0 avec une TPDU de 8192 octets (RFC 905 l'exclut de la classe 0,
/// tshark le décode). Le même avec 2048 octets était déjà du COTP.
#[test]
fn issue_298_a_class_0_cr_with_a_large_tpdu_is_cotp() {
    let request = |tpdu_size: u8| {
        let mut segment = vec![
            0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0x00, 0x00, 0x07, 0x78, 0x00, 0xc1, 0x02, 0x00,
            0x01, 0xc2, 0x02, 0x00, 0x01, 0xc0, 0x01,
        ];
        segment.push(tpdu_size);
        segment
    };
    for size in [0x0b, 0x0c, 0x0d] {
        assert_eq!(tcp(102, &request(size)), "COTP", "TPDU size {size:#04x}");
    }
}
