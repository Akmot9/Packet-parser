// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Les critères d'acceptation des constats de la relecture ligne à ligne
//! (#288), vérifiés par l'API publique : l'étiquette qu'une charge reçoit
//! sur son port. Les octets sont construits d'après la spécification citée
//! par chaque issue.

use std::path::Path;

use packet_parser::{TransportProtocol, classify_payload, parse};

mod common;
use common::{FileRead, read_capture};

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

/// Un DHCP Discover d'Ethernet (RFC 2131), `length` octets, cookie et
/// options puis bourrage nul, sur le modèle du Discover de `dhcp.pcap`.
fn dhcp_discover(length: usize, secs: u16) -> Vec<u8> {
    let mut message = vec![0x01, 0x01, 0x06, 0x00, 0x00, 0x00, 0x3d, 0x1d];
    message.extend_from_slice(&secs.to_be_bytes());
    message.resize(28, 0); // flags, ciaddr, yiaddr, siaddr, giaddr
    message.extend_from_slice(&[0x00, 0x0b, 0x82, 0x01, 0xfc, 0x42]);
    message.resize(236, 0); // fin de chaddr, sname, file
    message.extend_from_slice(&[0x63, 0x82, 0x53, 0x63, 0x35, 0x01, 0x01, 0xff]);
    message.resize(length, 0);
    message
}

/// #294 : sur UDP 67/68 et 427, DHCP et SRVLOC passent devant les sondes
/// aveugles de DIS et de RADIUS ; hors de ces ports, rien ne change.
#[test]
fn issue_294_dhcp_and_srvloc_keep_their_ports() {
    // `secs` égal à la longueur du datagramme : aussi un en-tête DIS valide.
    let discover = dhcp_discover(272, 272);
    assert_eq!(udp(67, &discover), "DHCP");
    assert_eq!(udp(68, &discover), "DHCP");
    assert_eq!(udp(40_001, &discover), "DIS");
    assert_eq!(udp(67, &dhcp_discover(272, 271)), "DHCP");

    // SrvTypeRqst SLPv1 de 20 octets : aussi un Access-Request RADIUS.
    let request = [
        0x01, 0x09, 0x00, 0x14, 0x00, 0x00, 0x65, 0x6e, 0x00, 0x6a, 0x12, 0x34, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x49, 0x54,
    ];
    assert_eq!(udp(427, &request), "SRVLOC");
    assert_eq!(tcp(427, &request), "SRVLOC");
    assert_eq!(udp(40_001, &request), "RADIUS");
}

/// #303 : RFC 4390 §2.1 (IP sur InfiniBand, htype 32) et RFC 2855 (IEEE
/// 1394, htype 24) imposent `hlen` = 0 et un `chaddr` nul ; un BOOTP
/// (RFC 951) dont la zone `vend` est nulle vaut celui qui n'en a pas.
#[test]
fn issue_303_zero_hlen_links_and_bootp_without_cookie_are_dhcp() {
    for htype in [32, 24] {
        let mut discover = dhcp_discover(300, 0);
        discover[1] = htype;
        discover[2] = 0;
        discover[28..34].fill(0);
        assert_eq!(udp(67, &discover), "DHCP", "htype {htype}");
        // Un chaddr non nul contredit le hlen nul.
        discover[28] = 0x01;
        assert_ne!(udp(67, &discover), "DHCP", "htype {htype}, chaddr non nul");
    }
    let mut ethernet = dhcp_discover(300, 0);
    ethernet[2] = 0;
    assert_ne!(udp(67, &ethernet), "DHCP", "Ethernet sans hlen");

    let mut bootp = dhcp_discover(300, 0);
    bootp[236..].fill(0);
    assert_eq!(udp(67, &bootp), "DHCP");
    assert_eq!(udp(67, &bootp[..236]), "DHCP");
    bootp[240] = 0x43; // une zone vend non nulle sans cookie reste refusée
    assert_ne!(udp(67, &bootp), "DHCP");
}

/// #302 : RFC 2608 §7, une réponse d'erreur peut s'arrêter après son code ;
/// RFC 2165 §17.1, les chaînes SLPv1 se lisent dans l'encodage annoncé.
#[test]
fn issue_302_srvloc_error_replies_and_v1_encodings() {
    use packet_parser::parse::application::protocols::srvloc::{SrvlocHeader, SrvlocPacket};

    let truncated = [
        0x02, 0x02, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x42, 0x00, 0x02, 0x65,
        0x6e, 0x00, 0x04,
    ];
    assert_eq!(udp(427, &truncated), "SRVLOC");

    let da_advert = |encoding: u16, url: &[u8], scope_list: &[u8]| {
        let mut message = vec![0x01, 0x08, 0x00, 0x00, 0x00, 0x00, b'f', b'r'];
        message.extend_from_slice(&encoding.to_be_bytes());
        message.extend_from_slice(&[0x00, 0x04, 0x00, 0x00]); // xid, error code
        for string in [url, scope_list] {
            message.extend_from_slice(&u16::try_from(string.len()).expect("court").to_be_bytes());
            message.extend_from_slice(string);
        }
        let length = u16::try_from(message.len()).expect("court");
        message[2..4].copy_from_slice(&length.to_be_bytes());
        message
    };
    let texts = |message: &[u8]| match SrvlocPacket::try_from(message).map(|packet| packet.header) {
        Ok(SrvlocHeader::V1(header)) => (
            header.url_text().into_owned(),
            header.scope_list_text().into_owned(),
        ),
        other => panic!("DAAdvert v1 attendu : {other:?}"),
    };

    let latin1 = da_advert(4, b"service:directory-agent://h", b"caf\xe9");
    assert_eq!(udp(427, &latin1), "SRVLOC");
    assert_eq!(texts(&latin1).1, "caf\u{e9}");

    let ucs2 = |text: &str| -> Vec<u8> { text.encode_utf16().flat_map(u16::to_be_bytes).collect() };
    let wide = da_advert(
        1000,
        &ucs2("service:directory-agent://h"),
        &ucs2("caf\u{e9}"),
    );
    assert_eq!(udp(427, &wide), "SRVLOC");
    assert_eq!(
        texts(&wide),
        (
            "service:directory-agent://h".to_string(),
            "caf\u{e9}".to_string()
        )
    );
}

/// Un nom DNS sur le fil, labels donnés en octets.
fn dns_name(labels: &[&[u8]]) -> Vec<u8> {
    let mut name = Vec::new();
    for label in labels {
        name.push(u8::try_from(label.len()).expect("label court"));
        name.extend_from_slice(label);
    }
    name.push(0);
    name
}

/// #297 : RFC 2181 §11, un label peut être binaire ; RFC 5936 §2.2.1, une
/// réponse AXFR qui suit la première peut laisser sa question vide. La
/// sonde aveugle UDP garde ses exigences : UTF-8 et question (#118).
#[test]
fn issue_297_binary_labels_and_axfr_responses_without_question_are_dns() {
    use packet_parser::parse::application::protocols::dns::DnsPacket;

    // Une requête A dont un label porte « ä » en Latin-1, comme la trame
    // 38951 de The-Ultimate-PCAP.pcapng.
    let query = |label: &[u8]| {
        let mut message = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        message.extend_from_slice(&dns_name(&[label, b"example"]));
        message.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        message
    };
    let latin1 = query(b"j\xe4germeister");
    assert_eq!(udp(53, &latin1), "DNS");
    let packet = DnsPacket::try_from(latin1.as_slice()).expect("label binaire");
    assert_eq!(packet.queries.queries[0].name, "j\\228germeister.example");
    assert_ne!(udp(40_001, &latin1), "DNS");
    assert_eq!(udp(40_001, &query(b"jagermeister")), "DNS");

    // Une réponse AXFR sans question : un enregistrement A de ns1.example.
    let axfr = |question: bool| {
        let mut message = vec![0x7b, 0xae, 0x84, 0x00, 0x00, u8::from(question), 0x00, 0x01];
        message.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        if question {
            message.extend_from_slice(&dns_name(&[b"example"]));
            message.extend_from_slice(&[0x00, 0xfc, 0x00, 0x01]); // AXFR, IN
        }
        message.extend_from_slice(&dns_name(&[b"ns1", b"example"]));
        message.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10]);
        message.extend_from_slice(&[0x00, 0x04, 0xc0, 0x00, 0x02, 0x01]);
        message
    };
    let framed = |message: Vec<u8>| {
        let mut segment = u16::try_from(message.len())
            .expect("court")
            .to_be_bytes()
            .to_vec();
        segment.extend_from_slice(&message);
        segment
    };
    assert_eq!(tcp(53, &framed(axfr(false))), "DNS");
    assert_eq!(tcp(53, &framed(axfr(true))), "DNS");
    assert_ne!(udp(40_001, &axfr(false)), "DNS");

    // Une requête sans question mais avec un enregistrement reste refusée.
    let mut query_without_question = axfr(false);
    query_without_question[2] = 0x00;
    assert!(DnsPacket::try_from_tcp(&framed(query_without_question)).is_err());
}

/// Un en-tête long : octet 0, version, DCID, SCID vide, puis `rest`.
fn quic_long_header(b0: u8, version: u32, dcid_len: u8, rest: &[u8]) -> Vec<u8> {
    let mut packet = vec![b0];
    packet.extend_from_slice(&version.to_be_bytes());
    packet.push(dcid_len);
    packet.extend(std::iter::repeat_n(0xAB, usize::from(dcid_len)));
    packet.push(0);
    packet.extend_from_slice(rest);
    packet
}

/// #299 : RFC 8999. Sur UDP 443, un Version Negotiation (version 0) et une
/// version réservée 0x?a?a?a?a sont du QUIC ; RFC 9000 §17.2, un en-tête
/// long v1 au CID de plus de 20 octets ne l'est pas. Hors port, la sonde
/// aveugle ne prend que la v1.
#[test]
fn issue_299_version_negotiation_reserved_versions_and_v1_connection_ids() {
    // Un Version Negotiation qui propose la v1 et la v2 (RFC 9369).
    let negotiation = quic_long_header(0xC6, 0, 8, &[0, 0, 0, 1, 0x6B, 0x33, 0x43, 0xCF]);
    assert_eq!(udp(443, &negotiation), "QUIC");
    assert_ne!(udp(40_001, &negotiation), "QUIC");

    // Un Initial en version réservée : son contenu est propre à la version.
    let mut protected = vec![0x00, 0x44, 0xBE]; // token vide, Length 1214
    protected.extend([0x5A; 1214]);
    let reserved = quic_long_header(0xC6, 0x0A0A_0A0A, 8, &protected);
    assert_eq!(udp(443, &reserved), "QUIC");
    assert_ne!(udp(40_001, &reserved), "QUIC");

    // L'exemple de l'issue : `c0 00000001 15`, 21 octets de DCID, SCID vide,
    // token vide, Length 21, puis 21 octets. Avec 20 octets de DCID, c'est
    // un Initial v1.
    let initial = |dcid_len| {
        let mut rest = vec![0x00, 0x15];
        rest.extend([0x5A; 21]);
        quic_long_header(0xC0, 1, dcid_len, &rest)
    };
    assert_eq!(udp(443, &initial(20)), "QUIC");
    assert_eq!(udp(40_001, &initial(20)), "QUIC");
    assert_ne!(udp(443, &initial(21)), "QUIC");
    assert_ne!(udp(40_001, &initial(21)), "QUIC");
}

/// #299, sur la capture de l'issue : les 74 datagrammes UDP 443 de
/// `ndpi_quic_interop_V.pcapng`, 13 Version Negotiation et 61 paquets en
/// version 0x0a0a0a0a, sont du QUIC, comme les décode tshark. Les mêmes
/// sur 4433 et 4434 restent hors de la sonde aveugle.
#[test]
fn issue_299_the_udp_443_datagrams_of_the_ndpi_capture_are_quic() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("pcaps_exemple/protocols/ntp/ndpi_quic_interop_V.pcapng");
    let FileRead::Frames {
        frames,
        read_error_after: None,
    } = read_capture(&path)
    else {
        panic!("capture illisible");
    };
    let (mut on_443, mut elsewhere) = (0, 0);
    for (index, (link_type, data)) in frames.iter().enumerate() {
        let number = index + 1;
        let flow = parse(*link_type, data).unwrap_or_else(|error| panic!("{number} : {error}"));
        let Some(transport) = flow
            .transport
            .as_ref()
            .filter(|transport| transport.protocol == TransportProtocol::Udp)
        else {
            continue;
        };
        let quic = flow
            .application
            .as_ref()
            .is_some_and(|application| application.protocol.label() == "QUIC");
        if [transport.source_port, transport.destination_port].contains(&Some(443)) {
            assert!(quic, "trame {number}");
            on_443 += 1;
        } else {
            assert!(!quic, "trame {number}");
            elsewhere += 1;
        }
    }
    assert_eq!((on_443, elsewhere), (74, 141));
}

/// #288, « Laissés à décider » : RFC 4795 §2.1.1. Le récepteur ignore les
/// bits Z (« MUST ignore them ») et le RCODE d'une requête (« the responder
/// ignores the RCODE and assumes it to be zero ») : une requête qui les
/// porte reste du LLMNR sur UDP 5355.
#[test]
fn issue_288_llmnr_receivers_ignore_z_bits_and_the_rcode_of_a_query() {
    let query = |flags: u16| {
        let mut message = vec![0x37, 0x4c];
        message.extend_from_slice(&flags.to_be_bytes());
        message.extend_from_slice(&[0x00, 0x01, 0, 0, 0, 0, 0, 0]); // 1 question
        message.extend_from_slice(&dns_name(&[b"demo"]));
        message.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN
        message
    };
    assert_eq!(udp(5355, &query(0x0000)), "LLMNR");
    for flags in [0x0080, 0x0010, 0x00f0, 0x0003, 0x00f5] {
        assert_eq!(udp(5355, &query(flags)), "LLMNR", "{flags:#06x}");
    }
    // Un opcode inconnu reste écarté : « MUST be silently discarded ».
    assert_ne!(udp(5355, &query(0x0800)), "LLMNR");
}

/// #288, « Laissés à décider » : TCP ne garde pas les frontières des
/// messages. Des messages EtherNet/IP ou Bitcoin complets qui pavent le
/// segment sont reconnus ; un dernier message coupé ne l'est pas, ces
/// sondes étant aveugles. Sur UDP, un datagramme EtherNet/IP porte un seul
/// message.
#[test]
fn issue_288_complete_messages_that_tile_a_tcp_segment() {
    // EtherNet/IP (CIP Vol. 2, §2-4.4) : RegisterSession, version 1.
    let register_session = |context: u8| {
        let mut message = vec![0x65, 0x00, 0x04, 0x00]; // commande, longueur
        message.extend_from_slice(&[0; 8]); // session, statut
        message.extend_from_slice(&[context; 8]); // sender context
        message.extend_from_slice(&[0; 4]); // options
        message.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // version, options
        message
    };
    let two = [register_session(1), register_session(2)].concat();
    assert_eq!(tcp(44818, &register_session(1)), "EtherNet/IP");
    assert_eq!(tcp(44818, &two), "EtherNet/IP");
    assert_eq!(tcp(44818, &two[..two.len() - 1]), "Unknown");
    assert_ne!(udp(44818, &two), "EtherNet/IP");

    // Bitcoin (protocole P2P de Bitcoin Core) : `verack`, puis `ping`.
    let message = |command: &[u8], checksum: [u8; 4], payload: &[u8]| {
        let mut message = vec![0xf9, 0xbe, 0xb4, 0xd9]; // mainnet
        let mut field = [0u8; 12];
        field[..command.len()].copy_from_slice(command);
        message.extend_from_slice(&field);
        message.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
        message.extend_from_slice(&checksum); // sha256d du payload
        message.extend_from_slice(payload);
        message
    };
    let verack = message(b"verack", [0x5d, 0xf6, 0xe0, 0xe2], &[]);
    let ping = message(b"ping", [0x25, 0x02, 0xfa, 0x94], &[1, 2, 3, 4, 5, 6, 7, 8]);
    let both = [verack.clone(), ping].concat();
    assert_eq!(tcp(8333, &verack), "Bitcoin");
    assert_eq!(tcp(8333, &both), "Bitcoin");
    assert_eq!(tcp(8333, &both[..both.len() - 1]), "Unknown");
    // Un second message d'un autre réseau (testnet3) : refusé.
    let mut other_network = verack.clone();
    other_network[..4].copy_from_slice(&[0x0b, 0x11, 0x09, 0x07]);
    assert_eq!(tcp(8333, &[verack, other_network].concat()), "Unknown");
}
