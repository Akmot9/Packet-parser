// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests SSH au niveau `PacketFlow`, sur trames completes.
//!
//! Les trames viennent de `pcaps_exemple/The-Ultimate-PCAP.pcapng`, deja au
//! depot. Elles sont figees ici en hexadecimal plutot que relues du fichier :
//! cette capture declare 313 IDB avec quatre link types differents, et
//! `pcap::Capture` n'expose qu'un seul datalink par fichier, si bien qu'aucun
//! outil du depot ne parvient a l'iterer (voir `examples/scan_pcaps.rs`).
//!
//! Chaque trame est Ethernet + VLAN 802.1Q + IPv6 + TCP, ce qui exerce la
//! chaine complete jusqu'a la banniere.

use packet_parser::{LinkType, parse};

/// Trame 5211 : client OpenSSH sur Ubuntu vers le port 22, terminaison CRLF
/// et commentaires de distribution.
const OPENSSH_UBUNTU_FRAME_HEX: &str = concat!(
    "001e7a793f110014699e11418100007986dd600f0134003d063e200300516012",
    "0110000000000b15002220030051601201210000000000000002eddc0016b826",
    "37e83a17905c50187080654f00005353482d322e302d4f70656e5353485f372e",
    "327032205562756e74752d347562756e7475322e310d0a"
);

/// Trame 5213 : reponse du serveur Cisco. Banniere terminee par un LF nu et
/// dont la version logicielle porte un tiret — deux ecarts a la RFC 4253 §4.2
/// qu'un parseur ecrit d'apres la seule norme rejetterait.
const CISCO_FRAME_HEX: &str = concat!(
    "001a6ca12b99001e7a793f118100007986dd6c000000002706ff200300516012",
    "012100000000000000022003005160120110000000000b1500220016eddc3a17",
    "905cb826381150180ff757b400005353482d322e302d436973636f2d312e3235",
    "0a"
);

/// Trame 11589 : client PuTTY, banniere sans commentaires.
const PUTTY_FRAME_HEX: &str = concat!(
    "b40c25058e13000c29c134dc8100007d86dd6000000000300640200300de2016",
    "0125fc3683174e86cb72200300de20160110000000000b1500221d8b00165c44",
    "602c2e811b6b501840a52d5e00005353482d322e302d50755454595f52656c65",
    "6173655f302e36330d0a"
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

fn assert_detected_as_ssh(hex_fixture: &str, expected_len: usize) {
    let bytes = frame(hex_fixture, expected_len);
    let flow = parse(LinkType::ETHERNET, bytes.as_slice()).expect("captured frame decodes");

    assert_eq!(
        flow.application
            .expect("an application layer is detected")
            .application_protocol,
        "SSH"
    );
}

#[test]
fn packet_flow_detects_openssh_banner() {
    assert_detected_as_ssh(OPENSSH_UBUNTU_FRAME_HEX, 119);
}

#[test]
fn packet_flow_detects_cisco_banner_with_bare_line_feed() {
    assert_detected_as_ssh(CISCO_FRAME_HEX, 97);
}

#[test]
fn packet_flow_detects_putty_banner() {
    assert_detected_as_ssh(PUTTY_FRAME_HEX, 106);
}

/// Oracle negatif. La detection SSH est ajoutee au probing a l'aveugle : elle
/// ne doit capturer que ce qui porte reellement la signature. Un scan des 75
/// captures du depot ne produit aucun label SSH parasite ; ces vecteurs
/// synthetiques verrouillent les confusions les plus plausibles.
#[test]
fn text_that_merely_starts_with_ssh_is_not_detected() {
    use packet_parser::parse::application::Application;

    for payload in [
        // Version de protocole inexistante.
        &b"SSH-3.0-OpenSSH_9.0\r\n"[..],
        // SSH-1 historique, hors perimetre.
        &b"SSH-1.5-OpenSSH_3.9\r\n"[..],
        // Prose commencant par le prefixe.
        &b"SSH-related notes for the team\r\n"[..],
        // Banniere tronquee par la segmentation TCP.
        &b"SSH-2.0-OpenSSH_8.9p1"[..],
    ] {
        let application = Application::try_from(payload).expect("payload is classified");

        assert_ne!(
            application.application_protocol, "SSH",
            "payload {payload:?} must not be labelled SSH"
        );
    }
}
