// Fuzz du dispatcher L7 par son entree publique sans trame,
// `classify_payload` (#219). Cinq octets de tete choisissent le transport et
// les deux ports, le reste est le payload : toutes les sondes de la table
// sont atteintes, regles a port comprises, et doivent rejeter proprement les
// octets hostiles.
//
// Ni panic ni boucle ; et, sur TCP ou UDP avec ses ports, l'etiquette est
// celle de `parse` sur la trame Ethernet/IPv4 batie autour du meme payload.
// C'est la parite de `tests/classify_payload_parity.rs`, tenue aussi hors du
// corpus.
#![no_main]

#[path = "../oracles/frames.rs"]
mod frames;

use frames::ethernet_ipv4_payload;
use libfuzzer_sys::fuzz_target;
use packet_parser::{LinkType, TransportProtocol, classify_payload, parse};

/// Au-dela, la longueur totale IPv4 (seize bits) que `ethernet_ipv4_payload`
/// ecrit sans la verifier deborderait : 65 535 moins vingt octets d'IPv4 et
/// vingt de TCP. Les payloads plus longs que `PROBE_CAP` restent compares.
const MAX_FRAMED_PAYLOAD: usize = u16::MAX as usize - 40;

fuzz_target!(|data: &[u8]| {
    let [selector, sp_hi, sp_lo, dp_hi, dp_lo, payload @ ..] = data else {
        return;
    };
    let source_port = u16::from_be_bytes([*sp_hi, *sp_lo]);
    let destination_port = u16::from_be_bytes([*dp_hi, *dp_lo]);
    let protocol = if selector & 1 == 0 {
        TransportProtocol::Tcp
    } else {
        TransportProtocol::Udp
    };

    // Ports inconnus : seules les sondes sans port, derriere leur garde de
    // transport.
    if selector & 2 != 0 {
        let _ = classify_payload(protocol, None, None, payload);
        return;
    }

    // Un protocole IP quelconque : rien n'est sonde hors TCP et UDP, quels
    // que soient les ports et les octets.
    if selector & 4 != 0 {
        let other = TransportProtocol::from_u8(*sp_hi);
        let application =
            classify_payload(other, Some(source_port), Some(destination_port), payload);
        if !matches!(other, TransportProtocol::Tcp | TransportProtocol::Udp) {
            assert!(application.is_none(), "{other} sonde : {application:?}");
        }
        return;
    }

    let application =
        classify_payload(protocol, Some(source_port), Some(destination_port), payload);
    if payload.len() <= MAX_FRAMED_PAYLOAD {
        let frame = ethernet_ipv4_payload(protocol, source_port, destination_port, payload);
        let flow = parse(LinkType::ETHERNET, &frame).expect("la trame de l'oracle se decode");
        assert_eq!(
            application,
            flow.application,
            "{protocol} {source_port} -> {destination_port}, {} octets",
            payload.len()
        );
    }
});
