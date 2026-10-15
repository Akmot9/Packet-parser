// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Trames IPv4 a longueur totale nulle (#168) : capturees sur un hote qui
//! delegue la segmentation TCP a sa carte (TSO, LSO de Windows), elles
//! courent jusqu'a la fin de la trame, comme les lit tshark
//! (`ip.tso_support`).

use std::path::Path;

use packet_parser::{parse, parse::internet::InternetDetails};

mod common;
use common::{FileRead, read_capture};

/// La trame `number` de `capture` (chemin sous `pcaps_exemple/`) : `length`
/// octets, longueur totale IPv4 nulle, un segment TCP de `tcp_payload`
/// octets que la crate classe TLS, comme tshark.
fn assert_tso_frame_is_tls(capture: &str, number: usize, length: usize, tcp_payload: usize) {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("pcaps_exemple");
    let FileRead::Frames { frames, .. } = read_capture(&base.join(capture)) else {
        panic!("{capture} illisible");
    };
    let (link_type, data) = &frames[number - 1];
    assert_eq!(data.len(), length, "{capture} trame {number}");
    let flow = parse(*link_type, data).expect("trame decodable");
    assert!(flow.corrupted.is_none(), "{:?}", flow.corrupted);
    let Some(Some(InternetDetails::Ipv4(ipv4))) =
        flow.internet.as_ref().map(|internet| &internet.details)
    else {
        panic!("IPv4 attendu");
    };
    assert_eq!(ipv4.total_length, 0);
    let transport = flow.transport.as_ref().expect("TCP");
    assert_eq!(transport.payload.map(<[u8]>::len), Some(tcp_payload));
    assert_eq!(
        flow.application.as_ref().map(|a| a.application_protocol),
        Some("TLS")
    );
}

/// `protocols/ntp/ndpi_line.pcap` trame 275 : 3 192 octets, un record TLS 1.2
/// Application Data complet de 3 133 octets. La couche internet etait
/// declaree corrompue ; la trame sort TLS.
#[test]
fn tso_frame_of_ndpi_line_is_tls() {
    assert_tso_frame_is_tls("protocols/ntp/ndpi_line.pcap", 275, 3192, 3138);
}

/// `The-Ultimate-PCAP.pcapng` trame 47 790, lue en place : 1 967 octets, un
/// record TLS Handshake de 1 908 octets (ClientHello vers le port 443).
#[test]
fn tso_frame_of_the_ultimate_pcap_is_tls() {
    assert_tso_frame_is_tls("The-Ultimate-PCAP.pcapng", 47_790, 1967, 1913);
}
