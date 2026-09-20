// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests OPC UA sur trames reelles (issue #95).
//!
//! Capture : `pcaps_exemple/protocols/opcua/opcua_loopback.pcap` (corpus de
//! tests nDPI, voir le `SOURCE.md` du dossier). Le decodeur OPC UA etait
//! publie depuis plusieurs versions sans qu'aucune trame reelle ne
//! l'exerce : le depot n'en avait aucune.
//!
//! Elle est en **LINKTYPE_NULL** (encapsulation loopback BSD) : quatre
//! octets de famille d'adresses, puis le paquet IP. C'est ce que le decodeur
//! de liaison ajoute par la meme occasion.

use std::{collections::BTreeMap, path::Path};

use packet_parser::{LinkType, parse, parse::application::protocols::opcua::OpcuaPacket};

mod common;
use common::{FileRead, read_capture};

const CAPTURE: &str = "pcaps_exemple/protocols/opcua/opcua_loopback.pcap";

/// Trame 5 : message OPC UA `HEL` (Hello) sur le loopback, 127.0.0.1:57420
/// -> 127.0.0.1:4840. tshark : `opcua`, `tcp.dstport == 4840`.
///
/// Les quatre premiers octets sont `02 00 00 00`, soit AF_INET dans
/// l'ordre d'octets de la machine de capture (little-endian ici), puis le
/// paquet IPv4 (`45 ...`). Le corps porte l'URL du point de terminaison,
/// `opc.tcp://localhost:4840`.
const OPCUA_HELLO_FRAME_HEX: &str = concat!(
    "020000004500006c00004000400600007f0000017f000001e04c12e861500a98",
    "d6b91181801818ebfe6000000101080a0f734406cc77346948454c4638000000",
    "0000000000000200000002000000004000800000180000006f70632e7463703a",
    "2f2f6c6f63616c686f73743a34383430"
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
fn packet_flow_labels_opcua_over_a_null_loopback_capture() {
    let bytes = frame(OPCUA_HELLO_FRAME_HEX, 112);

    // LINKTYPE_NULL = 0.
    let flow = parse(LinkType(0), bytes.as_slice()).expect("captured frame decodes");

    assert_eq!(
        flow.application
            .expect("an application layer is detected")
            .application_protocol,
        "OPC UA"
    );
}

/// Toute la capture : chaque trame que tshark voit en OPC UA ressort
/// etiquetee, et le decodeur rend les memes types de message.
#[test]
fn every_opcua_frame_of_the_capture_is_labelled_and_decoded() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(CAPTURE);
    let FileRead::Frames { frames, .. } = read_capture(&path) else {
        panic!("{CAPTURE} : capture illisible");
    };
    assert_eq!(frames.len(), 381, "{CAPTURE} compte 381 trames");

    let mut labelled = 0;
    let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
    for (index, (link_type, data)) in frames.iter().enumerate() {
        // Le LINKTYPE vient de l'en-tete du fichier, pas d'une supposition.
        assert_eq!(*link_type, LinkType(0), "trame {}", index + 1);

        let flow =
            parse(*link_type, data).unwrap_or_else(|error| panic!("trame {} : {error}", index + 1));
        if flow.application.as_ref().map(|a| a.application_protocol) != Some("OPC UA") {
            continue;
        }
        labelled += 1;

        let payload = flow
            .transport
            .as_ref()
            .and_then(|transport| transport.payload)
            .expect("une trame etiquetee porte un payload");
        let packet = OpcuaPacket::try_from(payload).expect("message OPC UA decode");
        // Un message par segment dans cette capture : aucun chunk n'est
        // fragmente, et aucun segment n'en enchaine deux.
        assert_eq!(packet.chunks.len(), 1, "trame {}", index + 1);
        // Les trois premiers octets du message, tels quels : HEL, ACK, OPN,
        // MSG, CLO.
        *kinds
            .entry(String::from_utf8_lossy(&payload[..3]).into_owned())
            .or_default() += 1;
    }

    // tshark (`-Y opcua`) en compte 187, avec la meme repartition de types.
    assert_eq!(labelled, 187);
    assert_eq!(
        kinds,
        BTreeMap::from([
            ("ACK".to_string(), 1),
            ("CLO".to_string(), 1),
            ("HEL".to_string(), 1),
            ("MSG".to_string(), 182),
            ("OPN".to_string(), 2),
        ])
    );
}

/// Le message Hello porte l'URL du point de terminaison, en clair.
#[test]
fn the_hello_message_carries_its_endpoint_url() {
    let bytes = frame(OPCUA_HELLO_FRAME_HEX, 112);
    let flow = parse(LinkType(0), bytes.as_slice()).expect("captured frame decodes");
    let payload = flow
        .transport
        .as_ref()
        .and_then(|transport| transport.payload)
        .expect("la couche transport porte le message");

    let packet = OpcuaPacket::try_from(payload).expect("message OPC UA decode");
    assert_eq!(packet.chunks.len(), 1);

    let url = b"opc.tcp://localhost:4840";
    assert!(
        payload.windows(url.len()).any(|window| window == url),
        "le Hello annonce son point de terminaison"
    );
}
