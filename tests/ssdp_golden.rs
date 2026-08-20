// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests SSDP sur des payloads UDP reels.
//!
//! Captures : `pcaps_exemple/The-Ultimate-PCAP.pcapng` (numeros de trame
//! notes sur chaque fixture). Le filtre `-Y ssdp` de tshark y compte 99
//! trames : 87 M-SEARCH et 12 NOTIFY, toutes vers 239.255.255.250:1900 ;
//! le corpus ne contient aucune reponse `HTTP/1.1 200 OK`. Les payloads sont
//! extraits avec `tshark -T fields -e udp.payload`.

use packet_parser::parse::application::protocols::ssdp::{SsdpMessageType, SsdpPacket};

/// Trame 8156 : M-SEARCH d'une box AVM (192.168.7.1:37185 ->
/// 239.255.255.250:1900), MX 5, ST avm-aha.
const MSEARCH_AVM_HEX: &str = concat!(
    "4d2d534541524348202a20485454502f312e310d0a484f53543a203233392e32",
    "35352e3235352e3235303a313930300d0a4d414e3a2022737364703a64697363",
    "6f766572220d0a4d583a20350d0a53543a2075726e3a736368656d61732d7570",
    "6e702d6f72673a6465766963653a61766d2d6168613a310d0a0d0a"
);

/// Trame 8199 : NOTIFY ssdp:alive d'un media renderer (192.168.7.12:5645 ->
/// 239.255.255.250:1900), rootdevice avec LOCATION, SERVER et USN.
const NOTIFY_ALIVE_HEX: &str = concat!(
    "4e4f54494659202a20485454502f312e310d0a484f53543a203233392e323535",
    "2e3235352e3235303a313930300d0a43414348452d434f4e54524f4c3a206d61",
    "782d6167653d313830300d0a4c4f434154494f4e3a20687474703a2f2f313932",
    "2e3136382e372e31323a383038302f4d6564696152656e64657265722f646573",
    "632e786d6c0d0a4e543a2075706e703a726f6f746465766963650d0a4e54533a",
    "20737364703a616c6976650d0a5345525645523a204b6e4f532f332e32205550",
    "6e502f312e3020444d502f332e350d0a55534e3a20757569643a356639656331",
    "62332d656435392d313930302d343533302d3030613064656465353431333a3a",
    "75706e703a726f6f746465766963650d0a0d0a"
);

/// Trame 38194 : M-SEARCH d'une autre pile (10.0.1.97:1900 ->
/// 239.255.255.250:1900). Trois ecarts de forme reels dans un seul message :
/// pas d'espace apres `:` (`ST:upnp:rootdevice`, `MAN:"ssdp:discover"`,
/// `MX:3`), en-tetes dans un ordre different, et un CRLF surnumeraire apres
/// la ligne vide finale.
const MSEARCH_NO_SPACE_HEX: &str = concat!(
    "4d2d534541524348202a20485454502f312e310d0a484f53543a203233392e32",
    "35352e3235352e3235303a313930300d0a53543a75706e703a726f6f74646576",
    "6963650d0a4d414e3a22737364703a646973636f766572220d0a4d583a330d0a",
    "0d0a0d0a"
);

fn payload(hex_fixture: &str, expected_len: usize) -> Vec<u8> {
    let bytes = hex::decode(hex_fixture).expect("invalid test hex fixture");
    assert_eq!(
        bytes.len(),
        expected_len,
        "fixture length must match capture"
    );
    bytes
}

#[test]
fn msearch_from_capture_parses() {
    let bytes = payload(MSEARCH_AVM_HEX, 123);
    let packet = SsdpPacket::try_from(bytes.as_slice()).expect("captured M-SEARCH parses");

    assert_eq!(packet.message_type, SsdpMessageType::MSearch);
    assert_eq!(packet.man, Some("\"ssdp:discover\""));
    assert_eq!(packet.mx, Some("5"));
    assert_eq!(packet.st, Some("urn:schemas-upnp-org:device:avm-aha:1"));
    assert_eq!(packet.nt, None);
    assert_eq!(packet.nts, None);
    assert_eq!(packet.usn, None);
    assert_eq!(packet.location, None);
    assert_eq!(packet.server, None);
}

#[test]
fn notify_alive_from_capture_parses() {
    let bytes = payload(NOTIFY_ALIVE_HEX, 275);
    let packet = SsdpPacket::try_from(bytes.as_slice()).expect("captured NOTIFY parses");

    assert_eq!(packet.message_type, SsdpMessageType::Notify);
    assert_eq!(packet.nt, Some("upnp:rootdevice"));
    assert_eq!(packet.nts, Some("ssdp:alive"));
    assert_eq!(
        packet.location,
        Some("http://192.168.7.12:8080/MediaRenderer/desc.xml")
    );
    assert_eq!(packet.server, Some("KnOS/3.2 UPnP/1.0 DMP/3.5"));
    assert_eq!(
        packet.usn,
        Some("uuid:5f9ec1b3-ed59-1900-4530-00a0dede5413::upnp:rootdevice")
    );
    assert_eq!(packet.man, None);
    assert_eq!(packet.st, None);
}

/// Le cas reel qui interdit d'exiger un espace apres `:` ou de refuser des
/// octets apres la ligne vide finale.
#[test]
fn msearch_without_space_after_colon_parses() {
    let bytes = payload(MSEARCH_NO_SPACE_HEX, 100);
    let packet = SsdpPacket::try_from(bytes.as_slice()).expect("captured M-SEARCH parses");

    assert_eq!(packet.message_type, SsdpMessageType::MSearch);
    assert_eq!(packet.man, Some("\"ssdp:discover\""));
    assert_eq!(packet.mx, Some("3"));
    assert_eq!(packet.st, Some("upnp:rootdevice"));
}
