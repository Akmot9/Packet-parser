// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests UMAS sur trames reelles (issue #10).
//!
//! Capture : `pcaps_exemple/protocols/umas/umas.pcap` (corpus de tests nDPI,
//! voir le `SOURCE.md` du dossier). UMAS est le protocole proprietaire de
//! Schneider Electric, transporte par Modbus/TCP sous le code fonction 0x5A.
//!
//! tshark ne decode pas UMAS : il s'arrete a Modbus/TCP. L'oracle est donc
//! double — les champs MBAP sont recoupes avec tshark (`mbtcp.trans_id`,
//! `mbtcp.unit_id`, `mbtcp.len`, `modbus.func_code`), et les octets UMAS sont
//! lus sur le wire et documentes ici.

use std::{collections::BTreeSet, path::Path};

use packet_parser::{
    LinkType, parse,
    parse::application::protocols::umas::{UMAS_REPLY, UmasFunction, UmasPacket},
};

mod common;
use common::{FileRead, read_capture};

const CAPTURE: &str = "pcaps_exemple/protocols/umas/umas.pcap";

/// Trame 4 : requete 192.168.63.100:7718 -> 192.168.63.253:502.
/// tshark : `modbus.func_code == 90`, `mbtcp.trans_id == 0`,
/// `mbtcp.unit_id == 0`, `mbtcp.len == 4`.
/// Payload TCP : `00 00 | 00 00 | 00 04 | 00 | 5a | 00 02`
/// soit MBAP(transaction 0, protocole 0, longueur 4, unite 0), code fonction
/// 0x5A, puis UMAS session 0x00 et fonction 0x02, sans donnees.
const UMAS_REQUEST_FRAME_HEX: &str = concat!(
    "00005414f24f3c970e9154ab080045000032044a400080060000c0a83f64c0a8",
    "3ffd1e2601f64684fc0b8310cfbe5018faf000d70000000000000004005a0002"
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
fn packet_flow_labels_a_umas_request_over_modbus_tcp() {
    let bytes = frame(UMAS_REQUEST_FRAME_HEX, 64);
    let flow = parse(LinkType::ETHERNET, bytes.as_slice()).expect("captured frame decodes");

    assert_eq!(
        flow.application
            .expect("an application layer is detected")
            .application_protocol,
        "UMAS",
        "le code fonction 0x5A doit l'emporter sur l'etiquette ModbusTCP"
    );
}

/// Trame 6 : reponse 192.168.63.253:502 -> 192.168.63.100:7718.
/// tshark : `modbus.func_code == 90`, `mbtcp.len == 50`.
/// Payload TCP : MBAP(transaction 0, protocole 0, longueur 50, unite 0),
/// code fonction 0x5A, UMAS session 0x00 et statut 0xFE (reponse), puis 47
/// octets de donnees dont la chaine ASCII `140 CPU 311 10` — le modele de
/// l'automate Modicon interroge.
const UMAS_REPLY_FRAME_HEX: &str = concat!(
    "3c970e9154ab00005414f24f08004500006003c700004006761fc0a83ffdc0a8",
    "3f6401f61e268310cfbe4684fc15501810006d3e0000000000000032005a00fe",
    "10ff5a010100000070020000270009000800000000000e313430204350552033",
    "3131203130010101000000001100"
);

#[test]
fn umas_reply_decodes_the_plc_model_against_the_wire() {
    let bytes = frame(UMAS_REPLY_FRAME_HEX, 110);
    let flow = parse(LinkType::ETHERNET, bytes.as_slice()).expect("captured frame decodes");
    let payload = flow
        .transport
        .as_ref()
        .and_then(|transport| transport.payload)
        .expect("la couche transport porte le PDU");

    let packet = UmasPacket::try_from(payload).expect("captured UMAS reply decodes");

    // Enveloppe Modbus, recoupee avec tshark.
    assert_eq!(packet.mbap.transaction_identifier, 0);
    assert_eq!(packet.mbap.protocol_identifier, 0);
    assert_eq!(packet.mbap.length, 50);
    assert_eq!(packet.mbap.unit_identifier, 0);
    assert_eq!(packet.mbap.pdu.function_code, 0x5A);

    // PDU UMAS, lu sur le wire.
    assert_eq!(packet.session_id, 0x00);
    assert_eq!(packet.function, UmasFunction::Reply);
    assert_eq!(packet.data.len(), 46);

    let model = b"140 CPU 311 10";
    assert!(
        packet.data.windows(model.len()).any(|w| w == model),
        "la reponse porte le modele de l'automate"
    );
}

/// Toute la capture : chaque trame que tshark voit en code fonction 0x5A
/// ressort etiquetee UMAS, et aucune autre.
#[test]
fn every_umas_frame_of_the_capture_is_labelled() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(CAPTURE);
    let FileRead::Frames { frames, .. } = read_capture(&path) else {
        panic!("{CAPTURE} : capture illisible");
    };
    assert_eq!(frames.len(), 191, "{CAPTURE} compte 191 trames");

    let mut labelled = 0;
    let mut sessions = BTreeSet::new();
    let mut functions = BTreeSet::new();
    for (index, (link_type, data)) in frames.iter().enumerate() {
        let flow =
            parse(*link_type, data).unwrap_or_else(|error| panic!("trame {} : {error}", index + 1));
        let Some(application) = flow.application.as_ref() else {
            continue;
        };
        assert_eq!(
            application.application_protocol,
            "UMAS",
            "trame {} : seul UMAS est attendu dans cette capture",
            index + 1
        );
        labelled += 1;

        let payload = flow
            .transport
            .as_ref()
            .and_then(|transport| transport.payload)
            .expect("une trame etiquetee porte un payload");
        let packet = UmasPacket::try_from(payload).expect("trame UMAS decodee");
        sessions.insert(packet.session_id);
        functions.insert(packet.function.code());
    }

    // tshark : `modbus.func_code == 90` compte 180 trames, aucune exception
    // (0xDA). Les 11 restantes sont du TCP sans payload.
    assert_eq!(labelled, 180);
    assert_eq!(sessions, BTreeSet::from([0x00, 0x01]));
    // 0xFE pour toutes les reponses, et treize codes de requete distincts :
    // 0x01, 0x02, 0x03, 0x04, 0x0a, 0x10, 0x12, 0x20, 0x33, 0x34, 0x35,
    // 0x50, 0x58.
    assert!(functions.contains(&UMAS_REPLY));
    assert_eq!(functions.len(), 14);
}

/// La sonde UMAS passe **avant** celle de Modbus/TCP : elle ne doit donc
/// reconnaitre que le code fonction 0x5A, sans quoi elle volerait tout le
/// trafic Modbus ordinaire.
///
/// Le corpus Modbus du depot porte exactement une trame UMAS reelle —
/// `MODBUS-TestDataPart2.pcap` trame 229, une requete 0x5A adressee a un
/// automate qui la refuse (sa reponse, code fonction 0xDA, est une exception
/// Modbus et reste donc etiquetee ModbusTCP).
#[test]
fn the_umas_probe_does_not_steal_ordinary_modbus_traffic() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("pcaps_exemple/protocols/modbus");
    // (capture, trames ModbusTCP attendues, trames UMAS attendues). Somme
    // recoupee avec tshark (`-Y mbtcp`) : 102 et 281, dont une seule 0x5A.
    for (capture, modbus, umas) in [
        ("Modbus.pcap", 102, 0),
        ("MODBUS-TestDataPart2.pcap", 280, 1),
    ] {
        let FileRead::Frames { frames, .. } = read_capture(&base.join(capture)) else {
            panic!("{capture} : capture illisible");
        };

        let mut seen = (0, 0);
        for (link_type, data) in &frames {
            let Ok(flow) = parse(*link_type, data) else {
                continue;
            };
            match flow.application.as_ref().map(|a| a.application_protocol) {
                Some("ModbusTCP") => seen.0 += 1,
                Some("UMAS") => seen.1 += 1,
                _ => {}
            }
        }
        assert_eq!(seen, (modbus, umas), "{capture}");
    }
}
