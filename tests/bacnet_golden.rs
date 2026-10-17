// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests BACnet/IP (ASHRAE 135, annexe J) sur trames reelles (epopee
//! #102).
//!
//! Captures : `pcaps_exemple/protocols/bacnet/` (voir son `SOURCE.md`) : des
//! lectures de propriete qu'un poste adresse a un automate Johnson Controls
//! (ITI, 2015) et, du corpus nDPI (2023), les sondes readProperty que des
//! scanners d'Internet envoient a un equipement expose, puis un reseau local
//! avec ses Who-Is, I-Am et messages de routage.
//!
//! L'oracle est tshark 4.6.6 (`tools/bacnet_oracle.sh`) : pour chaque
//! datagramme, BVLC (fonction, longueur), NPDU (version, controle,
//! adresses, sauts, message reseau) et APDU (type, invocation, service),
//! figes dans `tests/data/bacnet_tshark_oracle.tsv`.

use std::{collections::BTreeMap, fs, path::Path};

use packet_parser::{
    PacketFlow, parse,
    parse::{
        application::protocols::bacnet::{BacnetPacket, NpduMessage},
        transport::protocols::TransportProtocol,
    },
};

mod common;
use common::{FileRead, collect_capture_files, read_capture};

const CORPUS: &str = "pcaps_exemple/protocols/bacnet";
const ORACLE: &str = "tests/data/bacnet_tshark_oracle.tsv";

/// Les colonnes 3 a 19 d'une ligne d'oracle.
type OracleRow = [String; 17];

fn read_oracle(path: &Path) -> BTreeMap<String, BTreeMap<usize, OracleRow>> {
    let oracle = fs::read_to_string(path).expect("oracle lisible");
    let mut expected: BTreeMap<String, BTreeMap<usize, OracleRow>> = BTreeMap::new();
    for line in oracle.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 19, "ligne d'oracle malformee : {line}");
        let row: OracleRow = fields[2..]
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .try_into()
            .expect("dix-sept colonnes");
        expected
            .entry(fields[0].to_string())
            .or_default()
            .insert(fields[1].parse().expect("numero de trame"), row);
    }
    expected
}

fn opt<T: ToString>(value: Option<T>) -> String {
    value.map_or("-".to_string(), |v| v.to_string())
}

/// Les colonnes 6 a 19 d'une ligne d'oracle.
fn oracle_columns(packet: &BacnetPacket<'_>) -> [String; 14] {
    let npdu = packet.npdu.as_ref();
    let apdu = npdu.and_then(|n| match n.message {
        NpduMessage::Apdu(apdu) => Some(apdu),
        _ => None,
    });
    let network = npdu.and_then(|n| match n.message {
        NpduMessage::Network { message_type, .. } => Some(message_type),
        _ => None,
    });
    [
        format!("{:#04x}", packet.bvlc.function),
        // `bvlc.length` chez tshark : la longueur de l'en-tete BVLC consomme
        // — 4, ou 10 avec l'origine d'un Forwarded-NPDU — quand un NPDU suit,
        // et tout le message pour les fonctions de controle (resultat,
        // enregistrement, tables). Le champ du fil, lui, est compare au
        // datagramme par le decodeur.
        if packet.npdu.is_some() {
            (4 + if packet.forwarded_from.is_some() {
                6
            } else {
                0
            })
            .to_string()
        } else {
            packet.bvlc.length.to_string()
        },
        opt(npdu.map(|n| n.version)),
        opt(npdu.map(|n| format!("{:#04x}", n.control))),
        opt(npdu.and_then(|n| n.destination).map(|d| d.network)),
        opt(npdu.and_then(|n| n.destination).map(|d| d.address.len())),
        opt(npdu.and_then(|n| n.source).map(|s| s.network)),
        opt(npdu.and_then(|n| n.source).map(|s| s.address.len())),
        opt(npdu.and_then(|n| n.hop_count)),
        opt(network.map(|t| format!("{t:#04x}"))),
        opt(apdu.map(|a| a.apdu_type)),
        opt(apdu.and_then(|a| a.invoke_id)),
        opt(apdu.and_then(|a| a.confirmed_service().map(|_| a.service.unwrap()))),
        opt(apdu.and_then(|a| a.unconfirmed_service().map(|_| a.service.unwrap()))),
    ]
}

fn label(flow: &PacketFlow<'_>) -> Option<&'static str> {
    flow.application
        .as_ref()
        .map(|application| application.application_protocol)
}

/// Parite avec tshark sur les 45 datagrammes BACnet/IP du corpus ; les
/// datagrammes UDP vides restent sans application.
#[test]
fn every_datagram_matches_the_tshark_oracle() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let expected = read_oracle(&base.join(ORACLE));
    let mut captures = Vec::new();
    collect_capture_files(&base.join(CORPUS), &mut captures);
    assert_eq!(captures.len(), 2);

    let mut datagrams = 0;
    let mut empty = 0;
    let mut by_function: BTreeMap<u8, usize> = BTreeMap::new();
    let mut by_apdu: BTreeMap<u8, usize> = BTreeMap::new();
    let mut network_messages = 0;
    for path in &captures {
        let file = path.file_name().unwrap().to_string_lossy().to_string();
        let FileRead::Frames { frames, .. } = read_capture(path) else {
            panic!("{file} : capture illisible");
        };
        let rows = expected
            .get(&file)
            .unwrap_or_else(|| panic!("{file} absente de l'oracle"));
        for (index, (link_type, data)) in frames.iter().enumerate() {
            let number = index + 1;
            let flow =
                parse(*link_type, data).unwrap_or_else(|error| panic!("{file}:{number} : {error}"));
            let transport = flow.transport.as_ref().expect("transport");
            assert_eq!(
                transport.protocol,
                TransportProtocol::Udp,
                "{file}:{number}"
            );
            let Some(payload) = transport.payload.filter(|payload| !payload.is_empty()) else {
                assert!(
                    !rows.contains_key(&number),
                    "{file}:{number} : sans payload"
                );
                assert_ne!(label(&flow), Some("BACnet/IP"), "{file}:{number}");
                empty += 1;
                continue;
            };
            let row = rows
                .get(&number)
                .unwrap_or_else(|| panic!("{file}:{number} absente de l'oracle"));
            assert_eq!(
                (
                    transport.source_port,
                    transport.destination_port,
                    payload.len()
                ),
                (
                    Some(row[0].parse().unwrap()),
                    Some(row[1].parse().unwrap()),
                    row[2].parse().unwrap()
                ),
                "{file}:{number}"
            );
            assert_eq!(label(&flow), Some("BACnet/IP"), "{file}:{number}");
            let packet = BacnetPacket::try_from(payload)
                .unwrap_or_else(|error| panic!("{file}:{number} : {error}"));
            assert_eq!(&oracle_columns(&packet)[..], &row[3..17], "{file}:{number}");
            datagrams += 1;
            *by_function.entry(packet.bvlc.function).or_default() += 1;
            if let Some(npdu) = packet.npdu {
                match npdu.message {
                    NpduMessage::Apdu(apdu) => *by_apdu.entry(apdu.apdu_type).or_default() += 1,
                    NpduMessage::Network { .. } => network_messages += 1,
                    _ => panic!("{file}:{number} : message NPDU inattendu"),
                }
            }
        }
    }
    assert_eq!((datagrams, empty, network_messages), (45, 4, 2));
    assert_eq!(
        by_function,
        BTreeMap::from([(0x00, 2), (0x02, 1), (0x05, 1), (0x0a, 27), (0x0b, 14)])
    );
    assert_eq!(by_apdu, BTreeMap::from([(0, 18), (1, 11), (3, 9), (5, 1)]));
}

/// `iti_bacnet_test.pcap` trame 3 : reconnu sur 47808, et sur n'importe
/// quel port par la sonde aveugle ; altere d'un octet de type, de fonction,
/// de longueur ou de version, plus du tout.
#[test]
fn blind_probe_and_mutations() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let FileRead::Frames { frames, .. } =
        read_capture(&base.join(CORPUS).join("iti_bacnet_test.pcap"))
    else {
        panic!("capture illisible");
    };
    let (link_type, data) = &frames[2];
    let flow = parse(*link_type, data).expect("trame 3");
    assert_eq!(label(&flow), Some("BACnet/IP"));
    let payload_len = flow.transport.as_ref().unwrap().payload.unwrap().len();
    assert_eq!(payload_len, 17);
    // Ethernet + IPv4 sans options : ports UDP aux octets 34 a 38, payload a 42.
    let start = data.len() - payload_len;
    assert_eq!(start, 42);

    let mut moved = data.clone();
    moved[34..38].copy_from_slice(&[0x9c, 0x40, 0x9c, 0x41]);
    let flow = parse(*link_type, &moved).expect("trame deplacee");
    assert_eq!(label(&flow), Some("BACnet/IP"));

    for (name, offset, value) in [
        ("type BVLC", 0usize, 0x82u8),
        ("fonction BVLC inconnue", 1, 0x0d),
        ("longueur BVLC", 3, 0x12),
        ("version NPDU", 4, 0x02),
        ("type d'APDU", 6, 0x80),
    ] {
        let mut mutated = moved.clone();
        mutated[start + offset] = value;
        let flow = parse(*link_type, &mutated).expect("trame alteree");
        assert_ne!(label(&flow), Some("BACnet/IP"), "{name}");
        assert!(BacnetPacket::try_from(&mutated[start..]).is_err(), "{name}");
    }
}
