// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests RADIUS (RFC 2865) sur trames reelles (#101).
//!
//! Captures : `pcaps_exemple/protocols/radius/` (voir son `SOURCE.md`), les
//! deux du corpus de tests de Zeek, et les 72 paquets RADIUS de
//! `pcaps_exemple/The-Ultimate-PCAP.pcapng`, lus sur place.
//!
//! L'oracle est tshark 4.6.6 (`tools/radius_oracle.sh`) : pour chaque paquet,
//! l'en-tete (code, identifiant, longueur, authentificateur) et les
//! attributs (types, longueurs, identifiants de vendeur), figes dans
//! `tests/data/radius_tshark_oracle.tsv`. Les 51 256 autres trames de
//! l'Ultimate PCAP mesurent la sonde aveugle : aucune ne doit sortir RADIUS.

use std::{collections::BTreeMap, fs, path::Path};

use packet_parser::{
    PacketFlow, parse,
    parse::application::protocols::radius::{AttributeType, RadiusPacket},
};

mod common;
use common::{FileRead, collect_capture_files, read_capture};

const CORPUS: &str = "pcaps_exemple/protocols/radius";
const ULTIMATE: &str = "pcaps_exemple/The-Ultimate-PCAP.pcapng";
const ORACLE: &str = "tests/data/radius_tshark_oracle.tsv";

/// Les colonnes 3 a 11 d'une ligne d'oracle.
type OracleRow = [String; 9];

fn read_oracle(path: &Path) -> BTreeMap<String, BTreeMap<usize, OracleRow>> {
    let oracle = fs::read_to_string(path).expect("oracle lisible");
    let mut expected: BTreeMap<String, BTreeMap<usize, OracleRow>> = BTreeMap::new();
    for line in oracle.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 11, "ligne d'oracle malformee : {line}");
        let row: OracleRow = fields[2..]
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .try_into()
            .expect("neuf colonnes");
        expected
            .entry(fields[0].to_string())
            .or_default()
            .insert(fields[1].parse().expect("numero de trame"), row);
    }
    expected
}

fn join<T: ToString>(values: impl Iterator<Item = T>) -> String {
    let joined = values.map(|v| v.to_string()).collect::<Vec<_>>().join(",");
    if joined.is_empty() {
        "-".to_string()
    } else {
        joined
    }
}

fn oracle_row(packet: &RadiusPacket<'_>, source_port: u16, destination_port: u16) -> OracleRow {
    [
        source_port.to_string(),
        destination_port.to_string(),
        packet.code.to_string(),
        packet.identifier.to_string(),
        packet.length.to_string(),
        packet
            .authenticator
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        join(packet.attributes.iter().map(|a| a.attribute_type)),
        join(packet.attributes.iter().map(|a| a.length)),
        join(
            packet
                .attributes
                .iter()
                .filter(|a| a.kind == Some(AttributeType::VendorSpecific))
                .map(|a| a.vendor().map_or("?".to_string(), |(id, _)| id.to_string())),
        ),
    ]
}

fn label(flow: &PacketFlow<'_>) -> Option<&'static str> {
    flow.application
        .as_ref()
        .map(|application| application.application_protocol)
}

/// Parite avec tshark sur les 95 paquets RADIUS, et aucun faux positif de la
/// sonde aveugle sur le reste de l'Ultimate PCAP.
#[test]
fn every_packet_matches_the_tshark_oracle() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let expected = read_oracle(&base.join(ORACLE));
    let mut captures = Vec::new();
    collect_capture_files(&base.join(CORPUS), &mut captures);
    assert_eq!(captures.len(), 2);
    captures.push(base.join(ULTIMATE));

    let mut packets = 0;
    let mut other_frames = 0;
    let mut by_code: BTreeMap<u8, usize> = BTreeMap::new();
    let mut vendor_specific = 0;
    for path in &captures {
        let file = path.file_name().unwrap().to_string_lossy().to_string();
        let FileRead::Frames { frames, .. } = read_capture(path) else {
            panic!("{file} : capture illisible");
        };
        let rows = expected
            .get(&file)
            .unwrap_or_else(|| panic!("{file} absente de l'oracle"));
        let mut seen = 0;
        for (index, (link_type, data)) in frames.iter().enumerate() {
            let number = index + 1;
            let Ok(flow) = parse(*link_type, data) else {
                assert!(!rows.contains_key(&number), "{file}:{number} : illisible");
                other_frames += 1;
                continue;
            };
            let Some(row) = rows.get(&number) else {
                assert_ne!(
                    label(&flow),
                    Some("RADIUS"),
                    "{file}:{number} : faux positif"
                );
                other_frames += 1;
                continue;
            };
            assert_eq!(label(&flow), Some("RADIUS"), "{file}:{number}");
            let transport = flow.transport.as_ref().expect("transport");
            let packet = RadiusPacket::try_from(transport.payload.expect("payload UDP"))
                .unwrap_or_else(|error| panic!("{file}:{number} : {error}"));
            assert_eq!(
                &oracle_row(
                    &packet,
                    transport.source_port.unwrap(),
                    transport.destination_port.unwrap()
                ),
                row,
                "{file}:{number}"
            );
            *by_code.entry(packet.code).or_default() += 1;
            vendor_specific += packet
                .attributes
                .iter()
                .filter(|a| a.kind == Some(AttributeType::VendorSpecific))
                .count();
            packets += 1;
            seen += 1;
        }
        assert_eq!(seen, rows.len(), "{file} : des lignes d'oracle sans trame");
    }
    assert_eq!(packets, 95);
    assert_eq!(other_frames, 51_256);
    assert_eq!(
        by_code,
        BTreeMap::from([(1, 49), (2, 18), (3, 2), (11, 26)])
    );
    assert_eq!(vendor_specific, 28);
}

/// `radius.pcap` trame 1 (UDP 1645 -> 1812) : reconnu sur ses ports, et sur
/// n'importe quel autre par la sonde aveugle ; altere d'un octet de
/// longueur, de code ou d'attribut, plus du tout.
#[test]
fn blind_probe_and_mutations() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let FileRead::Frames { frames, .. } = read_capture(&base.join(CORPUS).join("radius.pcap"))
    else {
        panic!("capture illisible");
    };
    let (link_type, data) = &frames[0];
    let flow = parse(*link_type, data).expect("trame 1");
    assert_eq!(label(&flow), Some("RADIUS"));
    let payload_len = flow.transport.as_ref().unwrap().payload.unwrap().len();
    assert_eq!(payload_len, 139);
    // Ethernet + IPv4 sans options : ports UDP aux octets 34 a 38, payload a 42.
    let start = data.len() - payload_len;
    assert_eq!(start, 42);

    let mut moved = data.clone();
    moved[34..38].copy_from_slice(&[0x9c, 0x40, 0x9c, 0x41]); // 40000 -> 40001
    let flow = parse(*link_type, &moved).expect("trame deplacee");
    assert_eq!(label(&flow), Some("RADIUS"));

    for (name, offset, mask) in [
        ("code 6, reserve", 0usize, 0x07u8),
        ("longueur un de plus", 3, 0x01),
        // Octet 21 : la longueur du premier attribut (NAS-IP-Address).
        ("longueur d'attribut", 21, 0x01),
        ("longueur d'attribut debordante", 21, 0x80),
    ] {
        let mut mutated = moved.clone();
        mutated[start + offset] ^= mask;
        let flow = parse(*link_type, &mutated).expect("trame alteree");
        assert_ne!(label(&flow), Some("RADIUS"), "{name}");
        assert!(RadiusPacket::try_from(&mutated[start..]).is_err(), "{name}");
    }
    // L'authentificateur et une valeur d'attribut, eux, peuvent changer :
    // rien ici ne connait le secret partage.
    let mut other = moved.clone();
    other[start + 4] ^= 0xff;
    other[start + 22] ^= 0xff;
    let flow = parse(*link_type, &other).expect("trame alteree");
    assert_eq!(label(&flow), Some("RADIUS"));
}
