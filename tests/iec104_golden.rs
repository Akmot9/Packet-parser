// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests IEC 60870-5-104 sur trames reelles (epopee #102).
//!
//! Captures : `pcaps_exemple/protocols/iec104/` (voir son `SOURCE.md`), une
//! session complete du wiki Wireshark, un segment en sequence (SQ = 1), des
//! mesures horodatees du corpus nDPI, et deux captures ITI (commandes
//! horodatees, interrogations en sequence).
//!
//! L'oracle est tshark 4.6.6 sans reassemblage TCP (`tools/iec104_oracle.sh`,
//! la vue d'un parseur sans etat) : pour chaque segment a payload, APDU
//! par APDU, longueur, format, fonction U ou numeros de sequence, et pour
//! chaque ASDU type, SQ, nombre d'objets, cause, adresses d'origine et
//! commune, adresses d'objets. Fige dans `tests/data/iec104_tshark_oracle.tsv`.

use std::{collections::BTreeMap, fs, path::Path};

use packet_parser::{
    DecodeAsProtocol, PacketFlow, ParseConfig, parse,
    parse::application::protocols::iec104::{ApciFormat, Iec104Packet},
    parse_with,
};

use packet_parser::parse::transport::protocols::TransportProtocol;

mod common;
use common::{FileRead, collect_capture_files, read_capture};

const CORPUS: &str = "pcaps_exemple/protocols/iec104";
const ORACLE: &str = "tests/data/iec104_tshark_oracle.tsv";

/// Les colonnes 3 a 18 d'une ligne d'oracle.
type OracleRow = [String; 16];

fn read_oracle(path: &Path) -> BTreeMap<String, BTreeMap<usize, OracleRow>> {
    let oracle = fs::read_to_string(path).expect("oracle lisible");
    let mut expected: BTreeMap<String, BTreeMap<usize, OracleRow>> = BTreeMap::new();
    for line in oracle.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 18, "ligne d'oracle malformee : {line}");
        let row: OracleRow = fields[2..]
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .try_into()
            .expect("seize colonnes");
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

/// Les colonnes 6 a 17 : ce que tshark liste APDU par APDU.
fn oracle_columns(packet: &Iec104Packet<'_>) -> [String; 12] {
    let apdus = &packet.apdus;
    let asdus = apdus.iter().filter_map(|a| a.asdu.as_ref());
    [
        join(apdus.iter().map(|a| a.length)),
        join(apdus.iter().map(|a| match a.format {
            ApciFormat::Information { .. } => "0x00000000",
            ApciFormat::Supervisory { .. } => "0x00000001",
            ApciFormat::Unnumbered(_) => "0x00000003",
            _ => "-",
        })),
        join(apdus.iter().filter_map(|a| match a.format {
            ApciFormat::Unnumbered(function) => Some(format!("{:#010x}", function.bits() >> 2)),
            _ => None,
        })),
        join(apdus.iter().filter_map(|a| match a.format {
            ApciFormat::Information { send_sequence, .. } => Some(send_sequence),
            _ => None,
        })),
        join(apdus.iter().filter_map(|a| match a.format {
            ApciFormat::Information {
                receive_sequence, ..
            }
            | ApciFormat::Supervisory { receive_sequence } => Some(receive_sequence),
            _ => None,
        })),
        join(asdus.clone().map(|s| s.type_id)),
        join(
            asdus
                .clone()
                .map(|s| if s.sequence { "True" } else { "False" }),
        ),
        join(asdus.clone().map(|s| s.count)),
        join(asdus.clone().map(|s| s.cause)),
        join(asdus.clone().map(|s| s.originator)),
        join(asdus.clone().map(|s| s.common_address)),
        join(asdus.flat_map(|s| s.objects.iter().map(|o| o.address))),
    ]
}

fn label(flow: &PacketFlow<'_>) -> Option<&'static str> {
    flow.application
        .as_ref()
        .map(|application| application.application_protocol)
}

/// Parite avec tshark sur tous les segments a payload du corpus.
#[test]
fn every_segment_matches_the_tshark_oracle() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let expected = read_oracle(&base.join(ORACLE));
    let mut captures = Vec::new();
    collect_capture_files(&base.join(CORPUS), &mut captures);
    assert_eq!(captures.len(), 5);

    let mut segments = 0;
    let mut iec104 = 0;
    let mut apdus = 0;
    let mut asdus = 0;
    let mut objects = 0;
    let mut sequences = 0;
    let mut truncated = 0;
    let mut retransmissions = 0;
    let mut by_type: BTreeMap<u8, usize> = BTreeMap::new();
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
            if transport.protocol != TransportProtocol::Tcp {
                // Un datagramme NetBIOS s'est glisse dans iti_090813_diverse.pcap.
                assert_ne!(label(&flow), Some("IEC 104"), "{file}:{number}");
                assert!(!rows.contains_key(&number), "{file}:{number} : hors TCP");
                continue;
            }
            let Some(payload) = transport.payload.filter(|payload| !payload.is_empty()) else {
                assert!(
                    !rows.contains_key(&number),
                    "{file}:{number} : sans payload"
                );
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
            segments += 1;
            if row[15] == "1" {
                retransmissions += 1;
                continue;
            }
            if row[3] == "-" {
                assert_ne!(label(&flow), Some("IEC 104"), "{file}:{number}");
                continue;
            }
            assert_eq!(label(&flow), Some("IEC 104"), "{file}:{number}");
            let packet = Iec104Packet::try_from(payload)
                .unwrap_or_else(|error| panic!("{file}:{number} : {error}"));
            assert_eq!(&oracle_columns(&packet)[..], &row[3..15], "{file}:{number}");
            iec104 += 1;
            apdus += packet.apdus.len();
            truncated += usize::from(packet.truncated);
            for asdu in packet.apdus.iter().filter_map(|a| a.asdu.as_ref()) {
                asdus += 1;
                objects += asdu.objects.len();
                sequences += usize::from(asdu.sequence);
                *by_type.entry(asdu.type_id).or_default() += 1;
                assert_eq!(
                    asdu.objects.len(),
                    usize::from(asdu.count),
                    "{file}:{number}"
                );
                assert!(asdu.undecoded.is_empty(), "{file}:{number}");
            }
        }
    }
    assert_eq!(
        (
            segments,
            iec104,
            apdus,
            asdus,
            objects,
            sequences,
            truncated,
            retransmissions
        ),
        (374, 373, 448, 301, 668, 46, 0, 1)
    );
    assert_eq!(
        by_type,
        BTreeMap::from([
            (1, 29),
            (3, 24),
            (5, 3),
            (7, 3),
            (9, 3),
            (11, 24),
            (13, 17),
            (30, 11),
            (31, 3),
            (32, 3),
            (33, 3),
            (34, 3),
            (35, 3),
            (36, 9),
            (45, 11),
            (46, 12),
            (47, 6),
            (48, 6),
            (49, 6),
            (50, 16),
            (51, 6),
            (58, 5),
            (59, 10),
            (61, 5),
            (63, 5),
            (70, 3),
            (100, 72)
        ])
    );
}

/// `wireshark_iec104.pcap` trame 9 : l'interrogation generale sur 2404 ;
/// ailleurs, rien sans Decode As.
#[test]
fn port_guard_and_decode_as() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let FileRead::Frames { frames, .. } =
        read_capture(&base.join(CORPUS).join("wireshark_iec104.pcap"))
    else {
        panic!("capture illisible");
    };
    let (link_type, data) = &frames[8];
    let flow = parse(*link_type, data).expect("trame 9");
    assert_eq!(label(&flow), Some("IEC 104"));
    // Ethernet + IPv4 sans options : port de destination aux octets 36 et 37.
    let mut moved = data.clone();
    moved[36..38].copy_from_slice(&2405u16.to_be_bytes());
    let flow = parse(*link_type, &moved).expect("trame deplacee");
    assert_eq!(label(&flow), Some("Unknown"));
    let config = ParseConfig::new().decode_as(2405, DecodeAsProtocol::Iec104);
    let flow = parse_with(*link_type, &moved, &config).expect("trame declaree");
    assert_eq!(label(&flow), Some("IEC 104"));

    // Un octet altere : depart, longueur, nombre d'objets.
    let start = data.len() - 16;
    for (name, offset, value) in [
        ("octet de depart", 0usize, 0x69u8),
        ("longueur sous le minimum", 1, 3),
        ("nombre d'objets a zero", 7, 0x00),
    ] {
        let mut mutated = data.clone();
        mutated[start + offset] = value;
        let flow = parse(*link_type, &mutated).expect("trame alteree");
        assert_ne!(label(&flow), Some("IEC 104"), "{name}");
    }
}
