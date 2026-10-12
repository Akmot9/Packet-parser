// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests DIS (IEEE 1278.1) sur trames reelles (#123).
//!
//! Captures : `pcaps_exemple/protocols/dis/` (voir son `SOURCE.md`), cinq
//! fichiers, versions 4 a 7, PDU Transmitter, Signal, Underwater Acoustic
//! et Set Data, sur UDP 3000, 6993 et 22999.
//!
//! L'oracle est tshark 4.6.6 avec le decodage force sur ces trois ports
//! (`tools/dis_oracle.sh`) : pour chaque trame, l'en-tete (version,
//! exercice, type, famille, longueur, PDU Status) et le premier identifiant
//! d'entite du corps, figes dans `tests/data/dis_tshark_oracle.tsv` et
//! compares ici trame par trame. La crate est interrogee comme tshark, les
//! ports 6993 et 22999 declares par Decode As ; sans declaration, la sonde
//! aveugle etiquette toute trame dont les PDU pavent le datagramme — toutes
//! sauf les trois de `wireshark_3492_dis_test2.pcap` (Data Query, Set Data,
//! Data), qui annoncent 48 octets pour 160.

use std::{collections::BTreeMap, fs, path::Path};

use packet_parser::{
    DecodeAsProtocol, PacketFlow, ParseConfig, parse,
    parse::application::protocols::dis::{DisBody, DisPacket, PduType},
    parse_with,
};

mod common;
use common::{FileRead, collect_capture_files, read_capture};

const CORPUS: &str = "pcaps_exemple/protocols/dis";
const ORACLE: &str = "tests/data/dis_tshark_oracle.tsv";

/// Les colonnes 3 a 11 d'une ligne d'oracle.
type OracleRow = [String; 9];

fn read_oracle(path: &Path) -> BTreeMap<String, BTreeMap<usize, OracleRow>> {
    let oracle = fs::read_to_string(path).expect("oracle lisible");
    let mut expected: BTreeMap<String, BTreeMap<usize, OracleRow>> = BTreeMap::new();
    for line in oracle.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 11, "ligne d'oracle malformee : {line}");
        let frame: usize = fields[1].parse().expect("numero de trame");
        let row: OracleRow = fields[2..]
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .try_into()
            .expect("neuf colonnes");
        expected
            .entry(fields[0].to_string())
            .or_default()
            .insert(frame, row);
    }
    expected
}

/// Le premier identifiant d'entite du corps : tous les types du corpus
/// (Transmitter, Signal, Underwater Acoustic, Set Data) commencent par un.
fn entity_id(packet: &DisPacket<'_>) -> Option<(u16, u16, u16)> {
    let pdu = packet.pdus.first()?;
    let raw = match pdu.body {
        DisBody::Transmitter { entity_id, .. } | DisBody::Signal { entity_id, .. } => {
            return Some((entity_id.site, entity_id.application, entity_id.entity));
        }
        DisBody::EntityState { entity_id, .. } => {
            return Some((entity_id.site, entity_id.application, entity_id.entity));
        }
        DisBody::Opaque(body) => body,
        _ => return None,
    };
    let b = raw.get(..6)?;
    Some((
        u16::from_be_bytes([b[0], b[1]]),
        u16::from_be_bytes([b[2], b[3]]),
        u16::from_be_bytes([b[4], b[5]]),
    ))
}

fn oracle_row(packet: &DisPacket<'_>) -> OracleRow {
    let header = packet.pdus[0].header;
    let (site, application, entity) = entity_id(packet).expect("identifiant d'entite");
    [
        header.protocol_version.to_string(),
        header.exercise_id.to_string(),
        header.pdu_type.to_string(),
        header.protocol_family.to_string(),
        header.length.to_string(),
        site.to_string(),
        application.to_string(),
        entity.to_string(),
        header
            .status()
            .map_or("-".to_string(), |status| format!("{status:#04x}")),
    ]
}

fn label(flow: &PacketFlow<'_>) -> Option<&'static str> {
    flow.application
        .as_ref()
        .map(|application| application.application_protocol)
}

/// Parite avec tshark sur les 393 trames du corpus, les ports 6993 et 22999
/// declares par Decode As comme tshark les force.
#[test]
fn every_frame_matches_the_tshark_oracle() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let expected = read_oracle(&base.join(ORACLE));
    let mut captures = Vec::new();
    collect_capture_files(&base.join(CORPUS), &mut captures);
    assert_eq!(captures.len(), 5);
    let config = ParseConfig::new()
        .decode_as(6993, DecodeAsProtocol::Dis)
        .decode_as(22999, DecodeAsProtocol::Dis);

    let mut frames_checked = 0;
    let mut blind = 0;
    let mut by_type: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_version: BTreeMap<u8, usize> = BTreeMap::new();
    for path in &captures {
        let file = path.file_name().unwrap().to_string_lossy().to_string();
        let FileRead::Frames { frames, .. } = read_capture(path) else {
            panic!("{file} : capture illisible");
        };
        let oracle_frames = expected
            .get(&file)
            .unwrap_or_else(|| panic!("{file} absente de l'oracle"));
        assert_eq!(
            frames.len(),
            oracle_frames.len(),
            "{file} : tshark voit DIS partout"
        );
        for (index, (link_type, data)) in frames.iter().enumerate() {
            let number = index + 1;
            let row = &oracle_frames[&number];
            let flow = parse_with(*link_type, data, &config)
                .unwrap_or_else(|error| panic!("{file}:{number} : {error}"));
            assert_eq!(label(&flow), Some("DIS"), "{file}:{number}");
            let payload = flow.transport.as_ref().unwrap().payload.unwrap();
            let packet = DisPacket::try_from_lenient(payload)
                .unwrap_or_else(|error| panic!("{file}:{number} : {error}"));
            assert_eq!(&oracle_row(&packet), row, "{file}:{number}");
            assert_eq!(
                packet.pdus.len(),
                1,
                "{file}:{number} : un PDU par datagramme"
            );
            *by_type
                .entry(format!("{:?}", packet.pdus[0].pdu_type))
                .or_default() += 1;
            *by_version
                .entry(packet.pdus[0].header.protocol_version)
                .or_default() += 1;
            frames_checked += 1;

            // Sans declaration : la sonde aveugle, ou le port 3000.
            let default = parse(*link_type, data).unwrap();
            if label(&default) == Some("DIS") {
                blind += 1;
            } else {
                assert_eq!(file, "wireshark_3492_dis_test2.pcap", "{file}:{number}");
                assert_eq!(packet.trailing.len(), 112, "{file}:{number}");
                assert!(
                    matches!(
                        packet.pdus[0].pdu_type,
                        PduType::DataQuery | PduType::SetData | PduType::Data
                    ),
                    "{file}:{number}"
                );
            }
        }
    }
    assert_eq!(frames_checked, 393);
    assert_eq!(blind, 390, "toutes sauf les trois PDU a longueur fausse");
    assert_eq!(
        by_type,
        BTreeMap::from([
            ("Signal".to_string(), 302),
            ("Transmitter".to_string(), 72),
            ("UnderwaterAcoustic".to_string(), 16),
            ("DataQuery".to_string(), 1),
            ("SetData".to_string(), 1),
            ("Data".to_string(), 1),
        ])
    );
    assert_eq!(
        by_version,
        BTreeMap::from([(4, 3), (5, 269), (6, 111), (7, 10)])
    );
}

/// `wireshark_12043_dis_v7_transmitter.pcap` trame 1 : sur le port 3000,
/// la lecture tolerante ; les memes octets ailleurs, la sonde aveugle, qui
/// exige le pavage exact.
#[test]
fn port_3000_is_lenient_and_the_blind_probe_is_strict() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let FileRead::Frames { frames, .. } = read_capture(
        &base
            .join(CORPUS)
            .join("wireshark_12043_dis_v7_transmitter.pcap"),
    ) else {
        panic!("capture illisible");
    };
    let (link_type, data) = &frames[0];
    let flow = parse(*link_type, data).expect("trame 1");
    assert_eq!(label(&flow), Some("DIS"));

    // Un octet de plus apres le PDU : le port 3000 tolere, un autre port non.
    let mut longer = data.clone();
    longer.push(0);
    longer[16..18].copy_from_slice(&(u16::from_be_bytes([data[16], data[17]]) + 1).to_be_bytes());
    longer[38..40].copy_from_slice(&(u16::from_be_bytes([data[38], data[39]]) + 1).to_be_bytes());
    let flow = parse(*link_type, &longer).expect("trame allongee");
    assert_eq!(label(&flow), Some("DIS"));
    let payload = flow.transport.as_ref().unwrap().payload.unwrap();
    assert_eq!(
        DisPacket::try_from_lenient(payload).unwrap().trailing.len(),
        1
    );

    // Les deux ports valent 3000 : les deux changent.
    let mut moved = longer.clone();
    moved[34..38].copy_from_slice(&[0x0b, 0xb9, 0x0b, 0xb9]);
    let flow = parse(*link_type, &moved).expect("trame deplacee");
    assert_eq!(label(&flow), Some("Unknown"));
    // Sans l'octet de trop, le pavage est exact : la sonde aveugle suffit.
    let mut moved = data.clone();
    moved[34..38].copy_from_slice(&[0x0b, 0xb9, 0x0b, 0xb9]);
    let flow = parse(*link_type, &moved).expect("trame deplacee");
    assert_eq!(label(&flow), Some("DIS"));
}
