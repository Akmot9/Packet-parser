// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests ASTERIX sur trames reelles.
//!
//! Captures : `pcaps_exemple/protocols/asterix/` (voir son `SOURCE.md`) —
//! `cat048_multicast.pcap`, 203 datagrammes CAT 048 d'une capture du
//! mainteneur anonymisee, sur les ports UDP 8611 et 8612 ; `cat_034_048.pcap`,
//! 100 datagrammes CAT 034 et 048 des echantillons CroatiaControlLtd/asterix,
//! dont vingt portent deux data blocks ; et `cat21_re.ast`, un flux brut de
//! deux data blocks CAT 021 du meme depot.
//!
//! L'oracle est tshark 4.6.6 (`-d udp.port==8000-23000,asterix`) : la
//! sequence exacte des data items de chaque record, pour chaque trame, est
//! figee dans `tests/data/asterix_tshark_oracle.tsv` et comparee ici, et les
//! valeurs des items types sont recoupees avec sa sortie `-V`.

use std::{collections::BTreeMap, fs, path::Path};

use packet_parser::{
    LinkType, parse,
    parse::application::protocols::asterix::{
        AsterixPacket, cat034, cat048,
        fields::{AircraftAddress, TimeOfDay},
    },
};

mod common;
use common::{FileRead, read_capture};

const CORPUS: &str = "pcaps_exemple/protocols/asterix";
const ORACLE: &str = "tests/data/asterix_tshark_oracle.tsv";

fn frame(hex_fixture: &str, expected_len: usize) -> Vec<u8> {
    let bytes = hex::decode(hex_fixture).expect("invalid test hex fixture");
    assert_eq!(
        bytes.len(),
        expected_len,
        "fixture length must match capture"
    );
    bytes
}

fn asterix_payload(bytes: &[u8]) -> AsterixPacket<'_> {
    let flow = parse(LinkType::ETHERNET, bytes).expect("captured frame decodes");
    assert_eq!(
        flow.application
            .as_ref()
            .expect("an application layer is detected")
            .application_protocol,
        "ASTERIX"
    );
    let payload = flow
        .transport
        .as_ref()
        .and_then(|transport| transport.payload)
        .expect("la couche transport porte le datagramme");
    AsterixPacket::try_from(payload).expect("captured ASTERIX datagram decodes")
}

/// `cat048_multicast.pcap` trame 1 : 10.0.2.11:46227 -> 239.192.0.11:8611,
/// un data block CAT 048 de 49 octets, un record de 19 items (FSPEC
/// `ff c3 3f 78`). tshark : SAC 0, SIC 2, ToD 0.0078125 s, TYP 3, RHO
/// 85.234375 NM, THETA 242.940673828125 deg, Mode 3/A 01000, FL 0, adresse
/// 0x00000d, identification `0001000 `, hauteur 3D 2250 ft.
const CAT048_MULTICAST_FRAME_1_HEX: &str = concat!(
    "01005e40000b02000000020b08004500004d71c1400002110b090a00020befc0000bb49321a30039c022",
    "300031ffc33f78000200000160553cacc2020000000000000dc30c31c30c2000000601451006005a005b6",
    "0000000000000"
);

#[test]
fn packet_flow_labels_asterix_without_a_port_rule() {
    let bytes = frame(CAT048_MULTICAST_FRAME_1_HEX, 91);
    let packet = asterix_payload(&bytes);
    assert_eq!(packet.blocks.len(), 1);
    assert_eq!(
        (packet.blocks[0].category, packet.blocks[0].length),
        (48, 49)
    );
    assert_eq!(packet.blocks[0].records.len(), 1);
    assert_eq!(packet.blocks[0].records[0].fspec, &[0xff, 0xc3, 0x3f, 0x78]);
}

#[test]
fn cat048_target_report_decodes_against_the_wire() {
    let bytes = frame(CAT048_MULTICAST_FRAME_1_HEX, 91);
    let packet = asterix_payload(&bytes);
    let record = &packet.blocks[0].records[0];
    let ids: Vec<&str> = record.items.iter().map(|item| item.id).collect();
    assert_eq!(
        ids,
        [
            "I048/010", "I048/140", "I048/020", "I048/040", "I048/070", "I048/090", "I048/130",
            "I048/220", "I048/240", "I048/170", "I048/080", "I048/100", "I048/110", "I048/120",
            "I048/230", "I048/055", "I048/050", "I048/065", "I048/060",
        ]
    );
    // Radar Plot Characteristics et Radial Doppler Speed : primary
    // subfield vide, un octet chacun.
    assert_eq!(record.item("I048/130"), Some(&[0x00][..]));
    assert_eq!(record.item("I048/120"), Some(&[0x00][..]));

    let report = cat048::TargetReport::from_record(record).expect("record CAT 048");
    assert_eq!(report.data_source.map(|d| (d.sac, d.sic)), Some((0, 2)));
    assert_eq!(report.time_of_day.map(|t| t.raw), Some(1));
    assert_eq!(
        report.time_of_day.map(TimeOfDay::seconds),
        Some(0.007_812_5)
    );
    assert_eq!(
        report.descriptor.map(|d| d.detection),
        Some(cat048::DetectionType::SsrPlusPsr)
    );
    let position = report.polar_position.unwrap();
    assert_eq!(position.range_nm(), 85.234_375);
    assert_eq!(position.azimuth_deg(), 242.940_673_828_125);
    assert_eq!(report.mode_3a.unwrap().to_string(), "1000");
    assert_eq!(report.flight_level.unwrap().flight_level(), 0.0);
    assert_eq!(report.aircraft_address, Some(AircraftAddress(0x0d)));
    assert_eq!(report.aircraft_identification.unwrap().as_str(), "0001000 ");
    assert_eq!(report.height_3d, Some(90)); // 90 x 25 ft = 2250 ft
    assert_eq!(report.track_number, None);
    assert_eq!(report.polar_velocity, None);
    assert_eq!(report.mode_s_mb_data_count, None);
}

/// `cat_034_048.pcap` trame 3 : 10.17.58.184:21154 -> 232.2.1.13:22113, deux
/// data blocks dans le meme datagramme — CAT 048 (55 octets, piste THY9TX)
/// puis CAT 034 (11 octets, franchissement de secteur). tshark : SAC 25,
/// SIC 13 ; 048 : ToD 27355.859375 s, TYP 5, RHO 194.82421875 NM, THETA
/// 128.759765625 deg, Mode 3/A 02303, FL 360, adresse 0x4baacd, un
/// registre BDS, piste 482, X 151.921875 NM, Y -121.96875 NM, GSP
/// 0.1268310546875 NM/s, HDG 263.6004638671875 deg ; 034 : type 2, ToD
/// 27355.953125 s, secteur 135 deg.
const CAT_034_048_FRAME_3_HEX: &str = concat!(
    "01005e02010dbc1665fe5fc208004500005e000040003d110fb70a113ab8e802010d52a25661004a869d",
    "300037ffff02190d356deea0c2d35b9004c305a0e0560bb84baacd50867951882001c65632b0a8000040",
    "01e24bf6c304081ebb734020f5",
    "22000bf0190d02356dfa60"
);

#[test]
fn a_datagram_carrying_two_data_blocks_decodes_both() {
    let bytes = frame(CAT_034_048_FRAME_3_HEX, 108);
    let packet = asterix_payload(&bytes);
    assert_eq!(
        packet
            .blocks
            .iter()
            .map(|block| (block.category, block.length, block.records.len()))
            .collect::<Vec<_>>(),
        [(48, 55, 1), (34, 11, 1)]
    );

    let target = &packet.blocks[0].records[0];
    assert_eq!(cat034::ServiceMessage::from_record(target), None);
    let report = cat048::TargetReport::from_record(target).unwrap();
    assert_eq!(report.data_source.map(|d| (d.sac, d.sic)), Some((25, 13)));
    assert_eq!(
        report.time_of_day.map(TimeOfDay::seconds),
        Some(27_355.859_375)
    );
    assert_eq!(
        report.descriptor.map(|d| d.detection),
        Some(cat048::DetectionType::SingleModeSRollCall)
    );
    assert_eq!(report.polar_position.unwrap().range_nm(), 194.824_218_75);
    assert_eq!(
        report.polar_position.unwrap().azimuth_deg(),
        128.759_765_625
    );
    assert_eq!(report.mode_3a.unwrap().to_string(), "2303");
    assert_eq!(report.flight_level.unwrap().flight_level(), 360.0);
    assert_eq!(report.aircraft_address.unwrap().to_string(), "4BAACD");
    assert_eq!(report.aircraft_identification.unwrap().trimmed(), "THY9TX");
    assert_eq!(report.mode_s_mb_data_count, Some(1));
    assert_eq!(report.track_number, Some(482));
    let cartesian = report.cartesian_position.unwrap();
    assert_eq!(f64::from(cartesian.x) / 128.0, 151.921_875);
    assert_eq!(f64::from(cartesian.y) / 128.0, -121.968_75);
    let velocity = report.polar_velocity.unwrap();
    assert_eq!(
        f64::from(velocity.ground_speed) / 16_384.0,
        0.126_831_054_687_5
    );
    assert_eq!(velocity.heading_deg(), 263.600_463_867_187_5);
    let status = report.track_status.unwrap();
    assert!(status.confirmed);
    assert_eq!(status.sensor, 2);

    let service = &packet.blocks[1].records[0];
    assert_eq!(cat048::TargetReport::from_record(service), None);
    let message = cat034::ServiceMessage::from_record(service).unwrap();
    assert_eq!(message.data_source.map(|d| (d.sac, d.sic)), Some((25, 13)));
    assert_eq!(
        message.message_type,
        Some(cat034::MessageType::SectorCrossing)
    );
    assert_eq!(
        message.time_of_day.map(TimeOfDay::seconds),
        Some(27_355.953_125)
    );
    assert_eq!(message.sector_number, Some(96));
    assert_eq!(message.sector_azimuth_deg(), Some(135.0));
}

/// Le flux brut CAT 021 (`cat21_re.ast`, 91 octets) est un buffer de deux
/// data blocks : le decodeur enchaine les blocs jusqu'au dernier octet.
#[test]
fn cat021_raw_stream_decodes_both_blocks() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(CORPUS)
        .join("cat21_re.ast");
    let bytes = fs::read(&path).expect("cat21_re.ast lisible");
    assert_eq!(bytes.len(), 91);
    let packet = AsterixPacket::try_from(bytes.as_slice()).expect("flux CAT 021 decode");
    assert_eq!(
        packet
            .blocks
            .iter()
            .map(|block| (block.category, block.length, block.records.len()))
            .collect::<Vec<_>>(),
        [(21, 44, 1), (21, 47, 1)]
    );
    // Les valeurs sont recoupees avec tshark dans les tests unitaires du
    // module cat021 ; ici, l'invariant du flux : les deux records portent la
    // meme source et des adresses cibles consecutives.
    use packet_parser::parse::application::protocols::asterix::cat021::TargetReport;
    let reports: Vec<TargetReport> = packet
        .blocks
        .iter()
        .map(|block| TargetReport::from_record(&block.records[0]).unwrap())
        .collect();
    assert!(
        reports
            .iter()
            .all(|r| r.data_source.map(|d| (d.sac, d.sic)) == Some((0, 1)))
    );
    assert_eq!(
        reports.iter().map(|r| r.target_address).collect::<Vec<_>>(),
        [Some(AircraftAddress(1)), Some(AircraftAddress(2))]
    );
}

/// Rend les data blocks d'un datagramme dans le format de l'oracle tshark :
/// `CAT:LEN:items;items|CAT:LEN:items`, les items par leur suffixe
/// (`010`, `RE`, `SP`).
fn oracle_shape(packet: &AsterixPacket<'_>) -> String {
    packet
        .blocks
        .iter()
        .map(|block| {
            let records = block
                .records
                .iter()
                .map(|record| {
                    record
                        .items
                        .iter()
                        .map(|item| item.id.rsplit('/').next().unwrap_or(item.id))
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .collect::<Vec<_>>()
                .join(";");
            format!("{}:{}:{records}", block.category, block.length)
        })
        .collect::<Vec<_>>()
        .join("|")
}

/// Parite exacte avec tshark sur les 303 trames du corpus : chaque trame
/// est etiquetee ASTERIX, et la sequence des data items de chaque record de
/// chaque data block est celle que tshark decode.
#[test]
fn every_frame_matches_the_tshark_oracle() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let oracle = fs::read_to_string(base.join(ORACLE)).expect("oracle lisible");
    let mut expected: BTreeMap<String, Vec<(usize, String)>> = BTreeMap::new();
    for line in oracle.lines().filter(|line| !line.starts_with('#')) {
        let mut fields = line.split('\t');
        let (Some(file), Some(number), Some(shape)) = (fields.next(), fields.next(), fields.next())
        else {
            panic!("ligne d'oracle malformee : {line}");
        };
        expected
            .entry(file.to_string())
            .or_default()
            .push((number.parse().expect("numero de trame"), shape.to_string()));
    }
    assert_eq!(
        expected.keys().collect::<Vec<_>>(),
        ["cat048_multicast.pcap", "cat_034_048.pcap"]
    );

    let mut blocks_by_category: BTreeMap<u8, usize> = BTreeMap::new();
    let mut records_by_category: BTreeMap<u8, usize> = BTreeMap::new();
    let mut frames_checked = 0;
    for (file, oracle_frames) in &expected {
        let path = base.join(CORPUS).join(file);
        let FileRead::Frames { frames, .. } = read_capture(&path) else {
            panic!("{file} : capture illisible");
        };
        assert_eq!(
            frames.len(),
            oracle_frames.len(),
            "{file} : tshark voit ASTERIX sur chaque trame"
        );
        for (number, shape) in oracle_frames {
            let (link_type, data) = &frames[number - 1];
            let flow =
                parse(*link_type, data).unwrap_or_else(|error| panic!("{file}:{number} : {error}"));
            assert_eq!(
                flow.application.as_ref().map(|a| a.application_protocol),
                Some("ASTERIX"),
                "{file}:{number}"
            );
            let payload = flow
                .transport
                .as_ref()
                .and_then(|transport| transport.payload)
                .expect("datagramme UDP");
            let packet = AsterixPacket::try_from(payload)
                .unwrap_or_else(|error| panic!("{file}:{number} : {error}"));
            assert_eq!(&oracle_shape(&packet), shape, "{file}:{number}");
            for block in &packet.blocks {
                *blocks_by_category.entry(block.category).or_default() += 1;
                *records_by_category.entry(block.category).or_default() += block.records.len();
            }
            frames_checked += 1;
        }
    }

    // Volumetrie de l'oracle : 303 trames, 34 data blocks CAT 034 (un record
    // chacun) et 289 CAT 048 portant 331 records — jusqu'a trois par bloc
    // dans cat_034_048.pcap.
    assert_eq!(frames_checked, 303);
    assert_eq!(blocks_by_category, BTreeMap::from([(34, 34), (48, 289)]));
    assert_eq!(records_by_category, BTreeMap::from([(34, 34), (48, 331)]));
}
