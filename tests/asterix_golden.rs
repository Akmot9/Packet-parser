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
const LIMITS: &str = "tests/data/asterix_tshark_limits.tsv";

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
    // Codes IFF militaires (#119) : Mode 2 et Mode 1 valides, a zero.
    let mode_2 = report.mode_2.expect("I048/050");
    assert!(mode_2.validated && !mode_2.garbled && !mode_2.smoothed);
    assert_eq!(mode_2.to_string(), "0000");
    let mode_1 = report.mode_1.expect("I048/055");
    assert!(mode_1.validated);
    assert_eq!(mode_1.to_string(), "00");
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
/// `CAT:LEN:items/longueur;items/longueur|CAT:LEN:...`, les items par leur
/// suffixe (`010`, `RE`, `SP`), la longueur du record FSPEC compris.
fn oracle_shape(packet: &AsterixPacket<'_>) -> String {
    packet
        .blocks
        .iter()
        .map(|block| {
            let records = block
                .records
                .iter()
                .map(|record| {
                    let items = record
                        .items
                        .iter()
                        .map(|item| item.id.rsplit('/').next().unwrap_or(item.id))
                        .collect::<Vec<_>>()
                        .join(",");
                    let length = record.fspec.len()
                        + record
                            .items
                            .iter()
                            .map(|item| item.data.len())
                            .sum::<usize>();
                    format!("{items}/{length}")
                })
                .collect::<Vec<_>>()
                .join(";");
            format!("{}:{}:{records}", block.category, block.length)
        })
        .collect::<Vec<_>>()
        .join("|")
}

/// La forme que la crate doit produire la ou tshark bute sur un I002/050 de
/// deux octets. Deux cas : le record parasite qu'il lit dans l'octet restant
/// d'un bloc CAT 002 (un record qui ne commence pas par 010) disparait et
/// cet octet revient au record precedent ; ou, quand tshark a declare la
/// trame malformee sans rien lire de plus, le dernier record du dernier bloc
/// (celui qui porte le 050) recoit l'octet.
fn expected_beyond_tshark_limit(shape: &str) -> String {
    let mut removed = 0;
    let mut blocks: Vec<String> = shape
        .split('|')
        .map(|block| {
            let Some((category, rest)) = block.split_once(':') else {
                return block.to_string();
            };
            let Some((length, records)) = rest.split_once(':') else {
                return block.to_string();
            };
            if category != "2" {
                return block.to_string();
            }
            let mut kept: Vec<String> = Vec::new();
            for record in records.split(';') {
                if record.starts_with("010") {
                    kept.push(record.to_string());
                    continue;
                }
                removed += 1;
                let previous = kept.last_mut().expect("un record parasite suit un record");
                *previous = one_more_octet(previous);
            }
            format!("{category}:{length}:{}", kept.join(";"))
        })
        .collect();
    if removed == 0 {
        let last = blocks.last_mut().expect("au moins un bloc");
        assert!(
            last.starts_with("2:"),
            "tshark bute sur un bloc CAT 002 : {shape}"
        );
        let (head, record) = last.rsplit_once(';').unwrap_or_else(|| {
            let (head, record) = last.rsplit_once(':').expect("un record");
            (head, record)
        });
        let separator = if last.contains(';') { ';' } else { ':' };
        *last = format!("{head}{separator}{}", one_more_octet(record));
    }
    blocks.join("|")
}

/// `010,000,030,050/8` -> `010,000,030,050/9`.
fn one_more_octet(record: &str) -> String {
    let (items, length) = record.split_once('/').expect("longueur de record");
    assert!(
        items.ends_with("050"),
        "l'octet restant est celui de I002/050 : {record}"
    );
    let length: usize = length.parse().expect("longueur de record");
    format!("{items}/{}", length + 1)
}

/// `1-4,9` -> [1, 2, 3, 4, 9].
fn expand_frames(spec: &str) -> Vec<usize> {
    spec.split(',')
        .flat_map(|part| {
            let (start, end) = match part.split_once('-') {
                Some((start, end)) => (start, end),
                None => (part, part),
            };
            let start: usize = start.parse().expect("numero de trame");
            let end: usize = end.parse().expect("numero de trame");
            start..=end
        })
        .collect()
}

/// Lit un oracle groupe (`capture \t trames \t forme`) : pour chaque
/// capture, les trames et leur forme, dans l'ordre des numeros.
fn read_oracle(path: &Path) -> BTreeMap<String, Vec<(usize, String)>> {
    let oracle = fs::read_to_string(path).expect("oracle lisible");
    let mut expected: BTreeMap<String, Vec<(usize, String)>> = BTreeMap::new();
    for line in oracle.lines().filter(|line| !line.starts_with('#')) {
        let mut fields = line.split('\t');
        let (Some(file), Some(frames), Some(shape)) = (fields.next(), fields.next(), fields.next())
        else {
            panic!("ligne d'oracle malformee : {line}");
        };
        let entry = expected.entry(file.to_string()).or_default();
        for frame in expand_frames(frames) {
            entry.push((frame, shape.to_string()));
        }
    }
    for frames in expected.values_mut() {
        frames.sort_unstable();
    }
    expected
}

/// Parite exacte avec tshark sur les 44 411 trames ASTERIX du corpus que
/// tshark decode en entier : chaque trame est etiquetee ASTERIX, et la
/// sequence des data items et la longueur de chaque record de chaque data
/// block sont celles que tshark decode. Les 96 trames sur lesquelles tshark
/// bute (`asterix_tshark_limits.tsv`) ont leur propre test.
#[test]
fn every_frame_matches_the_tshark_oracle() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let expected = read_oracle(&base.join(ORACLE));
    assert_eq!(
        expected.keys().collect::<Vec<_>>(),
        [
            "cat048_multicast.pcap",
            "cat_034_048.pcap",
            "cat_062_065.pcap",
            "wireshark_8579_radardata.pcap",
            "wireshark_9239_cat008only-2.pcap",
            "wireshark_9239_cat008only.pcap",
            "wireshark_9624_cat62_re.pcap",
            "wireshark_9953_cat021023.pcap",
        ]
    );
    let limited = read_oracle(&base.join(LIMITS));

    let mut blocks_by_category: BTreeMap<u8, usize> = BTreeMap::new();
    let mut records_by_category: BTreeMap<u8, usize> = BTreeMap::new();
    let mut frames_checked = 0;
    for (file, oracle_frames) in &expected {
        let path = base.join(CORPUS).join(file);
        let FileRead::Frames { frames, .. } = read_capture(&path) else {
            panic!("{file} : capture illisible");
        };
        let asterix_frames = oracle_frames.len() + limited.get(file).map_or(0, Vec::len);
        // Les captures du lot defense portent aussi d'autres trafics
        // (fragments IPv4, STP, IGMP, CAT 023/247 a cote de CAT 021...) :
        // seules les captures monoflux couvrent toutes leurs trames.
        if !file.starts_with("wireshark_8579") {
            assert!(
                frames.len() >= asterix_frames,
                "{file} : {} trames pour {asterix_frames} dans l'oracle",
                frames.len()
            );
        }
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

    // Volumetrie de l'oracle, recoupee avec `tshark -z io,stat` et les
    // comptes de SOURCE.md.
    assert_eq!(frames_checked, 44_411);
    assert_eq!(
        blocks_by_category,
        BTreeMap::from(BLOCKS_BY_CATEGORY),
        "data blocks par categorie"
    );
    assert_eq!(
        records_by_category,
        BTreeMap::from(RECORDS_BY_CATEGORY),
        "records par categorie"
    );
}

/// Data blocks par categorie sur les 44 411 trames de l'oracle, comptes
/// dans l'oracle lui-meme (`tools/asterix_oracle.py`).
const BLOCKS_BY_CATEGORY: [(u8, usize); 11] = [
    (1, 29_520),
    (2, 19_512),
    (8, 67),
    (21, 1_555),
    (23, 30),
    (34, 7_913),
    (48, 7_484),
    (62, 7_759),
    (63, 307),
    (65, 1_526),
    (247, 3),
];

/// Records par categorie, idem : jusqu'a 18 blocs par datagramme et
/// plusieurs records par bloc dans radardata.pcap.
const RECORDS_BY_CATEGORY: [(u8, usize); 11] = [
    (1, 65_146),
    (2, 19_677),
    (8, 67),
    (21, 1_555),
    (23, 30),
    (34, 7_913),
    (48, 33_665),
    (62, 16_434),
    (63, 331),
    (65, 1_526),
    (247, 3),
];

/// Les 96 trames de `wireshark_8579_radardata.pcap` sur lesquelles tshark
/// 4.6.6 bute portent toutes un record CAT 002 dont I002/050 (`repetitive
/// fx`) occupe deux octets : le dissecteur genere de Wireshark borne cet
/// item au seul extent que la specification liste, lit un octet, puis prend
/// l'octet restant pour un record parasite (26 trames, `;060/2` lu au-dela
/// du bloc) ou declare la trame malformee quand plus rien ne suit (70). La
/// crate suit la specification : chaque trame est etiquetee ASTERIX,
/// decodee jusqu'au dernier octet, et sa forme est celle de tshark sans le
/// record parasite, I002/050 comptant pour deux octets.
#[test]
fn frames_beyond_the_tshark_i002_050_limit_decode_against_the_specification() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let limited = read_oracle(&base.join(LIMITS));
    assert_eq!(
        limited.keys().collect::<Vec<_>>(),
        ["wireshark_8579_radardata.pcap"]
    );
    let mut checked = 0;
    let mut two_octet_050 = 0;
    for (file, oracle_frames) in &limited {
        let path = base.join(CORPUS).join(file);
        let FileRead::Frames { frames, .. } = read_capture(&path) else {
            panic!("{file} : capture illisible");
        };
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
            assert_eq!(
                oracle_shape(&packet),
                expected_beyond_tshark_limit(shape),
                "{file}:{number}"
            );
            two_octet_050 += packet
                .blocks
                .iter()
                .flat_map(|block| &block.records)
                .filter(|record| record.item("I002/050").is_some_and(|data| data.len() == 2))
                .count();
            checked += 1;
        }
    }
    assert_eq!(checked, 96);
    assert_eq!(two_octet_050, 96, "un I002/050 de deux octets par trame");
}
