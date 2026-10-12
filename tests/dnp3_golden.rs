// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests DNP3 (IEEE 1815) sur trames reelles (#99).
//!
//! Captures : `pcaps_exemple/protocols/dnp3/` (voir son `SOURCE.md`), seize
//! fichiers du corpus de tests de Zeek, TCP et UDP, dont une lecture sur le
//! port 20001 qui prouve le sondage sans port.
//!
//! L'oracle est tshark 4.6.6 sans reassemblage TCP (`tools/dnp3_oracle.sh`,
//! la vue d'un parseur sans etat) : pour chaque segment ou datagramme a
//! payload, la liaison (longueur, controle, fonction, adresses, CRC
//! d'en-tete), le transport (controle, premier, dernier, sequence) et,
//! quand le fragment applicatif tient dans la trame, l'application
//! (controle, fonction, IIN, en-tetes d'objets avec prefixes et plages).
//! tshark reassemble les fragments repartis sur plusieurs trames de liaison
//! et ne montre l'application que sur la derniere : le parseur sans etat
//! decode l'en-tete applicatif sur la premiere et rien sur les suivantes.

use std::{collections::BTreeMap, fs, path::Path};

use packet_parser::{
    PacketFlow, parse,
    parse::application::protocols::dnp3::{Dnp3Packet, LinkFrame},
};

mod common;
use common::{FileRead, collect_capture_files, read_capture};

const CORPUS: &str = "pcaps_exemple/protocols/dnp3";
const ORACLE: &str = "tests/data/dnp3_tshark_oracle.tsv";

/// Les colonnes 3 a 22 d'une ligne d'oracle.
type OracleRow = [String; 20];

fn read_oracle(path: &Path) -> BTreeMap<String, BTreeMap<usize, OracleRow>> {
    let oracle = fs::read_to_string(path).expect("oracle lisible");
    let mut expected: BTreeMap<String, BTreeMap<usize, OracleRow>> = BTreeMap::new();
    for line in oracle.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 22, "ligne d'oracle malformee : {line}");
        let row: OracleRow = fields[2..]
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .try_into()
            .expect("vingt colonnes");
        expected
            .entry(fields[0].to_string())
            .or_default()
            .insert(fields[1].parse().expect("numero de trame"), row);
    }
    expected
}

fn label(flow: &PacketFlow<'_>) -> Option<&'static str> {
    flow.application
        .as_ref()
        .map(|application| application.application_protocol)
}

fn join<T: ToString>(values: impl Iterator<Item = T>) -> String {
    let joined = values.map(|v| v.to_string()).collect::<Vec<_>>().join(",");
    if joined.is_empty() {
        "-".to_string()
    } else {
        joined
    }
}

/// Les colonnes liaison et transport (7 a 16) d'une trame.
fn link_columns(frame: &LinkFrame<'_>) -> [String; 10] {
    let header = frame.header;
    let (tr, fir, fin, seq) = match frame.transport {
        Some(transport) => (
            format!("{:#04x}", transport.raw),
            bool_name(transport.is_first()),
            bool_name(transport.is_final()),
            transport.sequence().to_string(),
        ),
        None => (
            "-".to_string(),
            "-".to_string(),
            "-".to_string(),
            "-".to_string(),
        ),
    };
    [
        header.length.to_string(),
        format!("{:#04x}", header.control),
        header.function_code().to_string(),
        header.destination.to_string(),
        header.source.to_string(),
        format!("{:#06x}", header.crc),
        tr,
        fir,
        fin,
        seq,
    ]
}

/// Les colonnes application (17 a 22) d'une trame.
fn application_columns(frame: &LinkFrame<'_>) -> [String; 6] {
    let application = frame.application.as_ref().expect("application");
    [
        format!("{:#04x}", application.header.control),
        application.header.function_code.to_string(),
        application
            .header
            .internal_indications
            .map_or("-".to_string(), |iin| {
                format!("{:#06x}", u16::from_be_bytes(iin))
            }),
        join(
            application
                .objects
                .iter()
                .map(|o| format!("{:#06x}", u16::from(o.group) << 8 | u16::from(o.variation))),
        ),
        join(
            application
                .objects
                .iter()
                .map(|o| (o.qualifier >> 4) & 0x07),
        ),
        join(application.objects.iter().map(|o| o.qualifier & 0x0f)),
    ]
}

fn bool_name(value: bool) -> String {
    if value { "True" } else { "False" }.to_string()
}

/// Parite avec tshark sur les 220 segments et datagrammes du corpus.
#[test]
fn every_frame_matches_the_tshark_oracle() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let expected = read_oracle(&base.join(ORACLE));
    let mut captures = Vec::new();
    collect_capture_files(&base.join(CORPUS), &mut captures);
    assert_eq!(captures.len(), 16);

    let mut segments = 0;
    let mut dnp3_frames = 0;
    let mut link_only = 0;
    let mut single_frame_fragments = 0;
    let mut first_of_many = 0;
    let mut continuations = 0;
    let mut objects = 0;
    let mut stop_application_with_objects = 0;
    let mut by_carrier: BTreeMap<&str, usize> = BTreeMap::new();
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
                    Some(row[1].parse().unwrap()),
                    Some(row[2].parse().unwrap()),
                    row[3].parse().unwrap()
                ),
                "{file}:{number}"
            );
            segments += 1;
            if row[4] == "-" {
                assert_ne!(label(&flow), Some("DNP3"), "{file}:{number}");
                continue;
            }
            assert_eq!(label(&flow), Some("DNP3"), "{file}:{number}");
            *by_carrier
                .entry(if row[0] == "tcp" { "tcp" } else { "udp" })
                .or_default() += 1;
            let packet = Dnp3Packet::try_from(payload)
                .unwrap_or_else(|error| panic!("{file}:{number} : {error}"));
            assert_eq!(
                packet.frames.len(),
                1,
                "{file}:{number} : une trame par segment"
            );
            let frame = &packet.frames[0];
            assert_eq!(&link_columns(frame)[..], &row[4..14], "{file}:{number}");
            assert_eq!(
                frame.user_data.len(),
                usize::from(frame.header.length) - 5,
                "{file}:{number}"
            );
            dnp3_frames += 1;

            let Some(transport) = frame.transport else {
                assert_eq!(row[10], "-", "{file}:{number}");
                assert_eq!(frame.application, None);
                link_only += 1;
                continue;
            };
            match (transport.is_first(), transport.is_final()) {
                (true, true) => {
                    assert_ne!(
                        row[14], "-",
                        "{file}:{number} : tshark montre l'application"
                    );
                    let columns = application_columns(frame);
                    let application = frame.application.as_ref().unwrap();
                    if row[17] == "-" && !application.objects.is_empty() {
                        // tshark ne dissèque pas les objets d'un STOP_APPL ; la
                        // crate les lit comme ceux de n'importe quelle requete.
                        assert_eq!(application.header.function_code, 18, "{file}:{number}");
                        assert_eq!(&columns[..3], &row[14..17], "{file}:{number}");
                        stop_application_with_objects += 1;
                        single_frame_fragments += 1;
                        continue;
                    }
                    assert_eq!(&columns[..], &row[14..20], "{file}:{number}");
                    assert!(
                        application.undecoded.is_empty() || row[19].contains("13"),
                        "{file}:{number} : {} octets non decodes",
                        application.undecoded.len()
                    );
                    objects += application.objects.len();
                    single_frame_fragments += 1;
                }
                (true, false) => {
                    // tshark attend la fin du fragment ; le parseur sans etat
                    // lit deja l'en-tete applicatif du premier segment.
                    assert_eq!(row[14], "-", "{file}:{number}");
                    let application = frame
                        .application
                        .as_ref()
                        .expect("en-tete du premier segment");
                    // Le FIR applicatif, lui, ne marque que le premier fragment
                    // d'un message en plusieurs (trame 22 de dnp3_link_only.pcap).
                    assert!(application.header.function().is_some(), "{file}:{number}");
                    first_of_many += 1;
                }
                (false, _) => {
                    assert_eq!(frame.application, None, "{file}:{number}");
                    continuations += 1;
                }
            }
        }
    }
    assert_eq!(segments, 220);
    assert_eq!(dnp3_frames, 218);
    assert_eq!(by_carrier, BTreeMap::from([("tcp", 179), ("udp", 39)]));
    assert_eq!(link_only, 16);
    assert_eq!(single_frame_fragments, 159);
    assert_eq!(first_of_many, 7);
    assert_eq!(continuations, 36);
    assert_eq!(objects, 160);
    // Les quatre STOP_APPL de dnp3.pcap portent des en-tetes d'objets que
    // tshark ne dissèque pas pour cette fonction.
    assert_eq!(stop_application_with_objects, 4);
}

/// `dnp3_read.pcap` trame 4, alteree d'un octet : chaque alteration casse un
/// CRC, un octet de depart ou une longueur, et la trame cesse d'etre du
/// DNP3 — a l'aveugle comme au decodage.
#[test]
fn mutated_real_frames_are_rejected() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let FileRead::Frames { frames, .. } = read_capture(&base.join(CORPUS).join("dnp3_read.pcap"))
    else {
        panic!("capture illisible");
    };
    let (link_type, data) = &frames[3];
    let flow = parse(*link_type, data).expect("trame 4");
    assert_eq!(label(&flow), Some("DNP3"));
    let payload = flow.transport.as_ref().unwrap().payload.unwrap();
    assert_eq!(payload.len(), 27);
    // Ethernet + IPv4 + TCP sans option : le payload commence a l'octet 54.
    let start = data.len() - payload.len();
    assert_eq!(&data[start..], payload);

    let mut mutations: Vec<(&str, usize)> = vec![
        ("second start byte", 1),
        ("link length", 2),
        ("link control", 3),
        ("destination address", 4),
        ("header CRC", 8),
        ("transport control", 10),
        ("application function", 12),
        ("an object header", 14),
        ("last data byte", 24),
        ("block CRC", 25),
    ];
    for (name, offset) in mutations.drain(..) {
        let mut mutated = data.clone();
        mutated[start + offset] ^= 0x01;
        assert!(
            Dnp3Packet::try_from(&mutated[start..]).is_err(),
            "accepted mutated frame: {name}"
        );
        let flow = parse(*link_type, &mutated).expect("trame alteree");
        assert_ne!(label(&flow), Some("DNP3"), "{name}");
    }
    // Et la trame intacte, elle, reste du DNP3 sur n'importe quel port.
    let mut moved = data.clone();
    moved[36..38].copy_from_slice(&40_000u16.to_be_bytes());
    let flow = parse(*link_type, &moved).expect("trame deplacee");
    assert_eq!(label(&flow), Some("DNP3"));
}
