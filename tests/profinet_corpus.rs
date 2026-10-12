// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden PROFINET sur `pcaps_exemple/protocols/profinet/` (issues #133 et
//! #141), oracle tshark 4.6.6 dans `tests/data/profinet_tshark_oracle.tsv` :
//! pour chaque trame PN-RT, son Frame ID, et pour les messages DCP le
//! service et le NameOfStation (`pn_dcp.suboption_device_nameofstation`),
//! plus l'indicateur `_ws.malformed`.
//!
//! La crate doit retrouver toutes les trames PN-RT par leur EtherType (VLAN
//! compris), classer chaque Frame ID comme tshark, lire le meme NameOfStation
//! sur chaque message DCP, et ne refuser que ce que tshark declare malforme.
//! L'histogramme des issues est fige en fin de test, comme `golden_pcaps`.

use std::collections::BTreeMap;
use std::path::Path;

use packet_parser::parse::internet::protocols::profinet::{
    FrameId, ProfinetPacket, validate_frame,
};
use packet_parser::{CorruptedLayerKind, NetworkProtocol, parse};

mod common;
use common::{FileRead, collect_capture_files, read_capture};

/// Trames PN-RT par capture, comptees par `tshark -Y pn_rt`.
const PN_RT_FRAMES: &[(&str, usize)] = &[
    ("cisagov_profinet_io_cm.pcap", 10),
    ("cisagov_profinet_io_cm_mixed_1.pcap", 164),
    ("iti_ChangeIPUsingDCP.pcap", 4),
    ("iti_PROFINET-RT.pcap", 14),
    ("iti_profinet-wireshark-bug.pcap", 4),
    ("miguelob_pn.pcapng", 18),
    ("miguelob_pn_dcp.pcapng", 18),
];

struct OracleRow {
    frame_id: u16,
    service: Option<(u8, u8)>,
    name_of_station: String,
    malformed: bool,
}

fn read_oracle() -> BTreeMap<(String, usize), OracleRow> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("profinet_tshark_oracle.tsv");
    let text = std::fs::read_to_string(&path).expect("oracle tshark lisible");
    text.lines()
        .skip(1)
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let fields: Vec<&str> = line.split('\t').collect();
            assert_eq!(fields.len(), 7, "ligne d'oracle : {line}");
            let service = match (fields[3], fields[4]) {
                ("", _) | (_, "") => None,
                (id, kind) => Some((
                    id.parse().expect("service id"),
                    kind.parse().expect("service type"),
                )),
            };
            (
                (
                    fields[0].to_string(),
                    fields[1].parse().expect("numero de trame"),
                ),
                OracleRow {
                    frame_id: fields[2].parse().expect("frame id"),
                    service,
                    name_of_station: fields[5].to_string(),
                    malformed: fields[6] == "1",
                },
            )
        })
        .collect()
}

/// Variante de `ProfinetPacketError` derriere le texte de `CorruptedLayer`.
fn error_variant(error: &str) -> &'static str {
    const VARIANTS: &[(&str, &str)] = &[
        ("Unknown Frame ID", "UnknownFrameId"),
        ("Invalid DCP block length", "InvalidDcpBlockLength"),
        ("Invalid name of station", "InvalidNameOfStation"),
        ("Packet too short", "PacketTooShort"),
        ("too short for a Frame ID", "FrameTooShort"),
        ("is not a DCP frame", "NotDcp"),
        ("DCP data length", "DcpDataOverflow"),
        ("needed for its BlockInfo", "DcpBlockTooShort"),
        ("DCP block option", "DcpBlockOverflow"),
    ];
    VARIANTS
        .iter()
        .find(|(needle, _)| error.contains(needle))
        .map(|(_, name)| *name)
        .unwrap_or_else(|| panic!("erreur PROFINET inattendue : {error}"))
}

#[test]
fn profinet_frames_match_the_tshark_oracle_and_their_outcome_is_frozen() {
    let oracle = read_oracle();
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("pcaps_exemple")
        .join("protocols")
        .join("profinet");
    let mut captures = Vec::new();
    collect_capture_files(dir.as_path(), &mut captures);
    captures.sort();

    let mut per_file: BTreeMap<String, usize> = BTreeMap::new();
    let mut outcomes: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut seen = 0;
    for path in &captures {
        let name = path
            .file_name()
            .expect("nom de fichier")
            .to_string_lossy()
            .into_owned();
        let FileRead::Frames {
            frames,
            read_error_after,
        } = read_capture(path)
        else {
            panic!("{name}: format de capture non lu");
        };
        assert_eq!(read_error_after, None, "{name}: lecture interrompue");
        for (index, (link_type, data)) in frames.iter().enumerate() {
            let frame_number = index + 1;
            let flow = parse(*link_type, data)
                .unwrap_or_else(|error| panic!("{name}#{frame_number}: {error}"));
            let is_profinet = flow.data_link.network_protocol() == NetworkProtocol::Profinet;
            let row = oracle.get(&(name.clone(), frame_number));
            assert_eq!(
                is_profinet,
                row.is_some(),
                "{name}#{frame_number}: tshark et la crate ne voient pas la meme trame PN-RT"
            );
            let Some(row) = row else { continue };
            seen += 1;
            *per_file.entry(name.clone()).or_default() += 1;
            let payload = flow.data_link.network_payload();

            // Rien n'est parse au-dessus d'une trame PROFINET, valide ou non.
            assert!(
                flow.transport.is_none() && flow.application.is_none(),
                "{name}#{frame_number}"
            );

            // Le Frame ID est classe comme tshark le lit.
            let expected_class = FrameId::from_u16(row.frame_id).unwrap_or_else(|| {
                panic!(
                    "{name}#{frame_number}: Frame ID {:#06x} sans classe",
                    row.frame_id
                )
            });
            let validated = validate_frame(payload);
            let outcome = match (&flow.internet, &flow.corrupted) {
                (Some(internet), None) => {
                    assert_eq!(internet.protocol_name, "Profinet");
                    assert!(internet.source.is_none() && internet.payload.is_empty());
                    assert_eq!(
                        validated,
                        Ok(expected_class.clone()),
                        "{name}#{frame_number}"
                    );
                    assert!(
                        !row.malformed,
                        "{name}#{frame_number}: tshark la declare malformee"
                    );
                    "Profinet"
                }
                (None, Some(corrupted)) => {
                    assert_eq!(corrupted.layer, CorruptedLayerKind::Internet);
                    assert!(validated.is_err(), "{name}#{frame_number}");
                    assert!(
                        row.malformed,
                        "{name}#{frame_number}: refusee par la crate ({}) mais pas par tshark",
                        corrupted.error
                    );
                    error_variant(&corrupted.error)
                }
                (internet, corrupted) => {
                    panic!("{name}#{frame_number}: internet={internet:?} corrupted={corrupted:?}")
                }
            };
            *outcomes.entry(outcome).or_default() += 1;

            // Sur un message DCP lisible, le service et le NameOfStation sont ceux de tshark.
            if expected_class.is_dcp() && !row.malformed {
                let packet = ProfinetPacket::try_from(payload)
                    .unwrap_or_else(|error| panic!("{name}#{frame_number}: {error}"));
                assert_eq!(
                    Some((packet.service_id, packet.service_type)),
                    row.service,
                    "{name}#{frame_number}"
                );
                assert_eq!(
                    packet.name_of_station, row.name_of_station,
                    "{name}#{frame_number}"
                );
            }
        }
    }
    assert_eq!(
        seen,
        oracle.len(),
        "trames PN-RT de l'oracle non rencontrees"
    );

    let expected_per_file: BTreeMap<String, usize> = PN_RT_FRAMES
        .iter()
        .map(|(file, count)| ((*file).to_string(), *count))
        .collect();
    assert_eq!(
        per_file, expected_per_file,
        "trames PN-RT par capture (oracle : tshark -Y pn_rt)"
    );

    // 232 trames PN-RT. Avant #133 et #141, 129 sortaient `corrupted` ; il
    // reste la seule que tshark declare malformee : miguelob_pn_dcp.pcapng#3,
    // une Identify request de 32 octets capturee en sortie, dont
    // DCPDataLength annonce 4 octets de blocs quand 2 sont presents.
    let expected: BTreeMap<&str, usize> = [("Profinet", 231), ("DcpDataOverflow", 1)]
        .into_iter()
        .collect();
    assert_eq!(
        outcomes, expected,
        "\nissue de la validation par trame PN-RT (a figer si le changement est voulu) :\n{outcomes:#?}\n"
    );
}
