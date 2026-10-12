// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests RTPS (OMG DDSI-RTPS 2.x) sur trames reelles (#120).
//!
//! Captures : `pcaps_exemple/protocols/rtps/` (voir son `SOURCE.md`), huit
//! fichiers et six implementations (RTI Connext et Connext Micro, Cyclone
//! DDS, OpenDDS, OpenSplice, CoreDX), en Ethernet comme en LINKTYPE_NULL,
//! sur des ports fixes comme aleatoires.
//!
//! L'oracle est tshark 4.6.6 sans reassemblage IP (`tools/rtps_oracle.sh`) :
//! pour chaque trame RTPS, version, vendorId, guidPrefix, la suite des
//! sous-messages avec leur `octetsToNextHeader`, les identifiants d'entite
//! et les numeros de sequence, figes dans `tests/data/rtps_tshark_oracle.tsv`
//! et compares ici trame par trame — pings RTI (seize octets, `NDDSPING`)
//! compris, que tshark compte comme du RTPS. Les 16 fragments IPv4 de
//! `RTPS_Discovery.pcapng` n'y sont pas : un parseur sans etat ne voit
//! jamais le message qu'ils composent.

use std::{collections::BTreeMap, fs, path::Path};

use packet_parser::{
    PacketFlow, parse,
    parse::application::protocols::rtps::{
        RtpsPacket, RtpsPing, SubmessageDetails, SubmessageKind,
    },
};

mod common;
use common::{FileRead, collect_capture_files, read_capture};

const CORPUS: &str = "pcaps_exemple/protocols/rtps";
const ORACLE: &str = "tests/data/rtps_tshark_oracle.tsv";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Une ligne de l'oracle : les colonnes 3 a 10, telles quelles.
#[derive(Debug, PartialEq, Eq)]
struct OracleRow {
    version: String,
    vendor_id: String,
    guid_prefix: String,
    submessage_ids: String,
    octets_to_next_header: String,
    reader_ids: String,
    writer_ids: String,
    sequence_numbers: String,
}

fn read_oracle(path: &Path) -> BTreeMap<String, BTreeMap<usize, OracleRow>> {
    let oracle = fs::read_to_string(path).expect("oracle lisible");
    let mut expected: BTreeMap<String, BTreeMap<usize, OracleRow>> = BTreeMap::new();
    for line in oracle.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 10, "ligne d'oracle malformee : {line}");
        let frame: usize = fields[1].parse().expect("numero de trame");
        let row = OracleRow {
            version: fields[2].to_string(),
            vendor_id: fields[3].to_string(),
            guid_prefix: fields[4].to_string(),
            submessage_ids: fields[5].to_string(),
            octets_to_next_header: fields[6].to_string(),
            reader_ids: fields[7].to_string(),
            writer_ids: fields[8].to_string(),
            sequence_numbers: fields[9].to_string(),
        };
        let previous = expected
            .entry(fields[0].to_string())
            .or_default()
            .insert(frame, row);
        assert!(previous.is_none(), "trame {frame} en double dans l'oracle");
    }
    expected
}

fn join<T: ToString>(values: &[T]) -> String {
    if values.is_empty() {
        "-".to_string()
    } else {
        values
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// La ligne d'oracle que la crate produit pour un message, dans le format
/// de tshark : `octetsToNextHeader` tel que porte par le wire (zero pour un
/// dernier sous-message etendu jusqu'a la fin), identifiants d'entite des
/// sous-messages qui en portent, et les numeros de sequence que tshark
/// expose sous `rtps.sm.seqNumber`.
fn oracle_row(packet: &RtpsPacket<'_>) -> OracleRow {
    let (major, minor) = packet.version();
    let version = format!("{major}.{minor}");
    let vendor_id = format!("{:#06x}", packet.vendor_id());
    let Some(message) = packet.message() else {
        // Ping RTI : ni guidPrefix ni sous-message.
        return OracleRow {
            version,
            vendor_id,
            guid_prefix: "-".to_string(),
            submessage_ids: "-".to_string(),
            octets_to_next_header: "-".to_string(),
            reader_ids: "-".to_string(),
            writer_ids: "-".to_string(),
            sequence_numbers: "-".to_string(),
        };
    };
    let mut ids = Vec::new();
    let mut lengths = Vec::new();
    let mut readers = Vec::new();
    let mut writers = Vec::new();
    let mut sequence_numbers: Vec<i64> = Vec::new();
    for submessage in &message.submessages {
        ids.push(format!("{:#04x}", submessage.id));
        // tshark ne renseigne pas `rtps.sm.octetsToNextHeader` pour un
        // sous-message vendeur (0x80 et au-dela) : il en liste l'identifiant
        // et saute le corps.
        if !matches!(submessage.kind, SubmessageKind::VendorSpecific(_)) {
            lengths.push(submessage.octets_to_next_header);
        }
        match submessage.details {
            SubmessageDetails::Data {
                reader_id,
                writer_id,
                writer_sequence_number,
                ..
            }
            | SubmessageDetails::DataFrag {
                reader_id,
                writer_id,
                writer_sequence_number,
                ..
            }
            | SubmessageDetails::HeartbeatFrag {
                reader_id,
                writer_id,
                writer_sequence_number,
                ..
            }
            | SubmessageDetails::NackFrag {
                reader_id,
                writer_id,
                writer_sequence_number,
                ..
            } => {
                readers.push(reader_id);
                writers.push(writer_id);
                sequence_numbers.push(writer_sequence_number);
            }
            SubmessageDetails::Heartbeat {
                reader_id,
                writer_id,
                first_sequence_number,
                last_sequence_number,
                ..
            } => {
                readers.push(reader_id);
                writers.push(writer_id);
                sequence_numbers.push(first_sequence_number);
                sequence_numbers.push(last_sequence_number);
            }
            SubmessageDetails::AckNack {
                reader_id,
                writer_id,
                bitmap_base,
                ..
            } => {
                readers.push(reader_id);
                writers.push(writer_id);
                sequence_numbers.push(bitmap_base);
            }
            SubmessageDetails::Gap {
                reader_id,
                writer_id,
                gap_start,
                gap_list_base,
                ..
            } => {
                readers.push(reader_id);
                writers.push(writer_id);
                sequence_numbers.push(gap_start);
                sequence_numbers.push(gap_list_base);
            }
            _ => {}
        }
    }
    OracleRow {
        version,
        vendor_id,
        guid_prefix: hex(&message.header.guid_prefix),
        submessage_ids: join(&ids),
        octets_to_next_header: join(&lengths),
        reader_ids: join(
            &readers
                .iter()
                .map(|id| format!("{id:#010x}"))
                .collect::<Vec<_>>(),
        ),
        writer_ids: join(
            &writers
                .iter()
                .map(|id| format!("{id:#010x}"))
                .collect::<Vec<_>>(),
        ),
        sequence_numbers: join(
            &sequence_numbers
                .iter()
                // `-T fields` rend le SequenceNumber_t signe (-4294967296 pour
                // le `high` -1 d'OpenDDS), la ou `-V` l'affiche non signe.
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
        ),
    }
}

/// Le message RTPS d'un flux, si la crate l'a etiquete ainsi.
fn rtps_message<'a>(flow: &'a PacketFlow<'a>) -> Option<RtpsPacket<'a>> {
    let application = flow.application.as_ref()?;
    if application.application_protocol != "RTPS" {
        return None;
    }
    let payload = flow.transport.as_ref()?.payload?;
    Some(RtpsPacket::try_from(payload).expect("une trame etiquetee RTPS se decode"))
}

/// Parite avec tshark sur les 231 trames RTPS du corpus : chaque trame de
/// l'oracle est etiquetee RTPS et decodee a l'identique ; toute autre trame
/// du dossier (les 16 fragments IPv4) ne l'est pas.
#[test]
fn every_frame_matches_the_tshark_oracle() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let expected = read_oracle(&base.join(ORACLE));
    let mut captures = Vec::new();
    collect_capture_files(&base.join(CORPUS), &mut captures);
    assert_eq!(captures.len(), 8);

    let mut frames_checked = 0;
    let mut other_frames = 0;
    let mut pings = 0;
    let mut by_vendor: BTreeMap<u16, usize> = BTreeMap::new();
    let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
    for path in &captures {
        let file = path.file_name().unwrap().to_string_lossy().to_string();
        let FileRead::Frames { frames, .. } = read_capture(path) else {
            panic!("{file} : capture illisible");
        };
        let oracle_frames = expected
            .get(&file)
            .unwrap_or_else(|| panic!("{file} absente de l'oracle"));
        for (index, (link_type, data)) in frames.iter().enumerate() {
            let number = index + 1;
            let flow =
                parse(*link_type, data).unwrap_or_else(|error| panic!("{file}:{number} : {error}"));
            match (oracle_frames.get(&number), rtps_message(&flow)) {
                (Some(row), Some(packet)) => {
                    assert_eq!(&oracle_row(&packet), row, "{file}:{number}");
                    *by_vendor.entry(packet.vendor_id()).or_default() += 1;
                    match &packet {
                        RtpsPacket::Message(message) => {
                            for submessage in &message.submessages {
                                *by_kind.entry(format!("{:?}", submessage.kind)).or_default() += 1;
                            }
                        }
                        RtpsPacket::Ping(RtpsPing { text, .. }) => {
                            assert_eq!(text, b"NDDSPING");
                            pings += 1;
                        }
                        _ => unreachable!("message ou ping"),
                    }
                    frames_checked += 1;
                }
                (None, None) => other_frames += 1,
                (Some(_), None) => {
                    let payload = flow.transport.as_ref().and_then(|t| t.payload);
                    let error = payload.map(|p| RtpsPacket::try_from(p).err());
                    panic!(
                        "{file}:{number} : tshark voit RTPS, pas la crate ({:?}, {error:?})",
                        flow.application.as_ref().map(|a| a.application_protocol)
                    )
                }
                (None, Some(_)) => panic!("{file}:{number} : la crate voit RTPS, pas tshark"),
            }
        }
    }
    assert_eq!(frames_checked, 231);
    // Huit pings RTI (sept dans RTPS_Discovery.pcapng, un dans rtps.pcap).
    assert_eq!(pings, 8);
    assert_eq!(
        other_frames, 16,
        "les fragments IPv4 de RTPS_Discovery.pcapng"
    );
    // Six implementations : RTI Connext 0x0101, OpenSplice 0x0102, OpenDDS
    // 0x0103, CoreDX 0x0106, Connext Micro 0x010a, Cyclone DDS 0x0110.
    assert_eq!(
        by_vendor,
        BTreeMap::from([
            (0x0101, 128),
            (0x0102, 1),
            (0x0103, 13),
            (0x0106, 1),
            (0x010a, 1),
            (0x0110, 87)
        ])
    );
    assert_eq!(
        by_kind.keys().collect::<Vec<_>>(),
        [
            "AckNack",
            "Data",
            "DataFrag",
            "Gap",
            "Heartbeat",
            "InfoDestination",
            "InfoSource",
            "InfoTimestamp",
            "VendorSpecific(128)",
        ]
    );
}

/// `talker-listener-rtps.pcapng` trame 9 (Cyclone DDS, LINKTYPE_NULL,
/// 127.0.0.1:54020 -> 127.0.0.1:58584) : la detection ne doit rien au
/// port. tshark : INFO_DST, INFO_TS, DATA (writerSN 1) et HEARTBEAT
/// (1..1, count 2) du writer P2P_BUILTIN_PARTICIPANT_MESSAGE.
#[test]
fn packet_flow_labels_rtps_on_a_random_port_over_linktype_null() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let FileRead::Frames { frames, .. } =
        read_capture(&base.join(CORPUS).join("talker-listener-rtps.pcapng"))
    else {
        panic!("capture illisible");
    };
    let (link_type, data) = &frames[8];
    let flow = parse(*link_type, data).expect("trame 9");
    let transport = flow.transport.as_ref().expect("UDP");
    assert_eq!(
        (transport.source_port, transport.destination_port),
        (Some(54_020), Some(58_584))
    );
    let packet = rtps_message(&flow).expect("etiquette RTPS");
    let message = packet.message().expect("un message, pas un ping");
    assert_eq!(message.header.vendor_id, 0x0110);
    let kinds: Vec<SubmessageKind> = message.submessages.iter().map(|s| s.kind).collect();
    assert_eq!(
        kinds,
        [
            SubmessageKind::InfoDestination,
            SubmessageKind::InfoTimestamp,
            SubmessageKind::Data,
            SubmessageKind::Heartbeat
        ]
    );
    assert!(matches!(
        message.submessages[3].details,
        SubmessageDetails::Heartbeat {
            writer_id: 0x0002_00c2,
            first_sequence_number: 1,
            last_sequence_number: 1,
            count: 2,
            ..
        }
    ));
}
