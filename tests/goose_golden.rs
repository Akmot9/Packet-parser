// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests GOOSE (IEC 61850-8-1) sur trames reelles (epopee #102).
//!
//! Captures : `pcaps_exemple/protocols/goose/` (voir son `SOURCE.md`), un
//! relais GE F650, un simulateur sur VLAN 10 et trois IED d'un poste, avec
//! ou sans etiquette VLAN, GOOSE seul ou au milieu de MMS, NTP et TCP.
//!
//! L'oracle est tshark 4.6.6 : pour chaque trame GOOSE, VLAN, APPID,
//! longueur, reserves, gocbRef, timeAllowedtoLive, datSet, goID, stNum,
//! sqNum, simulation, confRev, ndsCom, numDatSetEntries, nombre et types
//! des elements de allData, figes dans `tests/data/goose_tshark_oracle.tsv`
//! et compares ici trame par trame.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use packet_parser::{
    NetworkProtocol, PacketFlow, parse,
    parse::internet::{Internet, InternetDetails, protocols::goose::GoosePacket},
};

mod common;
use common::{FileRead, collect_capture_files, read_capture};

const CORPUS: &str = "pcaps_exemple/protocols/goose";
const ORACLE: &str = "tests/data/goose_tshark_oracle.tsv";

/// La trame GOOSE d'un flux, telle que la crate la voit : la couche
/// internet, sans transport ni application au-dessus.
fn goose_message<'a>(flow: &'a PacketFlow<'a>) -> Option<&'a GoosePacket<'a>> {
    let internet = flow.internet.as_ref()?;
    let InternetDetails::Goose(packet) = internet.details.as_ref()? else {
        return None;
    };
    assert_eq!(internet.protocol_name, "GOOSE");
    assert!(internet.source.is_none() && internet.destination.is_none());
    assert!(flow.transport.is_none() && flow.application.is_none());
    Some(packet)
}

/// Les colonnes de l'oracle a partir de la trame 3 : VLAN, APPID, longueur,
/// reserves, gocbRef, timeAllowedtoLive, datSet, goID, stNum, sqNum,
/// simulation, confRev, ndsCom, numDatSetEntries, elements de allData et
/// leurs types (le numero de choix de `Data`, soit l'etiquette BER).
fn oracle_row(vlan: Option<u16>, packet: &GoosePacket<'_>) -> String {
    let pdu = &packet.pdu;
    let codes: Vec<String> = pdu
        .all_data
        .iter()
        .map(|element| (element.tag & 0x1f).to_string())
        .collect();
    let flag = |value: bool| if value { "True" } else { "False" };
    [
        vlan.map_or("-".to_string(), |id| id.to_string()),
        format!("0x{:04x}", packet.app_id),
        packet.length.to_string(),
        format!("0x{:04x}", packet.reserved1),
        format!("0x{:04x}", packet.reserved2),
        pdu.gocb_ref.to_string(),
        pdu.time_allowed_to_live.to_string(),
        pdu.data_set.to_string(),
        pdu.go_id.unwrap_or("-").to_string(),
        pdu.st_num.to_string(),
        pdu.sq_num.to_string(),
        flag(pdu.simulation).to_string(),
        pdu.conf_rev.to_string(),
        flag(pdu.nds_com).to_string(),
        pdu.num_dat_set_entries.to_string(),
        pdu.all_data.len().to_string(),
        if codes.is_empty() {
            "-".to_string()
        } else {
            codes.join(",")
        },
    ]
    .join("\t")
}

fn read_frames(path: &Path) -> Vec<(packet_parser::LinkType, Vec<u8>)> {
    let FileRead::Frames {
        frames,
        read_error_after: None,
    } = read_capture(path)
    else {
        panic!("{} : capture illisible", path.display());
    };
    frames
}

/// Parite exacte avec tshark sur les 494 trames GOOSE du dossier : la crate
/// reconnait exactement les trames que tshark voit, ni plus ni moins, et en
/// decode les memes champs — VLAN retiree par la couche liaison comprise.
#[test]
fn every_goose_frame_matches_the_tshark_oracle() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let oracle = fs::read_to_string(base.join(ORACLE)).expect("oracle lisible");
    let mut expected: BTreeMap<String, BTreeMap<usize, String>> = BTreeMap::new();
    for line in oracle.lines().filter(|line| !line.starts_with('#')) {
        let (file, rest) = line.split_once('\t').expect("ligne d'oracle");
        let (number, row) = rest.split_once('\t').expect("ligne d'oracle");
        expected
            .entry(file.to_string())
            .or_default()
            .insert(number.parse().expect("numero de trame"), row.to_string());
    }

    let mut captures = Vec::new();
    collect_capture_files(&base.join(CORPUS), &mut captures);
    let names: Vec<String> = captures
        .iter()
        .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(
        expected.keys().cloned().collect::<Vec<_>>(),
        sorted,
        "l'oracle couvre chaque capture du dossier"
    );

    let mut per_capture: BTreeMap<String, usize> = BTreeMap::new();
    let mut publishers: BTreeSet<String> = BTreeSet::new();
    let mut tagged = 0;
    for (path, name) in captures.iter().zip(&names) {
        let mut actual = BTreeMap::new();
        for (index, (link_type, data)) in read_frames(path).iter().enumerate() {
            let flow = parse(*link_type, data).expect("trame du corpus decodable");
            let is_goose = flow.data_link.network_protocol() == NetworkProtocol::Goose;
            let Some(packet) = goose_message(&flow) else {
                assert!(
                    !is_goose,
                    "{name} trame {} : EtherType 0x88B8 non decode",
                    index + 1
                );
                continue;
            };
            assert!(is_goose, "{name} trame {}", index + 1);
            let vlan = flow
                .data_link
                .as_ethernet()
                .and_then(|ethernet| ethernet.vlan.as_ref())
                .map(|tag| tag.id);
            tagged += usize::from(vlan.is_some());
            actual.insert(index + 1, oracle_row(vlan, packet));
            *per_capture.entry(name.clone()).or_default() += 1;
            publishers.insert(packet.pdu.gocb_ref.to_string());

            // Sans EtherType, la sonde aveugle de la couche internet
            // retrouve la meme trame.
            let probed =
                Internet::try_from(flow.data_link.network_payload()).expect("sonde aveugle GOOSE");
            assert_eq!(probed.protocol_name, "GOOSE");
            let Some(InternetDetails::Goose(reprobed)) = probed.details else {
                panic!("{name} trame {} : details GOOSE attendus", index + 1);
            };
            assert_eq!(&reprobed, packet);
        }
        assert_eq!(&actual, &expected[name], "{name} : ecart avec tshark");
    }

    assert_eq!(
        per_capture,
        BTreeMap::from([
            ("iti_GOOSE.pcap".to_string(), 8),
            ("iti_GOOSE_DEMO.pcap".to_string(), 1),
            ("iti_Sample_File_GOOSE.pcap".to_string(), 451),
            ("iti_Sample_File_MMS_and_GOOSE.pcap".to_string(), 34),
        ])
    );
    // 451 trames sur VLAN 0 et une sur VLAN 10.
    assert_eq!(tagged, 452);
    assert_eq!(
        publishers,
        BTreeSet::from([
            "111".to_string(),
            "AA1C1Q01A1LD0/LLN0$GO$gcb_A".to_string(),
            "AA1C1Q05A1LD0/LLN0$GO$gcb_A".to_string(),
            "AA1C1Q07A1LD0/LLN0$GO$gcb_A".to_string(),
            "GEDeviceF650/LLN0$GO$gcb01".to_string(),
        ])
    );
}

/// Le mecanisme de retransmission d'IEC 61850-8-1 sur le poste reel : un
/// changement d'etat (stNum + 1) repart a sqNum 0, et chaque trame sans
/// changement incremente sqNum ; une perte de la capture romprait la suite.
#[test]
fn state_and_sequence_numbers_follow_the_retransmission_scheme() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = base.join(CORPUS).join("iti_Sample_File_GOOSE.pcap");
    let mut last: BTreeMap<String, (u32, u32)> = BTreeMap::new();
    let mut state_changes = 0;
    let mut retransmissions = 0;
    let mut gaps = 0;
    for (link_type, data) in read_frames(&path) {
        let flow = parse(link_type, &data).expect("trame decodable");
        let packet = goose_message(&flow).expect("chaque trame est GOOSE");
        let pdu = &packet.pdu;
        assert_eq!(pdu.time_allowed_to_live, 15000);
        assert_eq!(pdu.num_dat_set_entries, 25);
        assert_eq!(pdu.all_data.len(), 25);
        if let Some((st_num, sq_num)) = last.get(pdu.gocb_ref) {
            if pdu.st_num == *st_num && pdu.sq_num == sq_num + 1 {
                retransmissions += 1;
            } else if pdu.st_num == st_num + 1 && pdu.sq_num == 0 {
                state_changes += 1;
            } else {
                gaps += 1;
            }
        }
        last.insert(pdu.gocb_ref.to_string(), (pdu.st_num, pdu.sq_num));
    }
    assert_eq!(last.len(), 3, "trois IED publient");
    // 448 transitions entre trames d'un meme IED : 250 changements d'etat
    // (sqNum repart a 0) et 198 retransmissions, aucune perte.
    assert_eq!((state_changes, retransmissions, gaps), (250, 198, 0));
}

/// Oracle negatif : aucune trame des autres dossiers du corpus n'est prise
/// pour du GOOSE, ni par son EtherType ni par la sonde aveugle appliquee a
/// son payload de couche liaison.
#[test]
fn no_other_capture_is_labelled_goose() {
    let protocols = Path::new(env!("CARGO_MANIFEST_DIR")).join("pcaps_exemple/protocols");
    let goose_dir = protocols.join("goose");
    let mut captures: Vec<PathBuf> = Vec::new();
    collect_capture_files(&protocols, &mut captures);
    captures.retain(|path| !path.starts_with(&goose_dir));
    assert!(captures.len() > 100, "corpus negatif trop maigre");

    let mut frames_checked = 0;
    for path in &captures {
        let FileRead::Frames { frames, .. } = read_capture(path) else {
            continue;
        };
        for (index, (link_type, data)) in frames.iter().enumerate() {
            let Ok(flow) = parse(*link_type, data) else {
                continue;
            };
            for layer in flow.flatten() {
                assert!(
                    goose_message(layer).is_none(),
                    "{} trame {} : faux positif GOOSE",
                    path.display(),
                    index + 1
                );
                assert!(
                    GoosePacket::try_from(layer.data_link.network_payload()).is_err(),
                    "{} trame {} : le payload de couche liaison passe pour du GOOSE",
                    path.display(),
                    index + 1
                );
            }
            frames_checked += 1;
        }
    }
    assert!(frames_checked > 50_000, "{frames_checked} trames seulement");
}
