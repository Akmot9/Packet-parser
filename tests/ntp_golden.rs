// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden test NTP sur datagrammes reels (#161, #162).
//!
//! Captures : le poste IEC 61850 de
//! `pcaps_exemple/protocols/goose/iti_Sample_File_MMS_and_GOOSE.pcap` (voir
//! son `SOURCE.md`), 52 datagrammes NTP — 26 requetes et 26 reponses, v4 et
//! v1, dont les reponses a un client dont l'horloge est en avance sur celle
//! du serveur, celles que la crate rejetait —, et l'echange de
//! `pcaps_exemple/protocols/iec104/iti_JavaRMI_and_IEC_Misc.pcap` : un
//! client Java qui emet un horodatage de l'ere 1 (2036) et un serveur de
//! stratum 1 dont l'identifiant de reference, `SHM`, n'est pas dans la
//! liste de la RFC 5905.
//!
//! L'oracle est tshark 4.6.6 : pour chaque datagramme, ports, LI, version,
//! mode, stratum, poll, precision, root delay, root dispersion, identifiant
//! de reference et les quatre horodatages a la nanoseconde, figes dans
//! `tests/data/ntp_tshark_oracle.tsv` et compares ici datagramme par
//! datagramme.

use std::{collections::BTreeMap, fs, net::Ipv4Addr, path::Path};

use chrono::{DateTime, SecondsFormat, Utc};
use packet_parser::{parse, parse::application::protocols::ntp::NtpPacket};

mod common;
use common::{FileRead, read_capture};

const CORPUS: &str = "pcaps_exemple/protocols";
const ORACLE: &str = "tests/data/ntp_tshark_oracle.tsv";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Un horodatage nul est rendu `NULL` par tshark comme par l'oracle.
fn timestamp(value: DateTime<Utc>) -> String {
    if value.timestamp() == 0 && value.timestamp_subsec_nanos() == 0 {
        "NULL".to_string()
    } else {
        value.to_rfc3339_opts(SecondsFormat::Nanos, true)
    }
}

/// Les colonnes de l'oracle a partir de la trame 3.
fn oracle_row(
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
    packet: &NtpPacket,
) -> String {
    let (li, version, mode) = packet.flags;
    // L'identifiant de reference tel que tshark le montre : ses quatre octets.
    let reference_id = hex(&payload[12..16]);
    // Et tel que la crate le nomme : nul au stratum 0, code ASCII au stratum
    // 1, adresse IPv4 au-dela.
    let expected_display = match packet.stratum {
        0 => "NULL".to_string(),
        1 => String::from_utf8_lossy(&payload[12..16])
            .trim_end_matches('\0')
            .to_string(),
        _ => Ipv4Addr::new(payload[12], payload[13], payload[14], payload[15]).to_string(),
    };
    assert_eq!(packet.reference_id.to_string(), expected_display);
    [
        source_port.to_string(),
        destination_port.to_string(),
        li.to_string(),
        version.to_string(),
        mode.to_string(),
        packet.stratum.to_string(),
        packet.poll.to_string(),
        packet.precision.to_string(),
        packet.root_delay.to_string(),
        packet.root_dispersion.to_string(),
        reference_id,
        timestamp(packet.reference_timestamp),
        timestamp(packet.originate_timestamp),
        timestamp(packet.receive_timestamp),
        timestamp(packet.transmit_timestamp),
    ]
    .join("\t")
}

/// Parite exacte avec tshark sur les 54 datagrammes NTP du corpus : la crate
/// etiquette exactement ceux que tshark voit, et en decode les memes champs
/// — reponses de serveur a un client en avance, horodatage de l'ere 1 et
/// identifiant de reference hors liste compris (#161, #162).
#[test]
fn every_ntp_datagram_matches_the_tshark_oracle() {
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
    assert_eq!(expected.values().map(BTreeMap::len).sum::<usize>(), 54);

    let mut by_version_and_mode: BTreeMap<(u8, u8), usize> = BTreeMap::new();
    let mut client_ahead = 0;
    for (name, rows) in &expected {
        let FileRead::Frames {
            frames,
            read_error_after: None,
        } = read_capture(&base.join(CORPUS).join(name))
        else {
            panic!("{name} : capture illisible");
        };

        let mut actual = BTreeMap::new();
        for (index, (link_type, data)) in frames.iter().enumerate() {
            let flow = parse(*link_type, data).expect("trame du corpus decodable");
            let Some(application) = flow.application.as_ref() else {
                continue;
            };
            if application.application_protocol != "NTP" {
                continue;
            }
            let transport = flow.transport.as_ref().expect("NTP est sur UDP");
            let payload = transport.payload.expect("un datagramme NTP a un payload");
            let packet =
                NtpPacket::try_from(payload).expect("un datagramme etiquete NTP se decode");
            *by_version_and_mode
                .entry((packet.flags.1, packet.flags.2))
                .or_default() += 1;
            if packet.originate_timestamp > packet.receive_timestamp {
                client_ahead += 1;
            }
            actual.insert(
                index + 1,
                oracle_row(
                    transport.source_port.expect("port UDP"),
                    transport.destination_port.expect("port UDP"),
                    payload,
                    &packet,
                ),
            );
        }
        assert_eq!(&actual, rows, "{name} : ecart avec tshark");
    }

    // 25 echanges v4 et 2 echanges v1 : (version, mode) -> datagrammes.
    assert_eq!(
        by_version_and_mode,
        BTreeMap::from([((4, 3), 25), ((4, 4), 25), ((1, 3), 2), ((1, 4), 2)])
    );
    // Dans 18 reponses du poste, l'horloge du client (originate) est en
    // avance sur celle du serveur (receive) : exactement ce que le decodeur
    // rejetait ; la reponse au client Java l'est aussi, son originate etant
    // l'horodatage de l'ere 1 que le client a emis.
    assert_eq!(client_ahead, 19);
}
