// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests MQTT 5 sur trames reelles (#291).
//!
//! Captures : les quatre pieces jointes du tracker Wireshark de
//! `pcaps_exemple/protocols/mqtt/` (`wireshark_*`, voir son `SOURCE.md`),
//! enregistrees par l'auteur de Mosquitto entre un client et un broker v5 :
//! un CONNECT a Will, SUBSCRIBE, SUBACK, UNSUBSCRIBE et UNSUBACK a proprietes
//! (#15257), puis toutes les variantes de PUBACK, PUBREC, PUBREL et PUBCOMP
//! (#15428, port 1888).
//!
//! L'oracle est tshark 4.6.9 (`tools/mqtt_oracle.sh`) : pour chaque paquet,
//! son type et sa remaining length, figes dans
//! `tests/data/mqtt_tshark_oracle.tsv`. La sonde MQTT est aveugle sur TCP :
//! le port 1888 ne joue aucun role.

use std::{collections::BTreeMap, fs, path::Path};

use packet_parser::{
    PacketFlow, parse,
    parse::application::protocols::mqtt::{MqttPacket, MqttPacketType},
};

mod common;
use common::{FileRead, collect_capture_files, read_capture};

const CORPUS: &str = "pcaps_exemple/protocols/mqtt";
const ORACLE: &str = "tests/data/mqtt_tshark_oracle.tsv";

/// UNSUBACK sans reason code (`b003000200` : packet id 2, proprietes vides),
/// envoye par le Mosquitto de developpement de 2018. MQTT 5.0 §3.11.3 exige
/// un code par topic filter de l'UNSUBSCRIBE, qui en porte au moins un :
/// tshark le lit, la crate le refuse.
const NON_CONFORMANT_UNSUBACK: (&str, usize) = ("wireshark_15257_mqtt-malformed.pcapng", 11);

/// Type et remaining length, par trame, par capture.
type Oracle = BTreeMap<String, BTreeMap<usize, (u8, u32)>>;

fn read_oracle(path: &Path) -> Oracle {
    let oracle = fs::read_to_string(path).expect("oracle lisible");
    let mut expected = Oracle::new();
    for line in oracle.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 4, "ligne d'oracle malformee : {line}");
        expected.entry(fields[0].to_string()).or_default().insert(
            fields[1].parse().expect("numero de trame"),
            (
                fields[2].parse().expect("type de paquet"),
                fields[3].parse().expect("remaining length"),
            ),
        );
    }
    expected
}

fn label(flow: &PacketFlow<'_>) -> Option<&'static str> {
    flow.application
        .as_ref()
        .map(|application| application.protocol.label())
}

/// Parite avec tshark sur les 150 paquets MQTT 5, l'UNSUBACK non conforme
/// excepte, et aucun faux positif sur les segments sans MQTT.
#[test]
fn every_mqtt5_packet_matches_the_tshark_oracle() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let expected = read_oracle(&base.join(ORACLE));
    let mut captures = Vec::new();
    collect_capture_files(&base.join(CORPUS), &mut captures);
    captures.retain(|path| {
        path.file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with("wireshark_"))
    });
    assert_eq!(captures.len(), 4);

    let mut by_type: BTreeMap<u8, usize> = BTreeMap::new();
    let mut other_frames = 0;
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
            let flow = parse(*link_type, data).unwrap_or_else(|_| panic!("{file}:{number}"));
            let Some(&(packet_type, remaining_length)) = rows.get(&number) else {
                assert_ne!(label(&flow), Some("MQTT"), "{file}:{number} : faux positif");
                other_frames += 1;
                continue;
            };
            seen += 1;
            let payload = flow
                .transport
                .as_ref()
                .and_then(|transport| transport.payload)
                .expect("payload TCP");
            if (file.as_str(), number) == NON_CONFORMANT_UNSUBACK {
                assert_eq!(payload, [0xb0, 0x03, 0x00, 0x02, 0x00]);
                assert_ne!(label(&flow), Some("MQTT"), "{file}:{number}");
                continue;
            }
            assert_eq!(label(&flow), Some("MQTT"), "{file}:{number}");
            let packet = MqttPacket::try_from(payload)
                .unwrap_or_else(|error| panic!("{file}:{number} : {error}"));
            assert_eq!(
                (
                    packet.fixed_header.packet_type as u8,
                    packet.fixed_header.remaining_length
                ),
                (packet_type, remaining_length),
                "{file}:{number}"
            );
            *by_type.entry(packet_type).or_default() += 1;
        }
        assert_eq!(seen, rows.len(), "{file} : des lignes d'oracle sans trame");
    }
    assert_eq!(by_type.values().sum::<usize>(), 149);
    // 420 trames : 150 paquets MQTT, 270 segments sans payload (poignees de
    // main, ACK, fermetures).
    assert_eq!(other_frames, 270);
    assert_eq!(by_type.get(&(MqttPacketType::Unsubscribe as u8)), Some(&1));
    assert_eq!(by_type.get(&(MqttPacketType::Pubrel as u8)), Some(&12));
}
