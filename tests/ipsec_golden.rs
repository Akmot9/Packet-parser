// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests IKE et ESP sur trames reelles (#124).
//!
//! Captures : `pcaps_exemple/protocols/ipsec/` (voir son `SOURCE.md`), trois
//! fichiers, 858 trames : 535 messages IKE (IKEv1 main mode sur UDP 500,
//! IKEv2 sur UDP 500 et derriere le marqueur non-ESP d'UDP 4500) et 323
//! paquets ESP (8 natifs, protocole IP 50 ; 315 dans UDP 4500).
//!
//! L'oracle est tshark 4.6.6 (`tools/ipsec_oracle.sh`) : pour chaque message
//! IKE, l'en-tete (SPI, version, type d'echange, drapeaux, identifiant,
//! longueur) et la chaine des payloads de premier niveau avec leurs
//! longueurs ; pour chaque paquet ESP, le SPI et le numero de sequence.
//! Fige dans `tests/data/ipsec_tshark_oracle.tsv`, compare ici trame par
//! trame, sans aucun Decode As : chaque trame IKE porte 500 ou 4500 d'un
//! cote, et ESP natif est reconnu par le protocole IP.

use std::{collections::BTreeMap, fs, path::Path};

use packet_parser::{
    DecodeAsProtocol, PacketFlow, ParseConfig, TransportDetails, parse,
    parse::{
        application::protocols::ike::{IkePacket, UdpEncapsulation},
        transport::protocols::{TransportProtocol, esp::EspPacket},
    },
    parse_with,
};

mod common;
use common::{FileRead, collect_capture_files, read_capture};

const CORPUS: &str = "pcaps_exemple/protocols/ipsec";
const ORACLE: &str = "tests/data/ipsec_tshark_oracle.tsv";

/// Les colonnes 3 a 14 d'une ligne d'oracle.
type OracleRow = [String; 12];

fn read_oracle(path: &Path) -> BTreeMap<String, BTreeMap<usize, OracleRow>> {
    let oracle = fs::read_to_string(path).expect("oracle lisible");
    let mut expected: BTreeMap<String, BTreeMap<usize, OracleRow>> = BTreeMap::new();
    for line in oracle.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 14, "ligne d'oracle malformee : {line}");
        let frame: usize = fields[1].parse().expect("numero de trame");
        let row: OracleRow = fields[2..]
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .try_into()
            .expect("douze colonnes");
        expected
            .entry(fields[0].to_string())
            .or_default()
            .insert(frame, row);
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

fn ike_row(packet: &IkePacket<'_>, carrier: &str) -> OracleRow {
    let header = packet.header;
    [
        "ike".to_string(),
        carrier.to_string(),
        format!("{:016x}", header.initiator_spi),
        format!("{:016x}", header.responder_spi),
        format!("{:#04x}", header.version),
        header.exchange_type.to_string(),
        format!("{:#04x}", header.flags),
        format!("{:#010x}", header.message_id),
        header.length.to_string(),
        join(packet.payload_types()),
        join(packet.payloads.iter().map(|payload| payload.length)),
        "-".to_string(),
    ]
}

fn esp_row(esp: &EspPacket<'_>, carrier: &str) -> OracleRow {
    let mut row: OracleRow = Default::default();
    row[0] = "esp".to_string();
    row[1] = carrier.to_string();
    row[2] = format!("{:#010x}", esp.spi);
    for column in row.iter_mut().skip(3).take(8) {
        *column = "-".to_string();
    }
    row[11] = esp.sequence.to_string();
    row
}

fn label(flow: &PacketFlow<'_>) -> Option<&'static str> {
    flow.application
        .as_ref()
        .map(|application| application.application_protocol)
}

/// Parite avec tshark sur les 858 trames du corpus, sans Decode As.
#[test]
fn every_frame_matches_the_tshark_oracle() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let expected = read_oracle(&base.join(ORACLE));
    let mut captures = Vec::new();
    collect_capture_files(&base.join(CORPUS), &mut captures);
    assert_eq!(captures.len(), 3);

    let mut ike = 0;
    let mut esp_native = 0;
    let mut esp_nat_t = 0;
    let mut encrypted = 0;
    let mut by_exchange: BTreeMap<(u8, u8), usize> = BTreeMap::new();
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
            "{file} : tshark voit IKE ou ESP partout"
        );
        for (index, (link_type, data)) in frames.iter().enumerate() {
            let number = index + 1;
            let row = &oracle_frames[&number];
            let flow =
                parse(*link_type, data).unwrap_or_else(|error| panic!("{file}:{number} : {error}"));
            let transport = flow.transport.as_ref().expect("transport");
            let carrier = row[1].as_str();
            match (row[0].as_str(), carrier) {
                ("ike", _) => {
                    assert_eq!(label(&flow), Some("IKE"), "{file}:{number}");
                    let payload = transport.payload.expect("payload UDP");
                    let packet = IkePacket::from_udp(payload)
                        .unwrap_or_else(|error| panic!("{file}:{number} : {error}"));
                    assert_eq!(&ike_row(&packet, carrier), row, "{file}:{number}");
                    match carrier {
                        "natt" => assert!(
                            matches!(
                                UdpEncapsulation::classify(payload),
                                Ok(UdpEncapsulation::Ike(_))
                            ),
                            "{file}:{number} : marqueur non-ESP attendu"
                        ),
                        _ => assert!(
                            IkePacket::try_from(payload).is_ok(),
                            "{file}:{number} : message nu attendu"
                        ),
                    }
                    let header = packet.header;
                    let last_is_sk = packet.payloads.last().is_some_and(|p| p.payload_type == 46);
                    assert_eq!(
                        packet.encrypted_body.is_some(),
                        header.encryption_flag() || last_is_sk,
                        "{file}:{number}"
                    );
                    encrypted += usize::from(packet.encrypted_body.is_some());
                    *by_exchange
                        .entry((header.major_version(), header.exchange_type))
                        .or_default() += 1;
                    ike += 1;
                }
                ("esp", "natt") => {
                    assert_eq!(label(&flow), Some("ESP"), "{file}:{number}");
                    let payload = transport.payload.expect("payload UDP");
                    assert!(matches!(
                        UdpEncapsulation::classify(payload),
                        Ok(UdpEncapsulation::Esp(_))
                    ));
                    let esp = EspPacket::try_from(payload)
                        .unwrap_or_else(|error| panic!("{file}:{number} : {error}"));
                    assert_eq!(&esp_row(&esp, carrier), row, "{file}:{number}");
                    esp_nat_t += 1;
                }
                ("esp", "native") => {
                    assert_eq!(
                        transport.protocol,
                        TransportProtocol::Esp,
                        "{file}:{number}"
                    );
                    assert_eq!(transport.payload, None, "{file}:{number}");
                    assert_eq!(label(&flow), None, "{file}:{number}");
                    let Some(TransportDetails::Esp(esp)) = &transport.details else {
                        panic!("{file}:{number} : details ESP attendus");
                    };
                    assert_eq!(&esp_row(esp, carrier), row, "{file}:{number}");
                    esp_native += 1;
                }
                other => panic!("{file}:{number} : ligne d'oracle inattendue {other:?}"),
            }
        }
    }
    assert_eq!((ike, esp_nat_t, esp_native), (535, 315, 8));
    assert_eq!(
        by_exchange,
        BTreeMap::from([
            ((1, 2), 6),
            ((1, 5), 3),
            ((1, 32), 3),
            ((2, 34), 281),
            ((2, 35), 224),
            ((2, 37), 18),
        ])
    );
    // IKEv1 : les huit messages apres l'echange des cles (trames 5 a 12) ;
    // IKEv2 : tout INFORMATIONAL et tout IKE_AUTH porte un SK, sauf la trame
    // 192 du corpus nDPI, dont l'unique payload est de type prive 127.
    assert_eq!(encrypted, 8 + 241);
}

/// `ipsec_isakmp_esp.pcap` : la trame 42 (IKE derriere le marqueur) et la
/// trame 11 (ESP) sur UDP 4500. Deplacees sur un autre port, elles
/// retombent en `Unknown` ; declarees par Decode As, elles reviennent.
#[test]
fn port_4500_is_demultiplexed_and_other_ports_need_decode_as() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let FileRead::Frames { frames, .. } =
        read_capture(&base.join(CORPUS).join("ipsec_isakmp_esp.pcap"))
    else {
        panic!("capture illisible");
    };
    for (frame, expected, protocol) in [
        (42, "IKE", DecodeAsProtocol::Ike),
        (11, "ESP", DecodeAsProtocol::Esp),
    ] {
        let (link_type, data) = &frames[frame - 1];
        let flow = parse(*link_type, data).expect("trame");
        assert_eq!(label(&flow), Some(expected), "trame {frame}");

        // Ethernet + IPv4 sans options : ports UDP aux octets 34 a 38.
        let mut moved = data.clone();
        moved[34..38].copy_from_slice(&[0x11, 0x95, 0x11, 0x95]); // 4501
        let flow = parse(*link_type, &moved).expect("trame deplacee");
        assert_eq!(label(&flow), Some("Unknown"), "trame {frame}");

        let config = ParseConfig::new().decode_as(4501, protocol);
        let flow = parse_with(*link_type, &moved, &config).expect("trame declaree");
        assert_eq!(label(&flow), Some(expected), "trame {frame}");
    }
}
