// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden test LLDP (IEEE 802.1AB) sur trames reelles, epopee #177.
//!
//! Captures du depot qui en portent : `protocols/profinet/` — commutateurs
//! Siemens SCALANCE et automates SIMATIC, TLV PROFINET et IEEE 802.3 — et,
//! lue en place, `The-Ultimate-PCAP.pcapng` — deux commutateurs Cisco, 12
//! trames Ethernet aux adresses de gestion IPv4 et IPv6 et 59 mPackets IEEE
//! 802.3br, TLV IEEE 802.1 et 802.3.
//!
//! L'oracle est tshark 4.6.6 (`tools/lldp_oracle.sh`, profil vide) : pour
//! chaque trame, les types et longueurs des TLV, le chassis, le port, le
//! TTL, le nom, la description du port, les capacites, les adresses de
//! gestion et les OUI d'organisation, figes dans
//! `tests/data/lldp_tshark_oracle.tsv` et compares ici trame par trame.

use std::{collections::BTreeMap, fs, net::IpAddr, path::Path};

use packet_parser::{
    parse,
    parse::internet::{Internet, InternetDetails, protocols::lldp::LldpPacket},
};

mod common;
use common::{FileRead, read_capture};

const PROTOCOLS: &str = "pcaps_exemple/protocols";
const ORACLE: &str = "tests/data/lldp_tshark_oracle.tsv";

fn read_oracle(path: &Path) -> BTreeMap<String, BTreeMap<usize, Vec<String>>> {
    let mut oracle: BTreeMap<String, BTreeMap<usize, Vec<String>>> = BTreeMap::new();
    for line in fs::read_to_string(path).expect("oracle lisible").lines() {
        if line.starts_with('#') {
            continue;
        }
        let fields: Vec<String> = line.split('\t').map(str::to_string).collect();
        assert_eq!(fields.len(), 19, "ligne d'oracle malformee : {line}");
        let number = fields[1].parse().expect("numero de trame");
        oracle
            .entry(fields[0].clone())
            .or_default()
            .insert(number, fields[2..].to_vec());
    }
    oracle
}

fn frames_of(path: &Path) -> Vec<(packet_parser::LinkType, Vec<u8>)> {
    let FileRead::Frames { frames, .. } = read_capture(path) else {
        panic!("{} illisible", path.display());
    };
    frames
}

fn list<T: ToString>(values: impl Iterator<Item = T>) -> String {
    let values: Vec<String> = values.map(|value| value.to_string()).collect();
    if values.is_empty() {
        "-".to_string()
    } else {
        values.join(",")
    }
}

fn text(value: Option<&str>) -> String {
    value.map_or_else(|| "-".to_string(), str::to_string)
}

/// Les colonnes de l'oracle, lues sur le LLDPDU decode par la crate.
fn columns(packet: &LldpPacket<'_>) -> Vec<String> {
    let chassis = match packet.chassis_id.subtype {
        4 => packet.chassis_id.as_mac().map(|mac| mac.to_string()),
        5 => packet
            .chassis_id
            .as_network_address()
            .map(|ip| ip.to_string()),
        _ => Some(hex::encode(packet.chassis_id.id)),
    };
    let port = match packet.port_id.subtype {
        3 => packet.port_id.as_mac().map(|mac| mac.to_string()),
        4 => packet.port_id.as_network_address().map(|ip| ip.to_string()),
        _ => packet.port_id.as_text().map(str::to_string),
    };
    let capabilities = packet.system_capabilities();
    let addresses: Vec<_> = packet.management_addresses().collect();
    let ips = |v6: bool| {
        list(
            addresses
                .iter()
                .filter_map(|address| address.ip())
                .filter(|ip| matches!(ip, IpAddr::V6(_)) == v6),
        )
    };
    vec![
        list(packet.tlvs.iter().map(|tlv| tlv.tlv_type)),
        list(packet.tlvs.iter().map(|tlv| tlv.value.len())),
        packet.chassis_id.subtype.to_string(),
        text(chassis.as_deref()),
        packet.port_id.subtype.to_string(),
        text(port.as_deref()),
        packet.time_to_live.to_string(),
        text(packet.system_name()),
        text(packet.port_description()),
        capabilities.map_or_else(|| "-".into(), |c| format!("{:#06x}", c.capabilities)),
        capabilities.map_or_else(|| "-".into(), |c| format!("{:#06x}", c.enabled)),
        list(addresses.iter().map(|address| address.address_subtype)),
        ips(false),
        ips(true),
        list(addresses.iter().map(|address| address.interface_subtype)),
        list(addresses.iter().map(|address| address.interface_number)),
        list(
            packet
                .organization_tlvs()
                .map(|tlv| u32::from_be_bytes([0, tlv.oui[0], tlv.oui[1], tlv.oui[2]])),
        ),
    ]
}

/// Parite avec tshark : chaque trame LLDP de l'oracle est decodee dans la
/// couche internet, sans corruption, avec les memes TLV, le meme chassis, le
/// meme port, le meme TTL, le meme nom, les memes capacites, les memes
/// adresses de gestion et les memes OUI ; aucune autre trame des captures
/// ne passe pour du LLDP.
#[test]
fn every_lldp_frame_matches_the_tshark_oracle() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let oracle = read_oracle(&base.join(ORACLE));
    let mut decoded: BTreeMap<String, usize> = BTreeMap::new();
    for (name, rows) in &oracle {
        let frames = frames_of(&base.join(PROTOCOLS).join(name));
        for (index, (link_type, data)) in frames.iter().enumerate() {
            let number = index + 1;
            let flow = parse(*link_type, data).expect("trame decodable");
            let lldp = flow
                .internet
                .as_ref()
                .and_then(|internet| match &internet.details {
                    Some(InternetDetails::Lldp(packet)) => Some(packet),
                    _ => None,
                });
            let Some(row) = rows.get(&number) else {
                assert!(lldp.is_none(), "{name}:{number} : LLDP pour la crate seule");
                continue;
            };
            assert!(
                flow.corrupted.is_none(),
                "{name}:{number} : {:?}",
                flow.corrupted
            );
            let packet = lldp.unwrap_or_else(|| panic!("{name}:{number} : LLDP non decode"));
            assert_eq!(
                flow.internet
                    .as_ref()
                    .map(|internet| internet.protocol_name),
                Some("LLDP")
            );
            assert_eq!(&columns(packet), row, "{name}:{number} : ecart avec tshark");
            *decoded.entry(name.clone()).or_default() += 1;
        }
    }
    assert_eq!(
        decoded,
        BTreeMap::from([
            ("../The-Ultimate-PCAP.pcapng".to_string(), 71),
            (
                "profinet/cisagov_profinet_io_cm_mixed_1.pcap".to_string(),
                201
            ),
            ("profinet/miguelob_pn.pcapng".to_string(), 4),
        ])
    );
}

/// Sans EtherType, la sonde aveugle de `Internet::try_from` reconnait
/// chaque LLDPDU reel ; coupe d'un octet, il ne se decode plus : la trame
/// serait une couche internet corrompue, pas un LLDPDU plus court.
#[test]
fn blind_probe_and_truncation() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let oracle = read_oracle(&base.join(ORACLE));
    let mut probed = 0;
    for (name, rows) in &oracle {
        let frames = frames_of(&base.join(PROTOCOLS).join(name));
        for number in rows.keys() {
            let (link_type, data) = &frames[number - 1];
            let flow = parse(*link_type, data).expect("trame decodable");
            let internet = flow.internet.as_ref().expect("couche internet");
            let Some(InternetDetails::Lldp(packet)) = &internet.details else {
                panic!("{name}:{number} : LLDP attendu");
            };
            // Ce que la couche liaison remet apres l'EtherType : sans le CRC
            // d'un mPacket 802.3br (les 59 trames LLDP de S2.weberlab.de dans
            // l'Ultimate PCAP).
            let lldpdu = flow.data_link.network_payload();
            assert_eq!(
                packet.chassis_id.id.as_ptr(),
                lldpdu[3..].as_ptr(),
                "{name}:{number}"
            );
            let blind = Internet::try_from(lldpdu)
                .unwrap_or_else(|error| panic!("{name}:{number} sonde aveugle : {error:?}"));
            assert_eq!(blind.protocol_name, "LLDP", "{name}:{number}");
            let end = lldpdu.len() - packet.padding.len();
            assert!(
                LldpPacket::try_from(&lldpdu[..end - 1]).is_err(),
                "{name}:{number} coupe"
            );
            probed += 1;
        }
    }
    assert_eq!(probed, 276);
}
