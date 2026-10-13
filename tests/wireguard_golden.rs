// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden test WireGuard sur messages reels (epopee #103).
//!
//! Captures : `pcaps_exemple/protocols/wireguard/` (voir son `SOURCE.md`) —
//! WireGuard de Linux entre deux espaces de noms (depot Wireshark), clients
//! NordVPN, ProtonVPN (UDP 443), Mullvad (UDP 5060) et TunnelBear (corpus
//! nDPI), Tailscale et wireguard-go sur UDP 41641 (Corelight), et deux
//! captures sans WireGuard dont tshark prend des datagrammes pour du
//! WireGuard (Zoom, League of Legends).
//!
//! L'oracle est tshark 4.6.6 (`tools/wireguard_oracle.sh`, heuristique `wg`) :
//! pour chaque message, ports, longueur, type, octets reserves, index,
//! compteur, cle ephemere, mac1, mac2, nonce, cookie et keepalive, figes dans
//! `tests/data/wireguard_tshark_oracle.tsv` et compares ici message par
//! message. L'ecart est nomme, pas masque : les 25 datagrammes Zoom et LoL que
//! l'heuristique de tshark accepte et que la sonde aveugle refuse.

use std::{collections::BTreeMap, fs, path::Path};

use packet_parser::{
    DecodeAsProtocol, PacketFlow, ParseConfig, parse,
    parse::application::protocols::wireguard::{WireGuardMessage, WireGuardPacket},
    parse_with,
};

mod common;
use common::{FileRead, collect_capture_files, read_capture};

const CORPUS: &str = "pcaps_exemple/protocols/wireguard";
const ORACLE: &str = "tests/data/wireguard_tshark_oracle.tsv";

/// Les datagrammes que l'heuristique `wg` de tshark prend pour du WireGuard
/// et que la sonde aveugle refuse : un compteur au-dela de 2^60, ou un
/// paquet clair ni complete a seize octets ni arrete a une MTU.
const TSHARK_MISFIRES: &[(&str, &[usize])] = &[
    (
        "ndpi_zoom2.pcap",
        &[
            299, 300, 304, 305, 308, 309, 312, 313, 316, 317, 320, 321, 324, 325, 328, 329, 332,
            333, 336, 337, 340, 341,
        ],
    ),
    ("ndpi_lol_wild_rift_udp.pcap", &[1, 3, 5]),
];

fn read_oracle(path: &Path) -> BTreeMap<String, BTreeMap<usize, String>> {
    let oracle = fs::read_to_string(path).expect("oracle lisible");
    let mut expected: BTreeMap<String, BTreeMap<usize, String>> = BTreeMap::new();
    for line in oracle.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<&str> = line.splitn(3, '\t').collect();
        assert_eq!(fields.len(), 3, "ligne d'oracle malformee : {line}");
        expected.entry(fields[0].to_string()).or_default().insert(
            fields[1].parse().expect("numero de trame"),
            fields[2].to_string(),
        );
    }
    expected
}

fn frames_of(path: &Path) -> Vec<(packet_parser::LinkType, Vec<u8>)> {
    let FileRead::Frames {
        frames,
        read_error_after: None,
    } = read_capture(path)
    else {
        panic!("{} : capture illisible", path.display());
    };
    frames
}

fn label(flow: &PacketFlow<'_>) -> Option<&'static str> {
    flow.application
        .as_ref()
        .map(|application| application.application_protocol)
}

/// Le niveau de la trame etiquete WireGuard.
fn wireguard_level<'f, 'a>(flow: &'f PacketFlow<'a>) -> Option<&'f PacketFlow<'a>> {
    flow.flatten()
        .into_iter()
        .find(|level| label(level) == Some("WireGuard"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Les colonnes de l'oracle a partir du port source.
fn oracle_columns(source_port: u16, destination_port: u16, payload: &[u8]) -> String {
    let packet = WireGuardPacket::try_from(payload).expect("un message etiquete se decode");
    let dash = || "-".to_string();
    let index = |value: u32| format!("{value:#010x}");
    let (sender, receiver, counter, ephemeral, mac1, mac2, nonce, cookie, keepalive) =
        match &packet.message {
            WireGuardMessage::HandshakeInitiation(m) => (
                index(m.sender_index),
                dash(),
                dash(),
                hex(m.unencrypted_ephemeral),
                hex(m.mac1),
                hex(m.mac2),
                dash(),
                dash(),
                dash(),
            ),
            WireGuardMessage::HandshakeResponse(m) => (
                index(m.sender_index),
                index(m.receiver_index),
                dash(),
                hex(m.unencrypted_ephemeral),
                hex(m.mac1),
                hex(m.mac2),
                dash(),
                dash(),
                dash(),
            ),
            WireGuardMessage::CookieReply(m) => (
                dash(),
                index(m.receiver_index),
                dash(),
                dash(),
                dash(),
                dash(),
                hex(m.nonce),
                hex(m.encrypted_cookie),
                dash(),
            ),
            WireGuardMessage::TransportData(m) => (
                dash(),
                index(m.receiver_index),
                m.counter.to_string(),
                dash(),
                dash(),
                dash(),
                dash(),
                dash(),
                if m.is_keepalive() {
                    "1".to_string()
                } else {
                    dash()
                },
            ),
            _ => panic!("message inconnu"),
        };
    [
        source_port.to_string(),
        destination_port.to_string(),
        payload.len().to_string(),
        packet.message_type.to_string(),
        hex(&packet.reserved),
        sender,
        receiver,
        counter,
        ephemeral,
        mac1,
        mac2,
        nonce,
        cookie,
        keepalive,
    ]
    .join("\t")
}

/// Parite exacte avec tshark : la crate etiquette WireGuard exactement les
/// messages que tshark voit, sauf les 25 datagrammes Zoom et LoL nommes, et
/// en decode les memes champs ; aucun autre datagramme du corpus — disco de
/// Tailscale, handshakes etendus de TunnelBear, OpenVPN obfusque de NordVPN
/// — ne sort WireGuard.
#[test]
fn every_message_matches_the_tshark_oracle() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let oracle = read_oracle(&base.join(ORACLE));
    let mut captures = Vec::new();
    collect_capture_files(&base.join(CORPUS), &mut captures);
    assert_eq!(captures.len(), 9);

    let mut messages = 0;
    let mut misfires = 0;
    let mut by_type: BTreeMap<u8, usize> = BTreeMap::new();
    let mut by_port: BTreeMap<u16, usize> = BTreeMap::new();
    let mut keepalives = 0;
    let mut mtu_capped = 0;
    for path in &captures {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let empty = BTreeMap::new();
        let rows = oracle.get(&name).unwrap_or(&empty);
        let named: &[usize] = TSHARK_MISFIRES
            .iter()
            .find(|(file, _)| *file == name)
            .map_or(&[], |(_, frames)| frames);
        let mut seen = 0;
        for (index, (link_type, data)) in frames_of(path).iter().enumerate() {
            let number = index + 1;
            let flow = parse(*link_type, data).expect("trame du corpus decodable");
            let level = wireguard_level(&flow);
            let Some(row) = rows.get(&number) else {
                assert!(
                    level.is_none(),
                    "{name}:{number} : WireGuard pour la crate seule"
                );
                continue;
            };
            seen += 1;
            if named.contains(&number) {
                assert!(
                    level.is_none(),
                    "{name}:{number} : ecart de tshark etiquete WireGuard"
                );
                misfires += 1;
                continue;
            }
            let level = level.unwrap_or_else(|| panic!("{name}:{number} : message non etiquete"));
            let transport = level.transport.as_ref().expect("WireGuard est sur UDP");
            let payload = transport.payload.expect("un message a un payload");
            let (source, destination) = (
                transport.source_port.expect("port UDP"),
                transport.destination_port.expect("port UDP"),
            );
            assert_eq!(
                &oracle_columns(source, destination, payload),
                row,
                "{name}:{number} : ecart avec tshark"
            );
            *by_type.entry(payload[0]).or_default() += 1;
            // Le port du serveur : 51820, ou celui du service (Tailscale,
            // ProtonVPN sur 443, Mullvad sur 5060).
            let port = if source == 51_820 || destination == 51_820 {
                51_820
            } else {
                source.min(destination)
            };
            *by_port.entry(port).or_default() += 1;
            if payload.len() == 32 {
                keepalives += 1;
            }
            if payload[0] == 4 && !(payload.len() - 32).is_multiple_of(16) {
                mtu_capped += 1;
            }
            messages += 1;
        }
        assert_eq!(seen, rows.len(), "{name} : des lignes d'oracle sans trame");
    }

    assert_eq!(messages, 128);
    assert_eq!(misfires, 25);
    // Six handshakes complets, aucun Cookie Reply (aucune capture reelle
    // n'en porte : voir le test unitaire synthetique du decodeur).
    assert_eq!(by_type, BTreeMap::from([(1, 6), (2, 6), (4, 116)]));
    assert_eq!(
        by_port,
        BTreeMap::from([(443, 14), (5_060, 10), (41_641, 46), (51_820, 58)])
    );
    assert_eq!(keepalives, 5);
    // Cinq messages de 1 452 octets : 1 420 octets de clair, la MTU de
    // wg-quick, qui n'est pas un multiple de seize.
    assert_eq!(mtu_capped, 5);
}

/// Les voisins des messages WireGuard du corpus, que ni tshark ni la crate
/// ne prennent pour du WireGuard : les messages « disco » de Tailscale sur
/// le meme port 41641 (`TS` et l'emoji U+1F4AC), les deux handshakes etendus
/// de TunnelBear (204 et 100 octets), l'OpenVPN obfusque de NordVPN sur UDP
/// 1198 et la trame 41 de ProtonVPN, retouchee a la main (voir `SOURCE.md`).
#[test]
fn wireguard_neighbours_are_not_wireguard() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    type Selector = fn(usize, u16, u16, &[u8]) -> bool;
    let neighbours: [(&str, Selector, usize); 4] = [
        (
            "corelight_tailscale_linux.pcap",
            |_, _, _, payload| payload.starts_with(b"TS\xf0\x9f\x92\xac"),
            61,
        ),
        (
            "ndpi_tunnelbear.pcap",
            |number, _, _, payload| number <= 2 && matches!(payload.len(), 204 | 100),
            2,
        ),
        (
            "ndpi_nordvpn.pcap",
            |_, source, destination, _| source == 1198 || destination == 1198,
            43,
        ),
        ("ndpi_protonvpn.pcap", |number, _, _, _| number == 41, 1),
    ];
    for (name, selected, expected) in neighbours {
        let mut count = 0;
        for (index, (link_type, data)) in
            frames_of(&base.join(CORPUS).join(name)).iter().enumerate()
        {
            let flow = parse(*link_type, data).expect("trame decodable");
            let Some(transport) = flow.transport.as_ref() else {
                continue;
            };
            let (Some(source), Some(destination), Some(payload)) = (
                transport.source_port,
                transport.destination_port,
                transport.payload,
            ) else {
                continue;
            };
            if selected(index + 1, source, destination, payload) {
                assert!(wireguard_level(&flow).is_none(), "{name}:{}", index + 1);
                count += 1;
            }
        }
        assert_eq!(count, expected, "{name}");
    }
}

/// Les 128 messages deplaces hors de leur port (UDP 40000 -> 40001) : la
/// sonde aveugle les reconnait tous. Altere de trois octets reserves non
/// nuls, comme le fait Cloudflare WARP, un message n'est plus reconnu a
/// l'aveugle, mais l'est sur 51820 et sur un port declare par Decode As.
#[test]
fn blind_probe_port_51820_and_decode_as() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let oracle = read_oracle(&base.join(ORACLE));
    let config = ParseConfig::new().decode_as(40_001, DecodeAsProtocol::WireGuard);
    let mut replayed = 0;
    for (name, rows) in &oracle {
        if TSHARK_MISFIRES.iter().any(|(file, _)| file == name) {
            continue;
        }
        let frames = frames_of(&base.join(CORPUS).join(name));
        for number in rows.keys() {
            let (link_type, data) = &frames[number - 1];
            let flow = parse(*link_type, data).expect("trame decodable");
            let payload = wireguard_level(&flow)
                .and_then(|level| level.transport.as_ref())
                .and_then(|transport| transport.payload)
                .expect("message WireGuard");
            let start = payload.as_ptr() as usize - data.as_ptr() as usize;

            let mut moved = data.clone();
            moved[start - 8..start - 4].copy_from_slice(&[0x9c, 0x40, 0x9c, 0x41]);
            let flow = parse(*link_type, &moved).expect("trame deplacee");
            assert!(
                wireguard_level(&flow).is_some(),
                "{name}:{number} hors port"
            );

            let mut warp = moved.clone();
            warp[start + 1..start + 4].copy_from_slice(&[0x02, 0x78, 0x00]);
            let flow = parse(*link_type, &warp).expect("trame alteree");
            assert!(wireguard_level(&flow).is_none(), "{name}:{number} reserve");
            let flow = parse_with(*link_type, &warp, &config).expect("trame alteree");
            assert!(
                wireguard_level(&flow).is_some(),
                "{name}:{number} Decode As"
            );

            let mut on_51820 = warp.clone();
            on_51820[start - 8..start - 4].copy_from_slice(&[0x9c, 0x40, 0xca, 0x6c]);
            let flow = parse(*link_type, &on_51820).expect("trame alteree");
            assert!(
                wireguard_level(&flow).is_some(),
                "{name}:{number} sur 51820"
            );
            replayed += 1;
        }
    }
    assert_eq!(replayed, 128);
}
