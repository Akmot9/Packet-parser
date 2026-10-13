// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden test NTP sur datagrammes reels (#161, #162, #164, #165).
//!
//! Captures :
//! - le poste IEC 61850 de
//!   `pcaps_exemple/protocols/goose/iti_Sample_File_MMS_and_GOOSE.pcap` (voir
//!   son `SOURCE.md`), 52 datagrammes NTP — requetes et reponses, v4 et v1,
//!   dont les reponses a un client dont l'horloge est en avance sur celle du
//!   serveur, que la crate rejetait (#161) ;
//! - l'echange de `pcaps_exemple/protocols/iec104/iti_JavaRMI_and_IEC_Misc.pcap` :
//!   un client Java qui emet un horodatage de l'ere 1 (2036) et un serveur
//!   de stratum 1 dont l'identifiant de reference, `SHM`, n'est pas dans la
//!   liste de la RFC 5905 (#162) ;
//! - les captures de `pcaps_exemple/protocols/ntp/` (voir son `SOURCE.md`) :
//!   deux vrais NTP et des datagrammes QUIC, KCP, PFCP... que l'ancienne
//!   sonde aveugle prenait pour du NTP (nDPI, #164), et des NTP a MAC SHA-1,
//!   SHA-256 et SHA-512 (tracker Wireshark) ;
//! - lues en place, `pcaps_exemple/The-Ultimate-PCAP.pcapng` — requetes NTS,
//!   MS-SNTP authentifie, mode symetrique, serveurs a amont IPv6 dont
//!   l'identifiant de reference se lit comme une adresse multicast, clients
//!   non synchronises (#165) — et `pcaps_exemple/4SICS-GeekLounge-151020.pcap`.
//!
//! L'oracle est tshark 4.6.6 (`tools/ntp_oracle.sh`) : pour chaque datagramme,
//! ports, LI, version, mode, stratum, poll, precision, root delay, root
//! dispersion, identifiant de reference et les quatre horodatages a la
//! nanoseconde, figes dans `tests/data/ntp_tshark_oracle.tsv` et compares ici
//! datagramme par datagramme ; aucune autre trame de `pcaps_exemple/` ne
//! sort NTP. Deux ecarts sont nommes, pas masques : les
//! messages de controle du mode 6 (ntpq), dont le format n'est pas celui que
//! [`NtpPacket`] modelise, et les erreurs ICMP qui citent un datagramme NTP —
//! la crate etiquette la trame ICMP, pas le datagramme cite.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::Ipv4Addr,
    path::{Path, PathBuf},
};

use chrono::{DateTime, SecondsFormat, Utc};
use packet_parser::{PacketFlow, parse, parse::application::protocols::ntp::NtpPacket};

mod common;
use common::{FileRead, collect_capture_files, read_capture};

const CORPUS: &str = "pcaps_exemple/protocols";
const EXAMPLES: &str = "pcaps_exemple";
const ORACLE: &str = "tests/data/ntp_tshark_oracle.tsv";

/// Une ligne d'oracle : le porteur (`udp` ou `icmp`), le mode, et les
/// colonnes a partir du port source.
struct Row {
    carrier: String,
    mode: Option<u8>,
    columns: String,
}

fn read_oracle(path: &Path) -> BTreeMap<String, BTreeMap<usize, Row>> {
    let oracle = fs::read_to_string(path).expect("oracle lisible");
    let mut expected: BTreeMap<String, BTreeMap<usize, Row>> = BTreeMap::new();
    for line in oracle.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<&str> = line.splitn(4, '\t').collect();
        assert_eq!(fields.len(), 4, "ligne d'oracle malformee : {line}");
        let columns = fields[3].to_string();
        let mode = columns
            .split('\t')
            .nth(4)
            .and_then(|mode| mode.parse().ok());
        expected.entry(fields[0].to_string()).or_default().insert(
            fields[1].parse().expect("numero de trame"),
            Row {
                carrier: fields[2].to_string(),
                mode,
                columns,
            },
        );
    }
    expected
}

/// Les captures du golden : celles de l'oracle, et tout le corpus de
/// `pcaps_exemple/` — aucune autre trame ne doit sortir NTP.
fn captures(
    base: &Path,
    oracle: &BTreeMap<String, BTreeMap<usize, Row>>,
) -> Vec<(String, PathBuf)> {
    let mut names: BTreeSet<String> = oracle.keys().cloned().collect();
    let corpus = base.join(CORPUS);
    let mut all = Vec::new();
    collect_capture_files(&base.join(EXAMPLES), &mut all);
    for path in all {
        let name = match path.strip_prefix(&corpus) {
            Ok(relative) => relative.to_string_lossy().to_string(),
            Err(_) => format!(
                "../{}",
                path.strip_prefix(base.join(EXAMPLES))
                    .expect("capture du corpus")
                    .to_string_lossy()
            ),
        };
        names.insert(name);
    }
    names
        .into_iter()
        .map(|name| {
            let path = base.join(CORPUS).join(&name);
            (name, path)
        })
        .collect()
}

fn frames_of(name: &str, path: &Path) -> Vec<(packet_parser::LinkType, Vec<u8>)> {
    let FileRead::Frames {
        frames,
        read_error_after: None,
    } = read_capture(path)
    else {
        panic!("{name} : capture illisible");
    };
    frames
}

fn label(flow: &PacketFlow<'_>) -> Option<&'static str> {
    flow.application
        .as_ref()
        .map(|application| application.application_protocol)
}

/// Le niveau de la trame etiquete NTP : l'interieur du tunnel pour les
/// trames 6in4 de l'Ultimate PCAP (IPv6 dans IPv4).
fn ntp_level<'f, 'a>(flow: &'f PacketFlow<'a>) -> Option<&'f PacketFlow<'a>> {
    flow.flatten()
        .into_iter()
        .find(|level| label(level) == Some("NTP"))
}

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

/// L'identifiant de reference tel que la crate doit le nommer : un code
/// ASCII ou `NULL` au stratum 0 (sinon ses octets), un code au stratum 1,
/// une adresse IPv4 — ou le hachage d'un amont IPv6 qui en a la forme —
/// au-dela.
fn expected_display(stratum: u8, bytes: [u8; 4]) -> String {
    let code = {
        let end = bytes
            .iter()
            .rposition(|&b| b != 0 && b != b' ')
            .map_or(0, |i| i + 1);
        bytes[..end]
            .iter()
            .all(u8::is_ascii_graphic)
            .then(|| String::from_utf8_lossy(&bytes[..end]).to_string())
    };
    match (stratum, code) {
        (0, Some(code)) if code.is_empty() => "NULL".to_string(),
        (0 | 1, Some(code)) => code,
        (0, None) => format!("{bytes:02X?}"),
        _ => Ipv4Addr::from(bytes).to_string(),
    }
}

/// Les colonnes de l'oracle a partir du port source.
fn oracle_columns(
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
    packet: &NtpPacket,
) -> String {
    let (li, version, mode) = packet.flags;
    let reference = [payload[12], payload[13], payload[14], payload[15]];
    assert_eq!(
        packet.reference_id.to_string(),
        expected_display(packet.stratum, reference)
    );
    [
        source_port.to_string(),
        destination_port.to_string(),
        li.to_string(),
        version.to_string(),
        mode.to_string(),
        packet.stratum.to_string(),
        packet.poll_exponent().to_string(),
        packet.precision.to_string(),
        packet.root_delay.to_string(),
        packet.root_dispersion.to_string(),
        hex(&reference),
        timestamp(packet.reference_timestamp),
        timestamp(packet.originate_timestamp),
        timestamp(packet.receive_timestamp),
        timestamp(packet.transmit_timestamp),
    ]
    .join("\t")
}

/// Parite exacte avec tshark : la crate etiquette NTP exactement les
/// datagrammes NTP (modes 1 a 5) que tshark voit, et en decode les memes
/// champs ; tout autre datagramme, faux positifs d'hier compris, reste hors
/// de NTP.
#[test]
fn every_ntp_datagram_matches_the_tshark_oracle() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let oracle = read_oracle(&base.join(ORACLE));

    let mut datagrams = 0;
    let mut control_messages = 0;
    let mut icmp_quotes = 0;
    let mut by_version_and_mode: BTreeMap<(u8, u8), usize> = BTreeMap::new();
    let mut client_ahead = 0;
    let mut with_trailer: BTreeMap<usize, usize> = BTreeMap::new();
    let mut multicast_like_reference = 0;
    let mut stratum_0_reference = 0;
    for (name, path) in captures(base, &oracle) {
        let empty = BTreeMap::new();
        let rows = oracle.get(&name).unwrap_or(&empty);
        let mut seen = 0;
        // Hors de l'oracle, une capture que pcap-file ne lit pas (NetXRay) ou
        // pas jusqu'au bout (enregistrement malforme) compte pour ce qu'elle
        // donne ; celles de l'oracle doivent se lire en entier.
        let frames = if rows.is_empty() {
            match read_capture(&path) {
                FileRead::Frames { frames, .. } => frames,
                FileRead::Unsupported => continue,
            }
        } else {
            frames_of(&name, &path)
        };
        for (index, (link_type, data)) in frames.iter().enumerate() {
            let number = index + 1;
            let flow = parse(*link_type, data);
            let level = flow.as_ref().ok().and_then(ntp_level);
            let is_ntp = level.is_some();
            let Some(row) = rows.get(&number) else {
                assert!(
                    !is_ntp,
                    "{name}:{number} : etiquete NTP, tshark n'y voit pas de NTP"
                );
                continue;
            };
            seen += 1;
            if row.carrier == "icmp" {
                assert!(!is_ntp, "{name}:{number} : citation ICMP etiquetee NTP");
                icmp_quotes += 1;
                continue;
            }
            if matches!(row.mode, Some(6 | 7)) {
                assert!(
                    !is_ntp,
                    "{name}:{number} : message de controle etiquete NTP"
                );
                control_messages += 1;
                continue;
            }
            let level =
                level.unwrap_or_else(|| panic!("{name}:{number} : datagramme NTP non etiquete"));
            let transport = level.transport.as_ref().expect("NTP est sur UDP");
            let payload = transport.payload.expect("un datagramme NTP a un payload");
            let packet =
                NtpPacket::try_from(payload).expect("un datagramme etiquete NTP se decode");
            assert_eq!(
                oracle_columns(
                    transport.source_port.expect("port UDP"),
                    transport.destination_port.expect("port UDP"),
                    payload,
                    &packet,
                ),
                row.columns,
                "{name}:{number} : ecart avec tshark"
            );
            *by_version_and_mode
                .entry((packet.flags.1, packet.flags.2))
                .or_default() += 1;
            if packet.flags.2 == 4 && packet.originate_timestamp > packet.receive_timestamp {
                client_ahead += 1;
            }
            if payload.len() > 48 {
                *with_trailer.entry(payload.len()).or_default() += 1;
            }
            if packet.stratum >= 2 && (224..=239).contains(&payload[12]) {
                multicast_like_reference += 1;
            }
            if packet.stratum == 0 && payload[12..16] != [0; 4] {
                stratum_0_reference += 1;
            }
            datagrams += 1;
        }
        assert_eq!(seen, rows.len(), "{name} : des lignes d'oracle sans trame");
    }

    assert_eq!(datagrams, 1_308);
    // Les deux ecarts nommes : messages de controle (ntpq) et erreurs ICMP
    // qui citent un datagramme NTP.
    assert_eq!(control_messages, 104);
    assert_eq!(icmp_quotes, 36);
    assert_eq!(
        by_version_and_mode,
        BTreeMap::from([
            ((1, 3), 2),
            ((1, 4), 2),
            ((3, 3), 29),
            ((3, 4), 31),
            ((4, 1), 38),
            ((4, 3), 609),
            ((4, 4), 597),
        ])
    );
    // Dans 63 reponses de serveur, l'horloge du client (originate) est en
    // avance sur celle du serveur (receive) : exactement ce que le decodeur
    // rejetait (#161).
    assert_eq!(client_ahead, 63);
    // Apres l'en-tete : crypto-NAK (4 octets), MAC MD5 (20), SHA-1 (24),
    // SHA-256 (36) ou SHA-512 (68, wireshark_16640_NTP-with-mac.pcap),
    // Extended Authenticator de MS-SNTP (72), champs d'extension NTS (180 et
    // 492 octets).
    assert_eq!(
        with_trailer,
        BTreeMap::from([
            (52, 41),
            (68, 44),
            (72, 16),
            (84, 1),
            (116, 3),
            (120, 6),
            (228, 58),
            (540, 2)
        ])
    );
    // #165 : 23 reponses dont l'amont IPv6 a un hachage qui se lit comme une
    // adresse multicast, et 62 datagrammes au stratum 0 qui portent un
    // identifiant (kiss codes, et requetes de clients non synchronises).
    assert_eq!(multicast_like_reference, 23);
    assert_eq!(stratum_0_reference, 72);
}

/// Les faux positifs de l'ancienne sonde aveugle dans `protocols/ntp/`
/// (#164) : le decodeur tolerant du port 123 les accepte, la sonde aveugle
/// non.
const FORMER_FALSE_POSITIVES: &[(&str, &[usize])] = &[
    (
        "ntp/ndpi_crynet.pcap",
        &[120, 121, 124, 133, 139, 162, 163, 167, 177, 194, 200],
    ),
    ("ntp/ndpi_kcp.pcap", &[1, 18]),
    ("ntp/ndpi_line.pcap", &[41]),
    ("ntp/ndpi_openvpn_obfuscated.pcapng", &[78]),
    ("ntp/ndpi_pfcp.pcapng", &[11]),
    (
        "ntp/ndpi_quic_interop_V.pcapng",
        &[
            20, 40, 58, 60, 65, 69, 80, 81, 84, 100, 145, 163, 196, 205, 206,
        ],
    ),
];

/// Des datagrammes que l'ancien decodeur refusait et que le decodeur
/// assoupli par #165 accepte — identifiant de stratum 0 quelconque, Receive
/// apres Transmit — : la sonde aveugle les refuse. Segments KCP (`01 00 00
/// 00` au stratum 0, root delay de plus de 20 000 s), QUIC, CryNet, et les
/// datagrammes ASTERIX CAT 021 de `wireshark_9953_cat021023.pcap`, dont 1 555
/// ont la forme d'un en-tete NTP.
const LENIENT_LOOKALIKES: &[(&str, &[usize])] = &[
    ("asterix/wireshark_9953_cat021023.pcap", &[2, 3, 4]),
    ("ntp/ndpi_crynet.pcap", &[119]),
    ("ntp/ndpi_kcp.pcap", &[3, 24]),
    ("ntp/ndpi_quic_interop_V.pcapng", &[27, 78]),
];

#[test]
fn former_false_positives_are_no_longer_ntp() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut checked = 0;
    for (name, numbers) in FORMER_FALSE_POSITIVES.iter().chain(LENIENT_LOOKALIKES) {
        let frames = frames_of(name, &base.join(CORPUS).join(name));
        for &number in *numbers {
            let (link_type, data) = &frames[number - 1];
            let flow = parse(*link_type, data).expect("trame decodable");
            assert!(ntp_level(&flow).is_none(), "{name}:{number} : encore NTP");
            // L'etiquette qu'ils gardent : ASTERIX pour les datagrammes de
            // surveillance, Unknown pour les autres.
            let expected = if name.starts_with("asterix/") {
                "ASTERIX"
            } else {
                "Unknown"
            };
            assert_eq!(label(&flow), Some(expected), "{name}:{number}");
            let transport = flow.transport.as_ref().expect("UDP");
            assert!(transport.source_port != Some(123) && transport.destination_port != Some(123));
            let payload = transport.payload.expect("payload UDP");
            assert!(
                NtpPacket::try_from(payload).is_ok(),
                "{name}:{number} : le decodeur tolerant ne l'accepte plus"
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 39);
}

/// Les datagrammes NTP reels, deplaces hors du port 123 (UDP 40000 ->
/// 40001) : la sonde aveugle les reconnait — requetes NTS et MS-SNTP,
/// precision tue de chrony, clients non synchronises au stratum 0 compris —,
/// sauf une requete de chrony dont Receive suit Transmit.
#[test]
fn real_datagrams_are_ntp_off_port_too() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let oracle = read_oracle(&base.join(ORACLE));
    let mut replayed = 0;
    let mut refused = Vec::new();
    for (name, rows) in &oracle {
        let frames = frames_of(name, &base.join(CORPUS).join(name));
        for (number, row) in rows {
            if row.carrier != "udp" || matches!(row.mode, Some(6 | 7)) {
                continue;
            }
            let (link_type, data) = &frames[number - 1];
            let flow = parse(*link_type, data).expect("trame decodable");
            let level = ntp_level(&flow).expect("datagramme NTP");
            let payload = level.transport.as_ref().unwrap().payload.unwrap();
            // L'en-tete UDP precede le payload : ses ports en sont les huit
            // premiers octets moins quatre.
            let start = payload.as_ptr() as usize - data.as_ptr() as usize;
            let mut moved = data.clone();
            moved[start - 8..start - 4].copy_from_slice(&[0x9c, 0x40, 0x9c, 0x41]);
            let moved_flow = parse(*link_type, &moved).expect("trame deplacee");
            if ntp_level(&moved_flow).is_none() {
                refused.push(format!("{name}:{number}"));
            }
            replayed += 1;
        }
    }
    assert_eq!(replayed, 1_308);
    // Une requete de chrony aux horodatages Receive et Transmit aleatoires
    // (precision 32), Receive apres Transmit : seule la sonde aveugle
    // compare les deux, et la refuse.
    assert_eq!(refused, ["ntp/tcpdump_ntp.pcap:3"]);
}
