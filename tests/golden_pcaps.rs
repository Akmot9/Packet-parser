// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Snapshot de classification applicative sur le corpus reel (audit 8.1.0
//! §5.3, prerequis a toute refonte du dispatch L7) : l'histogramme
//! {etiquette -> nombre de flux} sur `pcaps_exemple/protocols/` (hors
//! `s7comm/`, couvert par sa propre regression, selection < 2 Mo) est fige.
//!
//! Une regression de classification — un protocole qui cesse d'etre reconnu,
//! un faux positif qui apparait — casse ce test avec un diff lisible. Toute
//! evolution volontaire du dispatch doit mettre a jour l'attendu **dans le
//! meme commit**, avec sa justification.

use std::collections::BTreeMap;
use std::path::Path;

use packet_parser::parse;

mod common;
use common::{FileRead, collect_capture_files, read_capture};

/// Etiquette d'un flux : son protocole applicatif, ou un marqueur explicite.
const NO_APPLICATION: &str = "(sans application)";
const LINK_ERROR: &str = "(erreur L2)";

fn classification_histogram() -> BTreeMap<String, usize> {
    let protocol_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("pcaps_exemple")
        .join("protocols");
    let mut captures = Vec::new();
    collect_capture_files(protocol_dir.as_path(), &mut captures);
    captures.sort();
    assert!(!captures.is_empty(), "corpus introuvable");

    let mut histogram: BTreeMap<String, usize> = BTreeMap::new();
    for path in &captures {
        let FileRead::Frames { frames, .. } = read_capture(path) else {
            continue;
        };
        for (link_type, data) in &frames {
            let Ok(flow) = parse(*link_type, data) else {
                *histogram.entry(LINK_ERROR.to_string()).or_default() += 1;
                continue;
            };
            for flattened in flow.flatten() {
                let label = flattened
                    .application
                    .as_ref()
                    .map_or(NO_APPLICATION, |application| {
                        application.application_protocol
                    });
                *histogram.entry(label.to_string()).or_default() += 1;
            }
        }
    }
    histogram
}

#[test]
fn application_classification_histogram_is_frozen() {
    let actual = classification_histogram();

    // Fige le 2026-08-19 sur 58 captures (2 893 trames), avant la refonte du
    // dispatch L7 en table declarative. Les 42 « erreur L2 » sont les trames
    // de mqtt_packets_MosquittoLinux.pcap et consorts au LINKTYPE non
    // supporte, deja comptees par la regression s7comm.
    //
    // Evolutions volontaires (meme jour) :
    // - DNS 102 -> 104 : correction NXDOMAIN — l'exigence aa=1 sur rcode 3
    //   rejetait les reponses des resolveurs recursifs
    //   (dns_query_nonexistent.pcapng#2, dns_lab.pcapng#18) ;
    // - NTP 4 -> 0, TLS 584 -> 587, Unknown 419 -> 418 : gardes de transport
    //   sur les sondes aveugles. Les quatre « NTP » etaient des faux positifs
    //   sur du TCP (dont trois Encrypted Alerts TLS de dump.pcapng, 0x15 lu
    //   comme LI/VN/mode) — le corpus n'a aucune vraie capture NTP
    //   (protocols/ntp/ ne contient qu'un .gitkeep).
    //
    // 2026-08-20 (issue #57) : ajout de protocols/ethernet_ip/ (3 captures
    // ITI/ICS-Security-Tools, 13 trames). Les 4 trames EtherNet/IP reelles
    // (ListIdentity requete/reponse, SendRRData, SendUnitData) creent
    // l'entree "EtherNet/IP" ; les 9 trames restantes d'enip_test.pcap sont
    // du handshake/teardown TCP sans payload -> "(sans application)"
    // 1233 -> 1242.
    //
    // 2026-08-20 (issue #5) : ajout de protocols/openvpn/ (2 samples publics
    // de la wiki Wireshark, 878 trames, session tls-auth sur UDP puis TCP
    // 1194). Le module openvpn n'etant pas encore cable dans le dispatch,
    // aucune etiquette OpenVPN : les 766 trames portant un message OpenVPN
    // sortent "Unknown" (439 datagrammes UDP + 327 segments TCP a payload,
    // comptes par `tshark -Y openvpn` moins la trame ICMP ci-dessous) ;
    // les 112 restantes n'ont pas de L7 (111 segments TCP purs
    // handshake/ACK sans payload, plus la trame UDP 440 — un ICMP port
    // unreachable qui embarque l'extrait du datagramme OpenVPN, que tshark
    // compte "openvpn" mais que la crate classe ICMP). "(sans application)"
    // 1242 -> 1354, "Unknown" 418 -> 1184. Au cablage du port 1194, ces 766
    // "Unknown" deviendront l'entree "OpenVPN".
    //
    // 2026-08-20 (issue #58) : ajout de protocols/giop/corba.pcap (corpus de
    // tests nDPI, 28 trames, verifie avec tshark 4.6.6). Les 3 messages GIOP
    // qui tiennent dans leur segment TCP (trames 4, 6, 12 : Request "echo" et
    // deux Reply) creent l'entree "GIOP" ; 9 trames TCP sans payload
    // (handshake/ACK) vont en "(sans application)" ; les 16 restantes sortent
    // "Unknown" (+16, 1184 -> 1200) : 10 datagrammes UDP MIOP (le dispatch ne
    // sonde GIOP que sur TCP), 5 segments d'un Request/Reply GIOP deborde de
    // son segment (s=4152/4017, tronque par la segmentation TCP) et 1 message
    // ZIOP (GIOP compresse, magic "ZIOP", hors perimetre).
    //
    // Constate lors du meme gel (travaux concurrents deja presents dans
    // l'arbre, hors issue #58) :
    // - les 5 trames de protocols/ftp/ sortent desormais en flux aplatis
    //   "IP-in-IP" (externe) + "FTP" (interne), soit +5 "FTP", +5 "IP-in-IP"
    //   et -5 "(sans application)" (1354 + 9 - 5 = 1358) ;
    // - le cablage OpenVPN (issue #5) est arrive : les 766 trames OpenVPN
    //   annoncees ci-dessus quittent "Unknown" pour l'entree "OpenVPN"
    //   (1184 + 16 - 766 = 434).
    let expected: BTreeMap<String, usize> = [
        (LINK_ERROR, 42_usize),
        (NO_APPLICATION, 1358),
        ("DHCP", 6),
        ("DHCPv6", 4),
        ("DNS", 104),
        ("EtherNet/IP", 4),
        ("FTP", 5),
        ("GIOP", 3),
        ("HTTP", 62),
        ("IP-in-IP", 5),
        ("MQTT", 38),
        ("ModbusTCP", 383),
        ("NNTP", 6),
        ("OpenVPN", 766),
        ("SMTP", 6),
        ("TLS", 587),
        ("Unknown", 434),
        ("mDNS", 4),
    ]
    .into_iter()
    .map(|(label, count)| (label.to_string(), count))
    .collect();

    assert_eq!(
        actual, expected,
        "\nhistogramme observe (a figer dans `expected` si le changement est voulu) :\n{:#?}\n",
        actual
    );
}
