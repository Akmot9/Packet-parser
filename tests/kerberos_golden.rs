// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests Kerberos V5 (#379) sur des trames reelles :
//! `pcaps_exemple/The-Ultimate-PCAP.pcapng` (TCP 88, un domaine Active
//! Directory), les dix captures de `pcaps_exemple/protocols/kerberos/` (voir
//! leur `SOURCE.md`) et deux datagrammes de
//! `protocols/ldap/ldap-krb5-sign-seal-01.cap`.
//!
//! L'oracle est tshark 4.6.9 (`tools/kerberos_oracle.sh`), rendu sans etat
//! comme la crate : reassemblage coupe, chaque segment lu seul. Pour chaque
//! message, le type, la longueur de l'enregistrement TCP, le code d'erreur,
//! les royaumes et les noms du client et du service sont figes dans
//! `tests/data/kerberos_tshark_oracle.tsv`.
//!
//! Les 133 TGS-REQ portent chacun un AP-REQ dans leur pre-authentification :
//! le decodeur le lit aussi, sur ces octets reels.
//!
//! Oracle negatif : aucune autre trame de ces captures ne sort `Kerberos`,
//! et les autres charges du port 88, des segments de suite, sortent
//! `Unknown`.

use std::{collections::BTreeMap, fs, path::Path};

use packet_parser::{
    TransportProtocol, parse,
    parse::application::protocols::kerberos::{
        KerberosMessage, KerberosMessageType, KerberosPrincipalName, KerberosRecord,
    },
};

mod common;
use common::{FileRead, collect_capture_files, read_capture};

const ORACLE: &str = "tests/data/kerberos_tshark_oracle.tsv";
const ROOT: &str = "pcaps_exemple";

fn text(bytes: Option<&[u8]>) -> String {
    bytes.map_or_else(
        || "-".to_string(),
        |bytes| String::from_utf8_lossy(bytes).into_owned(),
    )
}

/// Le type et les composantes d'un nom, comme l'oracle les ecrit.
fn name(name: Option<KerberosPrincipalName<'_>>) -> [String; 2] {
    let Some(name) = name else {
        return ["-".to_string(), "-".to_string()];
    };
    let components: Vec<String> = name
        .components()
        .map(|component| String::from_utf8_lossy(component).into_owned())
        .collect();
    // Un nom que le segment coupe avant sa premiere composante : l'oracle
    // n'en a que le type.
    let components = if components.is_empty() {
        "-".to_string()
    } else {
        components.join("/")
    };
    [name.name_type.to_string(), components]
}

#[test]
fn every_kerberos_message_matches_the_tshark_oracle() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let oracle = fs::read_to_string(base.join(ORACLE)).expect("oracle lisible");
    let mut rows: BTreeMap<(String, usize), Vec<String>> = BTreeMap::new();
    for line in oracle.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<String> = line.split('\t').map(str::to_string).collect();
        assert_eq!(fields.len(), 13, "ligne d'oracle malformee : {line}");
        let frame = fields[1].parse().expect("numero de trame");
        rows.insert((fields[0].clone(), frame), fields);
    }
    assert_eq!(rows.len(), 453);

    let root = base.join(ROOT);
    let mut captures = vec![root.join("The-Ultimate-PCAP.pcapng")];
    collect_capture_files(&root.join("protocols"), &mut captures);

    let mut per_capture: BTreeMap<String, usize> = BTreeMap::new();
    let mut kinds: BTreeMap<(String, u8), usize> = BTreeMap::new();
    let mut errors: BTreeMap<i32, usize> = BTreeMap::new();
    let mut truncated = 0usize;
    let mut ap_requests = 0usize;
    let mut continuations: BTreeMap<String, usize> = BTreeMap::new();
    for path in &captures {
        let capture = path
            .strip_prefix(&root)
            .expect("capture du corpus")
            .to_string_lossy()
            .replace('\\', "/");
        let FileRead::Frames { frames, .. } = read_capture(path) else {
            continue;
        };
        for (index, (link_type, data)) in frames.iter().enumerate() {
            let number = index + 1;
            let key = (capture.clone(), number);
            let Ok(flow) = parse(*link_type, data) else {
                assert!(!rows.contains_key(&key), "{capture} trame {number}");
                continue;
            };
            let flow = *flow.flatten().last().expect("au moins un flux");
            let label = flow
                .application
                .as_ref()
                .map(|application| application.protocol.label());
            let transport = flow.transport.as_ref();
            let payload = transport.and_then(|transport| transport.payload);
            let on_port = transport.is_some_and(|transport| {
                transport.source_port == Some(88) || transport.destination_port == Some(88)
            });
            let Some(row) = rows.get(&key) else {
                assert_ne!(label, Some("Kerberos"), "{capture} trame {number}");
                // Le reste du port 88 : des segments de suite.
                if on_port && payload.is_some_and(|payload| !payload.is_empty()) {
                    assert_eq!(label, Some("Unknown"), "{capture} trame {number}");
                    assert_eq!(
                        transport.map(|transport| transport.protocol),
                        Some(TransportProtocol::Tcp),
                        "{capture} trame {number}"
                    );
                    *continuations.entry(capture.clone()).or_default() += 1;
                }
                continue;
            };
            assert_eq!(label, Some("Kerberos"), "{capture} trame {number}");
            let transport = transport.expect("couche transport");
            let payload = payload.expect("charge");
            let is_udp = transport.protocol == TransportProtocol::Udp;
            let (record, message) = if is_udp {
                let message = KerberosMessage::try_from(payload)
                    .unwrap_or_else(|error| panic!("{capture} trame {number} : {error}"));
                // Un datagramme, un message entier.
                assert!(!message.is_truncated(), "{capture} trame {number}");
                assert_eq!(message.wire_length(), payload.len());
                ("-".to_string(), message)
            } else {
                let record = KerberosRecord::try_from(payload)
                    .unwrap_or_else(|error| panic!("{capture} trame {number} : {error}"));
                // La marque annonce le message ; le segment le coupe quand
                // il est plus court.
                assert_eq!(record.length as usize, record.message.wire_length());
                assert_eq!(
                    record.is_truncated(),
                    payload.len() < 4 + record.length as usize,
                    "{capture} trame {number}"
                );
                assert_eq!(KerberosRecord::records(payload).count(), 1);
                (record.length.to_string(), record.message)
            };
            assert!(message.rest().is_empty(), "{capture} trame {number}");
            let [client_type, client] = name(message.client_name());
            let [service_type, service] = name(message.service_name());
            let decoded = [
                capture.clone(),
                number.to_string(),
                if is_udp { "udp" } else { "tcp" }.to_string(),
                payload.len().to_string(),
                record,
                message.message_type.code().to_string(),
                message
                    .error_code()
                    .map_or_else(|| "-".to_string(), |code| code.to_string()),
                text(message.realm()),
                text(message.client_realm()),
                client_type,
                client,
                service_type,
                service,
            ];
            assert_eq!(decoded.as_slice(), row.as_slice());

            *per_capture.entry(capture.clone()).or_default() += 1;
            let transport_name = if is_udp { "udp" } else { "tcp" };
            *kinds
                .entry((transport_name.to_string(), message.message_type.code()))
                .or_default() += 1;
            if let Some(code) = message.error_code() {
                *errors.entry(code).or_default() += 1;
            }
            truncated += usize::from(message.is_truncated());

            // Un TGS-REQ presente son ticket dans un AP-REQ, que porte sa
            // pre-authentification (champ [3], PA-TGS-REQ) : un message
            // Kerberos dans un autre, le seul AP-REQ du port 88.
            if message.message_type == KerberosMessageType::TgsReq {
                let padata = message.field(3).expect("padata d'un TGS-REQ");
                let request = (0..padata.len())
                    .filter(|offset| padata[*offset] == 0x6e)
                    .find_map(|offset| KerberosMessage::try_from(&padata[offset..]).ok())
                    .unwrap_or_else(|| panic!("{capture} trame {number} : pas d'AP-REQ"));
                assert_eq!(request.message_type, KerberosMessageType::ApReq);
                assert_eq!(request.field(0), Some(&[0x02, 0x01, 0x05][..]));
                assert_eq!(request.field(1), Some(&[0x02, 0x01, 0x0e][..]));
                // Les lectures de l'echange avec le KDC ne s'y appliquent
                // pas.
                assert_eq!(request.realm(), None);
                assert_eq!(request.service_name(), None);
                ap_requests += 1;
            }
        }
    }
    assert_eq!(per_capture.values().sum::<usize>(), 453);
    let counts = |entries: &[(&str, usize)]| -> BTreeMap<String, usize> {
        entries
            .iter()
            .map(|(capture, count)| (capture.to_string(), *count))
            .collect()
    };
    assert_eq!(
        per_capture,
        counts(&[
            ("The-Ultimate-PCAP.pcapng", 134),
            (
                "protocols/kerberos/ndpi_kerberos-constrained-delegation.pcap",
                8
            ),
            ("protocols/kerberos/ndpi_kerberos-cross-realm.pcap", 2),
            ("protocols/kerberos/ndpi_kerberos-error.pcap", 2),
            ("protocols/kerberos/ndpi_kerberos-login.pcap", 28),
            ("protocols/kerberos/ndpi_kerberos-pkinit.pcap", 8),
            ("protocols/kerberos/ndpi_kerberos-s4u2self.pcap", 14),
            ("protocols/kerberos/ndpi_kerberos-short-realm.pcap", 4),
            ("protocols/kerberos/ndpi_kerberos-user.pcap", 2),
            ("protocols/kerberos/ndpi_kerberos.pcap", 19),
            ("protocols/kerberos/ndpi_kerberos2.pcap", 230),
            ("protocols/ldap/ldap-krb5-sign-seal-01.cap", 2),
        ]),
        "messages par capture"
    );
    // Les cinq messages de l'echange avec le KDC, sur les deux transports :
    // AS-REQ (10), AS-REP (11), TGS-REQ (12), TGS-REP (13), KRB-ERROR (30).
    let kinds: Vec<(&str, u8, usize)> = kinds
        .iter()
        .map(|((transport, kind), count)| (transport.as_str(), *kind, *count))
        .collect();
    assert_eq!(
        kinds,
        [
            ("tcp", 10, 91),
            ("tcp", 11, 38),
            ("tcp", 12, 118),
            ("tcp", 13, 105),
            ("tcp", 30, 63),
            ("udp", 10, 4),
            ("udp", 11, 2),
            ("udp", 12, 15),
            ("udp", 13, 15),
            ("udp", 30, 2),
        ],
        "messages par transport et type"
    );
    // 6 : client inconnu ; 7 : service inconnu ; 13 : option refusee ; 14 :
    // chiffrement non gere ; 25 : pre-authentification requise ; 52 :
    // reponse trop grande pour UDP ; 68 : mauvais royaume.
    assert_eq!(
        errors.into_iter().collect::<Vec<_>>(),
        [(6, 3), (7, 7), (13, 7), (14, 1), (25, 45), (52, 1), (68, 1)],
        "codes d'erreur"
    );
    // Un AP-REQ par TGS-REQ.
    assert_eq!(ap_requests, 133, "AP-REQ dans les TGS-REQ");
    // 150 des 415 messages de TCP depassent leur segment.
    assert_eq!(truncated, 150, "messages coupes");
    assert_eq!(
        continuations,
        counts(&[
            ("The-Ultimate-PCAP.pcapng", 82),
            (
                "protocols/kerberos/ndpi_kerberos-constrained-delegation.pcap",
                3
            ),
            ("protocols/kerberos/ndpi_kerberos-user.pcap", 2),
            ("protocols/kerberos/ndpi_kerberos.pcap", 29),
            ("protocols/kerberos/ndpi_kerberos2.pcap", 65),
        ]),
        "segments de suite"
    );
}
