// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests Java RMI (JRMP) sur la capture JDK du corpus (#313).
//!
//! Capture : `pcaps_exemple/protocols/java_rmi/jdk11-loopback.pcap`, deux
//! JVM OpenJDK 11 sur la boucle locale (voir son `SOURCE.md`) : registre
//! sur TCP 1099, objet exporte sur 50050, connecteur JMX sur 50051.
//!
//! L'oracle est tshark 4.6.9 (`tools/java_rmi_oracle.sh`), qui decode RMI
//! sur 1099 et, par Decode As, sur 50050 et 50051 : type de chaque message,
//! version et protocole des en-tetes de flux, nom d'hote et port des
//! ProtocolAck, figes dans `tests/data/java_rmi_tshark_oracle.tsv`. tshark
//! ne lit ni l'en-tete d'appel ni celui de retour : ce que la crate en tire
//! est recoupe par la structure de la session (objets bien connus du
//! registre et du DGC, UID des DgcAck).

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use packet_parser::{
    DecodeAsProtocol, PacketFlow, ParseConfig, parse,
    parse::application::protocols::java_rmi::{
        JAVA_RMI_DGC_INTERFACE_HASH, JAVA_RMI_REGISTRY_INTERFACE_HASH, JavaRmiPacket,
        JavaRmiProtocol, JavaRmiReturnType, JavaRmiUid, JavaRmiWellKnownObject,
    },
    parse_with,
};

mod common;
use common::{FileRead, read_capture};

const CAPTURE: &str = "pcaps_exemple/protocols/java_rmi/jdk11-loopback.pcap";
const ORACLE: &str = "tests/data/java_rmi_tshark_oracle.tsv";
const REGISTRY_PORT: u16 = 1099;
/// L'objet `Station` et le connecteur JMX : des ports que choisit
/// l'application, que tshark comme la crate ne connaissent que declares.
const OBJECT_PORTS: [u16; 2] = [50050, 50051];

/// Une ligne de l'oracle : le type de message (`None` pour une
/// « Continuation »), puis les champs que tshark decode.
struct Row {
    message: Option<u8>,
    version: Option<u16>,
    protocol: Option<u8>,
    hostname: Option<String>,
    port: Option<u16>,
}

fn field(value: &str) -> Option<&str> {
    (value != "-").then_some(value)
}

fn read_oracle(path: &Path) -> BTreeMap<usize, Row> {
    let oracle = fs::read_to_string(path).expect("oracle lisible");
    let mut rows = BTreeMap::new();
    for line in oracle.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 7, "ligne d'oracle malformee : {line}");
        assert_eq!(fields[0], "jdk11-loopback.pcap");
        let hex_byte = |value| field(value).map(|v| u8::from_str_radix(v, 16).expect("octet"));
        rows.insert(
            fields[1].parse().expect("numero de trame"),
            Row {
                message: hex_byte(fields[2]),
                version: field(fields[3]).map(|v| v.parse().expect("version")),
                protocol: hex_byte(fields[4]),
                hostname: field(fields[5]).map(str::to_string),
                port: field(fields[6]).map(|v| v.parse().expect("port")),
            },
        );
    }
    rows
}

fn label(flow: &PacketFlow<'_>) -> Option<&'static str> {
    flow.application
        .as_ref()
        .map(|application| application.protocol.label())
}

/// Ce que la session a echange, au-dela de ce que tshark compare.
#[derive(Default)]
struct Session {
    by_message: BTreeMap<u8, usize>,
    registry_methods: BTreeMap<&'static str, usize>,
    dgc_methods: BTreeMap<&'static str, usize>,
    application_calls: usize,
    exceptional: Vec<usize>,
    return_ids: BTreeSet<(i32, i64, i16)>,
    dgc_acks: usize,
    continuations: usize,
    refused_header: usize,
    blind: usize,
}

fn uid_key(uid: JavaRmiUid) -> (i32, i64, i16) {
    (uid.unique, uid.time, uid.count)
}

#[test]
fn every_segment_matches_the_tshark_oracle() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let rows = read_oracle(&base.join(ORACLE));
    let FileRead::Frames { frames, .. } = read_capture(&base.join(CAPTURE)) else {
        panic!("capture illisible");
    };
    assert_eq!(frames.len(), 394);
    let config = OBJECT_PORTS
        .iter()
        .fold(ParseConfig::new(), |config, port| {
            config.decode_as(*port, DecodeAsProtocol::JavaRmi)
        });

    let mut session = Session::default();
    let mut seen = 0;
    for (index, (link_type, data)) in frames.iter().enumerate() {
        let number = index + 1;
        let flow = parse(*link_type, data).unwrap_or_else(|_| panic!("trame {number}"));
        let declared = parse_with(*link_type, data, &config).expect("trame lisible");
        let transport = flow.transport.as_ref().expect("TCP");
        let Some(payload) = transport.payload.filter(|payload| !payload.is_empty()) else {
            assert!(!rows.contains_key(&number), "trame {number} sans charge");
            continue;
        };
        let row = rows
            .get(&number)
            .unwrap_or_else(|| panic!("trame {number} absente de l'oracle"));
        seen += 1;
        let ports = [transport.source_port, transport.destination_port];
        let on_registry = ports.contains(&Some(REGISTRY_PORT));
        let decoded = JavaRmiPacket::try_from(payload);

        let Some(message) = row.message else {
            // EndpointIdentifier du client : pas d'octet de type.
            assert!(decoded.is_err(), "trame {number} : {decoded:?}");
            assert_eq!(label(&flow), Some("Unknown"), "trame {number}");
            assert_eq!(label(&declared), Some("Unknown"), "trame {number}");
            session.continuations += 1;
            continue;
        };
        if message == 0x4a && !matches!(row.protocol, Some(0x4b..=0x4d)) {
            // Protocole inconnu : tshark lit l'en-tete, la crate le refuse.
            assert!(decoded.is_err(), "trame {number}");
            assert_eq!(label(&flow), Some("Unknown"), "trame {number}");
            session.refused_header += 1;
            continue;
        }
        let packet = decoded.unwrap_or_else(|error| panic!("trame {number} : {error}"));
        assert_eq!(packet.message_type(), message, "trame {number}");
        *session.by_message.entry(message).or_default() += 1;

        // Sur 1099, tout message ; ailleurs, seuls les messages qui se
        // reconnaissent seuls, sauf port declare.
        let expected = if on_registry || packet.is_self_identifying() {
            "Java RMI"
        } else {
            "Unknown"
        };
        assert_eq!(label(&flow), Some(expected), "trame {number}");
        assert_eq!(label(&declared), Some("Java RMI"), "trame {number}");
        if !on_registry && packet.is_self_identifying() {
            session.blind += 1;
        }

        match packet {
            JavaRmiPacket::Header(header) => {
                assert_eq!(Some(header.version), row.version, "trame {number}");
                assert_eq!(Some(header.protocol.code()), row.protocol, "trame {number}");
                if let Some(next) = header.message() {
                    // SingleOpProtocol : l'appel suit l'en-tete.
                    assert_eq!(header.protocol, JavaRmiProtocol::SingleOp);
                    let Ok(JavaRmiPacket::Call(call)) = next else {
                        panic!("trame {number} : {next:?}");
                    };
                    let (_, method) = call.well_known_method().expect("appel du registre");
                    *session.registry_methods.entry(method).or_default() += 1;
                }
            }
            JavaRmiPacket::ProtocolAck(endpoint) => {
                assert_eq!(endpoint.hostname_str(), row.hostname.as_deref());
                assert_eq!(Some(endpoint.port), row.port, "trame {number}");
                // Le port du client, tel que le serveur le voit.
                assert!(ports.contains(&Some(endpoint.port)), "trame {number}");
            }
            JavaRmiPacket::Call(call) => match call.well_known_method() {
                Some((JavaRmiWellKnownObject::Registry, method)) => {
                    assert_eq!(transport.destination_port, Some(REGISTRY_PORT));
                    assert_eq!(call.hash, JAVA_RMI_REGISTRY_INTERFACE_HASH);
                    *session.registry_methods.entry(method).or_default() += 1;
                }
                Some((JavaRmiWellKnownObject::Dgc, method)) => {
                    assert_eq!(call.object.object_number, 2);
                    assert_eq!(call.hash, JAVA_RMI_DGC_INTERFACE_HASH);
                    *session.dgc_methods.entry(method).or_default() += 1;
                }
                other => {
                    // Objet applicatif : stub 1.2, la methode est son hash.
                    assert_eq!(other, None, "trame {number}");
                    assert_eq!(call.object.well_known(), None, "trame {number}");
                    assert_eq!(call.operation, -1, "trame {number}");
                    session.application_calls += 1;
                }
            },
            JavaRmiPacket::Return(ret) => {
                if ret.return_type == JavaRmiReturnType::Exceptional {
                    session.exceptional.push(number);
                    let message = b"echec volontaire de la capture";
                    assert!(ret.value.windows(message.len()).any(|w| w == message));
                }
                assert!(
                    session.return_ids.insert(uid_key(ret.ack_id)),
                    "trame {number} : UID de retour deja vu"
                );
            }
            JavaRmiPacket::DgcAck(uid) => {
                assert!(
                    session.return_ids.contains(&uid_key(uid)),
                    "trame {number} : DgcAck d'un retour jamais vu"
                );
                session.dgc_acks += 1;
            }
            _ => {}
        }
    }
    assert_eq!(seen, rows.len(), "des lignes d'oracle sans trame");
    assert_eq!(seen, 236);

    let by_message: Vec<(u8, usize)> = session.by_message.into_iter().collect();
    assert_eq!(
        by_message,
        [
            (0x4a, 10),
            (0x4e, 9),
            (0x4f, 1),
            (0x50, 59),
            (0x51, 60),
            (0x52, 42),
            (0x53, 42),
            (0x54, 3),
        ]
    );
    assert_eq!(session.continuations, 9);
    assert_eq!(session.refused_header, 1);
    // bind (JNDI du connecteur JMX), list (dont celui en SingleOp), deux
    // lookup (station, jmxrmi), unbind a l'arret du connecteur.
    let registry: Vec<_> = session.registry_methods.into_iter().collect();
    assert_eq!(
        registry,
        [("bind", 1), ("list", 2), ("lookup", 2), ("unbind", 1)]
    );
    let dgc: Vec<_> = session.dgc_methods.into_iter().collect();
    assert_eq!(dgc, [("clean", 2), ("dirty", 20)]);
    assert_eq!(session.application_calls, 59 - 5 - 22);
    // Station.fail().
    assert_eq!(session.exceptional, [69]);
    assert_eq!(session.dgc_acks, 3);
    // Hors de 1099, sans Decode As : les en-tetes de flux, Call et Return
    // des ports 50050 et 50051, soit les 129 de la capture moins les quatre
    // en-tetes, cinq appels et six retours du registre.
    assert_eq!(session.blind, 114);
}
