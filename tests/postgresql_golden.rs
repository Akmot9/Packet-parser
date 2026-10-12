// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests PostgreSQL sur trames reelles (#98).
//!
//! Captures : `pcaps_exemple/protocols/postgresql/` (voir son `SOURCE.md`),
//! quatorze fichiers du corpus de tests de Zeek : douze sessions psql
//! reelles (loopback, VM vers AWS, application en conteneurs, poste Windows)
//! et deux **negatifs** rejoues sur le port 5432, HTTP et MySQL.
//!
//! L'oracle est tshark 4.6.6 sans reassemblage TCP (`tools/postgresql_oracle.sh`,
//! la vue d'un parseur sans etat) : pour chaque segment a payload, les
//! types et longueurs des messages `pgsql`, figes dans
//! `tests/data/postgresql_tshark_oracle.tsv`. Sur les negatifs, ce que
//! tshark etiquette `pgsql` est son propre faux positif : la crate doit n'en
//! avoir aucun, et le nombre est mesure, pas redoute.
//!
//! La reponse d'un octet a SSLRequest (`S` ou `N`) n'a ni en-tete ni
//! longueur : elle n'est decodee que sur le port 5432 ou un port declare,
//! jamais par la sonde aveugle — c'est l'arbitrage que le corpus tranche.
//! Chaque segment PostgreSQL est aussi rejoue avec ses ports deplaces hors
//! de 5432 : la sonde aveugle en retient 262 sur 276, et les quatorze
//! qu'elle laisse sont les segments sans preuve forte — reponse SSL,
//! `Terminate` ou `ReadyForQuery` seuls.

use std::{collections::BTreeMap, fs, path::Path};

use packet_parser::{
    DecodeAsProtocol, PacketFlow, ParseConfig, parse,
    parse::application::protocols::postgresql::{
        PostgreSqlMessageBody, PostgreSqlMessageType, PostgreSqlPacket,
    },
    parse_with,
};

mod common;
use common::{FileRead, collect_capture_files, read_capture};

const CORPUS: &str = "pcaps_exemple/protocols/postgresql";
const ORACLE: &str = "tests/data/postgresql_tshark_oracle.tsv";
const NEGATIVES: [&str; 2] = ["http-on-port-5432.pcap", "mysql-on-port-5432.pcap"];

struct OracleRow {
    source_port: u16,
    destination_port: u16,
    payload_len: usize,
    /// Vide quand tshark ne voit pas de message pgsql.
    types: Vec<String>,
    /// Vide quand tshark n'affiche pas de longueur (reponse SSL d'un octet).
    lengths: Vec<u32>,
    /// tshark ne dissèque pas un segment qu'il sait retransmis ; le parseur
    /// sans etat, lui, voit les memes octets que la premiere fois.
    retransmitted: bool,
}

fn read_oracle(path: &Path) -> BTreeMap<String, BTreeMap<usize, OracleRow>> {
    let oracle = fs::read_to_string(path).expect("oracle lisible");
    let mut expected: BTreeMap<String, BTreeMap<usize, OracleRow>> = BTreeMap::new();
    for line in oracle.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 8, "ligne d'oracle malformee : {line}");
        let split = |column: &str| -> Vec<String> {
            if column == "-" {
                Vec::new()
            } else {
                column.split('|').map(ToString::to_string).collect()
            }
        };
        let row = OracleRow {
            source_port: fields[2].parse().expect("port source"),
            destination_port: fields[3].parse().expect("port destination"),
            payload_len: fields[4].parse().expect("longueur du payload"),
            types: split(fields[5]),
            lengths: if fields[6] == "-" {
                Vec::new()
            } else {
                fields[6]
                    .split(',')
                    .map(|length| length.parse().expect("longueur de message"))
                    .collect()
            },
            retransmitted: fields[7] == "1",
        };
        expected
            .entry(fields[0].to_string())
            .or_default()
            .insert(fields[1].parse().expect("numero de trame"), row);
    }
    expected
}

/// Le nom que tshark donne a un message, vers la variante de la crate.
/// Un nom inconnu fait echouer le test : l'oracle a change de forme.
fn expected_type(tshark: &str) -> PostgreSqlMessageType {
    use PostgreSqlMessageType as T;
    match tshark {
        "Startup message" => T::StartupMessage,
        "SSL request" => T::SslRequest,
        "SSL response" => T::SslResponse,
        "Authentication request" => T::Authentication,
        "Parameter status" => T::ParameterStatusOrSync,
        "Backend key data" => T::BackendKeyData,
        "Ready for query" => T::ReadyForQuery,
        "Simple query" => T::Query,
        "Row description" => T::RowDescription,
        "Data row" => T::DataRowOrDescribe,
        "Command completion" => T::CloseOrCommandComplete,
        "Termination" => T::Terminate,
        "Error" => T::ErrorResponseOrExecute,
        "Notice" => T::NoticeResponse,
        "Password message" | "SASLInitialResponse message" | "SASLResponse message" => {
            T::PasswordOrSaslResponse
        }
        "Empty query" => T::EmptyQueryResponse,
        other => panic!("type tshark non prevu : {other}"),
    }
}

fn label(flow: &PacketFlow<'_>) -> Option<&'static str> {
    flow.application
        .as_ref()
        .map(|application| application.application_protocol)
}

/// Parite avec tshark sur les 331 segments a payload du corpus : types et
/// longueurs des messages sur les douze captures positives, et aucun faux
/// positif sur les deux negatives, la ou tshark en compte six.
#[test]
fn every_segment_matches_the_tshark_oracle() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let expected = read_oracle(&base.join(ORACLE));
    let mut captures = Vec::new();
    collect_capture_files(&base.join(CORPUS), &mut captures);
    assert_eq!(captures.len(), 14);

    let mut segments = 0;
    let mut pgsql_segments = 0;
    let mut ssl_responses = 0;
    let mut messages = 0;
    let mut retransmissions = 0;
    let mut blind = 0;
    let mut blind_misses: BTreeMap<String, usize> = BTreeMap::new();
    let mut tshark_false_positives = 0;
    let mut crate_false_positives = 0;
    for path in &captures {
        let file = path.file_name().unwrap().to_string_lossy().to_string();
        let negative = NEGATIVES.contains(&file.as_str());
        let FileRead::Frames { frames, .. } = read_capture(path) else {
            panic!("{file} : capture illisible");
        };
        let rows = expected
            .get(&file)
            .unwrap_or_else(|| panic!("{file} absente de l'oracle"));
        for (index, (link_type, data)) in frames.iter().enumerate() {
            let number = index + 1;
            let flow =
                parse(*link_type, data).unwrap_or_else(|error| panic!("{file}:{number} : {error}"));
            let transport = flow.transport.as_ref().expect("transport");
            let payload = transport.payload.filter(|payload| !payload.is_empty());
            let Some(payload) = payload else {
                assert!(
                    !rows.contains_key(&number),
                    "{file}:{number} : sans payload"
                );
                continue;
            };
            let row = rows
                .get(&number)
                .unwrap_or_else(|| panic!("{file}:{number} absente de l'oracle"));
            assert_eq!(
                (
                    transport.source_port,
                    transport.destination_port,
                    payload.len()
                ),
                (
                    Some(row.source_port),
                    Some(row.destination_port),
                    row.payload_len
                ),
                "{file}:{number}"
            );
            segments += 1;
            if row.retransmitted {
                assert!(row.types.is_empty(), "{file}:{number}");
                retransmissions += 1;
                continue;
            }

            if negative {
                tshark_false_positives += usize::from(!row.types.is_empty());
                if label(&flow) == Some("PostgreSQL") {
                    crate_false_positives += 1;
                }
                continue;
            }
            if row.types.is_empty() {
                assert_ne!(label(&flow), Some("PostgreSQL"), "{file}:{number}");
                continue;
            }
            assert_eq!(label(&flow), Some("PostgreSQL"), "{file}:{number}");
            let packet = PostgreSqlPacket::try_from(payload)
                .unwrap_or_else(|error| panic!("{file}:{number} : {error}"));
            let types: Vec<PostgreSqlMessageType> =
                packet.messages.iter().map(|m| m.message_type).collect();
            let expected_types: Vec<PostgreSqlMessageType> =
                row.types.iter().map(|t| expected_type(t)).collect();
            assert_eq!(types, expected_types, "{file}:{number}");
            if row.lengths.is_empty() {
                // La reponse SSL d'un octet : tshark n'affiche pas de longueur.
                assert_eq!(
                    types,
                    [PostgreSqlMessageType::SslResponse],
                    "{file}:{number}"
                );
                assert_eq!(
                    packet.messages[0].body,
                    PostgreSqlMessageBody::SslResponse {
                        accepted: payload == b"S"
                    },
                    "{file}:{number}"
                );
                ssl_responses += 1;
            } else {
                let lengths: Vec<u32> = packet.messages.iter().map(|m| m.length).collect();
                assert_eq!(lengths, row.lengths, "{file}:{number}");
            }
            messages += packet.messages.len();
            pgsql_segments += 1;

            // Le meme segment hors du port 5432 : la sonde aveugle seule.
            let mut moved = data.clone();
            for offset in [34usize, 36] {
                if u16::from_be_bytes([moved[offset], moved[offset + 1]]) == 5432 {
                    moved[offset..offset + 2].copy_from_slice(&5433u16.to_be_bytes());
                }
            }
            let flow = parse(*link_type, &moved).expect("segment deplace");
            if label(&flow) == Some("PostgreSQL") {
                blind += 1;
            } else {
                assert_eq!(
                    types.len(),
                    1,
                    "{file}:{number} : plusieurs messages manques a l'aveugle"
                );
                *blind_misses.entry(format!("{:?}", types[0])).or_default() += 1;
            }
        }
    }
    assert_eq!(segments, 331);
    assert_eq!(retransmissions, 4);
    assert_eq!(pgsql_segments, 276);
    assert_eq!(ssl_responses, 8);
    assert_eq!(messages, 558);
    // La sonde aveugle : tout ce qui porte une preuve forte, et rien de ce
    // qui n'en porte pas.
    assert_eq!(blind, 262);
    assert_eq!(
        blind_misses,
        BTreeMap::from([
            ("SslResponse".to_string(), 8),
            ("Terminate".to_string(), 5),
            ("ReadyForQuery".to_string(), 1),
        ])
    );
    // La mesure : HTTP (2 segments avec reassemblage coupe) et MySQL (4) sur
    // le port 5432 trompent tshark ; la crate, jamais.
    assert_eq!(tshark_false_positives, 6);
    assert_eq!(crate_false_positives, 0);
}

/// `psql-login.pcap` trame 6 : le `N` d'un octet que le serveur renvoie a
/// SSLRequest. Reconnu sur le port 5432 ou un port declare, pas ailleurs.
#[test]
fn one_byte_ssl_answers_need_the_port_or_decode_as() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let FileRead::Frames { frames, .. } = read_capture(&base.join(CORPUS).join("psql-login.pcap"))
    else {
        panic!("capture illisible");
    };
    let (link_type, data) = &frames[5];
    let flow = parse(*link_type, data).expect("trame 6");
    assert_eq!(flow.transport.as_ref().unwrap().payload, Some(&b"N"[..]));
    assert_eq!(label(&flow), Some("PostgreSQL"));

    // Ethernet + IPv4 sans options : port source aux octets 34 et 35.
    let mut moved = data.clone();
    moved[34..36].copy_from_slice(&5433u16.to_be_bytes());
    let flow = parse(*link_type, &moved).expect("trame deplacee");
    assert_eq!(label(&flow), Some("Unknown"));
    let config = ParseConfig::new().decode_as(5433, DecodeAsProtocol::PostgreSql);
    let flow = parse_with(*link_type, &moved, &config).expect("trame declaree");
    assert_eq!(label(&flow), Some("PostgreSQL"));

    for (answer, accepted) in [(&b"S"[..], true), (&b"N"[..], false)] {
        let packet = PostgreSqlPacket::try_from(answer).expect("reponse SSL");
        assert_eq!(packet.messages.len(), 1);
        assert_eq!(
            packet.messages[0].message_type,
            PostgreSqlMessageType::SslResponse
        );
        assert_eq!(
            packet.messages[0].body,
            PostgreSqlMessageBody::SslResponse { accepted }
        );
    }
    // Deux octets ne sont plus une reponse SSL ; un `G` (GSSENC) n'est pas
    // reconnu : le corpus n'en porte pas.
    assert!(PostgreSqlPacket::try_from(&b"SN"[..]).is_err());
    assert!(PostgreSqlPacket::try_from(&b"G"[..]).is_err());
}

/// Mutation : les trames reelles alterees d'un octet ou d'une longueur
/// doivent etre rejetees, sinon le golden ne prouve rien.
#[test]
fn mutated_real_frames_are_rejected() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let FileRead::Frames { frames, .. } =
        read_capture(&base.join(CORPUS).join("psql-login-no-sslrequest.pcap"))
    else {
        panic!("capture illisible");
    };
    let payload_of = |frame: usize| -> Vec<u8> {
        let (link_type, data) = &frames[frame - 1];
        let flow = parse(*link_type, data).expect("trame");
        assert_eq!(label(&flow), Some("PostgreSQL"), "trame {frame}");
        flow.transport.as_ref().unwrap().payload.unwrap().to_vec()
    };
    let startup = payload_of(4);
    let backend = payload_of(24);
    assert_eq!((startup.len(), backend.len()), (76, 465));

    let mut mutations: Vec<(&str, Vec<u8>)> = Vec::new();

    let mut longer = startup.clone();
    longer[..4].copy_from_slice(&77u32.to_be_bytes());
    mutations.push(("startup length longer than the segment", longer));

    let mut shorter = startup.clone();
    shorter[..4].copy_from_slice(&75u32.to_be_bytes());
    mutations.push(("startup length shorter than the segment", shorter));

    let mut version = startup.clone();
    version[4..8].copy_from_slice(&0x0002_0000u32.to_be_bytes());
    mutations.push(("startup protocol 2.0", version));

    let mut unterminated = startup.clone();
    unterminated[75] = b'x';
    mutations.push(("startup without its final NUL", unterminated));

    let mut unknown_type = backend.clone();
    unknown_type[0] = b'?';
    mutations.push(("backend first message of unknown type", unknown_type));

    let mut bad_length = backend.clone();
    bad_length[1..5].copy_from_slice(&55u32.to_be_bytes());
    mutations.push(("backend first message one byte too long", bad_length));

    let mut tiny_length = backend.clone();
    tiny_length[1..5].copy_from_slice(&3u32.to_be_bytes());
    mutations.push(("backend message length below its own field", tiny_length));

    let mut truncated = backend.clone();
    truncated.pop();
    mutations.push(("backend last message truncated", truncated));

    let mut trailing = backend.clone();
    trailing.push(0);
    mutations.push(("backend with a trailing byte", trailing));

    for (name, bytes) in &mutations {
        assert!(
            PostgreSqlPacket::try_from(bytes.as_slice()).is_err(),
            "accepted mutated frame: {name}"
        );
    }
    // Et la trame intacte, elle, est toujours acceptee.
    assert_eq!(
        PostgreSqlPacket::try_from(backend.as_slice())
            .expect("trame intacte")
            .messages
            .len(),
        17
    );
}
