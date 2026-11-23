// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests LDAP (#372) sur neuf captures reelles : le poste Windows et
//! le controleur de domaine de `pcaps_exemple/The-Ultimate-PCAP.pcapng`
//! (messages en clair, tampons SASL sous jeton Kerberos de la RFC 4121,
//! CLDAP sur UDP 389), et les huit captures de
//! `pcaps_exemple/protocols/ldap/` (longueurs BER courtes d'un client
//! OpenLDAP, jetons Kerberos de la RFC 1964, signature NTLMSSP ; voir leur
//! `SOURCE.md`).
//!
//! L'oracle est tshark 4.6.9 (`tools/ldap_oracle.sh`), rendu sans etat comme
//! la crate : reassemblage TCP et LDAP coupes, analyse des numeros de
//! sequence coupee. Pour chaque segment ou datagramme, la longueur de chaque
//! tampon SASL, l'identifiant, l'operation et le code de resultat de chaque
//! message sont figes dans `tests/data/ldap_tshark_oracle.tsv`.
//!
//! Un ecart avec tshark, voulu : d'un tampon SASL signe que son segment
//! coupe, tshark ne lit aucun message ; la crate lit le debut du premier
//! ([`CUT_SIGNED_BUFFERS`]).
//!
//! Oracle negatif : les segments de suite de TCP 389, que tshark ne dissèque
//! pas non plus, sortent `Unknown`, et aucune autre trame de ces captures ne
//! sort `LDAP`.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use packet_parser::{
    PacketFlow, parse,
    parse::application::protocols::ldap::{LdapMessage, LdapOperation, LdapPdu, LdapSaslToken},
    parse::transport::protocols::TransportProtocol,
};

mod common;
use common::{FileRead, read_capture};

const ORACLE: &str = "tests/data/ldap_tshark_oracle.tsv";

/// Les captures, par leur chemin sous `pcaps_exemple/`.
const CAPTURES: [&str; 9] = [
    "The-Ultimate-PCAP.pcapng",
    "protocols/ldap/ldap-and-search.pcap",
    "protocols/ldap/ldap-attribute-value-list.pcap",
    "protocols/ldap/ldap-controls-dirsync-01.cap",
    "protocols/ldap/ldap-extensible-match-with-dn.pcap",
    "protocols/ldap/ldap-extensible-match.pcap",
    "protocols/ldap/ldap-krb5-sign-seal-01.cap",
    "protocols/ldap/ldap-substring.pcap",
    "protocols/ldap/ntlm_ldap.pcapng",
];

/// Lignes de l'oracle par capture.
const ROWS: [(&str, usize); 9] = [
    ("The-Ultimate-PCAP.pcapng", 440),
    ("ldap-and-search.pcap", 5),
    ("ldap-attribute-value-list.pcap", 5),
    ("ldap-controls-dirsync-01.cap", 5),
    ("ldap-extensible-match-with-dn.pcap", 5),
    ("ldap-extensible-match.pcap", 5),
    ("ldap-krb5-sign-seal-01.cap", 24),
    ("ldap-substring.pcap", 10),
    ("ntlm_ldap.pcapng", 20),
];

/// Tampons SASL signes que leur segment coupe (3 165 octets annonces dans
/// un segment de 1 440), tous dans `The-Ultimate-PCAP.pcapng` : tshark n'en
/// lit aucun message, la crate lit le debut d'un SearchResultEntry.
const CUT_SIGNED_BUFFERS: [usize; 6] = [40752, 41506, 41870, 42775, 43185, 43340];

/// Une ligne de l'oracle.
struct Row {
    transport: TransportProtocol,
    payload_length: usize,
    sasl_lengths: Vec<u32>,
    identifiers: Vec<u32>,
    operations: Vec<u32>,
    results: Vec<u32>,
    bind_results: Vec<u32>,
}

fn numbers(field: &str) -> Vec<u32> {
    if field == "-" {
        return Vec::new();
    }
    field
        .split(',')
        .map(|value| value.parse().expect("entier de l'oracle"))
        .collect()
}

fn read_oracle(path: &Path) -> BTreeMap<(String, usize), Row> {
    let oracle = fs::read_to_string(path).expect("oracle lisible");
    let mut rows = BTreeMap::new();
    for line in oracle.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 9, "ligne d'oracle malformee : {line}");
        let row = Row {
            transport: match fields[2] {
                "tcp" => TransportProtocol::Tcp,
                "udp" => TransportProtocol::Udp,
                other => panic!("transport inconnu : {other}"),
            },
            payload_length: fields[3].parse().expect("longueur de la charge"),
            sasl_lengths: numbers(fields[4]),
            identifiers: numbers(fields[5]),
            operations: numbers(fields[6]),
            results: numbers(fields[7]),
            bind_results: numbers(fields[8]),
        };
        assert_eq!(row.identifiers.len(), row.operations.len(), "{line}");
        rows.insert(
            (
                fields[0].to_string(),
                fields[1].parse().expect("numero de trame"),
            ),
            row,
        );
    }
    rows
}

/// L'etiquette, le transport, la presence d'un port LDAP et la charge.
fn summary<'a>(
    flow: &'a PacketFlow<'a>,
) -> (
    Option<&'static str>,
    Option<TransportProtocol>,
    bool,
    Option<&'a [u8]>,
) {
    let label = flow
        .application
        .as_ref()
        .map(|application| application.protocol.label());
    let transport = flow.transport.as_ref();
    let on_port = transport.is_some_and(|transport| {
        [transport.source_port, transport.destination_port]
            .iter()
            .any(|port| matches!(port, Some(389 | 3268)))
    });
    (
        label,
        transport.map(|transport| transport.protocol),
        on_port,
        transport.and_then(|transport| transport.payload),
    )
}

fn frames(capture: &str) -> Vec<(packet_parser::LinkType, Vec<u8>)> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("pcaps_exemple")
        .join(capture);
    let FileRead::Frames {
        frames,
        read_error_after,
    } = read_capture(&path)
    else {
        panic!("{capture} illisible");
    };
    assert_eq!(read_error_after, None, "{capture}");
    frames
}

/// Ce que la crate lit d'une charge, dans l'ordre des colonnes de l'oracle.
#[derive(Default)]
struct Decoded {
    sasl_lengths: Vec<u32>,
    identifiers: Vec<u32>,
    operations: Vec<u32>,
    results: Vec<u32>,
    bind_results: Vec<u32>,
}

impl Decoded {
    fn push(&mut self, message: &LdapMessage<'_>) {
        self.identifiers.push(message.message_id);
        self.operations.push(u32::from(message.operation.as_u8()));
        if let Some(result) = message.result() {
            if message.operation == LdapOperation::BindResponse {
                self.bind_results.push(result.code);
            } else {
                self.results.push(result.code);
            }
        }
    }
}

/// Compteurs figes du corpus.
#[derive(Default, Debug, PartialEq, Eq)]
struct Totals {
    messages: usize,
    cut_messages: usize,
    several_pdus: usize,
    buffers: usize,
    cut_buffers: usize,
    /// Tampons par jeton et par etat : (jeton, chiffre).
    tokens: BTreeMap<(&'static str, Option<bool>), usize>,
    operations: BTreeMap<u32, usize>,
    results: BTreeSet<u32>,
}

#[test]
fn every_ldap_payload_matches_the_tshark_oracle() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let rows = read_oracle(&base.join(ORACLE));
    assert_eq!(rows.len(), 519);

    let mut per_capture: BTreeMap<&str, usize> = BTreeMap::new();
    let mut continuations: BTreeMap<&str, usize> = BTreeMap::new();
    let mut cut_signed = Vec::new();
    let mut totals = Totals::default();
    for capture in CAPTURES {
        let name = capture.rsplit('/').next().expect("nom de fichier");
        for (index, (link_type, data)) in frames(capture).iter().enumerate() {
            let number = index + 1;
            let Ok(flow) = parse(*link_type, data) else {
                assert!(
                    !rows.contains_key(&(name.to_string(), number)),
                    "{name} trame {number} : LDAP pour tshark, illisible pour la crate"
                );
                continue;
            };
            let (label, transport, on_port, payload) = summary(&flow);
            let Some(row) = rows.get(&(name.to_string(), number)) else {
                assert_ne!(
                    label,
                    Some("LDAP"),
                    "{name} trame {number} : LDAP pour la crate, pas pour tshark"
                );
                // Une charge sur un port LDAP que tshark ne dissèque pas.
                if on_port && label.is_some() {
                    assert_eq!(label, Some("Unknown"), "{name} trame {number}");
                    assert_eq!(transport, Some(TransportProtocol::Tcp), "{name} {number}");
                    *continuations.entry(name).or_default() += 1;
                }
                continue;
            };
            *per_capture.entry(name).or_default() += 1;
            assert_eq!(label, Some("LDAP"), "{name} trame {number}");
            assert_eq!(transport, Some(row.transport), "{name} trame {number}");
            let payload = payload.expect("charge");
            assert_eq!(payload.len(), row.payload_length, "{name} trame {number}");

            let pdus: Vec<LdapPdu<'_>> = LdapPdu::pdus(payload)
                .collect::<Result<_, _>>()
                .unwrap_or_else(|error| panic!("{name} trame {number} : {error}"));
            assert!(!pdus.is_empty(), "{name} trame {number}");
            if pdus.len() > 1 {
                totals.several_pdus += 1;
            }
            // Les PDU pavent la charge : chacun occupe la longueur qu'il
            // annonce, et seul le dernier peut etre coupe.
            let mut rest = payload;
            for pdu in &pdus {
                assert_eq!(LdapPdu::try_from(rest).as_ref(), Ok(pdu));
                let announced = match pdu {
                    LdapPdu::Message(message) => message.wire_length(),
                    LdapPdu::SaslBuffer(buffer) => 4 + buffer.length as usize,
                    _ => panic!("{name} trame {number} : PDU inconnu"),
                };
                let consumed = rest.len() - pdu.rest().len();
                if pdu.is_truncated() {
                    assert!(consumed < announced, "{name} trame {number}");
                    assert!(pdu.rest().is_empty(), "{name} trame {number}");
                } else {
                    assert_eq!(consumed, announced, "{name} trame {number}");
                }
                rest = pdu.rest();
            }
            assert!(rest.is_empty(), "{name} trame {number}");

            let mut decoded = Decoded::default();
            let mut cut_signed_buffer = false;
            for pdu in &pdus {
                match pdu {
                    LdapPdu::Message(message) => {
                        decoded.push(message);
                        totals.messages += 1;
                        if message.is_truncated() {
                            totals.cut_messages += 1;
                        }
                    }
                    LdapPdu::SaslBuffer(buffer) => {
                        decoded.sasl_lengths.push(buffer.length);
                        totals.buffers += 1;
                        let kind = match buffer.token {
                            LdapSaslToken::KerberosWrap { .. } => "rfc4121",
                            LdapSaslToken::KerberosV1Wrap { .. } => "rfc1964",
                            LdapSaslToken::NtlmSignature { .. } => "ntlmssp",
                            _ => panic!("{name} trame {number} : jeton inconnu"),
                        };
                        *totals
                            .tokens
                            .entry((kind, buffer.token.is_sealed()))
                            .or_default() += 1;
                        let inner: Vec<LdapMessage<'_>> = buffer
                            .messages()
                            .collect::<Result<_, _>>()
                            .unwrap_or_else(|error| panic!("{name} trame {number} : {error}"));
                        if buffer.is_truncated() {
                            totals.cut_buffers += 1;
                            // tshark ne lit rien d'un tampon coupe.
                            if let [message] = inner.as_slice() {
                                assert!(message.is_truncated(), "{name} trame {number}");
                                assert_eq!(message.operation, LdapOperation::SearchResultEntry);
                                cut_signed_buffer = true;
                            } else {
                                assert!(inner.is_empty(), "{name} trame {number}");
                            }
                            continue;
                        }
                        // Un jeton signe rend ses messages, un jeton chiffre
                        // ou une signature NTLMSSP n'en rend aucun.
                        assert_eq!(
                            inner.is_empty(),
                            buffer.token.is_sealed() != Some(false),
                            "{name} trame {number}"
                        );
                        for message in &inner {
                            assert!(!message.is_truncated(), "{name} trame {number}");
                            decoded.push(message);
                            totals.messages += 1;
                        }
                    }
                    _ => panic!("{name} trame {number} : PDU inconnu"),
                }
            }
            if cut_signed_buffer {
                cut_signed.push(number);
            }
            assert_eq!(
                decoded.sasl_lengths, row.sasl_lengths,
                "{name} trame {number}"
            );
            assert_eq!(decoded.identifiers, row.identifiers, "{name} {number}");
            assert_eq!(decoded.operations, row.operations, "{name} trame {number}");
            assert_eq!(decoded.results, row.results, "{name} trame {number}");
            assert_eq!(decoded.bind_results, row.bind_results, "{name} {number}");
            for operation in &decoded.operations {
                *totals.operations.entry(*operation).or_default() += 1;
            }
            totals.results.extend(&decoded.results);
            totals.results.extend(&decoded.bind_results);
        }
    }

    assert_eq!(
        per_capture.into_iter().collect::<Vec<_>>(),
        ROWS,
        "segments LDAP par capture"
    );
    assert_eq!(cut_signed, CUT_SIGNED_BUFFERS);
    // Segments de suite, sans en-tete : `Unknown` pour la crate comme pour
    // tshark.
    assert_eq!(
        continuations.into_iter().collect::<Vec<_>>(),
        [
            ("The-Ultimate-PCAP.pcapng", 66),
            ("ldap-krb5-sign-seal-01.cap", 6),
            ("ntlm_ldap.pcapng", 3),
        ]
    );
    // Les messages d'un tampon coupe ne sont pas comptes : l'oracle ne les
    // connait pas.
    let expected = Totals {
        messages: 510,
        cut_messages: 53,
        several_pdus: 55,
        buffers: 260,
        cut_buffers: 12,
        tokens: BTreeMap::from([
            (("ntlmssp", None), 12),
            (("rfc1964", Some(false)), 3),
            (("rfc1964", Some(true)), 20),
            (("rfc4121", Some(false)), 150),
            (("rfc4121", Some(true)), 75),
        ]),
        // BindRequest, BindResponse, UnbindRequest, SearchRequest,
        // SearchResultEntry, SearchResultDone, ModifyRequest,
        // ModifyResponse, SearchResultReference.
        operations: BTreeMap::from([
            (0, 46),
            (1, 47),
            (2, 34),
            (3, 140),
            (4, 114),
            (5, 118),
            (6, 1),
            (7, 1),
            (19, 9),
        ]),
        // success, saslBindInProgress, noSuchObject, invalidCredentials.
        results: BTreeSet::from([0, 14, 32, 49]),
    };
    assert_eq!(totals, expected);
}
