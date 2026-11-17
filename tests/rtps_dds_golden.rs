// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests de la couche DDS de RTPS (#317) : QoS en ligne,
//! encapsulation et decouverte SPDP et SEDP, sur les huit captures de
//! `pcaps_exemple/protocols/rtps/` (six implementations, voir son
//! `SOURCE.md`).
//!
//! L'oracle est tshark 4.6.9 (`tools/rtps_dds_oracle.sh`), fige dans
//! `tests/data/rtps_dds_tshark_oracle.tsv` : pour chaque trame RTPS non
//! fragmentee, les identifiants d'encapsulation, les PID dans l'ordre du
//! fil (PID_SENTINEL compris), les noms de topic, de type et d'entite, les
//! GUID, les key hash, les locators, le status info, la fiabilite, la
//! durabilite et l'ensemble des endpoints integres. La crate reconstruit la
//! meme ligne depuis [`RtpsSubmessage::inline_qos`],
//! [`RtpsSubmessage::serialized_payload`] et [`RtpsSubmessage::discovery`] ;
//! le second test recoupe ce que tshark ne verifie pas.

use std::{collections::BTreeMap, fs, path::Path};

use packet_parser::{
    PacketFlow, parse,
    parse::application::protocols::rtps::{
        RtpsMessage, RtpsPacket, RtpsSubmessage, SubmessageDetails,
        dds::{RtpsBuiltinTopic, RtpsLocatorRole, RtpsParameterList},
    },
};

mod common;
use common::{FileRead, collect_capture_files, read_capture};

const CORPUS: &str = "pcaps_exemple/protocols/rtps";
const ORACLE: &str = "tests/data/rtps_dds_tshark_oracle.tsv";
/// Colonnes de l'oracle apres la capture et la trame.
const COLUMNS: usize = 15;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn read_oracle(path: &Path) -> BTreeMap<String, BTreeMap<usize, Vec<String>>> {
    let oracle = fs::read_to_string(path).expect("oracle lisible");
    let mut expected: BTreeMap<String, BTreeMap<usize, Vec<String>>> = BTreeMap::new();
    for line in oracle.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(
            fields.len(),
            COLUMNS + 2,
            "ligne d'oracle malformee : {line}"
        );
        let frame: usize = fields[1].parse().expect("numero de trame");
        let row = fields[2..].iter().map(ToString::to_string).collect();
        let previous = expected
            .entry(fields[0].to_string())
            .or_default()
            .insert(frame, row);
        assert!(previous.is_none(), "trame {frame} en double dans l'oracle");
    }
    expected
}

/// Les quinze listes de l'oracle, remplies dans l'ordre du fil.
#[derive(Default)]
struct Row {
    lists: [Vec<String>; COLUMNS],
}

impl Row {
    const ENCAPSULATION: usize = 0;
    const PID: usize = 1;
    const TOPIC: usize = 2;
    const TYPE: usize = 3;
    const ENTITY: usize = 4;
    const PARTICIPANT_GUID: usize = 5;
    const ENDPOINT_GUID: usize = 6;
    const KEY_HASH: usize = 7;
    const LOCATOR_KIND: usize = 8;
    const LOCATOR_PORT: usize = 9;
    const LOCATOR_IPV4: usize = 10;
    const STATUS_INFO: usize = 11;
    const RELIABILITY: usize = 12;
    const DURABILITY: usize = 13;
    const BUILTIN_ENDPOINTS: usize = 14;

    fn push(&mut self, column: usize, value: String) {
        self.lists[column].push(value);
    }

    /// Les parametres d'une liste dans le format de tshark, puis le
    /// PID_SENTINEL que tshark liste aussi.
    fn parameters(&mut self, list: &RtpsParameterList<'_>) {
        for parameter in list.iter() {
            self.push(Self::PID, format!("{:#06x}", parameter.id));
            let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
            let word = |value: Option<u32>| format!("{:#010x}", value.expect("quatre octets"));
            match parameter.id {
                0x0005 => self.push(Self::TOPIC, text(parameter.string().expect("chaine"))),
                0x0007 => self.push(Self::TYPE, text(parameter.string().expect("chaine"))),
                0x0062 => self.push(Self::ENTITY, text(parameter.string().expect("chaine"))),
                0x0050 => self.push(
                    Self::PARTICIPANT_GUID,
                    hex(&parameter.guid().expect("GUID")),
                ),
                0x005a => self.push(Self::ENDPOINT_GUID, hex(&parameter.guid().expect("GUID"))),
                0x0070 => self.push(Self::KEY_HASH, hex(&parameter.guid().expect("key hash"))),
                // StatusInfo_t est un octet[4], lu en grand-boutiste.
                0x0071 => self.push(
                    Self::STATUS_INFO,
                    format!(
                        "{:#010x}",
                        u32::from_be_bytes(parameter.value[..4].try_into().unwrap())
                    ),
                ),
                0x001a => self.push(Self::RELIABILITY, word(parameter.u32_value())),
                0x001d => self.push(Self::DURABILITY, word(parameter.u32_value())),
                0x0058 => self.push(Self::BUILTIN_ENDPOINTS, word(parameter.u32_value())),
                id if RtpsLocatorRole::from_pid(id).is_some() => {
                    let locator = parameter.locator().expect("Locator_t de 24 octets");
                    self.push(Self::LOCATOR_KIND, format!("{:#010x}", locator.kind as u32));
                    self.push(Self::LOCATOR_PORT, locator.port.to_string());
                    if let Some(address) = locator.ipv4() {
                        self.push(Self::LOCATOR_IPV4, address.to_string());
                    }
                }
                _ => {}
            }
        }
        self.push(Self::PID, "0x0001".to_string());
    }

    fn into_oracle(self) -> Option<Vec<String>> {
        if self.lists[Self::ENCAPSULATION].is_empty() && self.lists[Self::PID].is_empty() {
            return None;
        }
        Some(
            self.lists
                .into_iter()
                .map(|list| {
                    if list.is_empty() {
                        "-".to_string()
                    } else {
                        list.join(";")
                    }
                })
                .collect(),
        )
    }
}

fn crate_row(message: &RtpsMessage<'_>, at: &str) -> Option<Vec<String>> {
    let mut row = Row::default();
    for (index, submessage) in message.submessages.iter().enumerate() {
        let at = format!("{at}, sous-message {index}");
        if let Some(qos) = submessage.inline_qos() {
            row.parameters(&qos.unwrap_or_else(|error| panic!("{at} : QoS en ligne : {error}")));
        }
        if let Some(payload) = submessage.serialized_payload() {
            let payload = payload.unwrap_or_else(|error| panic!("{at} : donnees : {error}"));
            row.push(
                Row::ENCAPSULATION,
                format!("{:#06x}", payload.encapsulation.code()),
            );
        }
        if let Some(discovery) = submessage.discovery() {
            let discovery = discovery.unwrap_or_else(|error| panic!("{at} : decouverte : {error}"));
            row.parameters(&discovery.parameters);
        }
    }
    row.into_oracle()
}

fn rtps_message<'a>(flow: &'a PacketFlow<'a>) -> Option<RtpsPacket<'a>> {
    let application = flow.application.as_ref()?;
    if application.protocol.label() != "RTPS" {
        return None;
    }
    let payload = flow.transport.as_ref()?.payload?;
    Some(RtpsPacket::try_from(payload).expect("une trame etiquetee RTPS se decode"))
}

/// Chaque trame RTPS du corpus, avec sa capture et son numero.
fn for_each_message(mut visit: impl FnMut(&str, usize, &RtpsMessage<'_>)) {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut captures = Vec::new();
    collect_capture_files(&base.join(CORPUS), &mut captures);
    assert_eq!(captures.len(), 8);
    for path in &captures {
        let file = path.file_name().unwrap().to_string_lossy().to_string();
        let FileRead::Frames { frames, .. } = read_capture(path) else {
            panic!("{file} : capture illisible");
        };
        for (index, (link_type, data)) in frames.iter().enumerate() {
            let number = index + 1;
            let flow =
                parse(*link_type, data).unwrap_or_else(|error| panic!("{file}:{number} : {error}"));
            if let Some(RtpsPacket::Message(message)) = rtps_message(&flow) {
                visit(&file, number, &message);
            }
        }
    }
}

#[test]
fn every_frame_matches_the_tshark_oracle() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let expected = read_oracle(&base.join(ORACLE));
    let mut checked: BTreeMap<String, usize> = BTreeMap::new();
    for_each_message(|file, number, message| {
        let at = format!("{file}:{number}");
        let row = crate_row(message, &at);
        let oracle = expected.get(file).and_then(|frames| frames.get(&number));
        assert_eq!(row.as_ref(), oracle, "{at}");
        if row.is_some() {
            *checked.entry(file.to_string()).or_default() += 1;
        }
    });
    let oracle_frames: BTreeMap<String, usize> = expected
        .iter()
        .map(|(file, frames)| (file.clone(), frames.len()))
        .collect();
    assert_eq!(checked, oracle_frames, "toute trame de l'oracle est vue");
    assert_eq!(checked.values().sum::<usize>(), 137);
}

/// Le guidPrefix de l'emetteur d'un sous-message : celui de l'en-tete,
/// jusqu'a un INFO_SRC (§8.3.4.1).
fn source_prefixes(message: &RtpsMessage<'_>) -> Vec<[u8; 12]> {
    let mut prefix = message.header.guid_prefix;
    message
        .submessages
        .iter()
        .map(|submessage| {
            if let SubmessageDetails::InfoSource { guid_prefix, .. } = submessage.details {
                prefix = guid_prefix;
            }
            prefix
        })
        .collect()
}

fn writer_of(submessage: &RtpsSubmessage<'_>) -> Option<u32> {
    match submessage.details {
        SubmessageDetails::Data { writer_id, .. } => Some(writer_id),
        _ => None,
    }
}

#[test]
fn discovery_is_consistent_with_its_message() {
    let mut by_topic: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut by_vendor: BTreeMap<u16, usize> = BTreeMap::new();
    let mut topics = Vec::new();
    let mut key_only = 0;
    let mut disposed = Vec::new();
    let mut leases = 0;
    let mut domains: BTreeMap<u32, usize> = BTreeMap::new();
    for_each_message(|file, number, message| {
        let at = format!("{file}:{number}");
        let prefixes = source_prefixes(message);
        for (submessage, prefix) in message.submessages.iter().zip(&prefixes) {
            if let Some(Ok(qos)) = submessage.inline_qos()
                && let Some(status) = qos.status_info()
                && (status.disposed() || status.unregistered())
            {
                // Le key hash d'une instance d'un topic integre est le GUID
                // de l'entite qui se retire.
                if let Some(key) = qos.key_hash()
                    && writer_of(submessage)
                        .and_then(RtpsBuiltinTopic::from_writer)
                        .is_some()
                {
                    assert_eq!(&key[..12], prefix, "{at}");
                }
                disposed.push((
                    at.clone(),
                    writer_of(submessage),
                    status.flags,
                    qos.key_hash().is_some(),
                ));
            }
            let Some(discovery) = submessage.discovery() else {
                continue;
            };
            let discovery = discovery.expect("decouverte valide");
            let list = discovery.parameters;
            *by_topic.entry(discovery.topic.name()).or_default() += 1;
            assert!(!discovery.secure, "{at} : pas de DDS Security au corpus");
            assert!(discovery.encapsulation.is_parameter_list());
            if discovery.key_only {
                key_only += 1;
                continue;
            }
            // Les accesseurs de la liste rendent le premier parametre de
            // leur PID.
            assert_eq!(list.topic_name(), list.get(0x0005).and_then(|p| p.string()));
            match discovery.topic {
                RtpsBuiltinTopic::Participant => {
                    let guid = list.participant_guid().expect("PID_PARTICIPANT_GUID");
                    assert_eq!(&guid[..12], prefix, "{at} : le participant est l'emetteur");
                    assert_eq!(guid[12..], [0, 0, 1, 0xc1], "{at} : ENTITYID_PARTICIPANT");
                    let version = list.protocol_version().expect("PID_PROTOCOL_VERSION");
                    assert_eq!(version.0, 2, "{at}");
                    *by_vendor
                        .entry(list.vendor_id().expect("PID_VENDORID"))
                        .or_default() += 1;
                    assert!(list.builtin_endpoint_set().is_some(), "{at}");
                    if list.participant_lease_duration().is_some() {
                        leases += 1;
                    }
                    if let Some(domain) = list.domain_id() {
                        *domains.entry(domain).or_default() += 1;
                    }
                    assert!(
                        list.locators().any(|(role, _)| matches!(
                            role,
                            RtpsLocatorRole::MetatrafficUnicast
                                | RtpsLocatorRole::MetatrafficMulticast
                        )),
                        "{at} : un participant annonce son metatrafic"
                    );
                }
                RtpsBuiltinTopic::Publication | RtpsBuiltinTopic::Subscription => {
                    let guid = list.endpoint_guid().expect("PID_ENDPOINT_GUID");
                    assert_eq!(&guid[..12], prefix, "{at} : l'endpoint est a l'emetteur");
                    let topic = list.topic_name().expect("PID_TOPIC_NAME");
                    assert!(list.type_name().is_some(), "{at} : PID_TYPE_NAME");
                    topics.push(String::from_utf8_lossy(topic).into_owned());
                }
                _ => unreachable!("{at} : pas de DCPSTopic au corpus"),
            }
        }
    });
    assert_eq!(
        by_topic,
        BTreeMap::from([
            ("DCPSParticipant", 61),
            ("DCPSPublication", 19),
            ("DCPSSubscription", 21)
        ])
    );
    // PID_VENDORID des SPDP : RTI Connext, OpenSplice, CoreDX, Connext
    // Micro, Cyclone DDS. La capture OpenDDS ne porte pas de decouverte.
    assert_eq!(
        by_vendor,
        BTreeMap::from([
            (0x0101, 46),
            (0x0102, 2),
            (0x0106, 1),
            (0x010a, 1),
            (0x0110, 11)
        ])
    );
    assert_eq!(key_only, 0);
    assert_eq!(leases, 61, "tout SPDP annonce sa duree de bail");
    // Seul Cyclone DDS ecrit PID_DOMAIN_ID ; les autres s'en tiennent au
    // domaine que donne le port.
    assert_eq!(domains, BTreeMap::from([(0, 11)]));
    // Le participant RTI qui se retire (SPDP, unregister et dispose, avec
    // son key hash), puis un dispose et un unregister d'instances OpenDDS
    // qui ne portent qu'une cle serialisee.
    assert_eq!(
        disposed,
        [
            ("rtps.pcap:29".to_string(), Some(0x0001_00c2), 3, true),
            (
                "wireshark_6449_opendds_messenger.pcap:12".to_string(),
                Some(0x0000_0102),
                1,
                false
            ),
            (
                "wireshark_6449_opendds_messenger.pcap:13".to_string(),
                Some(0x0000_0102),
                2,
                false
            ),
        ]
    );
    topics.sort();
    topics.dedup();
    assert_eq!(topics.len(), 29);
    assert!(topics.iter().any(|topic| topic == "rt/chatter"));
    assert!(
        topics
            .iter()
            .any(|topic| topic == "rti/distlog/administration/command_request")
    );
}
