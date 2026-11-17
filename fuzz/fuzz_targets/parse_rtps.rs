// Fuzz du decodeur RTPS : en-tete, ping RTI, sous-messages de tous types
// (dont les bitmaps d'ACKNACK, GAP et NACK_FRAG), octetsToNextHeader nul,
// flags d'ordre d'octets. Ni panic ni boucle infinie ; quand le decodage
// reussit, les sous-messages pavent exactement le message, chaque corps
// emprunte a l'entree, et le type suit l'identifiant.
//
// Couche DDS (#317) : QoS en ligne, donnees serialisees et decouverte de
// chaque DATA et DATA_FRAG. Quand elles se decodent, chaque ParameterList,
// chaque valeur et les donnees pointent dans le corps du sous-message, les
// parametres pavent la liste, et tous les accesseurs typees se lisent sans
// panic.
#![no_main]

#[path = "../oracles/seeds.rs"]
mod seeds;

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use packet_parser::parse::application::protocols::rtps::{
    RtpsPacket, SubmessageDetails, SubmessageKind,
    dds::{RtpsBuiltinTopic, RtpsParameterList},
};
use seeds::{inside, replay_mutated};

// Trame 9 de pcaps_exemple/protocols/rtps/talker-listener-rtps.pcapng
// (Cyclone DDS) : INFO_DST, INFO_TS, DATA, HEARTBEAT.
const CYCLONE_FRAME_9: &[u8] = &[
    0x52, 0x54, 0x50, 0x53, 0x02, 0x01, 0x01, 0x10, 0x54, 0xa6, 0x10, 0x01, 0x31, 0x98, 0x43, 0xec,
    0xa3, 0x66, 0x9a, 0x35, 0x0e, 0x01, 0x0c, 0x00, 0x5a, 0xb8, 0x10, 0x01, 0x16, 0x36, 0xc7, 0xd5,
    0x18, 0x95, 0xc5, 0x4e, 0x09, 0x01, 0x08, 0x00, 0xb7, 0xee, 0xe9, 0x60, 0xf3, 0x95, 0x40, 0x6e,
    0x15, 0x05, 0x30, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x02, 0x00, 0xc7, 0x00, 0x02, 0x00, 0xc2,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x54, 0xa6, 0x10, 0x01,
    0x31, 0x98, 0x43, 0xec, 0xa3, 0x66, 0x9a, 0x35, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x07, 0x01, 0x1c, 0x00, 0x00, 0x02, 0x00, 0xc7, 0x00, 0x02, 0x00, 0xc2,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00,
];

// Trame 8 de la meme capture : INFO_DST puis trois ACKNACK (bitmap d'un mot).
const CYCLONE_FRAME_8: &[u8] = &[
    0x52, 0x54, 0x50, 0x53, 0x02, 0x01, 0x01, 0x10, 0x5a, 0xb8, 0x10, 0x01, 0x16, 0x36, 0xc7, 0xd5,
    0x18, 0x95, 0xc5, 0x4e, 0x0e, 0x01, 0x0c, 0x00, 0x54, 0xa6, 0x10, 0x01, 0x31, 0x98, 0x43, 0xec,
    0xa3, 0x66, 0x9a, 0x35, 0x06, 0x03, 0x18, 0x00, 0x00, 0x00, 0x03, 0xc7, 0x00, 0x00, 0x03, 0xc2,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x06, 0x03, 0x18, 0x00, 0x00, 0x00, 0x04, 0xc7, 0x00, 0x00, 0x04, 0xc2, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x03, 0x1c, 0x00,
    0x00, 0x02, 0x00, 0xc7, 0x00, 0x02, 0x00, 0xc2, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00,
];

// Graines de la couche DDS, en hexadecimal (memes trames que les tests du
// module `rtps::dds`). Trame 1 de wireshark_15868_micro_2_4_11.pcapng : le
// DATA SPDP de RTI Connext Micro, key hash en ligne puis donnees PL_CDR_LE
// (GUID, nom, endpoints integres, version, vendorId, trois locators, bail,
// PID vendeur, liste de proprietes).
const MICRO_SPDP: &str = concat!(
    "525450530201010a010a0000dec0adde00000000090108000500000051b81e0515079c01",
    "00001000000100c7000100c2000000000100000070001000010a0000dec0adde00000000",
    "000001c1010001000003000050001000010a0000dec0adde00000000000001c162001400",
    "0f0000005f7061727469636970616e745f300000580004003f0000001500040002010000",
    "16000400010a0000310018000100000097550000000000000000000000000000c0a8010a",
    "320018000100000096550000000000000000000000000000c0a8010a33001800010000008c",
    "550000000000000000000000000000efff00010200080064000000000000000080040002",
    "04000b5900b80004000000160000006464732e7379735f696e666f2e686f73746e616d65",
    "0000000d0000004175746f7361722d686f737400000000180000006464732e7379735f69",
    "6e666f2e70726f636573735f6964000200000039000000140000006464732e7379735f69",
    "6e666f2e746172676574001b0000007463323978744f73656b436f72655461736b696e67",
    "362e3272320000140000007274692e736572766963652e76657273696f6e000900000032",
    "2e342e31312e300000000001000000"
);
// Trame 29 de rtps.pcap : le retrait d'un participant RTI, QoS en ligne
// seules (key hash, status info).
const RTI_SPDP_RETREAT: &str = concat!(
    "5254505302010101c0a87a0100003a4c0000000109010800790d4a5931b4c8ae15033400",
    "0000100000000000000100c2000000000200000070001000c0a87a0100003a4c00000001",
    "000001c1710004000000000301000100"
);
// Trame 12 de wireshark_6449_opendds_messenger.pcap : une cle seule CDR_LE
// derriere un status info.
const OPENDDS_KEY_ONLY: &str = concat!(
    "525450530201010301030000000000000000000109010800ee58934e6b9db814150b0000",
    "000010000000000000000102ffffffff00000000710004000000000101000000000100006300",
    "0000"
);

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("graine hexadecimale"))
        .collect()
}

static DDS_SEEDS: LazyLock<[Vec<u8>; 3]> =
    LazyLock::new(|| [MICRO_SPDP, RTI_SPDP_RETREAT, OPENDDS_KEY_ONLY].map(unhex));

/// Une ParameterList decodee : elle et ses valeurs empruntent au corps, ses
/// parametres la pavent, et chaque accesseur se lit sans panic.
fn check_list(body: &[u8], list: &RtpsParameterList<'_>) {
    assert!(inside(body, list.bytes));
    let mut covered = 0;
    for parameter in list.iter() {
        assert!(inside(list.bytes, parameter.value));
        assert_ne!(parameter.id, 0x0001, "le sentinel termine la liste");
        assert_eq!(parameter.little_endian, list.little_endian);
        covered += 4 + parameter.value.len();
        let _ = (
            parameter.name(),
            parameter.is_vendor_specific(),
            parameter.must_understand(),
        );
        if let Some(text) = parameter.string() {
            assert!(inside(parameter.value, text));
        }
        let _ = (
            parameter.guid(),
            parameter.duration(),
            parameter.u32_value(),
        );
        if let Some(locator) = parameter.locator() {
            let _ = (locator.ipv4(), locator.ipv6());
        }
    }
    assert_eq!(covered, list.bytes.len(), "les parametres pavent la liste");
    let _ = (list.topic_name(), list.type_name(), list.entity_name());
    let _ = (
        list.participant_guid(),
        list.endpoint_guid(),
        list.key_hash(),
    );
    let _ = (
        list.status_info(),
        list.domain_id(),
        list.protocol_version(),
    );
    let _ = (
        list.vendor_id(),
        list.builtin_endpoint_set(),
        list.participant_lease_duration(),
    );
    let _ = (
        list.reliability(),
        list.durability(),
        list.locators().count(),
    );
}

fn exercise(data: &[u8]) {
    let message = match RtpsPacket::try_from(data) {
        Ok(RtpsPacket::Message(message)) => message,
        Ok(RtpsPacket::Ping(ping)) => {
            assert_eq!(data.len(), 16);
            assert_eq!(&ping.text, b"NDDSPING");
            assert_eq!(ping.version_major, 2);
            return;
        }
        Ok(_) => unreachable!("message ou ping"),
        Err(_) => return,
    };
    assert_eq!(message.header.version_major, 2);
    assert!(message.header.magic == *b"RTPS" || message.header.magic == *b"RTPX");
    assert!(!message.submessages.is_empty());
    let mut covered = 20;
    for submessage in &message.submessages {
        assert!(
            data.as_ptr_range().contains(&submessage.body.as_ptr()) || submessage.body.is_empty()
        );
        assert_eq!(submessage.little_endian, submessage.flags & 0x01 != 0);
        match submessage.kind {
            SubmessageKind::VendorSpecific(id) => assert!(id >= 0x80 && id == submessage.id),
            _ => assert!(submessage.id < 0x80),
        }
        if submessage.octets_to_next_header != 0 {
            assert_eq!(
                usize::from(submessage.octets_to_next_header),
                submessage.body.len()
            );
        }
        covered += 4 + submessage.body.len();

        let body = submessage.body;
        let carries_data = matches!(
            submessage.details,
            SubmessageDetails::Data { .. } | SubmessageDetails::DataFrag { .. }
        );
        match submessage.inline_qos() {
            Some(Ok(qos)) => {
                assert!(carries_data && submessage.flags & 0x02 != 0);
                assert_eq!(qos.little_endian, submessage.little_endian);
                check_list(body, &qos);
            }
            Some(Err(_)) => assert!(carries_data),
            None => assert!(!carries_data || submessage.flags & 0x02 == 0),
        }
        let payload = submessage.serialized_payload();
        if let Some(Ok(payload)) = &payload {
            assert!(carries_data);
            assert!(inside(body, payload.data) && body.ends_with(payload.data));
            // L'en-tete d'encapsulation precede les donnees dans le corps.
            let header = &body[..body.len() - payload.data.len()];
            assert!(header.len() >= 4);
            let code = u16::from_be_bytes([header[header.len() - 4], header[header.len() - 3]]);
            assert_eq!(payload.encapsulation.code(), code);
            if let Some(Ok(list)) = payload.parameters() {
                assert!(payload.encapsulation.is_parameter_list());
                check_list(body, &list);
            }
        }
        if let Some(discovery) = submessage.discovery() {
            let SubmessageDetails::Data { writer_id, .. } = submessage.details else {
                panic!("la decouverte vient d'un DATA");
            };
            let topic = RtpsBuiltinTopic::from_writer(writer_id);
            assert!(topic.is_some(), "un writer de la decouverte");
            assert!(payload.is_some(), "la decouverte suppose des donnees");
            if let Ok(discovery) = discovery {
                assert_eq!(Some(discovery.topic), topic);
                assert!(discovery.encapsulation.is_parameter_list());
                assert_eq!(discovery.secure, writer_id >> 24 == 0xff);
                let _ = discovery.topic.name();
                check_list(body, &discovery.parameters);
            }
        }
    }
    assert_eq!(covered, data.len(), "les sous-messages pavent le message");
}

fuzz_target!(|data: &[u8]| {
    exercise(data);

    // Deux octets de fuzz choisissent une position et une mutation XOR sur
    // une graine reelle : les chemins profonds (bitmaps, numeros de
    // sequence, flags, ParameterList) sont atteints des le depart.
    let [spdp, retreat, key_only] = &*DDS_SEEDS;
    replay_mutated(
        &[CYCLONE_FRAME_9, CYCLONE_FRAME_8, spdp, retreat, key_only],
        data,
        exercise,
    );
});
