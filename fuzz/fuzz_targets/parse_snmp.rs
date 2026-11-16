// Fuzz du decodeur SNMP (v1, v2c, v3) : BER, longueurs definies, entiers,
// communaute, en-tete v3 et PDU chiffree, PDU standard et Trap v1, liste de
// variables et valeurs typees. Ni panic ni boucle ; quand le decodage
// reussit, la forme du message est celle de sa version, celle de la PDU est
// celle de son type, et chaque emprunt pointe dans l'entree.
#![no_main]

#[path = "../oracles/seeds.rs"]
mod seeds;

use libfuzzer_sys::fuzz_target;
use packet_parser::parse::application::protocols::snmp::{
    SnmpMessage, SnmpPacket, SnmpPdu, SnmpPduPayload, SnmpPduType, SnmpV3Data, SnmpValue,
    SnmpVersion,
};
use seeds::{inside, replay_mutated};

// The-Ultimate-PCAP.pcapng, trame 11415 : get-next-request.
const GET_NEXT: &[u8] = &[
    0x30, 0x35, 0x02, 0x01, 0x01, 0x04, 0x14, 0x6e, 0x35, 0x72, 0x41, 0x44, 0x31, 0x69, 0x67, 0x33,
    0x31, 0x34, 0x49, 0x71, 0x66, 0x69, 0x6f, 0x59, 0x42, 0x57, 0x77, 0xa1, 0x1a, 0x02, 0x04, 0x55,
    0xe8, 0x83, 0x1e, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0c, 0x30, 0x0a, 0x06, 0x06, 0x2b,
    0x06, 0x01, 0x02, 0x01, 0x0b, 0x05, 0x00,
];

// The-Ultimate-PCAP.pcapng, trame 11416 : get-response, une variable.
const RESPONSE: &[u8] = &[
    0x30, 0x3a, 0x02, 0x01, 0x01, 0x04, 0x14, 0x6e, 0x35, 0x72, 0x41, 0x44, 0x31, 0x69, 0x67, 0x33,
    0x31, 0x34, 0x49, 0x71, 0x66, 0x69, 0x6f, 0x59, 0x42, 0x57, 0x77, 0xa2, 0x1f, 0x02, 0x04, 0x55,
    0xe8, 0x83, 0x1e, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x11, 0x30, 0x0f, 0x06, 0x08, 0x2b,
    0x06, 0x01, 0x02, 0x01, 0x0b, 0x01, 0x00, 0x41, 0x03, 0x00, 0x99, 0x2f,
];

// The-Ultimate-PCAP.pcapng, trame 36787 : SNMPv3, get-request de decouverte.
const V3_GET: &[u8] = &[
    0x30, 0x3e, 0x02, 0x01, 0x03, 0x30, 0x11, 0x02, 0x04, 0x42, 0x26, 0x10, 0x99, 0x02, 0x03, 0x00,
    0xff, 0xe3, 0x04, 0x01, 0x04, 0x02, 0x01, 0x03, 0x04, 0x10, 0x30, 0x0e, 0x04, 0x00, 0x02, 0x01,
    0x00, 0x02, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x30, 0x14, 0x04, 0x00, 0x04, 0x00,
    0xa0, 0x0e, 0x02, 0x04, 0x53, 0x20, 0x3d, 0x2b, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
];

// Synthetique, aucune capture du depot ne porte de Trap v1 (RFC 1157) :
// enterpriseSpecific, sans variable.
const TRAP_V1: &[u8] = &[
    0x30, 0x27, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa4, 0x1a, 0x06,
    0x06, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x09, 0x40, 0x04, 0xc0, 0x00, 0x02, 0x01, 0x02, 0x01, 0x06,
    0x02, 0x01, 0x01, 0x43, 0x02, 0x30, 0x39, 0x30, 0x00,
];

fn check_pdu(data: &[u8], pdu: &SnmpPdu<'_>) {
    assert!(inside(data, pdu.raw));
    let bindings = match &pdu.payload {
        SnmpPduPayload::Standard {
            variable_bindings, ..
        } => {
            assert_ne!(pdu.pdu_type, SnmpPduType::TrapV1);
            variable_bindings
        }
        SnmpPduPayload::TrapV1 {
            enterprise,
            variable_bindings,
            ..
        } => {
            assert_eq!(pdu.pdu_type, SnmpPduType::TrapV1);
            assert!(inside(data, enterprise));
            variable_bindings
        }
        _ => return,
    };
    for binding in bindings {
        assert!(inside(data, binding.oid));
        match &binding.value {
            SnmpValue::OctetString(bytes)
            | SnmpValue::ObjectIdentifier(bytes)
            | SnmpValue::Opaque(bytes)
            | SnmpValue::Unsupported { data: bytes, .. } => assert!(inside(data, bytes)),
            _ => {}
        }
    }
}

fn exercise(data: &[u8]) {
    let Ok(packet) = SnmpPacket::try_from(data) else {
        return;
    };
    match &packet.message {
        SnmpMessage::V1V2c(message) => {
            assert_ne!(packet.version, SnmpVersion::V3);
            assert!(inside(data, message.community));
            check_pdu(data, &message.pdu);
        }
        SnmpMessage::V3(message) => {
            assert_eq!(packet.version, SnmpVersion::V3);
            assert!(inside(data, message.flags) && inside(data, message.security_parameters));
            match &message.data {
                SnmpV3Data::ScopedPdu(scoped) => {
                    assert!(inside(data, scoped.context_engine_id));
                    assert!(inside(data, scoped.context_name));
                    check_pdu(data, &scoped.pdu);
                }
                SnmpV3Data::EncryptedPdu(bytes) => assert!(inside(data, bytes)),
                _ => {}
            }
        }
        _ => {}
    }
}

fuzz_target!(|data: &[u8]| {
    exercise(data);
    replay_mutated(&[GET_NEXT, RESPONSE, V3_GET, TRAP_V1], data, exercise);
});
