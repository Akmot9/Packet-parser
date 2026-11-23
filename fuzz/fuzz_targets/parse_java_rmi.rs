// Fuzz du decodeur Java RMI (JRMP) : en-tete de flux, ProtocolAck, Call et
// Return et leur bloc de donnees court ou long, messages de taille fixe. Ni
// panic ni boucle ; quand le decodage reussit, le type est le premier
// octet, chaque champ est celui du fil, les tranches pointent dans
// l'entree, celles qui la terminent (messages qui suivent l'en-tete,
// arguments, valeur) la finissent, le nom d'hote du ProtocolAck est suivi
// de son port, et le decodage a la demande du message suivant un en-tete,
// l'affichage et les accesseurs ne paniquent pas.
//
// Messages d'un segment (#383) : seul le dernier element de l'iterateur
// peut etre une erreur, et une entree qui est un message entier n'en rend
// qu'un, le meme.
#![no_main]

#[path = "../oracles/seeds.rs"]
mod seeds;

use libfuzzer_sys::fuzz_target;
use packet_parser::parse::application::protocols::java_rmi::{JavaRmiPacket, JavaRmiUid};
use seeds::{inside, replay_mutated};

// Graines : trames de pcaps_exemple/protocols/java_rmi/jdk11-loopback.pcap.
// Trame 4 : en-tete StreamProtocol.
const STREAM_HEADER: &[u8] = b"JRMI\x00\x02\x4b";
// Trame 6 : ProtocolAck, 127.0.0.1:36556.
const PROTOCOL_ACK: &[u8] = b"\x4e\x00\x09127.0.0.1\x00\x00\x8e\xcc";
// Trame 33 : Registry.list().
const REGISTRY_LIST: &[u8] = &[
    0x50, 0xac, 0xed, 0x00, 0x05, 0x77, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x44, 0x15, 0x4d, 0xc9, 0xd4, 0xe6, 0x3b, 0xdf,
];
// Trame 60 : Station.add(2, 3).
const STATION_ADD: &[u8] = &[
    0x50, 0xac, 0xed, 0x00, 0x05, 0x77, 0x2a, 0x18, 0xab, 0x9a, 0x45, 0x55, 0xf8, 0xf9, 0x8a, 0xbf,
    0xcb, 0x98, 0xab, 0x00, 0x00, 0x01, 0xa1, 0xe8, 0xed, 0x9c, 0x5b, 0x80, 0x01, 0xff, 0xff, 0xff,
    0xff, 0x94, 0xa9, 0xaf, 0x30, 0x66, 0x52, 0xc3, 0xa6, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x03,
];
// Trame 61 : retour de add, la valeur 5.
const STATION_ADD_RETURN: &[u8] = &[
    0x51, 0xac, 0xed, 0x00, 0x05, 0x77, 0x13, 0x01, 0xbf, 0xcb, 0x98, 0xab, 0x00, 0x00, 0x01, 0xa1,
    0xe8, 0xed, 0x9c, 0x5b, 0x80, 0x0a, 0x00, 0x00, 0x00, 0x05,
];
// Trame 53 : DgcAck.
const DGC_ACK: &[u8] = &[
    0x54, 0xbf, 0xcb, 0x98, 0xab, 0x00, 0x00, 0x01, 0xa1, 0xe8, 0xed, 0x9c, 0x5b, 0x80, 0x07,
];
// Trame 319 : en-tete SingleOpProtocol suivi de Registry.list().
const SINGLE_OP_LIST: &[u8] = &[
    0x4a, 0x52, 0x4d, 0x49, 0x00, 0x02, 0x4c, 0x50, 0xac, 0xed, 0x00, 0x05, 0x77, 0x22, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x44, 0x15, 0x4d, 0xc9, 0xd4, 0xe6, 0x3b, 0xdf,
];

fn be<const N: usize>(data: &[u8], offset: usize) -> [u8; N] {
    std::array::from_fn(|index| data[offset + index])
}

fn assert_uid(uid: JavaRmiUid, data: &[u8], offset: usize) {
    assert_eq!(uid.unique, i32::from_be_bytes(be(data, offset)));
    assert_eq!(uid.time, i64::from_be_bytes(be(data, offset + 4)));
    assert_eq!(uid.count, i16::from_be_bytes(be(data, offset + 12)));
}

/// Offset de l'en-tete d'appel ou de retour : apres `TC_BLOCKDATA` et sa
/// longueur d'un octet, ou `TC_BLOCKDATALONG` et ses quatre octets.
fn block_start(data: &[u8]) -> usize {
    match data[5] {
        0x77 => 7,
        0x7a => 10,
        other => panic!("bloc 0x{other:02x} accepte"),
    }
}

fn exercise(data: &[u8]) {
    let messages: Vec<_> = JavaRmiPacket::messages(data).collect();
    assert_eq!(messages.is_empty(), data.is_empty());
    assert!(messages.iter().rev().skip(1).all(|message| message.is_ok()));

    let Ok(packet) = JavaRmiPacket::try_from(data) else {
        return;
    };
    assert_eq!(messages, [Ok(packet)]);
    assert_eq!(packet.message_type(), data[0]);
    assert_eq!(
        packet.is_self_identifying(),
        matches!(data[0], 0x4a | 0x50 | 0x51)
    );
    match packet {
        JavaRmiPacket::Header(header) => {
            assert_eq!(&data[..4], b"JRMI");
            assert_eq!(header.version, u16::from_be_bytes([data[4], data[5]]));
            assert!(matches!(header.version, 1 | 2));
            assert_eq!(header.protocol.code(), data[6]);
            assert_eq!(header.messages.len() + 7, data.len());
            assert!(inside(data, header.messages));
            if let Some(Ok(next)) = header.message() {
                assert_eq!(next.message_type(), data[7]);
                let _ = next.to_string();
            }
        }
        JavaRmiPacket::ProtocolAck(endpoint) => {
            let length = usize::from(u16::from_be_bytes([data[1], data[2]]));
            assert_eq!(data.len(), 7 + length);
            assert_eq!(endpoint.hostname, &data[3..3 + length]);
            assert!(inside(data, endpoint.hostname));
            assert_eq!(
                u32::from(endpoint.port),
                u32::from_be_bytes(be(data, 3 + length))
            );
            let _ = endpoint.hostname_str();
        }
        JavaRmiPacket::Call(call) => {
            assert_eq!(&data[1..5], [0xac, 0xed, 0x00, 0x05]);
            let start = block_start(data);
            assert_eq!(
                call.object.object_number,
                i64::from_be_bytes(be(data, start))
            );
            assert_uid(call.object.space, data, start + 8);
            assert_eq!(call.operation, i32::from_be_bytes(be(data, start + 22)));
            assert_eq!(call.hash, i64::from_be_bytes(be(data, start + 26)));
            assert_eq!(call.arguments.len() + start + 34, data.len());
            assert!(data.ends_with(call.arguments) && inside(data, call.arguments));
            if let Some((object, method)) = call.well_known_method() {
                assert_eq!(call.object.well_known(), Some(object));
                assert!(!method.is_empty());
            }
        }
        JavaRmiPacket::Return(ret) => {
            assert_eq!(&data[1..5], [0xac, 0xed, 0x00, 0x05]);
            let start = block_start(data);
            assert!(matches!(data[start], 1 | 2));
            assert_uid(ret.ack_id, data, start + 1);
            assert_eq!(ret.value.len() + start + 15, data.len());
            assert!(data.ends_with(ret.value) && inside(data, ret.value));
        }
        JavaRmiPacket::DgcAck(uid) => {
            assert_eq!(data.len(), 15);
            assert_uid(uid, data, 1);
        }
        _ => assert_eq!(data.len(), 1),
    }
    let _ = packet.to_string();
}

fuzz_target!(|data: &[u8]| {
    exercise(data);
    replay_mutated(
        &[
            STREAM_HEADER,
            PROTOCOL_ACK,
            REGISTRY_LIST,
            STATION_ADD,
            STATION_ADD_RETURN,
            DGC_ACK,
            SINGLE_OP_LIST,
        ],
        data,
        exercise,
    );
});
