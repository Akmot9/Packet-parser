// Fuzz du decodeur OPC UA binaire (UACP) : en-tete de message, chunks
// enchaines et parcourus a la demande, Hello, Acknowledge, Error,
// ReverseHello, conversation securisee, dernier chunk tronque. Ni panic ni
// boucle ; quand le decodage reussit, les chunks rendus par l'iterateur
// pavent l'entree, seul le dernier peut etre partiel, chaque emprunt pointe
// dans l'entree, et `len` et `get` s'accordent avec lui. Apres un chunk
// complet, un reste de moins de 8 octets est le debut d'en-tete du suivant,
// que TCP a coupe (#296) : l'iterateur s'arrete avant lui, et ses octets
// presents commencent un type de message et un type de chunk connus (#333).
#![no_main]

#[path = "../oracles/seeds.rs"]
mod seeds;

use libfuzzer_sys::fuzz_target;
use packet_parser::parse::application::protocols::opcua::{
    OpcuaChunkType, OpcuaMessageType, OpcuaPacket, OpcuaPayload, OpcuaTcpHeader,
};
use seeds::{inside, replay_mutated};

// opcua_loopback.pcap, trame 5 : Hello, avec son EndpointUrl.
const HELLO: &[u8] = &[
    0x48, 0x45, 0x4c, 0x46, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
    0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x80, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
    0x6f, 0x70, 0x63, 0x2e, 0x74, 0x63, 0x70, 0x3a, 0x2f, 0x2f, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68,
    0x6f, 0x73, 0x74, 0x3a, 0x34, 0x38, 0x34, 0x30,
];

// opcua_loopback.pcap, trame 7 : Acknowledge.
const ACKNOWLEDGE: &[u8] = &[
    0x41, 0x43, 0x4b, 0x46, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
    0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x80, 0x00, 0x00,
];

// opcua_loopback.pcap, trame 13 : MSG, GetEndpointsRequest.
const MESSAGE: &[u8] = &[
    0x4d, 0x53, 0x47, 0x46, 0x5d, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0xac, 0x01, 0x00, 0x00, 0x82, 0x4c,
    0xdf, 0x99, 0xa8, 0xf3, 0xd8, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
    0xff, 0xff, 0x10, 0x27, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x6f, 0x70, 0x63,
    0x2e, 0x74, 0x63, 0x70, 0x3a, 0x2f, 0x2f, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74,
    0x3a, 0x34, 0x38, 0x34, 0x30, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

// Synthetique, la capture n'a pas de message d'erreur : ERR,
// Bad_TcpMessageTypeInvalid et sa raison.
// Les sept types de message UACP, recopies de la specification (Part 6,
// §7.1.2.2) plutot que lus dans la crate.
const MESSAGE_TYPES: [&[u8]; 7] = [b"HEL", b"ACK", b"ERR", b"RHE", b"OPN", b"MSG", b"CLO"];

const ERROR: &[u8] = &[
    0x45, 0x52, 0x52, 0x46, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7e, 0x80, 0x03, 0x00, 0x00, 0x00,
    0x62, 0x61, 0x64,
];

fn exercise(data: &[u8]) {
    let header = OpcuaTcpHeader::try_from(data);
    if let [a, b, c, chunk, ..] = *data {
        let known = OpcuaMessageType::try_from([a, b, c]).is_ok()
            && OpcuaChunkType::try_from(chunk).is_ok();
        assert!(known || header.is_err());
    }
    let Ok(packet) = OpcuaPacket::try_from(data) else {
        return;
    };
    assert!(header.is_ok() && !packet.chunks.is_empty());
    let mut covered = 0;
    let mut count = 0;
    for chunk in packet.chunks.iter() {
        assert!(covered < data.len(), "un chunk apres le chunk partiel");
        let size = chunk.header.message_size as usize;
        assert!(size >= 8);
        let text = |field: Option<&str>| field.is_none_or(|text| inside(data, text.as_bytes()));
        match &chunk.payload {
            OpcuaPayload::Partial(body) => {
                assert!(size > data.len() - covered);
                assert!(data.ends_with(body) && inside(data, body));
                covered = data.len();
                count += 1;
                continue;
            }
            OpcuaPayload::Hello(hello) => assert!(text(hello.endpoint_url)),
            OpcuaPayload::Error(error) => assert!(text(error.reason)),
            OpcuaPayload::ReverseHello(hello) => {
                assert!(text(hello.server_uri) && text(hello.endpoint_url));
            }
            OpcuaPayload::SecureConversation(conversation) => {
                assert_eq!(conversation.data.len() + 12, size);
                assert!(inside(data, conversation.data));
            }
            _ => {}
        }
        covered += size;
        count += 1;
    }
    let rest = &data[covered..];
    if !rest.is_empty() {
        assert!(covered > 0 && rest.len() < 8, "reste de {} octets", rest.len());
        let message_type = rest.get(..3).unwrap_or(rest);
        assert!(
            MESSAGE_TYPES
                .iter()
                .any(|known| known.starts_with(message_type)),
            "{message_type:?}"
        );
        assert!(
            rest.get(3)
                .is_none_or(|chunk| OpcuaChunkType::try_from(*chunk).is_ok())
        );
    }
    assert_eq!(packet.chunks.len(), count);
    assert!(packet.chunks.get(0).is_some() && packet.chunks.get(count).is_none());
    let _ = format!("{:?}", packet.chunks);
}

fuzz_target!(|data: &[u8]| {
    exercise(data);
    replay_mutated(&[HELLO, ACKNOWLEDGE, MESSAGE, ERROR], data, exercise);
});
