// Fuzz du decodeur PostgreSQL (protocole v3) : messages types enchaines,
// messages sans type du debut de session (Startup, SSLRequest,
// CancelRequest, GSSENCRequest), reponse SSL d'un octet, corps Parse, Bind,
// Execute et Query. Ni panic ni boucle ; quand le decodage reussit, les
// messages types pavent exactement l'entree, chaque longueur declaree est
// celle de son payload, et chaque emprunt pointe dans l'entree.
#![no_main]

#[path = "../oracles/seeds.rs"]
mod seeds;

use libfuzzer_sys::fuzz_target;
use packet_parser::parse::application::protocols::postgresql::{
    PostgreSqlMessageBody, PostgreSqlMessageType, PostgreSqlPacket,
};
use seeds::{inside, replay_mutated};

// psql-login.pcap, trame 4 : SSLRequest.
const SSL_REQUEST: &[u8] = &[0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f];

// psql-login-no-sslrequest.pcap, trame 4 : StartupMessage, quatre parametres.
const STARTUP: &[u8] = &[
    0x00, 0x00, 0x00, 0x4c, 0x00, 0x03, 0x00, 0x00, 0x75, 0x73, 0x65, 0x72, 0x00, 0x7a, 0x65, 0x65,
    0x6b, 0x00, 0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x00, 0x7a, 0x65, 0x65, 0x6b, 0x00,
    0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x6e, 0x61, 0x6d, 0x65,
    0x00, 0x70, 0x73, 0x71, 0x6c, 0x00, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x65, 0x6e, 0x63,
    0x6f, 0x64, 0x69, 0x6e, 0x67, 0x00, 0x55, 0x54, 0x46, 0x38, 0x00, 0x00,
];

// psql-create-insert-select-delete-drop.pcap, trame 12 : Query.
const QUERY: &[u8] = &[
    0x51, 0x00, 0x00, 0x00, 0x1c, 0x44, 0x52, 0x4f, 0x50, 0x20, 0x54, 0x41, 0x42, 0x4c, 0x45, 0x20,
    0x49, 0x46, 0x20, 0x45, 0x58, 0x49, 0x53, 0x54, 0x53, 0x20, 0x74, 0x3b, 0x00,
];

// psql-create-insert-select-delete-drop.pcap, trame 15 : CommandComplete
// puis ReadyForQuery, un seul segment.
const COMMAND_COMPLETE: &[u8] = &[
    0x43, 0x00, 0x00, 0x00, 0x11, 0x43, 0x52, 0x45, 0x41, 0x54, 0x45, 0x20, 0x54, 0x41, 0x42, 0x4c,
    0x45, 0x00, 0x5a, 0x00, 0x00, 0x00, 0x05, 0x49,
];

// greenhouse-app.pcap, trame 15 : RowDescription, CommandComplete et
// ReadyForQuery.
const ROW_DESCRIPTION: &[u8] = &[
    0x54, 0x00, 0x00, 0x00, 0x37, 0x00, 0x02, 0x6f, 0x69, 0x64, 0x00, 0x00, 0x00, 0x04, 0xdf, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x04, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x74, 0x79, 0x70,
    0x61, 0x72, 0x72, 0x61, 0x79, 0x00, 0x00, 0x00, 0x04, 0xdf, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x1a,
    0x00, 0x04, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x43, 0x00, 0x00, 0x00, 0x0d, 0x53, 0x45, 0x4c,
    0x45, 0x43, 0x54, 0x20, 0x30, 0x00, 0x5a, 0x00, 0x00, 0x00, 0x05, 0x54,
];

// Synthetique, aucune capture du depot ne porte de CancelRequest : cle
// secrete de quatre octets.
const CANCEL_REQUEST: &[u8] = &[
    0x00, 0x00, 0x00, 0x10, 0x04, 0xd2, 0x16, 0x2e, 0x00, 0x00, 0x30, 0x39, 0xde, 0xad, 0xbe, 0xef,
];

fn text(data: &[u8], field: &str) -> bool {
    inside(data, field.as_bytes())
}

fn exercise(data: &[u8]) {
    let Ok(packet) = PostgreSqlPacket::try_from(data) else {
        return;
    };
    assert!(!packet.messages.is_empty());
    let mut typed = 0;
    for message in &packet.messages {
        assert!(inside(data, message.payload));
        let length = message.length as usize;
        match message.message_type {
            PostgreSqlMessageType::SslResponse => assert_eq!((length, data.len()), (1, 1)),
            PostgreSqlMessageType::StartupMessage
            | PostgreSqlMessageType::SslRequest
            | PostgreSqlMessageType::CancelRequest
            | PostgreSqlMessageType::GssEncRequest => {
                assert_eq!(message.payload.len() + 8, length);
            }
            _ => {
                assert_eq!(message.payload.len() + 4, length);
                typed += 1 + length;
            }
        }
        match &message.body {
            PostgreSqlMessageBody::Parse(parse) => {
                assert!(text(data, parse.statement) && text(data, parse.query));
            }
            PostgreSqlMessageBody::Bind(bind) => {
                assert!(text(data, bind.portal) && text(data, bind.statement));
                for value in bind.parameter_values.iter().flatten() {
                    assert!(inside(data, value));
                }
            }
            PostgreSqlMessageBody::Execute(execute) => assert!(text(data, execute.portal)),
            PostgreSqlMessageBody::Query { query } => assert!(text(data, query)),
            PostgreSqlMessageBody::Startup(startup) => {
                for (name, value) in &startup.parameters {
                    assert!(text(data, name) && text(data, value));
                }
            }
            PostgreSqlMessageBody::CancelRequest { secret_key, .. } => {
                assert!(inside(data, secret_key));
            }
            PostgreSqlMessageBody::Raw(raw) => assert!(inside(data, raw)),
            _ => {}
        }
    }
    if typed == 0 {
        assert_eq!(packet.messages.len(), 1);
    } else {
        assert_eq!(typed, data.len());
    }
}

fuzz_target!(|data: &[u8]| {
    exercise(data);
    replay_mutated(
        &[
            SSL_REQUEST,
            STARTUP,
            QUERY,
            COMMAND_COMPLETE,
            ROW_DESCRIPTION,
            CANCEL_REQUEST,
        ],
        data,
        exercise,
    );
});
