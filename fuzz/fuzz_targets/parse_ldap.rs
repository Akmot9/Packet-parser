// Fuzz du decodeur LDAP : enveloppe BER d'un message, tampon de la couche
// de securite SASL et ses trois jetons, iteration sur les PDU d'un payload.
// Ni panic ni boucle ; quand le decodage reussit, chaque emprunt pointe dans
// l'entree, la longueur annoncee est celle que l'oracle relit dans les
// octets, un PDU entier occupe exactement cette longueur, et l'iterateur
// rend les memes PDU que des `try_from` enchaines.
#![no_main]

#[path = "../oracles/seeds.rs"]
mod seeds;

use libfuzzer_sys::fuzz_target;
use packet_parser::parse::application::protocols::ldap::{
    LdapMessage, LdapOperation, LdapPdu, LdapSaslBuffer, LdapSaslToken,
};
use seeds::{inside, replay_mutated};

// The-Ultimate-PCAP.pcapng, trame 40032 : BindRequest SASL (GSS-SPNEGO) de 80
// octets, longueurs BER sur cinq octets.
const BIND_REQUEST: &[u8] = &[
    0x30, 0x84, 0x00, 0x00, 0x00, 0x4a, 0x02, 0x01, 0x08, 0x60, 0x84, 0x00, 0x00, 0x00, 0x41, 0x02,
    0x01, 0x03, 0x04, 0x00, 0xa3, 0x84, 0x00, 0x00, 0x00, 0x36, 0x04, 0x0a, 0x47, 0x53, 0x53, 0x2d,
    0x53, 0x50, 0x4e, 0x45, 0x47, 0x4f, 0x04, 0x28, 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
    0x01, 0x00, 0x00, 0x00, 0xb7, 0x82, 0x08, 0xe2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x61, 0x4a, 0x00, 0x00, 0x00, 0x0f,
];

// Meme capture, trame 39248 : deux messages dans un datagramme de 186 octets
// (SearchResultEntry, SearchResultDone).
const CLDAP_RESPONSE: &[u8] = &[
    0x30, 0x84, 0x00, 0x00, 0x00, 0x9e, 0x02, 0x01, 0x01, 0x64, 0x84, 0x00, 0x00, 0x00, 0x95, 0x04,
    0x00, 0x30, 0x84, 0x00, 0x00, 0x00, 0x8d, 0x30, 0x84, 0x00, 0x00, 0x00, 0x87, 0x04, 0x08, 0x4e,
    0x65, 0x74, 0x6c, 0x6f, 0x67, 0x6f, 0x6e, 0x31, 0x84, 0x00, 0x00, 0x00, 0x77, 0x04, 0x75, 0x17,
    0x00, 0x00, 0x00, 0xfd, 0xf3, 0x03, 0x00, 0x10, 0x1b, 0x11, 0x4e, 0xd4, 0x28, 0x12, 0x4e, 0x9c,
    0x1d, 0x09, 0xa4, 0xa3, 0x51, 0x07, 0x2b, 0x06, 0x61, 0x64, 0x32, 0x30, 0x32, 0x34, 0x08, 0x77,
    0x65, 0x62, 0x65, 0x72, 0x6c, 0x61, 0x62, 0x02, 0x64, 0x65, 0x00, 0xc0, 0x18, 0x0b, 0x76, 0x6d,
    0x33, 0x39, 0x2d, 0x61, 0x64, 0x32, 0x30, 0x32, 0x34, 0xc0, 0x18, 0x06, 0x41, 0x44, 0x32, 0x30,
    0x32, 0x34, 0x00, 0x0b, 0x56, 0x4d, 0x33, 0x39, 0x2d, 0x41, 0x44, 0x32, 0x30, 0x32, 0x34, 0x00,
    0x00, 0x17, 0x44, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x2d, 0x46, 0x69, 0x72, 0x73, 0x74, 0x2d,
    0x53, 0x69, 0x74, 0x65, 0x2d, 0x4e, 0x61, 0x6d, 0x65, 0x00, 0xc0, 0x52, 0x05, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0x30, 0x84, 0x00, 0x00, 0x00, 0x10, 0x02, 0x01, 0x01, 0x65, 0x84, 0x00,
    0x00, 0x00, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
];

// Meme capture, trame 41296 : tampon SASL signe (jeton Wrap de la RFC 4121)
// qui porte un SearchRequest et un controle, 176 octets.
const SIGNED_SEARCH: &[u8] = &[
    0x00, 0x00, 0x00, 0xac, 0x05, 0x04, 0x04, 0xff, 0x00, 0x0c, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00,
    0x5c, 0x18, 0x06, 0x6f, 0x6a, 0xee, 0xe4, 0x03, 0x8f, 0xff, 0x8e, 0x1b, 0xa0, 0xc6, 0xf0, 0x09,
    0x30, 0x84, 0x00, 0x00, 0x00, 0x8a, 0x02, 0x01, 0x08, 0x63, 0x84, 0x00, 0x00, 0x00, 0x57, 0x04,
    0x00, 0x0a, 0x01, 0x00, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0xf0, 0x01, 0x01,
    0x00, 0x87, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x30, 0x84,
    0x00, 0x00, 0x00, 0x32, 0x04, 0x1a, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74,
    0x69, 0x6f, 0x6e, 0x4e, 0x61, 0x6d, 0x69, 0x6e, 0x67, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74,
    0x04, 0x14, 0x6e, 0x54, 0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x44, 0x65, 0x73, 0x63,
    0x72, 0x69, 0x70, 0x74, 0x6f, 0x72, 0xa0, 0x84, 0x00, 0x00, 0x00, 0x24, 0x30, 0x84, 0x00, 0x00,
    0x00, 0x1e, 0x04, 0x17, 0x31, 0x2e, 0x32, 0x2e, 0x38, 0x34, 0x30, 0x2e, 0x31, 0x31, 0x33, 0x35,
    0x35, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x33, 0x33, 0x39, 0x01, 0x01, 0xff, 0x04, 0x00,
];

// Meme capture, trame 40284 : tampon SASL chiffre, 75 octets.
const SEALED: &[u8] = &[
    0x00, 0x00, 0x00, 0x47, 0x05, 0x04, 0x06, 0xff, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00,
    0x3a, 0x8d, 0x97, 0xb0, 0xfa, 0xf4, 0x74, 0x26, 0xb0, 0x16, 0x6f, 0xdb, 0x91, 0x19, 0x5b, 0x79,
    0x56, 0xcb, 0x80, 0x32, 0x2a, 0x85, 0xa4, 0x08, 0x31, 0xb4, 0xb1, 0x86, 0xab, 0x3d, 0xd4, 0x58,
    0xe4, 0xcb, 0xcc, 0x24, 0x1e, 0x79, 0x3c, 0x4c, 0xcc, 0xb3, 0x7e, 0xc5, 0x6f, 0xbb, 0xfe, 0x2f,
    0xe9, 0x78, 0x65, 0xd8, 0x96, 0xb9, 0xa6, 0x26, 0xc4, 0x15, 0x3f,
];

// protocols/ldap/ldap-and-search.pcap, trame 4 : BindRequest simple, longueurs
// BER sur un octet.
const SIMPLE_BIND: &[u8] = &[
    0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00,
];

// protocols/ldap/ldap-controls-dirsync-01.cap, trame 8 : tampon SASL signe
// (jeton Wrap de la RFC 1964) qui porte un UnbindRequest, 61 octets.
const V1_SIGNED_UNBIND: &[u8] = &[
    0x00, 0x00, 0x00, 0x39, 0x60, 0x37, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02,
    0x02, 0x02, 0x01, 0x11, 0x00, 0xff, 0xff, 0xff, 0xff, 0x14, 0x18, 0xa3, 0x9b, 0x92, 0x9e, 0x3a,
    0x18, 0x01, 0x32, 0x86, 0x13, 0x11, 0x2a, 0x7d, 0xc5, 0x88, 0x04, 0xf8, 0xe6, 0x69, 0x99, 0xee,
    0xbe, 0x30, 0x84, 0x00, 0x00, 0x00, 0x05, 0x02, 0x01, 0x09, 0x42, 0x00, 0x01,
];

// protocols/ldap/ntlm_ldap.pcapng, trame 14 : tampon SASL sous signature
// NTLMSSP, 71 octets.
const NTLM: &[u8] = &[
    0x00, 0x00, 0x00, 0x43, 0x01, 0x00, 0x00, 0x00, 0x4d, 0x2f, 0x4f, 0x85, 0x51, 0x7c, 0xed, 0xa7,
    0x02, 0x00, 0x00, 0x00, 0x53, 0xe5, 0x2b, 0xc6, 0xae, 0x82, 0x71, 0xb1, 0xc7, 0xdb, 0xf4, 0x34,
    0x79, 0x31, 0x47, 0xd6, 0x96, 0x1a, 0x88, 0xf5, 0xc1, 0xdf, 0xd4, 0x62, 0x1d, 0x68, 0xa0, 0x11,
    0x17, 0x6f, 0xd8, 0x62, 0x35, 0xa2, 0x7b, 0xb1, 0xed, 0xe7, 0x45, 0xfe, 0x66, 0xf1, 0x86, 0x53,
    0x73, 0x1d, 0x53, 0x08, 0x21, 0x84, 0x74,
];

/// Numeros d'etiquette APPLICATION des operations de la RFC 4511.
const OPERATIONS: [u8; 21] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 19, 23, 24, 25,
];

/// Plus grande longueur d'un element BER : 2^31 - 1, la borne du decodeur.
const BER_MAX_LENGTH: usize = 0x7fff_ffff;
/// Plus grande longueur d'un tampon SASL : 2^24 - 1 (RFC 4752 §3.1).
const SASL_MAX_LENGTH: usize = 0x00ff_ffff;

/// Oracle : la longueur BER qui suit une etiquette, et le nombre d'octets
/// d'en-tete. Recopie la regle (forme courte, ou longue d'un a quatre
/// octets), sans rien importer du decodeur.
fn ber_length(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.get(1)?;
    if first < 0x80 {
        return Some((usize::from(first), 2));
    }
    let count = usize::from(first & 0x7f);
    if count == 0 || count > 4 {
        return None;
    }
    let octets = data.get(2..2 + count)?;
    let length = octets
        .iter()
        .fold(0usize, |length, octet| (length << 8) | usize::from(*octet));
    Some((length, 2 + count))
}

fn check_message(data: &[u8], message: &LdapMessage<'_>) {
    assert_eq!(data[0], 0x30);
    let (length, header) = ber_length(data).expect("longueur d'enveloppe lisible");
    assert!(length <= BER_MAX_LENGTH);
    assert_eq!(message.wire_length(), header + length);
    assert!(message.message_id <= 0x7fff_ffff);
    assert!(OPERATIONS.contains(&message.operation.as_u8()));
    assert!(inside(data, message.body));
    assert!(inside(data, message.rest()));
    if let Some(controls) = message.controls {
        assert!(inside(data, controls));
    }
    // Un message entier occupe sa longueur annoncee ; un message coupe va
    // jusqu'au bout de l'entree et n'a pas de suite.
    if message.is_truncated() {
        assert!(message.wire_length() > data.len());
        assert!(message.rest().is_empty());
    } else {
        assert_eq!(message.wire_length() + message.rest().len(), data.len());
    }
    let visible = &data[..data.len() - message.rest().len()];
    assert!(inside(visible, message.body));

    // Les lectures du corps : chacune pour son operation seulement, et ses
    // emprunts dans le corps.
    if let Some(result) = message.result() {
        assert!(matches!(
            message.operation,
            LdapOperation::BindResponse
                | LdapOperation::SearchResultDone
                | LdapOperation::ModifyResponse
                | LdapOperation::AddResponse
                | LdapOperation::DelResponse
                | LdapOperation::ModifyDnResponse
                | LdapOperation::CompareResponse
                | LdapOperation::ExtendedResponse
        ));
        assert!(result.code <= 0x7fff_ffff);
        assert!(inside(message.body, result.matched_dn));
        assert!(inside(message.body, result.diagnostic_message));
    }
    if let Some(bind) = message.bind_request() {
        assert_eq!(message.operation, LdapOperation::BindRequest);
        assert!((1..=127).contains(&bind.version));
        assert!(inside(message.body, bind.name));
    }
    if let Some(search) = message.search_request() {
        assert_eq!(message.operation, LdapOperation::SearchRequest);
        assert!(inside(message.body, search.base_object));
    }
}

fn check_buffer(data: &[u8], buffer: &LdapSaslBuffer<'_>) {
    assert_eq!(buffer.length.to_be_bytes(), data[..4]);
    let length = buffer.length as usize;
    assert!((16..=SASL_MAX_LENGTH).contains(&length));
    assert!(inside(data, buffer.data));
    assert!(inside(data, buffer.rest()));
    if buffer.is_truncated() {
        assert!(4 + length > data.len());
        assert!(buffer.rest().is_empty());
    } else {
        assert_eq!(4 + length + buffer.rest().len(), data.len());
    }
    // Le premier octet du jeton designe son en-tete, que l'oracle relit.
    let header = match buffer.token {
        LdapSaslToken::KerberosWrap {
            flags,
            extra_count,
            right_rotation_count,
            sequence_number,
            ..
        } => {
            assert_eq!(data[4..6], [0x05, 0x04]);
            assert_eq!(data[6], flags);
            assert_eq!(data[7], 0xff);
            assert_eq!(extra_count.to_be_bytes(), data[8..10]);
            assert_eq!(right_rotation_count.to_be_bytes(), data[10..12]);
            assert_eq!(sequence_number.to_be_bytes(), data[12..20]);
            assert_eq!(buffer.token.is_sealed(), Some(flags & 0x02 != 0));
            16
        }
        LdapSaslToken::KerberosV1Wrap {
            signing_algorithm,
            sealing_algorithm,
            ..
        } => {
            assert_eq!(data[4], 0x60);
            let (framed, framing) = ber_length(&data[4..]).expect("enveloppe GSS-API");
            assert_eq!(framing + framed, length);
            let token = &data[4 + framing..];
            assert_eq!(
                token[..13],
                [
                    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x02, 0x01
                ]
            );
            assert_eq!(signing_algorithm.to_le_bytes(), token[13..15]);
            assert_eq!(sealing_algorithm.to_le_bytes(), token[15..17]);
            assert_eq!(token[17..19], [0xff, 0xff]);
            assert_eq!(buffer.token.is_sealed(), Some(sealing_algorithm != 0xffff));
            framing + 35
        }
        LdapSaslToken::NtlmSignature {
            sequence_number, ..
        } => {
            assert_eq!(data[4..8], [1, 0, 0, 0]);
            assert_eq!(sequence_number.to_le_bytes(), data[16..20]);
            assert_eq!(buffer.token.is_sealed(), None);
            16
        }
        _ => unreachable!("jeton inconnu de l'oracle"),
    };
    assert!(header <= length);
    assert_eq!(
        buffer.data.len(),
        (length - header).min(data.len() - 4 - header)
    );

    // Le texte en clair : dans les donnees, et jamais pour un jeton chiffre
    // ni pour une signature NTLMSSP.
    let plaintext = buffer.plaintext();
    if buffer.token.is_sealed() != Some(false) {
        assert_eq!(plaintext, None);
    }
    if let Some(plaintext) = plaintext {
        assert!(inside(buffer.data, plaintext));
    }
    let mut rest = plaintext.unwrap_or_default();
    let mut failed = false;
    let mut count = 0usize;
    for item in buffer.messages() {
        assert!(!failed, "un message apres une erreur");
        assert!(!rest.is_empty());
        count += 1;
        assert_eq!(item, LdapMessage::try_from(rest));
        match item {
            Ok(message) => {
                check_message(rest, &message);
                rest = message.rest();
            }
            Err(_) => failed = true,
        }
    }
    assert!(failed || rest.is_empty());
    assert!(count <= buffer.data.len() / 7 + 1);
}

fn check_pdu(data: &[u8], pdu: &LdapPdu<'_>) {
    match pdu {
        LdapPdu::Message(message) => {
            assert_eq!(LdapMessage::try_from(data).as_ref(), Ok(message));
            check_message(data, message);
            assert_eq!(pdu.is_truncated(), message.is_truncated());
            assert_eq!(pdu.rest(), message.rest());
        }
        LdapPdu::SaslBuffer(buffer) => {
            // Une longueur de tampon s'ouvre par un octet nul.
            assert_eq!(data[0], 0);
            assert_eq!(LdapSaslBuffer::try_from(data).as_ref(), Ok(buffer));
            check_buffer(data, buffer);
            assert_eq!(pdu.is_truncated(), buffer.is_truncated());
            assert_eq!(pdu.rest(), buffer.rest());
        }
        _ => unreachable!("PDU inconnu de l'oracle"),
    }
}

fn exercise(data: &[u8]) {
    // Les deux decodeurs, appeles directement.
    if let Ok(message) = LdapMessage::try_from(data) {
        check_message(data, &message);
    }
    if let Ok(buffer) = LdapSaslBuffer::try_from(data) {
        check_buffer(data, &buffer);
    }
    let first = LdapPdu::try_from(data);
    if let Ok(pdu) = &first {
        check_pdu(data, pdu);
    }
    // Un octet nul en tete : un tampon ou rien ; sinon un message ou rien.
    match data.first() {
        Some(0) => assert!(!matches!(first, Ok(LdapPdu::Message(_)))),
        _ => assert!(!matches!(first, Ok(LdapPdu::SaslBuffer(_)))),
    }

    // L'iterateur : les memes PDU que des `try_from` enchaines, rien apres
    // une erreur ni apres un PDU coupe, au plus un PDU par sept octets (le
    // plus court message : `30 05 02 01 id 42 00`).
    let mut rest = data;
    let mut count = 0usize;
    let mut failed = false;
    for item in LdapPdu::pdus(data) {
        assert!(!failed, "un element apres une erreur");
        assert!(!rest.is_empty());
        count += 1;
        assert_eq!(item, LdapPdu::try_from(rest));
        match item {
            Ok(pdu) => {
                check_pdu(rest, &pdu);
                rest = pdu.rest();
            }
            Err(_) => failed = true,
        }
    }
    assert!(failed || rest.is_empty());
    assert!(count <= data.len() / 7 + 1);
    assert_eq!(count == 0, data.is_empty());
}

fuzz_target!(|data: &[u8]| {
    exercise(data);
    replay_mutated(
        &[
            BIND_REQUEST,
            CLDAP_RESPONSE,
            SIGNED_SEARCH,
            SEALED,
            SIMPLE_BIND,
            V1_SIGNED_UNBIND,
            NTLM,
        ],
        data,
        exercise,
    );
});
