// Fuzz du decodeur ONC RPC : message (appel ou reponse, saveurs et
// longueurs des `opaque_auth`, etats d'une reponse) et enregistrements de
// TCP (marque de fragment, fragments de suite, iteration). Ni panic ni
// boucle ; quand le decodage reussit, les mots relus a la main sont ceux du
// message, les saveurs sont du registre, chaque emprunt pointe dans
// l'entree, l'en-tete et ses emprunts pavent l'entree, une reponse sans
// resultat finit avec elle, la marque annonce au moins le plus court
// message, les fragments de suite se suivent jusqu'au dernier, un
// enregistrement coupe est le dernier, et l'iterateur rend les memes
// enregistrements que des `try_from` enchaines. Quand il echoue par « trop
// court » derriere une marque entiere, le segment coupe un fragment qui
// peut tenir le message qu'il ouvre.
#![no_main]

#[path = "../oracles/seeds.rs"]
mod seeds;

use libfuzzer_sys::fuzz_target;
use packet_parser::errors::application::oncrpc::OncRpcError;
use packet_parser::parse::application::protocols::oncrpc::{
    OncRpcAcceptStatus, OncRpcAuth, OncRpcBody, OncRpcMessage, OncRpcRecord, OncRpcReply,
};
use seeds::{inside, replay_mutated};

// protocols/oncrpc/ndpi_nfsv2.pcap, trame 1 : appel au portmapper sur UDP
// 111 (rpcbind version 3, GETADDR), 64 octets.
const GETADDR_CALL: &[u8] = &[
    0x38, 0x41, 0x16, 0x9f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x86, 0xa0,
    0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x86, 0xa5, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x03, 0x75, 0x64, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// Meme capture, trame 2 : sa reponse, 48 octets.
const GETADDR_REPLY: &[u8] = &[
    0x38, 0x41, 0x16, 0x9f, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x31, 0x33, 0x39, 0x2e,
    0x32, 0x35, 0x2e, 0x32, 0x32, 0x2e, 0x31, 0x30, 0x32, 0x2e, 0x34, 0x2e, 0x32, 0x34, 0x00, 0x00,
];

// protocols/oncrpc/wireshark_getsetacl.cap, trame 1 : appel NFSv3 ACCESS
// sur TCP 2049, marque de fragment comprise, 144 octets.
const TCP_ACCESS_CALL: &[u8] = &[
    0x80, 0x00, 0x00, 0x8c, 0x2a, 0x8d, 0x57, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x00, 0x01, 0x86, 0xa3, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x48, 0x02, 0xb0, 0x07, 0xa7, 0x00, 0x00, 0x00, 0x0f, 0x73, 0x61, 0x68, 0x6c,
    0x62, 0x65, 0x72, 0x67, 0x2d, 0x6c, 0x61, 0x70, 0x74, 0x6f, 0x70, 0x00, 0x00, 0x00, 0x03, 0xe8,
    0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x14,
    0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x69, 0x00, 0x00, 0x00, 0x77,
    0x00, 0x00, 0x00, 0x7a, 0x00, 0x00, 0x00, 0x7b, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x01, 0x00, 0x06, 0x00, 0x36, 0x43, 0x45, 0x2c,
    0xf6, 0x73, 0x48, 0xea, 0x92, 0x15, 0x2c, 0x6c, 0x30, 0x64, 0x13, 0x99, 0x00, 0x00, 0x00, 0x1f,
];

// Meme capture, trame 30 : les 96 premiers octets d'une reponse READDIRPLUS
// de 3 248 octets, que son segment coupe.
const CUT_READDIRPLUS_REPLY: &[u8] = &[
    0x80, 0x00, 0x0c, 0xb0, 0x32, 0x8d, 0x57, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x41, 0xed, 0x00, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x73, 0x5b, 0x17, 0xc6, 0x40, 0x69, 0x56, 0xa4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5b, 0xc0, 0x02,
];

fn word(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(data[offset..offset + 4].try_into().expect("quatre octets"))
}

/// Un `opaque_auth` lu a `offset` : sa saveur est du registre IANA, son
/// corps fait au plus 400 octets et pointe dans l'entree. Rend le decalage
/// qui le suit, bourrage compris.
fn check_auth(data: &[u8], offset: usize, auth: &OncRpcAuth<'_>) -> usize {
    assert_eq!(auth.flavor, word(data, offset));
    assert!(matches!(
        auth.flavor,
        0..=7 | 30_001 | 200_000 | 200_004 | 300_000..=300_002 | 390_000..=390_255 | 200_100_000
    ));
    assert_eq!(auth.body.len(), word(data, offset + 4) as usize);
    assert!(auth.body.len() <= 400);
    assert!(inside(data, auth.body));
    offset + 8 + auth.body.len().next_multiple_of(4)
}

/// `data` est le datagramme, ou ce que le segment porte du premier
/// fragment ; `missing` compte les octets que le fragment annonce au-dela.
fn check_message(data: &[u8], message: &OncRpcMessage<'_>, missing: usize) {
    assert_eq!(message.xid, word(data, 0));
    match message.body {
        OncRpcBody::Call(call) => {
            assert_eq!(word(data, 4), 0);
            assert_eq!(word(data, 8), 2);
            assert_eq!(call.program, word(data, 12));
            assert_eq!(call.version, word(data, 16));
            assert_eq!(call.procedure, word(data, 20));
            let offset = check_auth(data, 24, &call.credentials);
            let offset = check_auth(data, offset, &call.verifier);
            assert!(inside(data, call.arguments));
            assert_eq!(offset + call.arguments.len(), data.len());
        }
        OncRpcBody::Reply(reply) => {
            assert_eq!(word(data, 4), 1);
            match reply {
                OncRpcReply::Accepted(accepted) => {
                    assert_eq!(word(data, 8), 0);
                    let offset = check_auth(data, 12, &accepted.verifier);
                    assert_eq!(accepted.status.code(), word(data, offset));
                    assert!(accepted.status.code() <= 5);
                    assert!(inside(data, accepted.results));
                    let offset = match accepted.status {
                        OncRpcAcceptStatus::ProgramMismatch { low, high, .. } => {
                            assert_eq!(
                                [low, high],
                                [word(data, offset + 4), word(data, offset + 8)]
                            );
                            offset + 12
                        }
                        _ => offset + 4,
                    };
                    assert_eq!(offset + accepted.results.len(), data.len());
                    // Sans succes, pas de resultat : la reponse finit avec
                    // l'entree, et son fragment avec elle.
                    if accepted.status != OncRpcAcceptStatus::Success {
                        assert!(accepted.results.is_empty());
                        assert_eq!(missing, 0);
                    }
                }
                OncRpcReply::RpcMismatch { low, high, .. } => {
                    assert_eq!([word(data, 8), word(data, 12)], [1, 0]);
                    assert_eq!([low, high], [word(data, 16), word(data, 20)]);
                    assert_eq!((data.len(), missing), (24, 0));
                }
                OncRpcReply::AuthError { status, .. } => {
                    assert_eq!([word(data, 8), word(data, 12)], [1, 1]);
                    assert_eq!(status, word(data, 16));
                    assert_eq!((data.len(), missing), (20, 0));
                }
                _ => unreachable!("reponse inconnue de l'oracle"),
            }
        }
        _ => unreachable!("corps inconnu de l'oracle"),
    }
}

/// Une reponse sans resultat : un refus, ou une reponse acceptee sans
/// succes.
fn has_no_results(message: &OncRpcMessage<'_>) -> bool {
    match message.body {
        OncRpcBody::Reply(OncRpcReply::Accepted(accepted)) => {
            accepted.status != OncRpcAcceptStatus::Success
        }
        OncRpcBody::Reply(_) => true,
        _ => false,
    }
}

/// Les fragments de suite d'un enregistrement entier : des marques qui se
/// suivent, seule la derniere portant le bit de fin. Rend la somme de leurs
/// longueurs.
fn check_continuation(continuation: &[u8]) -> usize {
    let (mut offset, mut announced) = (0, 0);
    loop {
        let mark = word(continuation, offset);
        let length = (mark & 0x7fff_ffff) as usize;
        announced += length;
        offset += 4 + length;
        assert!(offset <= continuation.len());
        if mark & 0x8000_0000 != 0 {
            assert_eq!(offset, continuation.len());
            return announced;
        }
    }
}

/// Un enregistrement refuse. « Trop court » dit que le segment coupe : la
/// marque, ou un fragment qui annonce de quoi tenir le message qu'il ouvre
/// (40 octets pour un appel, 24 pour une reponse acceptee, 20 sinon). Une
/// marque entiere qui annonce moins est fausse, et le dit.
fn check_refusal(rest: &[u8], error: &OncRpcError) {
    match *error {
        OncRpcError::TooShort { .. } if rest.len() >= 4 => {
            let announced = (word(rest, 0) & 0x7fff_ffff) as usize;
            let carried = rest.len() - 4;
            assert!(carried < announced);
            let minimum = if carried >= 8 && word(rest, 8) == 0 {
                40
            } else if carried >= 12 && [word(rest, 8), word(rest, 12)] == [1, 0] {
                24
            } else {
                20
            };
            assert!(announced >= minimum);
        }
        OncRpcError::FragmentTooShort { length } => {
            assert_eq!(length, word(rest, 0) & 0x7fff_ffff);
        }
        _ => {}
    }
}

fn exercise(data: &[u8]) {
    if let Ok(message) = OncRpcMessage::try_from(data) {
        check_message(data, &message, 0);
    }

    // Les enregistrements de TCP : l'iterateur rend ce que des `try_from`
    // enchaines rendent, et s'arrete a la premiere erreur ou a la fin.
    let mut rest = data;
    for record in OncRpcRecord::records(data) {
        assert_eq!(record, OncRpcRecord::try_from(rest));
        let record = match record {
            Ok(record) => record,
            Err(error) => {
                check_refusal(rest, &error);
                rest = &[];
                continue;
            }
        };
        let mark = word(rest, 0);
        assert_eq!(record.length, mark & 0x7fff_ffff);
        assert_eq!(record.is_last_fragment, mark & 0x8000_0000 != 0);
        // Le plus court message fait vingt octets.
        assert!(record.length >= 20);
        let announced = record.length as usize;
        let carried = announced.min(rest.len() - 4);
        let fragment = &rest[4..4 + carried];
        check_message(fragment, &record.message, announced - carried);

        let continuation = record.continuation();
        assert!(inside(rest, continuation) && inside(rest, record.rest()));
        if carried < announced {
            // Le segment coupe le premier fragment.
            assert!(record.is_truncated());
            assert!(continuation.is_empty());
        } else if record.is_last_fragment {
            assert!(!record.is_truncated());
            assert!(continuation.is_empty());
            assert_eq!(4 + announced + record.rest().len(), rest.len());
        } else if record.is_truncated() {
            // Le dernier fragment manque : la suite prend le reste.
            assert_eq!(4 + announced + continuation.len(), rest.len());
        } else {
            assert_eq!(
                4 + announced + continuation.len() + record.rest().len(),
                rest.len()
            );
            let following = check_continuation(continuation);
            // Une reponse sans resultat tient dans son premier fragment.
            assert!(!has_no_results(&record.message) || following == 0);
        }
        // Un enregistrement coupe est le dernier.
        assert!(!record.is_truncated() || record.rest().is_empty());
        assert!(record.rest().len() < rest.len());
        rest = record.rest();
    }
    assert!(rest.is_empty());
}

fuzz_target!(|data: &[u8]| {
    exercise(data);
    replay_mutated(
        &[
            GETADDR_CALL,
            GETADDR_REPLY,
            TCP_ACCESS_CALL,
            CUT_READDIRPLUS_REPLY,
        ],
        data,
        exercise,
    );
});
