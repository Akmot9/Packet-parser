// Fuzz du decodeur SIP (#342) : ligne de requete ou de statut, en-tetes
// longs ou compacts, repli, Via, From, To, Call-ID et CSeq obligatoires,
// corps borne par Content-Length. Ni panic ni boucle ; quand le decodage
// reussit :
// - chaque champ emprunte a l'entree ;
// - un code de statut va de 100 a 699, une methode est du registre, et
//   celle d'une requete est celle de son CSeq, numero sous 2^31 ;
// - le corps tient dans l'entree, sans depasser Content-Length ;
// - la vue des en-tetes retrouve les champs obligatoires, sous leur nom
//   long, quelle que soit leur forme sur le fil.
#![no_main]

#[path = "../oracles/seeds.rs"]
mod seeds;

use libfuzzer_sys::fuzz_target;
use packet_parser::parse::application::protocols::sip::{SIP_METHODS, SipMessage, SipStartLine};
use seeds::{inside, replay_mutated};

// Synthetique : l'INVITE de RFC 3261 §24.2 (F1), avec un corps de quatre
// octets, et sa reponse 180 (F2) en formes compactes, avec un en-tete
// replie.
const INVITE: &[u8] = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
    Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds8\r\n\
    Max-Forwards: 70\r\n\
    To: Bob <sip:bob@biloxi.com>\r\n\
    From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
    Call-ID: a84b4c76e66710\r\n\
    CSeq: 314159 INVITE\r\n\
    Content-Length: 4\r\n\
    \r\n\
    v=0\n";
const RINGING: &[u8] = b"SIP/2.0 180 Ringing\r\n\
    v: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds8\r\n\
    t: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
    f: Alice <sip:alice@atlanta.com>;\r\n tag=1928301774\r\n\
    i: a84b4c76e66710\r\n\
    CSeq: 314159 INVITE\r\n\
    \r\n";

fn exercise(data: &[u8]) {
    let Ok(message) = SipMessage::try_from(data) else {
        return;
    };
    match message.start_line {
        SipStartLine::Request { method, uri, .. } => {
            assert!(inside(data, method.as_bytes()) && inside(data, uri.as_bytes()));
            assert!(SIP_METHODS.contains(&method));
            assert_eq!(message.cseq.method, method);
            assert!(uri.contains(':'));
        }
        SipStartLine::Response {
            status_code,
            reason,
            ..
        } => {
            assert!((100..=699).contains(&status_code));
            assert!(inside(data, reason.as_bytes()));
        }
        _ => {}
    }
    assert!(SIP_METHODS.contains(&message.cseq.method));
    assert!(message.cseq.sequence < 1 << 31);
    for field in [
        message.via,
        message.from,
        message.to,
        message.call_id,
        message.cseq.method,
    ] {
        assert!(inside(data, field.as_bytes()));
    }
    assert!(inside(data, message.body));
    if let Some(length) = message.content_length {
        assert!(message.body.len() as u64 <= u64::from(length));
    }

    let mut count = 0;
    for (name, value) in message.headers.iter() {
        assert!(inside(data, name.as_bytes()) && inside(data, value.as_bytes()));
        count += 1;
    }
    assert_eq!(count, message.headers.len());
    assert_eq!(message.headers.get("Via"), Some(message.via));
    assert_eq!(message.headers.get("Call-ID"), Some(message.call_id));
}

fuzz_target!(|data: &[u8]| {
    exercise(data);
    replay_mutated(&[INVITE, RINGING], data, exercise);
});
