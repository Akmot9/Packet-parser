// Fuzz du decodeur SRVLOC (SLP v1 et v2) : en-tetes des deux versions,
// longueur declaree egale au datagramme, chaines prefixees par leur
// longueur, et le corps v2 decode a la demande (SrvRqst, SrvRply et ses URL
// entries). Ni panic ni boucle ; quand le decodage reussit, la longueur
// declaree est celle de l'entree, chaque emprunt y pointe, et `body()` rend
// la forme que la fonction annonce ou une erreur, jamais une panique.
#![no_main]

#[path = "../oracles/seeds.rs"]
mod seeds;

use libfuzzer_sys::fuzz_target;
use packet_parser::parse::application::protocols::srvloc::{
    SrvlocBody, SrvlocHeader, SrvlocMessage, SrvlocPacket,
};
use seeds::{inside, replay_mutated};

// Synthetique, le depot n'a pas de capture SLP : DAAdvert v1, URL et liste
// de scopes (le `build_v1_packet` des tests unitaires).
const DA_ADVERT_V1: &[u8] = &[
    0x01, 0x08, 0x00, 0x17, 0x20, 0x00, 0x65, 0x6e, 0x00, 0x6a, 0x12, 0x34, 0x00, 0x00, 0x00, 0x03,
    0x73, 0x76, 0x63, 0x00, 0x02, 0x73, 0x63,
];

// Synthetique : SrvRqst v2, ses cinq chaines.
const SRV_RQST_V2: &[u8] = &[
    0x02, 0x01, 0x00, 0x00, 0x30, 0x20, 0x00, 0x00, 0x00, 0x00, 0x42, 0x42, 0x00, 0x02, 0x65, 0x6e,
    0x00, 0x00, 0x00, 0x0f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x3a, 0x70, 0x72, 0x69, 0x6e,
    0x74, 0x65, 0x72, 0x00, 0x07, 0x44, 0x45, 0x46, 0x41, 0x55, 0x4c, 0x54, 0x00, 0x00, 0x00, 0x00,
];

// Synthetique : SrvRply v2, deux URL entries, la seconde avec un bloc
// d'authentification.
const SRV_RPLY_V2: &[u8] = &[
    0x02, 0x02, 0x00, 0x00, 0x50, 0x20, 0x00, 0x00, 0x00, 0x00, 0x42, 0x42, 0x00, 0x02, 0x65, 0x6e,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x64, 0x00, 0x13, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65,
    0x3a, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x3a, 0x2f, 0x2f, 0x61, 0x00, 0x00, 0x00, 0x05,
    0x00, 0x13, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x3a, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x65,
    0x72, 0x3a, 0x2f, 0x2f, 0x62, 0x01, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

fn text(data: &[u8], field: &str) -> bool {
    inside(data, field.as_bytes())
}

fn exercise(data: &[u8]) {
    let Ok(packet) = SrvlocPacket::try_from(data) else {
        return;
    };
    let SrvlocMessage::Raw(raw) = &packet.payload else {
        return;
    };
    assert!(data.ends_with(raw) && inside(data, raw));
    let body = packet.body();
    match &packet.header {
        SrvlocHeader::V1(header) => {
            assert_eq!((header.version, header.function), (data[0], data[1]));
            assert_eq!(usize::from(header.packet_length), data.len());
            assert!(text(data, header.language) && text(data, header.url));
            assert!(text(data, header.scope_list));
            // Les octets du fil, et leur texte dans l'encodage annonce
            // (#302) : rien n'y est remplace pour un paquet accepte.
            assert_eq!(header.url_bytes.len(), usize::from(header.url_length));
            assert_eq!(
                header.scope_list_bytes.len(),
                usize::from(header.scope_list_length)
            );
            assert!(inside(data, header.url_bytes) && inside(data, header.scope_list_bytes));
            for (borrowed, bytes, decoded) in [
                (header.url, header.url_bytes, header.url_text()),
                (header.scope_list, header.scope_list_bytes, header.scope_list_text()),
            ] {
                if !borrowed.is_empty() {
                    assert_eq!(decoded, borrowed);
                }
                // UCS-2 : un caractere par unite de deux octets, aucune
                // substitution.
                if header.char_encoding == 1000 {
                    assert_eq!(decoded.chars().count() * 2, bytes.len());
                    assert!(!decoded.contains(char::REPLACEMENT_CHARACTER));
                }
            }
            assert!(matches!(body, Ok(SrvlocBody::Raw(body)) if body == *raw));
        }
        SrvlocHeader::V2(header) => {
            assert_eq!((header.version, header.function), (data[0], data[1]));
            assert_eq!(header.packet_length as usize, data.len());
            assert_eq!(header.lang_tag.len(), usize::from(header.lang_tag_len));
            assert!(text(data, header.lang_tag));
            match body {
                Ok(SrvlocBody::SrvRqstV2(request)) => {
                    assert_eq!(header.function, 1);
                    for field in [
                        request.pr_list,
                        request.service_type,
                        request.scope_list,
                        request.predicate,
                        request.slp_spi,
                    ] {
                        assert!(text(data, field));
                    }
                }
                Ok(SrvlocBody::SrvRplyV2(reply)) => {
                    assert_eq!(header.function, 2);
                    assert_eq!(reply.url_entries.len(), usize::from(reply.url_entry_count));
                    for entry in &reply.url_entries {
                        assert_eq!(entry.url.len(), usize::from(entry.url_length));
                        assert!(text(data, entry.url) && inside(data, entry.auth_blocks));
                    }
                }
                Ok(SrvlocBody::Raw(body)) => {
                    assert!(!matches!(header.function, 1 | 2));
                    assert_eq!(body, *raw);
                }
                Ok(_) | Err(_) => {}
            }
        }
        _ => {}
    }
}

fuzz_target!(|data: &[u8]| {
    exercise(data);
    replay_mutated(&[DA_ADVERT_V1, SRV_RQST_V2, SRV_RPLY_V2], data, exercise);
});
