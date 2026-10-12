// Fuzz du decodeur DNP3 (IEEE 1815) : en-tete de liaison et ses CRC, blocs
// de seize octets, transport, en-tete applicatif, en-tetes d'objets et
// tailles de l'annexe A, plusieurs trames par payload. Ni panic ni boucle
// infinie ; quand le decodage reussit, les trames pavent exactement l'entree,
// les donnees utilisateur ont la longueur annoncee, chaque objet tient dans
// les donnees utilisateur, et toute alteration d'un seul octet d'une graine
// reelle est rejetee : c'est le CRC qui rend le sondage aveugle sur.
#![no_main]

use libfuzzer_sys::fuzz_target;
use packet_parser::parse::application::protocols::dnp3::Dnp3Packet;

// dnp3_read.pcap, trame 4 : lecture des classes 1, 2, 3 et 0.
const READ_REQUEST: &[u8] = &[
    0x05, 0x64, 0x14, 0xc4, 0x02, 0x00, 0x03, 0x00, 0x45, 0x03, 0xc7, 0xc8, 0x01, 0x3c, 0x02, 0x06,
    0x3c, 0x03, 0x06, 0x3c, 0x04, 0x06, 0x3c, 0x01, 0x06, 0x42, 0xac,
];

// dnp3_read.pcap, trame 6 : reponse avec entrees binaires, sorties et analogiques.
const RESPONSE: &[u8] = &[
    0x05, 0x64, 0x74, 0x44, 0x03, 0x00, 0x02, 0x00, 0x68, 0x54, 0xf4, 0xc8, 0x81, 0x00, 0x00, 0x01,
    0x02, 0x00, 0x00, 0x08, 0x81, 0x01, 0x81, 0x01, 0x01, 0x01, 0xd3, 0x74, 0x01, 0x01, 0x01, 0x0a,
    0x02, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x1e, 0x6c, 0xa4, 0x01, 0x00,
    0x00, 0x0e, 0x01, 0xef, 0x03, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01, 0xed, 0x21, 0x78,
    0x03, 0x00, 0x00, 0x01, 0x2b, 0xd1, 0xff, 0xff, 0x01, 0xed, 0x03, 0x00, 0x00, 0x01, 0xe6, 0x2e,
    0x41, 0xc9, 0x00, 0x00, 0x01, 0x17, 0x0d, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xb5,
    0x0c, 0x02, 0xc6, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x8a, 0x0d, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x06, 0x93, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
];

// dnp3_udp_write.pcap, trame 1 : ecriture d'une heure (g50v1) sur UDP.
const UDP_WRITE: &[u8] = &[
    0x05, 0x64, 0x0e, 0xc4, 0x01, 0x00, 0x64, 0x00, 0xcd, 0x12, 0xcc, 0xce, 0x02, 0x50, 0x01, 0x00,
    0x07, 0x07, 0x00, 0x38, 0x35,
];

// dnp3_link_only.pcap, trame 2 : etat de liaison, sans donnees utilisateur.
const LINK_STATUS: &[u8] = &[
    0x05, 0x64, 0x05, 0x8b, 0x01, 0x00, 0x64, 0x00, 0xa0, 0x97,
];

fn exercise(data: &[u8]) {
    let Ok(packet) = Dnp3Packet::try_from(data) else {
        return;
    };
    assert!(!packet.frames.is_empty());
    let mut covered = 0;
    for frame in &packet.frames {
        assert!(data.as_ptr_range().contains(&frame.raw.as_ptr()));
        assert_eq!(frame.user_data.len(), usize::from(frame.header.length) - 5);
        assert!(frame.user_data.len() <= 250);
        assert_eq!(frame.transport.is_some(), !frame.user_data.is_empty());
        if let Some(application) = &frame.application {
            assert!(frame.transport.is_some_and(|t| t.is_first()));
            let mut end = if application.header.is_response() { 5 } else { 3 };
            for object in &application.objects {
                assert!(object.data.start >= end);
                assert!(object.data.end <= frame.user_data.len());
                let _ = frame.object_data(object);
                end = object.data.end;
            }
            assert!(application.undecoded.start >= end);
            assert_eq!(application.undecoded.end, frame.user_data.len());
        }
        covered += frame.raw.len();
    }
    assert_eq!(covered, data.len());
}

fuzz_target!(|data: &[u8]| {
    exercise(data);

    // Un seul octet altere sur une graine reelle casse un CRC : rejet.
    if let [offset, mask, ..] = data {
        for seed in [READ_REQUEST, RESPONSE, UDP_WRITE, LINK_STATUS] {
            let mut mutated = seed.to_vec();
            let offset = usize::from(*offset) % mutated.len();
            let mask = if *mask == 0 { 0x80 } else { *mask };
            mutated[offset] ^= mask;
            assert!(Dnp3Packet::try_from(mutated.as_slice()).is_err(), "single-byte mutation accepted at {offset}");
        }
    }

    // Deux octets de fuzz choisissent une position et une mutation XOR sur
    // une graine reelle, plusieurs fois : des trames aux CRC casses, et de
    // temps en temps des CRC recalcules par hasard — jamais de panic.
    for seed in [READ_REQUEST, RESPONSE, UDP_WRITE] {
        let mut seeded = seed.to_vec();
        for [offset, mask] in data.as_chunks::<2>().0 {
            let offset = usize::from(*offset) % seeded.len();
            seeded[offset] ^= mask;
        }
        exercise(seeded.as_slice());
    }
});
