// Fuzz du decodeur Valmet DNA : en-tete (magie, noeud, longueur egale au
// datagramme moins deux, famille), telegramme d'etat de 126 octets (adresse,
// horloge BCD, compteurs), message a etiquette (longueur ecrite deux fois,
// etiquette qui pave le datagramme, accesseurs texte) et balise de 42 octets.
// Ni panic ni boucle infinie ; quand le decodage reussit, les tailles
// recoupent l'entree, l'etiquette et le corps lui sont empruntes, l'horloge
// est dans ses plages, et la sonde aveugle publique (`Application::try_from`)
// dit « Valmet DNA » exactement quand la famille est connue.
#![no_main]

use libfuzzer_sys::fuzz_target;
use packet_parser::Application;
use packet_parser::parse::application::protocols::valmet_dna::{
    DnaClock, MessageKind, TimeBeacon, ValmetDnaMessage, ValmetDnaPacket,
};

// valmet-dna-multicast-anon.pcap, trame 1 : telegramme d'etat du noeud 0x801D.
const STATUS_TELEGRAM: &[u8] = &[
    0xab, 0x01, 0x80, 0x1d, 0x00, 0xff, 0x00, 0x7c, 0x00, 0x00, 0x0f, 0xff, 0x00, 0x10, 0x03, 0xb0,
    0x00, 0x00, 0x04, 0x8a, 0xce, 0x48, 0x18, 0xe0, 0x3d, 0x00, 0x18, 0x80, 0x3f, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x02, 0x01, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
    0x01, 0x01, 0x20, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x01, 0x8a, 0x00, 0x52,
    0xc5, 0x9c, 0x00, 0x00, 0x00, 0x01, 0xef, 0x00, 0xab, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x0f, 0x5b, 0xf1, 0x54, 0x05,
    0x97, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0xd6, 0x09, 0xd6,
];

// Meme capture, trame 9 : message a etiquette du noeud 0x8028, 43 octets de
// classe `di`.
const TAG_MESSAGE: &[u8] = &[
    0xab, 0x01, 0x80, 0x28, 0x00, 0xff, 0x00, 0x71, 0x00, 0x1e, 0x00, 0xd0, 0x00, 0x01, 0x05, 0x06,
    0x0a, 0x3b, 0x00, 0x00, 0x51, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x81, 0xa4, 0x7c, 0x18, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x05, 0xf4, 0xfc, 0xd8, 0x00, 0x00, 0x00, 0x2b, 0x3a, 0x65, 0x3a, 0x64, 0x69, 0x3a, 0x41, 0x4b,
    0x30, 0x35, 0x3a, 0x6e, 0x72, 0x69, 0x73, 0x30, 0x35, 0x3a, 0x6f, 0x69, 0x67, 0x77, 0x78, 0x6a,
    0x30, 0x32, 0x36, 0x3a, 0x6f, 0x69, 0x78, 0x77, 0x67, 0x65, 0x28, 0x32, 0x29, 0x3a, 0x61, 0x77,
    0x63, 0x72, 0x73,
];

// Meme capture, trame 591 : la balise du noeud 10.0.2.9 (UDP 4516 -> 4517).
const BEACON: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0xab, 0xcc, 0x00, 0x06, 0x23, 0x80, 0x00, 0x00, 0x3e, 0x0f, 0x25, 0x27,
    0x02, 0xd8, 0xff, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x86, 0x95, 0x09, 0x00,
    0x00, 0x03, 0x01, 0x01, 0x20, 0x20, 0x0a, 0x00, 0x02, 0x09,
];

// #230 : un en-tete seul, de longueur coherente (10 = 12 - 2) et de famille
// inconnue, est decode avec un corps vide. Entree du fuzz nocturne du
// 2026-11-04, construite et non capturee : elle garde ce cas sous le fuzz.
const HEADER_ONLY: &[u8] = &[
    0xab, 0x01, 0x81, 0x15, 0x0c, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00,
];

fn check_clock(clock: &DnaClock) {
    assert!(clock.fraction <= 9999);
    assert!(clock.second <= 59 && clock.minute <= 59 && clock.hour <= 23);
    assert!(clock.weekday <= 7);
    assert!((1..=31).contains(&clock.day) && (1..=12).contains(&clock.month));
    assert!(clock.year <= 9999);
    assert!(clock.microseconds_of_day() < 24 * 3_600_000_000);
}

fn exercise(data: &[u8]) {
    let known_kind = match ValmetDnaPacket::try_from(data) {
        Ok(packet) => {
            assert_eq!(usize::from(packet.length) + 2, data.len());
            // Le corps est exactement la fin de l'entree, empruntee. Un corps
            // vide pointe sur la fin de `data`, que `as_ptr_range()` exclut :
            // comparer les deux tranches, adresse et longueur (#230).
            assert!(std::ptr::eq(packet.body, &data[12..]));
            assert_eq!(packet.node_number(), (packet.source_node & 0xFF) as u8);
            match packet.message {
                ValmetDnaMessage::Status(status) => {
                    assert_eq!(packet.kind, Some(MessageKind::Status));
                    assert_eq!(data.len(), 126);
                    if let Some(clock) = &status.clock {
                        check_clock(clock);
                    }
                    let _ = (status.node_ip, status.multicast_group, status.node_number);
                    let _ = status.tick.wrapping_sub(status.previous_tick);
                }
                ValmetDnaMessage::Tag(tag) => {
                    assert_eq!(packet.kind, Some(MessageKind::Tag));
                    assert_eq!(72 + tag.tag.len(), data.len());
                    assert_eq!(usize::from(tag.tag_length), tag.tag.len());
                    assert!(tag.tag.is_empty() || data.as_ptr_range().contains(&tag.tag.as_ptr()));
                    if let Some(class) = tag.class() {
                        assert!(!class.is_empty());
                        assert!(tag.path().is_some());
                        assert!(tag.tag_text().is_some());
                    }
                }
                ValmetDnaMessage::Unknown => assert_eq!(packet.kind, None),
                _ => {}
            }
            packet.kind.is_some()
        }
        Err(_) => false,
    };
    // La sonde aveugle publique : « Valmet DNA » si et seulement si la famille
    // est connue (aucune sonde placee avant elle n'accepte un premier octet
    // 0xAB : NTP y lit une version 5, RTPS veut sa magie).
    if !data.is_empty() {
        let blind = Application::try_from(data).expect("payload non vide");
        assert_eq!(blind.application_protocol == "Valmet DNA", known_kind);
    }
    if let Ok(beacon) = TimeBeacon::try_from(data) {
        assert_eq!(data.len(), 42);
        if let Some(clock) = &beacon.clock {
            check_clock(clock);
        }
        let _ = (beacon.code, beacon.counter, beacon.node_ip);
    }
}

fuzz_target!(|data: &[u8]| {
    exercise(data);

    // Deux octets de fuzz choisissent une position et une mutation XOR sur
    // une graine (trois trames reelles, et l'en-tete seul de #230) : en-tete,
    // familles, longueurs, horloge et etiquette sont atteints des le depart.
    for seed in [STATUS_TELEGRAM, TAG_MESSAGE, BEACON, HEADER_ONLY] {
        let mut seeded = seed.to_vec();
        for [offset, mask] in data.as_chunks::<2>().0 {
            let offset = usize::from(*offset) % seeded.len();
            seeded[offset] ^= mask;
        }
        exercise(seeded.as_slice());
    }
});
