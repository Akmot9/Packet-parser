// Fuzz du decodeur .NET Message Framing : types d'enregistrement, tailles a
// longueur variable, chaines et enveloppes. Ni panic ni boucle ; quand le
// decodage reussit, les enregistrements pavent le segment, chaque emprunt
// pointe dans l'entree et une enveloppe ne depasse jamais sa taille
// annoncee.
#![no_main]

#[path = "../oracles/seeds.rs"]
mod seeds;

use libfuzzer_sys::fuzz_target;
use packet_parser::parse::application::protocols::nmf::{NmfRecord, NmfSegment};
use seeds::{inside, replay_mutated};

// pcaps_exemple/protocols/nmf/terrain_nmf_censure.pcap, trame 4 : le
// preambule, URI censuree.
const PREAMBLE: &[u8] = &[
    0x00, 0x01, 0x00, 0x01, 0x02, 0x02, 0x29, 0x6e, 0x65, 0x74, 0x2e, 0x74, 0x63, 0x70, 0x3a, 0x2f,
    0x2f, 0x68, 0x6f, 0x73, 0x74, 0x2f, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78,
    0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78,
    0x03, 0x08, 0x0c,
];

// Meme capture, trame 9 : les seize premiers octets d'une enveloppe a
// taille de 779 octets, table de chaines vide.
const ENVELOPE_START: &[u8] = &[
    0x06, 0x8b, 0x06, 0x00, 0x56, 0x02, 0x0b, 0x01, 0x73, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

fn exercise(data: &[u8]) {
    let Ok(segment) = NmfSegment::try_from(data) else {
        return;
    };
    assert_eq!(segment.as_bytes(), data);
    let mut count = 0usize;
    let mut last_truncated = false;
    for record in segment.records() {
        // Rien ne suit une enveloppe que le segment coupe.
        assert!(!last_truncated);
        last_truncated = record.is_truncated();
        count += 1;
        assert!(record.record_type() <= 0x0C);
        match record {
            NmfRecord::SizedEnvelope {
                declared_length,
                payload,
            } => {
                assert!(inside(data, payload));
                assert!(payload.len() <= declared_length as usize);
                // Une enveloppe de taille nulle est refusee.
                assert_ne!(declared_length, 0);
            }
            NmfRecord::Via(text) => {
                assert!(inside(data, text.as_bytes()));
                assert!(!text.is_empty());
            }
            NmfRecord::UnsizedEnvelope { chunks } => assert!(inside(data, chunks)),
            NmfRecord::ExtensibleEncoding(text)
            | NmfRecord::Fault(text)
            | NmfRecord::UpgradeRequest(text) => assert!(inside(data, text.as_bytes())),
            NmfRecord::Version { major, minor } => assert_eq!((major, minor), (1, 0)),
            _ => {}
        }
    }
    // Un enregistrement fait au moins un octet : la suite est finie.
    assert!((1..=data.len()).contains(&count));
}

fuzz_target!(|data: &[u8]| {
    exercise(data);
    replay_mutated(&[PREAMBLE, ENVELOPE_START], data, exercise);
});
