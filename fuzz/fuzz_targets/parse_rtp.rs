// Fuzz du decodeur RTP : en-tete fixe, liste CSRC, extension d'en-tete et
// bourrage. Ni panic ni boucle ; quand le decodage reussit, les champs sont
// ceux du fil, chaque emprunt pointe dans l'entree, et l'en-tete, la liste
// CSRC, l'extension, la charge et le bourrage pavent le datagramme.
#![no_main]

#[path = "../oracles/seeds.rs"]
mod seeds;

use libfuzzer_sys::fuzz_target;
use packet_parser::parse::application::protocols::rtp::{RTP_FIXED_HEADER_LENGTH, RtpPacket};
use seeds::{inside, replay_mutated};

// The-Ultimate-PCAP.pcapng, trame 47167 : type dynamique 104, extension
// d'en-tete RFC 8285 de deux mots.
const WITH_EXTENSION: &[u8] = &[
    0x90, 0x68, 0x1b, 0x67, 0xee, 0xda, 0x89, 0xf3, 0x12, 0xd4, 0xa9, 0x22, 0xbe, 0xde, 0x00, 0x02,
    0x22, 0x5e, 0x16, 0x5f, 0x31, 0x00, 0x35, 0x00, 0xe7, 0x2e, 0xf3, 0x97, 0x80, 0xd6, 0xe8, 0xc0,
    0x67, 0xf7, 0x56, 0x66, 0x1a, 0xb7, 0xd6, 0x9e, 0x7d, 0xce, 0x95, 0x00, 0x51, 0xe3, 0x16, 0xbf,
    0x82, 0x63, 0xc6, 0x80, 0xd8, 0x4e, 0x12, 0xc8, 0x54, 0x8f, 0x2b, 0x5b, 0x5e, 0xd1, 0x83, 0xcd,
    0xd7, 0xf3, 0x8b, 0xc4, 0x1f, 0x70, 0x50, 0x63, 0x93, 0xbb, 0xd7, 0xe2, 0x82,
];

// ndpi_line.pcap, trame 10 : evenement telephonique, marqueur leve,
// extension vide.
const TELEPHONE_EVENT: &[u8] = &[
    0x90, 0xe5, 0x00, 0x02, 0x00, 0x00, 0x2e, 0x03, 0x09, 0xbd, 0xa6, 0x74, 0x02, 0x40, 0x00, 0x00,
    0x08, 0x5e, 0x5c, 0x18, 0x63, 0x65, 0xe5, 0x2a, 0x61, 0x0b, 0xb4, 0x27, 0x43, 0x9e, 0x31, 0x64,
    0xa6, 0x3e, 0xff, 0x10,
];

fn exercise(data: &[u8]) {
    let Ok(packet) = RtpPacket::try_from(data) else {
        return;
    };
    assert_eq!(packet.version, 2);
    assert_eq!(data[0] >> 6, 2);
    assert_eq!(packet.csrc.len(), usize::from(data[0] & 0x0F));
    assert_eq!(packet.extension.is_some(), data[0] & 0x10 != 0);
    assert_eq!(packet.padding_length != 0, data[0] & 0x20 != 0);
    assert_eq!(u8::from(packet.marker) << 7 | packet.payload_type, data[1]);
    assert!(!(72..=76).contains(&packet.payload_type));
    assert_eq!(packet.sequence_number.to_be_bytes(), data[2..4]);
    assert_eq!(packet.timestamp.to_be_bytes(), data[4..8]);
    assert_eq!(packet.ssrc.to_be_bytes(), data[8..12]);

    assert!(inside(data, packet.csrc.as_bytes()));
    assert_eq!(packet.csrc.iter().count(), packet.csrc.len());
    assert_eq!(packet.csrc.is_empty(), packet.csrc.len() == 0);
    let extension = packet.extension.map_or(0, |extension| {
        assert!(inside(data, extension.data));
        assert_eq!(extension.data.len() % 4, 0);
        4 + extension.data.len()
    });
    assert!(inside(data, packet.payload));
    assert_eq!(
        RTP_FIXED_HEADER_LENGTH
            + packet.csrc.as_bytes().len()
            + extension
            + packet.payload.len()
            + usize::from(packet.padding_length),
        data.len()
    );
    if packet.padding_length != 0 {
        assert_eq!(data[data.len() - 1], packet.padding_length);
    }
    let _ = packet.static_payload_name();
}

fuzz_target!(|data: &[u8]| {
    exercise(data);
    replay_mutated(&[WITH_EXTENSION, TELEPHONE_EVENT], data, exercise);
});
