// Fuzz du decodeur DIS (IEEE 1278.1) : en-tete, soixante-douze types de
// PDU, corps Entity State, Transmitter et Signal, plusieurs PDU par
// datagramme, lecture stricte et tolerante. Ni panic ni boucle infinie ;
// quand le decodage reussit, les PDU et le reste pavent exactement
// l'entree, chaque corps emprunte a l'entree, et la lecture stricte n'accepte
// qu'un sous-ensemble de la lecture tolerante.
#![no_main]

use libfuzzer_sys::fuzz_target;
use packet_parser::parse::application::protocols::dis::{DisBody, DisPacket};

// wireshark_12043_dis_v7_transmitter.pcap, trame 1 : Transmitter DIS v7.
const V7_TRANSMITTER: &[u8] = &[
    0x07, 0x01, 0x19, 0x04, 0x7b, 0x32, 0x78, 0xcf, 0x00, 0x68, 0x00, 0x00, 0xfa, 0x80, 0xf0, 0x1b,
    0xff, 0xfe, 0xff, 0xfe, 0x07, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x05, 0xf5, 0xe1, 0x00, 0x46, 0xc3, 0x50, 0x00, 0xc3, 0x87, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// dis_voice_sample.pcap, trame 29 : tete d'un Signal DIS v6 (1 024 octets de
// donnees a suivre, remplaces par des zeros dans la graine).
const V6_SIGNAL_HEAD: &[u8] = &[
    0x06, 0x01, 0x1a, 0x04, 0x00, 0x02, 0xbb, 0x0e, 0x04, 0x20, 0x00, 0x00, 0x7d, 0xfd, 0x00, 0xfd,
    0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x1f, 0x40, 0x20, 0x00, 0x04, 0x00,
];

fn exercise(data: &[u8]) {
    let lenient = DisPacket::try_from_lenient(data);
    let strict = DisPacket::try_from(data);
    if strict.is_ok() {
        assert!(lenient.is_ok(), "la lecture stricte implique la tolerante");
    }
    let Ok(packet) = lenient else {
        assert!(strict.is_err());
        return;
    };
    assert!(!packet.pdus.is_empty());
    let mut covered = 0;
    for pdu in &packet.pdus {
        assert_eq!(pdu.raw.len(), usize::from(pdu.header.length));
        assert!(data.as_ptr_range().contains(&pdu.raw.as_ptr()));
        assert!((1..=7).contains(&pdu.header.protocol_version));
        assert!((1..=72).contains(&pdu.header.pdu_type));
        match pdu.body {
            DisBody::Signal { data: samples, .. } => {
                assert!(samples.is_empty() || data.as_ptr_range().contains(&samples.as_ptr()));
            }
            DisBody::EntityState {
                variable_parameters,
                variable_parameter_count,
                ..
            } => {
                assert_eq!(
                    variable_parameters.len(),
                    usize::from(variable_parameter_count) * 16
                );
            }
            DisBody::Opaque(body) => {
                assert!(body.is_empty() || data.as_ptr_range().contains(&body.as_ptr()));
            }
            _ => {}
        }
        covered += pdu.raw.len();
    }
    assert_eq!(covered + packet.trailing.len(), data.len());
    assert_eq!(strict.is_ok(), packet.trailing.is_empty());
}

fuzz_target!(|data: &[u8]| {
    exercise(data);

    // Deux octets de fuzz choisissent une position et une mutation XOR sur
    // une graine reelle : en-tetes, corps types et longueurs sont atteints
    // des le depart.
    let mut signal = V6_SIGNAL_HEAD.to_vec();
    signal.resize(1056, 0);
    for seed in [V7_TRANSMITTER, signal.as_slice()] {
        let mut seeded = seed.to_vec();
        for [offset, mask] in data.as_chunks::<2>().0 {
            let offset = usize::from(*offset) % seeded.len();
            seeded[offset] ^= mask;
        }
        exercise(seeded.as_slice());
    }
});
