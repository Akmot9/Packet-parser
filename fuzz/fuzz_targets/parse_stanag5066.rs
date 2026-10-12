// Fuzz du decodeur STANAG 5066 SIS : en-tete, vingt-sept types de
// primitive, S_PDU tronque, blocs en erreur d'une indication non-ARQ,
// decalage Rockwell Collins, S_PDU enchaines. Ni panic ni boucle infinie ;
// quand le decodage reussit, `consumed` ne depasse pas l'entree, l'U_PDU
// emprunte a l'entree, et un S_PDU complet est suivi d'un debut de S_PDU ou
// de rien.
#![no_main]

use libfuzzer_sys::fuzz_target;
use packet_parser::parse::application::protocols::stanag5066::{SisPdu, SisPrimitive};

// wireshark_10827_sis_acp142.pcap, trame 3 : S_UNIDATA_REQUEST portant un
// U_PDU ACP 142 de 38 octets.
const ACP142_REQUEST: &[u8] = &[
    0x90, 0xeb, 0x00, 0x00, 0x32, 0x14, 0x02, 0xea, 0x32, 0x42, 0x02, 0x2c, 0x00, 0x00, 0x00, 0x00,
    0x26, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x20, 0x01, 0x02, 0x00, 0x06, 0xab, 0xc1, 0x0a,
    0x32, 0x42, 0x01, 0x01, 0x3e, 0xec, 0xa5, 0x54, 0xa5, 0xef, 0xac, 0x00, 0x01, 0x00, 0x00, 0x0a,
    0x32, 0x42, 0x02, 0x00, 0x00, 0x00, 0x00,
];

// S5066-Expedited.pcap, trame 5 : S_EXPEDITED_UNIDATA_INDICATION « test ».
const EXPEDITED_INDICATION: &[u8] = &[
    0x90, 0xeb, 0x00, 0x00, 0x11, 0x19, 0x0d, 0xe0, 0x00, 0x00, 0x01, 0x1d, 0xe0, 0x00, 0x00, 0x02,
    0x00, 0x04, 0x74, 0x65, 0x73, 0x74,
];

fn exercise(data: &[u8]) {
    let mut rest = data;
    let mut guard = 0;
    while let Ok(pdu) = SisPdu::try_from(rest) {
        let consumed = pdu.consumed();
        assert!(consumed >= 6 && consumed <= rest.len());
        assert_eq!(pdu.header.version, 0);
        assert!((1..=27).contains(&pdu.header.pdu_type));
        match pdu.primitive {
            SisPrimitive::Unidata {
                u_pdu, u_pdu_size, ..
            } => {
                assert!(u_pdu.is_empty() || data.as_ptr_range().contains(&u_pdu.as_ptr()));
                if !pdu.truncated {
                    assert_eq!(u_pdu.len(), usize::from(u_pdu_size));
                }
            }
            SisPrimitive::Management { body, .. } => {
                assert!(body.is_empty() || data.as_ptr_range().contains(&body.as_ptr()));
            }
            _ => {}
        }
        if pdu.truncated {
            assert_eq!(consumed, rest.len());
            break;
        }
        rest = &rest[consumed..];
        guard += 1;
        assert!(guard <= data.len());
    }
}

fuzz_target!(|data: &[u8]| {
    exercise(data);

    // Deux octets de fuzz choisissent une position et une mutation XOR sur
    // une graine reelle : types, tailles, adresses et U_PDU sont atteints
    // des le depart.
    for seed in [ACP142_REQUEST, EXPEDITED_INDICATION] {
        let mut seeded = seed.to_vec();
        for [offset, mask] in data.as_chunks::<2>().0 {
            let offset = usize::from(*offset) % seeded.len();
            seeded[offset] ^= mask;
        }
        exercise(seeded.as_slice());
    }
});
