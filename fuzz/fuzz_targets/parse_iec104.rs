// Fuzz du decodeur IEC 60870-5-104 : APCI, formats I, S et U, en-tete
// d'ASDU, objets en sequence ou non, tailles d'elements de la norme,
// plusieurs APDU par segment et APDU coupes. Ni panic ni boucle infinie ;
// quand le decodage reussit, les APDU pavent le segment (le dernier
// eventuellement coupe), chaque element emprunte a l'entree, et un ASDU en
// sequence numerote ses objets a la suite.
#![no_main]

use libfuzzer_sys::fuzz_target;
use packet_parser::parse::application::protocols::iec104::{ApciFormat, Iec104Packet};

// wireshark_iec104.pcap, trame 9 : interrogation generale (C_IC_NA_1).
const INTERROGATION: &[u8] = &[
    0x68, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x64, 0x01, 0x06, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x14,
];

// wireshark_IEC104_SQ.pcapng : un ASDU M_SP_NA_1 en sequence de seize objets.
const SEQUENCE: &[u8] = &[
    0x68, 0x1d, 0x02, 0x00, 0x02, 0x00, 0x01, 0x90, 0x14, 0x00, 0x1e, 0x04, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
];

// wireshark_iec104.pcap, trame 7 : STARTDT act.
const STARTDT_ACT: &[u8] = &[
    0x68, 0x04, 0x07, 0x00, 0x00, 0x00,
];

fn exercise(data: &[u8]) {
    let Ok(packet) = Iec104Packet::try_from(data) else {
        return;
    };
    assert!(!packet.apdus.is_empty());
    let mut covered = 0;
    for (index, apdu) in packet.apdus.iter().enumerate() {
        let declared = 2 + usize::from(apdu.length);
        let last = index + 1 == packet.apdus.len();
        if packet.truncated && last {
            assert!(declared > data.len() - covered);
            covered = data.len();
        } else {
            covered += declared;
        }
        match apdu.format {
            ApciFormat::Information { .. } => {
                // Un format I porte un ASDU, sauf coupe par le segment avant
                // la fin de son en-tete.
                let Some(asdu) = apdu.asdu.as_ref() else {
                    assert!(packet.truncated && last);
                    continue;
                };
                assert!(asdu.count >= 1);
                assert!(asdu.objects.len() <= usize::from(asdu.count));
                for (rank, object) in asdu.objects.iter().enumerate() {
                    assert!(
                        object.element.is_empty() || data.as_ptr_range().contains(&object.element.as_ptr())
                    );
                    if asdu.sequence {
                        assert_eq!(object.address, asdu.objects[0].address + rank as u32);
                    }
                }
                assert!(asdu.undecoded.is_empty() || data.as_ptr_range().contains(&asdu.undecoded.as_ptr()));
            }
            ApciFormat::Supervisory { .. } | ApciFormat::Unnumbered(_) => {
                assert_eq!(apdu.length, 4);
                assert!(apdu.asdu.is_none());
            }
            _ => {}
        }
    }
    assert_eq!(covered, data.len());
}

fuzz_target!(|data: &[u8]| {
    exercise(data);

    // Deux octets de fuzz choisissent une position et une mutation XOR sur
    // une graine reelle : controles, en-tetes d'ASDU et comptes d'objets
    // sont atteints des le depart.
    for seed in [INTERROGATION, SEQUENCE, STARTDT_ACT] {
        let mut seeded = seed.to_vec();
        for [offset, mask] in data.as_chunks::<2>().0 {
            let offset = usize::from(*offset) % seeded.len();
            seeded[offset] ^= mask;
        }
        exercise(seeded.as_slice());
    }
});
