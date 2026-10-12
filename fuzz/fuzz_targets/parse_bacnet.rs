// Fuzz du decodeur BACnet/IP : BVLC (type, fonction, longueur egale au
// datagramme), Forwarded-NPDU, NPDU (version, controle, adresses, sauts,
// messages reseau) et APDU (types, segmentation, services). Ni panic ni
// boucle infinie ; quand le decodage reussit, la longueur BVLC est celle de
// l'entree et chaque emprunt pointe dans l'entree.
#![no_main]

use libfuzzer_sys::fuzz_target;
use packet_parser::parse::application::protocols::bacnet::{BacnetPacket, NpduMessage};

// iti_bacnet_test.pcap, trame 3 : readProperty unicast.
const READ_PROPERTY: &[u8] = &[
    0x81, 0x0a, 0x00, 0x11, 0x01, 0x04, 0x00, 0x05, 0x01, 0x0c, 0x0c, 0x02, 0x3f, 0xff, 0xff, 0x19,
    0x4b,
];

// iti_bacnet_test.pcap, trame 4 : ComplexACK.
const COMPLEX_ACK: &[u8] = &[
    0x81, 0x0a, 0x00, 0x17, 0x01, 0x00, 0x30, 0x01, 0x0c, 0x0c, 0x02, 0x3f, 0xff, 0xff, 0x19, 0x4b,
    0x3e, 0xc4, 0x02, 0x00, 0x01, 0xf4, 0x3f,
];

// ndpi_bacnet.pcap, trame 10 : Who-Is en broadcast, reseau 65535.
const WHO_IS: &[u8] = &[
    0x81, 0x0b, 0x00, 0x0c, 0x01, 0x20, 0xff, 0xff, 0x00, 0xff, 0x10, 0x08,
];

// ndpi_bacnet.pcap, trame 22 : I-Am-Router-To-Network.
const NETWORK_MESSAGE: &[u8] = &[
    0x81, 0x0b, 0x00, 0x0d, 0x01, 0xa0, 0xff, 0xff, 0x00, 0xff, 0x01, 0x00, 0x00,
];

fn exercise(data: &[u8]) {
    let Ok(packet) = BacnetPacket::try_from(data) else {
        return;
    };
    assert_eq!(usize::from(packet.bvlc.length), data.len());
    assert!(packet.body.is_empty() || data.as_ptr_range().contains(&packet.body.as_ptr()));
    if let Some(npdu) = packet.npdu {
        assert_eq!(npdu.version, 1);
        assert_eq!(npdu.hop_count.is_some(), npdu.destination.is_some());
        let _ = (npdu.expecting_reply(), npdu.priority());
        match npdu.message {
            NpduMessage::Apdu(apdu) => {
                assert!(apdu.apdu_type <= 7);
                assert!(apdu.data.is_empty() || data.as_ptr_range().contains(&apdu.data.as_ptr()));
                let _ = (apdu.confirmed_service(), apdu.unconfirmed_service());
            }
            NpduMessage::Network { message_type, vendor_id, data: body } => {
                assert_eq!(vendor_id.is_some(), message_type >= 0x80);
                assert!(body.is_empty() || data.as_ptr_range().contains(&body.as_ptr()));
            }
            _ => {}
        }
    }
}

fuzz_target!(|data: &[u8]| {
    exercise(data);

    // Deux octets de fuzz choisissent une position et une mutation XOR sur
    // une graine reelle : fonctions, controles, adresses et types d'APDU
    // sont atteints des le depart.
    for seed in [READ_PROPERTY, COMPLEX_ACK, WHO_IS, NETWORK_MESSAGE] {
        let mut seeded = seed.to_vec();
        for [offset, mask] in data.as_chunks::<2>().0 {
            let offset = usize::from(*offset) % seeded.len();
            seeded[offset] ^= mask;
        }
        exercise(seeded.as_slice());
    }
});
