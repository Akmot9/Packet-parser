// Fuzz du decodeur RDP (MS-RDPBCGR) : TPKT, COTP X.224, jeton et
// negociation des Connection Request et Confirm, PDU MCS (BER et PER), Send
// Data, plusieurs TPKT par segment et TPKT coupes. Ni panic ni boucle
// infinie ; quand le decodage reussit, les TPKT pavent le segment (le
// dernier eventuellement coupe), et chaque emprunt pointe dans l'entree.
#![no_main]

use libfuzzer_sys::fuzz_target;
use packet_parser::parse::application::protocols::rdp::{RdpPacket, RdpPayload};

// rdp-x509.pcap, trame 6 : Connection Request avec cookie et negociation.
const CONNECTION_REQUEST: &[u8] = &[
    0x03, 0x00, 0x00, 0x2f, 0x2a, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x43, 0x6f, 0x6f, 0x6b, 0x69,
    0x65, 0x3a, 0x20, 0x6d, 0x73, 0x74, 0x73, 0x68, 0x61, 0x73, 0x68, 0x3d, 0x4a, 0x4f, 0x48, 0x4e,
    0x2d, 0x50, 0x43, 0x20, 0x20, 0x0d, 0x0a, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// rdp-x509.pcap, trame 7 : Connection Confirm, securite RDP standard.
const CONNECTION_CONFIRM: &[u8] = &[
    0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00,
    0x00, 0x00, 0x00,
];

// rdp-proprietary-encryption.pcap, trame 21 : Channel Join Confirm (PER).
const CHANNEL_JOIN_CONFIRM: &[u8] = &[
    0x03, 0x00, 0x00, 0x0f, 0x02, 0xf0, 0x80, 0x3e, 0x00, 0x00, 0x07, 0x03, 0xf0, 0x03, 0xf0,
];

// rdp-proprietary-encryption.pcap, trame 32 : tete d'un Send Data Request, TPKT coupe.
const SEND_DATA_HEAD: &[u8] = &[
    0x03, 0x00, 0x00, 0x5e, 0x02, 0xf0, 0x80, 0x64, 0x00, 0x07, 0x03, 0xeb, 0x70, 0x50, 0x01, 0x02,
    0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x8b, 0x68, 0x9c, 0x55, 0xb7, 0xc8, 0x1a, 0x58, 0x75, 0x5f,
    0x62, 0x60, 0x00, 0x69, 0x95, 0xae, 0x78, 0xba, 0xb7,
];

fn exercise(data: &[u8]) {
    let Ok(packet) = RdpPacket::try_from(data) else {
        return;
    };
    assert!(!packet.pdus.is_empty());
    let mut covered = 0;
    for (index, pdu) in packet.pdus.iter().enumerate() {
        let declared = usize::from(pdu.tpkt_length);
        let last = index + 1 == packet.pdus.len();
        if packet.truncated && last {
            assert!(declared > data.len() - covered);
            covered = data.len();
        } else {
            covered += declared;
        }
        match &pdu.payload {
            RdpPayload::ConnectionRequest { token, .. } => {
                if let Some(token) = token {
                    assert!(token.is_empty() || data.as_ptr_range().contains(&token.as_ptr()));
                }
                let _ = pdu.payload.cookie_user();
            }
            RdpPayload::ConnectionConfirm { .. } => {}
            RdpPayload::Mcs(mcs) => {
                assert!(data.as_ptr_range().contains(&mcs.raw.as_ptr()));
                if let Some(send) = mcs.send_data {
                    assert!(send.data.is_empty() || data.as_ptr_range().contains(&send.data.as_ptr()));
                }
            }
            _ => {}
        }
    }
    assert_eq!(covered, data.len());
}

fuzz_target!(|data: &[u8]| {
    exercise(data);

    // Deux octets de fuzz choisissent une position et une mutation XOR sur
    // une graine reelle : en-tetes, jetons, negociations et choix PER sont
    // atteints des le depart.
    for seed in [CONNECTION_REQUEST, CONNECTION_CONFIRM, CHANNEL_JOIN_CONFIRM, SEND_DATA_HEAD] {
        let mut seeded = seed.to_vec();
        for [offset, mask] in data.as_chunks::<2>().0 {
            let offset = usize::from(*offset) % seeded.len();
            seeded[offset] ^= mask;
        }
        exercise(seeded.as_slice());
    }
});
