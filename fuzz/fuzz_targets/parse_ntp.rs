// Fuzz du decodeur NTP : octet LI/VN/Mode, stratum, reference selon le
// stratum, quatre horodatages de 64 bits convertis en dates. Ni panic ni
// boucle (les conversions de dates comprises) ; quand le decodage reussit,
// les champs sont ceux du fil, la forme de la reference est celle que le
// stratum impose, et l'affichage de la reference ne panique pas.
#![no_main]

#[path = "../oracles/seeds.rs"]
mod seeds;

use libfuzzer_sys::fuzz_target;
use packet_parser::parse::application::protocols::ntp::{NtpPacket, Refid};
use seeds::replay_mutated;

// ndpi_NTPv4.pcap, trame 1 : NTPv4, mode client.
const CLIENT_V4: &[u8] = &[
    0x23, 0x02, 0x07, 0xeb, 0x00, 0x00, 0x04, 0x50, 0x00, 0x00, 0x03, 0xab, 0x83, 0xbc, 0x03, 0xdf,
    0xd9, 0x4f, 0x51, 0xc3, 0x31, 0x65, 0xb8, 0x60, 0xd9, 0x44, 0x57, 0x55, 0x30, 0x33, 0x6f, 0xd0,
    0xd9, 0x44, 0x57, 0x55, 0x31, 0xb4, 0xe9, 0x78, 0xd9, 0x4f, 0x51, 0xf4, 0x2d, 0x26, 0xe2, 0xf4,
];

// ndpi_NTPv3.pcap, trame 1 : NTPv3, mode serveur.
const SERVER_V3: &[u8] = &[
    0x1c, 0x00, 0x04, 0xfa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xd9, 0x4f, 0x4f, 0x11, 0x00, 0x00, 0x00, 0x00, 0xd9, 0x4f, 0x4f, 0x11, 0x00, 0x00, 0x00, 0x00,
];

fn exercise(data: &[u8]) {
    let Ok(packet) = NtpPacket::try_from(data) else {
        return;
    };
    assert!(data.len() >= 48);
    let (leap, version, mode) = packet.flags;
    assert_eq!(leap << 6 | version << 3 | mode, data[0]);
    assert!((1..=4).contains(&version) && (1..=5).contains(&mode));
    assert_eq!([packet.stratum, packet.poll], data[1..3]);
    assert_eq!(packet.poll_exponent().to_be_bytes(), [data[2]]);
    assert_eq!(packet.precision.to_be_bytes(), [data[3]]);
    assert_eq!(packet.root_delay.to_be_bytes(), data[4..8]);
    assert_eq!(packet.root_dispersion.to_be_bytes(), data[8..12]);
    match &packet.reference_id {
        Refid::KissCode(bytes) => {
            assert_eq!(packet.stratum, 0);
            assert_eq!(bytes[..], data[12..16]);
        }
        Refid::ClockSource(bytes) => {
            assert_eq!(packet.stratum, 1);
            assert_eq!(bytes[..], data[12..16]);
        }
        Refid::Ipv4(address) => {
            assert!((2..=15).contains(&packet.stratum));
            assert_eq!(address.octets(), data[12..16]);
        }
        _ => {}
    }
    let _ = (packet.reference_id.code(), packet.reference_id.to_string());
}

fuzz_target!(|data: &[u8]| {
    exercise(data);
    replay_mutated(&[CLIENT_V4, SERVER_V3], data, exercise);
});
