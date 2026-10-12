// Trames Ethernet/IPv4 synthetiques et graines partagees par les cibles de
// fuzz `parse_packetflow` et `policy_dispatch` et par le test de parite
// `tests/fuzz_policy_parity.rs` (issue #108), incluses par `#[path]`.
#![allow(dead_code)] // chaque inclusion n'utilise qu'une partie du module

use packet_parser::parse::transport::protocols::TransportProtocol;

/// TPKT + COTP-DT + S7 Read Var : graine S7Comm historique de
/// `parse_s7comm`, octets synthetiques.
pub const READ_VAR_REQUEST: [u8; 31] = [
    0x03, 0x00, 0x00, 0x1f, 0x02, 0xf0, 0x80, 0x32, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00,
    0x00, 0x04, 0x01, 0x12, 0x0a, 0x10, 0x02, 0x00, 0x40, 0x00, 0x01, 0x84, 0x00, 0x00, 0x00,
];

/// TPKT + COTP CR reel : frame 7 de
/// pcaps_exemple/protocols/s7comm/s7comm_varservice_libnodavedemo.pcap.
pub const COTP_CONNECTION_REQUEST: [u8; 22] = [
    0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xc1, 0x02, 0x01, 0x00, 0xc2,
    0x02, 0x01, 0x02, 0xc0, 0x01, 0x09,
];

/// Graines des oracles texte (issue #66) : une commande complete dont le
/// verbe n'appartient qu'a un seul des trois protocoles. Sans graine, le
/// fuzzer n'atteignait le chemin FTP hors port que par hasard, quatre nuits
/// sur trente-quatre depuis la 10.3.0 (#107).
pub const STOR_COMMAND: &[u8] = b"STOR fichier.bin\r\n";
pub const EHLO_COMMAND: &[u8] = b"EHLO client.example\r\n";
pub const ARTICLE_COMMAND: &[u8] = b"ARTICLE 12345\r\n";

/// Port source par defaut des trames synthetiques : ephemere, hors de toute
/// garde de port de la table.
pub const EPHEMERAL_PORT: u16 = 40_000;

/// Ethernet + IPv4 (sans option, TEST-NET-1 vers TEST-NET-2) + TCP ou UDP,
/// autour de `payload`. Le checksum n'est pas calcule : la crate ne le
/// valide pas.
pub fn ethernet_ipv4_payload(
    transport_protocol: TransportProtocol,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let (ip_protocol, transport_header_length) = match transport_protocol {
        TransportProtocol::Tcp => (6, 20),
        TransportProtocol::Udp => (17, 8),
        _ => unreachable!("les graines ne sont definies que sur TCP et UDP"),
    };
    let ip_total_length = 20 + transport_header_length + payload.len();
    let mut frame = vec![
        0, 1, 2, 3, 4, 5, // destination MAC
        6, 7, 8, 9, 10, 11, // source MAC
        0x08, 0x00, // IPv4 EtherType
        0x45, 0x00, // IPv4 version/IHL, DSCP/ECN
    ];
    frame.extend_from_slice(&(ip_total_length as u16).to_be_bytes());
    frame.extend_from_slice(&[
        0x00,
        0x01, // identification
        0x40,
        0x00, // don't fragment
        64,
        ip_protocol,
        0,
        0, // checksum (not validated)
        192,
        0,
        2,
        1, // TEST-NET-1
        198,
        51,
        100,
        2, // TEST-NET-2
    ]);
    frame.extend_from_slice(&source_port.to_be_bytes());
    frame.extend_from_slice(&destination_port.to_be_bytes());

    match transport_protocol {
        TransportProtocol::Tcp => frame.extend_from_slice(&[
            0, 0, 0, 1, // sequence number
            0, 0, 0, 1, // acknowledgement number
            0x50, 0x18, // data offset, PSH+ACK
            0x20, 0x00, // window
            0, 0, // checksum
            0, 0, // urgent pointer
        ]),
        TransportProtocol::Udp => {
            let udp_length = (8 + payload.len()) as u16;
            frame.extend_from_slice(&udp_length.to_be_bytes());
            frame.extend_from_slice(&[0, 0]); // checksum
        }
        _ => unreachable!(),
    }
    frame.extend_from_slice(payload);
    frame
}

/// Deux octets de fuzz choisissent une position et une mutation XOR : les
/// entrees courtes restent proches d'une graine L2/L3/L4/L7 valide au lieu
/// de detruire Ethernet en premier et de ne jamais atteindre la politique.
pub fn xor_overlay(seed: &mut [u8], data: &[u8]) {
    for [offset, mask] in data.as_chunks::<2>().0 {
        let offset = usize::from(*offset) % seed.len();
        seed[offset] ^= mask;
    }
}
