// Fuzz du point d'entrée principal : aucun octet hostile ne doit provoquer
// de panic, seulement Ok(_) ou Err(_).
#![no_main]

use libfuzzer_sys::fuzz_target;
use packet_parser::{PacketFlow, parse::transport::protocols::TransportProtocol};

const READ_VAR_REQUEST: [u8; 31] = [
    0x03, 0x00, 0x00, 0x1f, 0x02, 0xf0, 0x80, 0x32, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00,
    0x00, 0x04, 0x01, 0x12, 0x0a, 0x10, 0x02, 0x00, 0x40, 0x00, 0x01, 0x84, 0x00, 0x00, 0x00,
];

// TPKT + COTP CR reel : frame 7 de
// pcaps_exemple/protocols/s7comm/s7comm_varservice_libnodavedemo.pcap.
const COTP_CONNECTION_REQUEST: [u8; 22] = [
    0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xc1, 0x02, 0x01, 0x00, 0xc2,
    0x02, 0x01, 0x02, 0xc0, 0x01, 0x09,
];

fn ethernet_ipv4_payload(
    transport_protocol: TransportProtocol,
    destination_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let (ip_protocol, transport_header_length) = match transport_protocol {
        TransportProtocol::Tcp => (6, 20),
        TransportProtocol::Udp => (17, 8),
        _ => unreachable!("S7 seed transport must be TCP or UDP"),
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
    frame.extend_from_slice(&40_000_u16.to_be_bytes());
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

fn application_protocol(frame: &[u8]) -> Option<&'static str> {
    PacketFlow::try_from(frame)
        .expect("la graine Ethernet structuree doit rester analysable")
        .application
        .map(|application| application.application_protocol)
}

fn xor_overlay(seed: &mut [u8], data: &[u8]) {
    // Two fuzz bytes choose an arbitrary frame offset and an XOR mutation.
    // This keeps short inputs close to the valid L2/L3/L4/L7 seed instead of
    // destroying Ethernet first and never reaching the S7 transport policy.
    for mutation in data.chunks_exact(2) {
        let offset = usize::from(mutation[0]) % seed.len();
        seed[offset] ^= mutation[1];
    }
}

fn exercise(data: &[u8]) {
    if let Ok(flow) = PacketFlow::try_from(data) {
        // FTP est volontairement garde par TCP/21 : le fuzzer doit aussi
        // proteger cet invariant semantique, pas seulement l'absence de panic.
        for parsed_flow in flow.flatten() {
            let application_protocol = parsed_flow
                .application
                .as_ref()
                .map(|application| application.application_protocol);

            match application_protocol {
                Some("FTP") => {
                    let transport = parsed_flow
                        .transport
                        .as_ref()
                        .expect("FTP doit toujours posseder une couche transport");
                    assert_eq!(transport.protocol, TransportProtocol::Tcp);
                    assert!(
                        transport.source_port == Some(21) || transport.destination_port == Some(21),
                        "FTP ne doit jamais etre detecte hors de TCP/21"
                    );
                }
                Some("S7Comm") => {
                    let transport = parsed_flow
                        .transport
                        .as_ref()
                        .expect("S7Comm doit toujours posseder une couche transport");
                    assert_eq!(
                        transport.protocol,
                        TransportProtocol::Tcp,
                        "S7Comm ne doit jamais etre detecte hors de TCP"
                    );
                }
                Some("COTP") => {
                    let transport = parsed_flow
                        .transport
                        .as_ref()
                        .expect("COTP doit toujours posseder une couche transport");
                    assert_eq!(transport.protocol, TransportProtocol::Tcp);
                    assert!(
                        transport.source_port == Some(102)
                            || transport.destination_port == Some(102),
                        "COTP doit rester garde par TCP/102"
                    );
                }
                _ => {}
            }
        }

        // Exerce aussi les chemins de conversion et d'aplatissement.
        let _ = flow.to_owned();
        let _ = flow.flatten();
    }
}

fuzz_target!(|data: &[u8]| {
    exercise(data);

    // A genuine Ethernet/IPv4/TCP/S7 frame reaches the positive invariant;
    // the same application payload over UDP exercises the rejection path.
    for protocol in [TransportProtocol::Tcp, TransportProtocol::Udp] {
        let mut seeded = ethernet_ipv4_payload(protocol, 102, &READ_VAR_REQUEST);
        xor_overlay(seeded.as_mut_slice(), data);
        exercise(seeded.as_slice());
    }

    // COTP n'est annonce que pour une enveloppe TPKT valide sur TCP/102. Les
    // memes octets applicatifs sur UDP ou hors du port ISO-TSAP sont des
    // oracles negatifs explicites contre les faux positifs.
    let cotp_tcp_102 = ethernet_ipv4_payload(TransportProtocol::Tcp, 102, &COTP_CONNECTION_REQUEST);
    assert_eq!(application_protocol(&cotp_tcp_102), Some("COTP"));

    let cotp_tcp_off_port =
        ethernet_ipv4_payload(TransportProtocol::Tcp, 10_102, &COTP_CONNECTION_REQUEST);
    assert_ne!(application_protocol(&cotp_tcp_off_port), Some("COTP"));

    let cotp_udp_102 = ethernet_ipv4_payload(TransportProtocol::Udp, 102, &COTP_CONNECTION_REQUEST);
    assert_ne!(application_protocol(&cotp_udp_102), Some("COTP"));

    for (protocol, destination_port) in [
        (TransportProtocol::Tcp, 102),
        (TransportProtocol::Tcp, 10_102),
        (TransportProtocol::Udp, 102),
    ] {
        let mut seeded =
            ethernet_ipv4_payload(protocol, destination_port, &COTP_CONNECTION_REQUEST);
        xor_overlay(seeded.as_mut_slice(), data);
        exercise(seeded.as_slice());
    }
});
