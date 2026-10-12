// Fuzz du point d'entree principal : aucun octet hostile ne doit provoquer
// de panic, seulement Ok(_) ou Err(_). Rien d'autre n'est verifie ici : les
// invariants de politique (FTP, SMTP et NNTP hors port, S7Comm, COTP, Decode
// As) vivent dans `policy_dispatch` (issue #108). Un oracle perime n'arrete
// plus cette cible, et son corpus de la nuit n'est plus perdu avec lui.
#![no_main]

#[path = "../oracles/frames.rs"]
mod frames;

use frames::{
    ARTICLE_COMMAND, COTP_CONNECTION_REQUEST, EHLO_COMMAND, EPHEMERAL_PORT, READ_VAR_REQUEST,
    STOR_COMMAND, ethernet_ipv4_payload, xor_overlay,
};
use libfuzzer_sys::fuzz_target;
use packet_parser::{
    DecodeAsProtocol, LinkType, PacketFlow, ParseConfig,
    parse::transport::protocols::TransportProtocol, parse_with,
};

/// Tous les protocoles declarables par l'appelant (Decode As, issue #65),
/// dans l'ordre de l'enum : le premier octet de l'entree en choisit un.
const DECODE_AS_PROTOCOLS: [DecodeAsProtocol; 24] = [
    DecodeAsProtocol::Ftp,
    DecodeAsProtocol::Smtp,
    DecodeAsProtocol::Nntp,
    DecodeAsProtocol::Cotp,
    DecodeAsProtocol::Dns,
    DecodeAsProtocol::Mdns,
    DecodeAsProtocol::Llmnr,
    DecodeAsProtocol::Ssdp,
    DecodeAsProtocol::Nbns,
    DecodeAsProtocol::Nbss,
    DecodeAsProtocol::Snmp,
    DecodeAsProtocol::Dhcpv6,
    DecodeAsProtocol::OpcUa,
    DecodeAsProtocol::PostgreSql,
    DecodeAsProtocol::ModbusTcp,
    DecodeAsProtocol::EthernetIp,
    DecodeAsProtocol::Ams,
    DecodeAsProtocol::QuicShortHeader,
    DecodeAsProtocol::OpenVpn,
    DecodeAsProtocol::Ptp,
    DecodeAsProtocol::Stanag5066,
    DecodeAsProtocol::Dis,
    DecodeAsProtocol::Ike,
    DecodeAsProtocol::Esp,
];

/// Les trois premiers octets de l'entree choisissent une configuration
/// Decode As (un protocole, un port) ; `parse_with` n'etait fuzze par
/// aucune cible avant #108.
fn decode_as_config(data: &[u8]) -> ParseConfig {
    let protocol = DECODE_AS_PROTOCOLS
        [usize::from(data.first().copied().unwrap_or(0)) % DECODE_AS_PROTOCOLS.len()];
    let port = u16::from_be_bytes([
        data.get(1).copied().unwrap_or(0),
        data.get(2).copied().unwrap_or(0),
    ]);
    ParseConfig::new().decode_as(port, protocol)
}

fn exercise(data: &[u8], config: &ParseConfig) {
    if let Ok(flow) = PacketFlow::try_from(data) {
        // Exerce aussi les chemins de conversion et d'aplatissement.
        // `to_owned_flow`, pas `to_owned` : depuis a488065, ce dernier n'est
        // plus que le `Clone` de `ToOwned`.
        let _ = flow.to_owned_flow();
        let _ = flow.flatten();
    }
    if let Ok(flow) = parse_with(LinkType::ETHERNET, data, config) {
        let _ = flow.flatten();
    }
}

fuzz_target!(|data: &[u8]| {
    let config = decode_as_config(data);
    exercise(data, &config);

    // Les graines gardent le fuzzer pres de chemins L2/L3/L4/L7 profonds :
    // S7Comm et COTP sur leur port et hors port, TCP et UDP ; une commande
    // propre a chacun des trois protocoles texte hors port, sur un port de
    // la famille, et sur UDP.
    let seeds: [(TransportProtocol, u16, &[u8]); 11] = [
        (TransportProtocol::Tcp, 102, &READ_VAR_REQUEST),
        (TransportProtocol::Udp, 102, &READ_VAR_REQUEST),
        (TransportProtocol::Tcp, 102, &COTP_CONNECTION_REQUEST),
        (TransportProtocol::Tcp, 10_102, &COTP_CONNECTION_REQUEST),
        (TransportProtocol::Udp, 102, &COTP_CONNECTION_REQUEST),
        (TransportProtocol::Tcp, 5_000, STOR_COMMAND),
        (TransportProtocol::Tcp, 25, STOR_COMMAND),
        (TransportProtocol::Udp, 5_000, STOR_COMMAND),
        (TransportProtocol::Tcp, 5_000, EHLO_COMMAND),
        (TransportProtocol::Tcp, 119, EHLO_COMMAND),
        (TransportProtocol::Tcp, 5_000, ARTICLE_COMMAND),
    ];
    for (protocol, destination_port, payload) in seeds {
        let mut seeded = ethernet_ipv4_payload(protocol, EPHEMERAL_PORT, destination_port, payload);
        xor_overlay(seeded.as_mut_slice(), data);
        exercise(seeded.as_slice(), &config);
    }
});
