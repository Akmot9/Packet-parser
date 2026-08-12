// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Parseur ICMPv6 (IPv6 next header 58, RFC 4443 et RFC 4861).
//!
//! ICMPv6 reprend la forme d'en-tete d'ICMPv4 mais pas sa numerotation : 128
//! est un Echo request la ou 8 l'est en v4, et les types 133 a 137 portent la
//! decouverte de voisins, qui n'a pas d'equivalent v4. Les deux parseurs sont
//! donc separes et joignables uniquement par leur numero de protocole IP.

use std::convert::TryFrom;
use std::net::Ipv6Addr;

use crate::{
    checks::transport::icmpv6::{
        ICMPV6_ECHO_HEADER_LENGTH, ICMPV6_ERROR_HEADER_LENGTH, ICMPV6_HEADER_LENGTH,
        ICMPV6_NEIGHBOR_HEADER_LENGTH, extract_icmpv6_code, validate_icmpv6_echo_length,
        validate_icmpv6_error_length, validate_icmpv6_min_length, validate_icmpv6_neighbor_length,
    },
    errors::transport::icmpv6::Icmpv6Error,
};

/// Types de message ICMPv6 interpretes (registre IANA « ICMPv6 Parameters »).
const DESTINATION_UNREACHABLE_TYPE: u8 = 1;
const PACKET_TOO_BIG_TYPE: u8 = 2;
const TIME_EXCEEDED_TYPE: u8 = 3;
const PARAMETER_PROBLEM_TYPE: u8 = 4;
const ECHO_REQUEST_TYPE: u8 = 128;
const ECHO_REPLY_TYPE: u8 = 129;
const NEIGHBOR_SOLICITATION_TYPE: u8 = 135;
const NEIGHBOR_ADVERTISEMENT_TYPE: u8 = 136;

/// Corps d'un message Echo (types 128 et 129).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmpv6Echo<'a> {
    pub identifier: u16,
    pub sequence_number: u16,
    pub data: &'a [u8],
}

/// Corps d'un message d'erreur (types 1 a 4) : quatre octets dependant du
/// type, puis le debut du paquet qui a provoque l'erreur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmpv6ErrorReport<'a> {
    /// Inutilise pour Destination Unreachable, porte le MTU pour Packet Too
    /// Big et le pointeur pour Parameter Problem : laisse brut.
    pub rest_of_header: u32,
    /// Paquet invoquant cite par l'emetteur, zero-copy.
    pub invoking_packet: &'a [u8],
}

/// Neighbor Solicitation (type 135, RFC 4861 §4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmpv6NeighborSolicitation<'a> {
    /// Adresse dont on cherche l'adresse de liaison.
    pub target_address: Ipv6Addr,
    /// Options NDP brutes (souvent Source Link-Layer Address), zero-copy.
    pub options: &'a [u8],
}

/// Neighbor Advertisement (type 136, RFC 4861 §4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmpv6NeighborAdvertisement<'a> {
    /// L'emetteur est un routeur.
    pub router: bool,
    /// Reponse a une sollicitation, par opposition a une annonce spontanee.
    pub solicited: bool,
    /// L'entree du cache de voisinage doit etre ecrasee.
    pub overrides: bool,
    pub target_address: Ipv6Addr,
    /// Options NDP brutes (souvent Target Link-Layer Address), zero-copy.
    pub options: &'a [u8],
}

/// Corps ICMPv6, choisi selon le type de message.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Icmpv6Body<'a> {
    Echo(Icmpv6Echo<'a>),
    Error(Icmpv6ErrorReport<'a>),
    NeighborSolicitation(Icmpv6NeighborSolicitation<'a>),
    NeighborAdvertisement(Icmpv6NeighborAdvertisement<'a>),
    /// Type non interprete : octets bruts apres l'en-tete commun.
    Other(&'a [u8]),
}

#[cfg_attr(all(doc, feature = "doc-diagrams"), aquamarine::aquamarine)]
/// Message ICMPv6 (RFC 4443).
///
/// L'en-tete commun tient en quatre octets ; la suite depend du type. Le
/// schema montre un Neighbor Solicitation, le cas le plus structure.
///
/// ```mermaid
/// ---
/// title: Icmpv6Packet (corps Neighbor Solicitation)
/// ---
/// packet-beta
/// 0-7: "Type u8"
/// 8-15: "Code u8"
/// 16-31: "Checksum u16"
/// 32-63: "Reserved u32"
/// 64-191: "Target Address 128 bits"
/// 192-223: "Options variable"
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmpv6Packet<'a> {
    pub message_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub body: Icmpv6Body<'a>,
}

/// Lit l'adresse cible des messages de decouverte de voisins.
///
/// L'appelant doit avoir passe [`validate_icmpv6_neighbor_length`] : les 16
/// octets sont alors garantis presents, ce qui rend la conversion infaillible.
fn target_address(payload: &[u8]) -> Ipv6Addr {
    let mut octets = [0_u8; 16];
    octets.copy_from_slice(&payload[8..ICMPV6_NEIGHBOR_HEADER_LENGTH]);
    Ipv6Addr::from(octets)
}

impl<'a> TryFrom<&'a [u8]> for Icmpv6Packet<'a> {
    type Error = Icmpv6Error;

    fn try_from(payload: &'a [u8]) -> Result<Self, Icmpv6Error> {
        validate_icmpv6_min_length(payload)?;

        let message_type = payload[0];
        let code = extract_icmpv6_code(message_type, payload[1])?;
        let checksum = u16::from_be_bytes([payload[2], payload[3]]);

        let body = match message_type {
            ECHO_REQUEST_TYPE | ECHO_REPLY_TYPE => {
                validate_icmpv6_echo_length(payload)?;
                Icmpv6Body::Echo(Icmpv6Echo {
                    identifier: u16::from_be_bytes([payload[4], payload[5]]),
                    sequence_number: u16::from_be_bytes([payload[6], payload[7]]),
                    data: &payload[ICMPV6_ECHO_HEADER_LENGTH..],
                })
            }
            DESTINATION_UNREACHABLE_TYPE
            | PACKET_TOO_BIG_TYPE
            | TIME_EXCEEDED_TYPE
            | PARAMETER_PROBLEM_TYPE => {
                validate_icmpv6_error_length(payload)?;
                Icmpv6Body::Error(Icmpv6ErrorReport {
                    rest_of_header: u32::from_be_bytes([
                        payload[4], payload[5], payload[6], payload[7],
                    ]),
                    invoking_packet: &payload[ICMPV6_ERROR_HEADER_LENGTH..],
                })
            }
            NEIGHBOR_SOLICITATION_TYPE => {
                validate_icmpv6_neighbor_length(payload)?;
                Icmpv6Body::NeighborSolicitation(Icmpv6NeighborSolicitation {
                    target_address: target_address(payload),
                    options: &payload[ICMPV6_NEIGHBOR_HEADER_LENGTH..],
                })
            }
            NEIGHBOR_ADVERTISEMENT_TYPE => {
                validate_icmpv6_neighbor_length(payload)?;
                // RFC 4861 §4.4 : les trois bits de poids fort du champ qui
                // suit le checksum portent Router, Solicited et Override.
                let flags = payload[4];
                Icmpv6Body::NeighborAdvertisement(Icmpv6NeighborAdvertisement {
                    router: flags & 0b1000_0000 != 0,
                    solicited: flags & 0b0100_0000 != 0,
                    overrides: flags & 0b0010_0000 != 0,
                    target_address: target_address(payload),
                    options: &payload[ICMPV6_NEIGHBOR_HEADER_LENGTH..],
                })
            }
            _ => Icmpv6Body::Other(&payload[ICMPV6_HEADER_LENGTH..]),
        };

        Ok(Icmpv6Packet {
            message_type,
            code,
            checksum,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trame 1 : Neighbor Solicitation pour 2001:db8:1:2::1000, avec option
    /// Source Link-Layer Address
    /// (pcaps_exemple/protocols/icmp/icmpv6_neighbor_solicitation.pcapng).
    const NEIGHBOR_SOLICITATION: &str =
        "870044b70000000020010db80001000200000000000010000101000c292f8031";

    /// Trame 2 : Neighbor Advertisement, flags solicited + override
    /// (meme capture).
    const NEIGHBOR_ADVERTISEMENT: &str =
        "88008beb6000000020010db80001000200000000000010000201000c291fa755";

    /// Trame 4 : Echo request, id 0xeaf5 seq 2 (meme capture).
    const ECHO_REQUEST: &str = concat!(
        "80009ed1eaf50002d588065400000000d3900c00000000001011121314151617",
        "18191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"
    );

    fn bytes(hex_fixture: &str) -> Vec<u8> {
        hex::decode(hex_fixture).expect("invalid test hex fixture")
    }

    #[test]
    fn parses_neighbor_solicitation_from_capture() {
        let raw = bytes(NEIGHBOR_SOLICITATION);
        let packet = Icmpv6Packet::try_from(raw.as_slice()).expect("captured NS parses");

        assert_eq!(packet.message_type, 135);
        assert_eq!(packet.code, 0);
        assert_eq!(packet.checksum, 0x44b7);
        let Icmpv6Body::NeighborSolicitation(solicitation) = &packet.body else {
            panic!("expected a neighbor solicitation, got {:?}", packet.body);
        };
        assert_eq!(
            solicitation.target_address,
            "2001:db8:1:2::1000".parse::<Ipv6Addr>().unwrap()
        );
        // Option 1 (Source Link-Layer Address), longueur 1 unite de 8 octets.
        assert_eq!(solicitation.options[0], 1);
        assert_eq!(solicitation.options.len(), 8);
    }

    #[test]
    fn parses_neighbor_advertisement_flags_from_capture() {
        let raw = bytes(NEIGHBOR_ADVERTISEMENT);
        let packet = Icmpv6Packet::try_from(raw.as_slice()).expect("captured NA parses");

        assert_eq!(packet.message_type, 136);
        let Icmpv6Body::NeighborAdvertisement(advertisement) = &packet.body else {
            panic!("expected a neighbor advertisement, got {:?}", packet.body);
        };
        // Wireshark lit « (sol, ovr) » sur cette trame : ni routeur, mais
        // sollicite et ecrasant.
        assert!(!advertisement.router);
        assert!(advertisement.solicited);
        assert!(advertisement.overrides);
        assert_eq!(
            advertisement.target_address,
            "2001:db8:1:2::1000".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(advertisement.options[0], 2);
    }

    #[test]
    fn parses_echo_request_from_capture() {
        let raw = bytes(ECHO_REQUEST);
        let packet = Icmpv6Packet::try_from(raw.as_slice()).expect("captured echo request parses");

        assert_eq!(packet.message_type, 128);
        let Icmpv6Body::Echo(echo) = &packet.body else {
            panic!("expected an echo body, got {:?}", packet.body);
        };
        assert_eq!(echo.identifier, 0xeaf5);
        assert_eq!(echo.sequence_number, 2);
        assert_eq!(echo.data, &raw[ICMPV6_ECHO_HEADER_LENGTH..]);
    }

    /// Le meme numero de type ne veut pas dire la meme chose qu'en v4 : 8 est
    /// un Echo request en ICMPv4, mais rien de defini en ICMPv6.
    #[test]
    fn type_8_is_not_an_echo_request_in_icmpv6() {
        let raw = bytes("0800000000000000");
        let packet = Icmpv6Packet::try_from(raw.as_slice()).expect("unknown type stays readable");

        assert_eq!(packet.message_type, 8);
        assert!(matches!(packet.body, Icmpv6Body::Other(_)));
    }

    /// Synthetique : troncature sous l'en-tete commun.
    #[test]
    fn rejects_packet_shorter_than_common_header() {
        let result = Icmpv6Packet::try_from(&[0x80, 0x00, 0x9e][..]);

        assert_eq!(
            result.unwrap_err(),
            Icmpv6Error::InvalidLength {
                expected: 4,
                actual: 3
            }
        );
    }

    /// Synthetique : Neighbor Solicitation tronquee avant l'adresse cible.
    #[test]
    fn rejects_neighbor_solicitation_without_target_address() {
        let mut raw = vec![135, 0, 0x44, 0xb7, 0, 0, 0, 0];
        raw.extend_from_slice(&[0x20, 0x01]);
        let result = Icmpv6Packet::try_from(raw.as_slice());

        assert_eq!(
            result.unwrap_err(),
            Icmpv6Error::InvalidNeighborLength {
                expected: 24,
                actual: 10
            }
        );
    }

    /// Synthetique : code 3 n'existe pas pour un Echo request ICMPv6.
    #[test]
    fn rejects_undefined_code_for_echo_request() {
        let result = Icmpv6Packet::try_from(&[128, 3, 0x9e, 0xd1, 0xea, 0xf5, 0x00, 0x02][..]);

        assert_eq!(
            result.unwrap_err(),
            Icmpv6Error::InvalidCodeForType {
                message_type: 128,
                code: 3
            }
        );
    }
}
