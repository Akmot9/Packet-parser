// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Parseur ICMPv4 (IP protocole 1, RFC 792).
//!
//! ICMP n'a ni port ni notion de session : il est atteint par le numero de
//! protocole IP, jamais par probing. La detection se fait donc dans
//! `Transport::try_from_parts`, sur `TransportProtocol::Icmp` uniquement.

use std::convert::TryFrom;

use crate::{
    checks::transport::icmp::{
        ICMP_ECHO_HEADER_LENGTH, ICMP_ERROR_HEADER_LENGTH, ICMP_HEADER_LENGTH, extract_icmp_code,
        validate_icmp_echo_length, validate_icmp_error_length, validate_icmp_min_length,
    },
    errors::transport::icmp::IcmpError,
};

/// Types de message ICMPv4 interpretes (registre IANA « ICMP Type Numbers »).
const ECHO_REPLY_TYPE: u8 = 0;
const DESTINATION_UNREACHABLE_TYPE: u8 = 3;
const REDIRECT_TYPE: u8 = 5;
const ECHO_REQUEST_TYPE: u8 = 8;
const TIME_EXCEEDED_TYPE: u8 = 11;
const PARAMETER_PROBLEM_TYPE: u8 = 12;

/// Corps d'un message Echo (types 0 et 8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpEcho<'a> {
    pub identifier: u16,
    pub sequence_number: u16,
    /// Donnees renvoyees telles quelles par le repondeur, zero-copy.
    pub data: &'a [u8],
}

/// Corps d'un message d'erreur (types 3, 11, 12) : quatre octets dependant du
/// type, puis le debut du datagramme qui a provoque l'erreur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpErrorReport<'a> {
    /// Champ de 4 octets suivant le checksum. Inutilise pour Time Exceeded,
    /// il porte le MTU pour « fragmentation needed » ou le pointeur pour
    /// Parameter Problem : laisse brut, a interpreter selon type et code.
    pub rest_of_header: u32,
    /// Datagramme original cite par le routeur, zero-copy.
    pub original_datagram: &'a [u8],
}

/// Corps ICMP, choisi selon le type de message.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IcmpBody<'a> {
    Echo(IcmpEcho<'a>),
    Error(IcmpErrorReport<'a>),
    /// Type non interprete : les octets qui suivent l'en-tete commun sont
    /// exposes bruts plutot que devines.
    Other(&'a [u8]),
}

/// Message ICMPv4 (RFC 792).
///
/// L'en-tete commun tient en quatre octets ; la suite depend du type. Le
/// schema montre la disposition d'un Echo, la plus courante.
///
/// ```mermaid
/// ---
/// title: IcmpPacket (corps Echo)
/// ---
/// packet-beta
/// 0-7: "Type u8"
/// 8-15: "Code u8"
/// 16-31: "Checksum u16"
/// 32-47: "Identifier u16"
/// 48-63: "Sequence Number u16"
/// 64-95: "Data variable"
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpPacket<'a> {
    pub message_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub body: IcmpBody<'a>,
}

impl<'a> TryFrom<&'a [u8]> for IcmpPacket<'a> {
    type Error = IcmpError;

    fn try_from(payload: &'a [u8]) -> Result<Self, IcmpError> {
        validate_icmp_min_length(payload)?;

        let message_type = payload[0];
        let code = extract_icmp_code(message_type, payload[1])?;
        let checksum = u16::from_be_bytes([payload[2], payload[3]]);

        let body = match message_type {
            // Echo reply et Echo request : identifiant, sequence, puis les
            // donnees renvoyees telles quelles.
            ECHO_REPLY_TYPE | ECHO_REQUEST_TYPE => {
                validate_icmp_echo_length(payload)?;
                IcmpBody::Echo(IcmpEcho {
                    identifier: u16::from_be_bytes([payload[4], payload[5]]),
                    sequence_number: u16::from_be_bytes([payload[6], payload[7]]),
                    data: &payload[ICMP_ECHO_HEADER_LENGTH..],
                })
            }
            // Messages d'erreur : quatre octets dependant du type, puis le
            // datagramme qui a provoque l'erreur.
            DESTINATION_UNREACHABLE_TYPE
            | REDIRECT_TYPE
            | TIME_EXCEEDED_TYPE
            | PARAMETER_PROBLEM_TYPE => {
                validate_icmp_error_length(payload)?;
                IcmpBody::Error(IcmpErrorReport {
                    rest_of_header: u32::from_be_bytes([
                        payload[4], payload[5], payload[6], payload[7],
                    ]),
                    original_datagram: &payload[ICMP_ERROR_HEADER_LENGTH..],
                })
            }
            _ => IcmpBody::Other(&payload[ICMP_HEADER_LENGTH..]),
        };

        Ok(IcmpPacket {
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

    /// Trame 1 : Echo request (pcaps_exemple/protocols/icmp/icmp_echo.pcapng).
    const ECHO_REQUEST: &str = concat!(
        "0800145c050034006162636465666768696a6b6c6d6e6f707172737475767761",
        "6263646566676869"
    );

    /// Trame 2 : Echo reply (pcaps_exemple/protocols/icmp/icmp_echo.pcapng).
    const ECHO_REPLY: &str = concat!(
        "00001c5c050034006162636465666768696a6b6c6d6e6f707172737475767761",
        "6263646566676869"
    );

    /// Trame 2 : Time exceeded en transit, citant le datagramme original
    /// (pcaps_exemple/protocols/icmp/icmp_traceroute.pcapng).
    const TIME_EXCEEDED: &str = concat!(
        "0b00f4ff000000004500005cff51000001018f1ac0a8648a040202010800baff",
        "05003800"
    );

    fn bytes(hex_fixture: &str) -> Vec<u8> {
        hex::decode(hex_fixture).expect("invalid test hex fixture")
    }

    #[test]
    fn parses_echo_request_from_capture() {
        let raw = bytes(ECHO_REQUEST);
        let packet = IcmpPacket::try_from(raw.as_slice()).expect("captured echo request parses");

        assert_eq!(packet.message_type, 8);
        assert_eq!(packet.code, 0);
        assert_eq!(packet.checksum, 0x145c);
        let IcmpBody::Echo(echo) = &packet.body else {
            panic!("expected an echo body, got {:?}", packet.body);
        };
        assert_eq!(echo.identifier, 0x0500);
        assert_eq!(echo.sequence_number, 0x3400);
        assert_eq!(echo.data, &raw[ICMP_ECHO_HEADER_LENGTH..]);
    }

    #[test]
    fn parses_echo_reply_from_capture() {
        let raw = bytes(ECHO_REPLY);
        let packet = IcmpPacket::try_from(raw.as_slice()).expect("captured echo reply parses");

        assert_eq!(packet.message_type, 0);
        assert_eq!(packet.checksum, 0x1c5c);
        assert!(matches!(packet.body, IcmpBody::Echo(_)));
    }

    #[test]
    fn parses_time_exceeded_and_exposes_original_datagram() {
        let raw = bytes(TIME_EXCEEDED);
        let packet = IcmpPacket::try_from(raw.as_slice()).expect("captured time exceeded parses");

        assert_eq!(packet.message_type, 11);
        assert_eq!(packet.code, 0);
        let IcmpBody::Error(report) = &packet.body else {
            panic!("expected an error body, got {:?}", packet.body);
        };
        assert_eq!(report.rest_of_header, 0);
        // Le datagramme cite commence par un en-tete IPv4 (version 4, IHL 5).
        assert_eq!(report.original_datagram[0], 0x45);
        assert_eq!(report.original_datagram, &raw[ICMP_ERROR_HEADER_LENGTH..]);
    }

    /// Synthetique : troncature sous l'en-tete commun.
    #[test]
    fn rejects_packet_shorter_than_common_header() {
        let result = IcmpPacket::try_from(&[0x08, 0x00, 0x14][..]);

        assert_eq!(
            result.unwrap_err(),
            IcmpError::InvalidLength {
                expected: 4,
                actual: 3
            }
        );
    }

    /// Synthetique : Echo annonce mais tronque avant identifiant et sequence.
    #[test]
    fn rejects_echo_without_identifier_and_sequence() {
        let result = IcmpPacket::try_from(&[0x08, 0x00, 0x14, 0x5c, 0x05][..]);

        assert_eq!(
            result.unwrap_err(),
            IcmpError::InvalidEchoLength {
                expected: 8,
                actual: 5
            }
        );
    }

    /// Synthetique : code 1 n'existe pas pour un Echo request.
    #[test]
    fn rejects_undefined_code_for_echo_request() {
        let result = IcmpPacket::try_from(&[0x08, 0x01, 0x14, 0x5c, 0x05, 0x00, 0x34, 0x00][..]);

        assert_eq!(
            result.unwrap_err(),
            IcmpError::InvalidCodeForType {
                message_type: 8,
                code: 1
            }
        );
    }
}
