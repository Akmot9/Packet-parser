// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use core::convert::TryFrom;

use crate::{
    checks::application::modbus_tcp::{
        extract_function_code, extract_length, extract_protocol_identifier,
        extract_transaction_identifier, extract_unit_identifier, is_plausible_pdu,
        validate_declared_total_length, validate_mbap_min_size,
    },
    errors::application::modbus_tcp::ModbusTcpError,
};

/// Modbus/TCP Protocol Packet
///
/// ```mermaid
/// ---
/// title: ModbusTcpPacket
/// ---
/// packet-beta
/// 0-15: "Transaction Identifier u16"
/// 16-31: "Protocol Identifier u16"
/// 32-47: "Length u16"
/// 48-55: "Unit Identifier u8"
/// 56-63: "Function Code u8"
/// 64-127: "PDU Data variable"
/// ```
#[derive(Debug)]
#[non_exhaustive]
pub struct ModbusTcpPacket<'a> {
    pub mbaps: Vec<MBAP<'a>>, // plusieurs MBAP dans un paquet Modbus/TCP
}

impl<'a> TryFrom<&'a [u8]> for ModbusTcpPacket<'a> {
    type Error = ModbusTcpError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        validate_mbap_min_size(value)?;

        let mut mbaps = Vec::new();
        let mut offset = 0usize;

        while offset < value.len() {
            let slice = &value[offset..];

            // Si on a des octets résiduels trop petits pour un MBAP, c'est une incohérence
            validate_mbap_min_size(slice)?;

            let mbap = MBAP::try_from(slice)?;
            // Progression garantie : extract_length impose length >= 1, donc
            // consumed = 6 + length >= 7 et la boucle avance toujours
            // (l'appel à validate_consumed_length était vacueux : consumed
            // ne peut jamais valoir 0 ici).
            let consumed = 6usize + mbap.length as usize;

            mbaps.push(mbap);
            offset += consumed;
        }

        Ok(ModbusTcpPacket { mbaps })
    }
}

impl ModbusTcpPacket<'_> {
    /// Sonde Modbus/TCP aveugle, hors du port 502 (#167).
    ///
    /// Plus stricte que [`TryFrom::try_from`], que le port 502 et Decode As
    /// gardent tolerant : un identifiant de protocole nul et une longueur qui
    /// pave le segment ne suffisent pas — tout protocole qui prefixe ses
    /// messages de deux octets puis d'une longueur sur quatre en a la forme,
    /// et 97 segments LDAP, DICOM, Elasticsearch et d'un jeu des corpus
    /// passaient pour du Modbus. Chaque PDU doit porter un code fonction
    /// public d'usage courant et la taille qu'il impose, en requete ou en
    /// reponse ; et deux en-tetes qui restent des PDU Modbus valides sont
    /// ecartes ([`MBAP::is_known_lookalike`]).
    pub(crate) fn is_blind_tcp_match(payload: &[u8]) -> bool {
        ModbusTcpPacket::try_from(payload).is_ok_and(|packet| {
            packet.mbaps.iter().all(|mbap| {
                !mbap.is_known_lookalike()
                    && is_plausible_pdu(mbap.pdu.function_code, mbap.pdu.pdu_data)
            })
        })
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub struct MBAP<'a> {
    pub transaction_identifier: u16,
    pub protocol_identifier: u16,
    pub length: u16,
    pub unit_identifier: u8,
    pub pdu: Modbus<'a>,
}

#[derive(Debug)]
#[non_exhaustive]
pub struct Modbus<'a> {
    pub function_code: u8,
    pub pdu_data: &'a [u8],
}

impl MBAP<'_> {
    /// Deux en-tetes qui, octet pour octet, font des PDU Modbus valides :
    ///
    /// - un LDAPMessage d'Active Directory, `30 84 00 00 LL LL 02 n` —
    ///   SEQUENCE a longueur sur quatre octets, puis l'INTEGER du messageID
    ///   lu comme unite 2 et code fonction n (1 a 4) ; un unbindRequest(2)
    ///   ou un abandonRequest y est une lecture de bobines (trame 3627 de
    ///   `NEWYORK.cap`, jeux de donnees OTRF) ;
    /// - un A-ASSOCIATE-RJ de DICOM, `03 00 00 00 00 04 00 r s c` — le
    ///   type 3 et sa longueur de quatre octets, puis le resultat lu comme
    ///   code fonction et la source comme nombre d'octets.
    ///
    /// Un vrai Modbus hors du port 502 n'y perd que la transaction 0x3084
    /// d'une unite 2, et, a la transaction 0x0300, une reponse de lecture
    /// d'un octet de l'unite 0.
    fn is_known_lookalike(&self) -> bool {
        let ldap = self.transaction_identifier == 0x3084
            && self.unit_identifier == 0x02
            && (1..=4).contains(&self.pdu.function_code);
        let dicom_reject =
            self.transaction_identifier == 0x0300 && self.length == 4 && self.unit_identifier == 0;
        ldap || dicom_reject
    }
}

impl<'a> TryFrom<&'a [u8]> for MBAP<'a> {
    type Error = ModbusTcpError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        validate_mbap_min_size(value)?;

        let transaction_identifier = extract_transaction_identifier(value)?;
        let protocol_identifier = extract_protocol_identifier(value)?;
        let length = extract_length(value)?;
        let unit_identifier = extract_unit_identifier(value)?;

        // Taille totale attendue = 6 + length
        let expected_total = validate_declared_total_length(value, length)?;

        // PDU = après unit id
        let pdu = &value[7..expected_total];
        let (function_code, pdu_data) = extract_function_code(pdu)?;

        let modbus_data = Modbus {
            function_code,
            pdu_data,
        };

        Ok(MBAP {
            transaction_identifier,
            protocol_identifier,
            length,
            unit_identifier,
            pdu: modbus_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_frame_2_request_read_input_registers() {
        // Wireshark Frame 2:
        // TI=0, PI=0, Length=6, Unit=255
        // Function=4, Reference=2258 (0x08D2), WordCount=2
        let bytes: [u8; 12] = [
            0x00, 0x00, // TI : 0
            0x00, 0x00, // PI : 0
            0x00, 0x06, // Length : 6
            0xFF, // Unit : 255
            0x04, // Function : 4
            0x08, 0xD2, // Reference : 2258
            0x00, 0x02, // Word count : 2
        ];

        let pkt = MBAP::try_from(bytes.as_slice()).unwrap();
        assert_eq!(pkt.transaction_identifier, 0);
        assert_eq!(pkt.protocol_identifier, 0);
        assert_eq!(pkt.length, 6);
        assert_eq!(pkt.unit_identifier, 0xFF);
        assert_eq!(pkt.pdu.function_code, 0x04);

        // let pdu = pkt.modbus().unwrap();
        // assert_eq!(pdu.function_code, 0x04);
        // assert_eq!(pdu.pdu_data, &[0x08, 0xD2, 0x00, 0x02]);
    }

    #[test]
    fn reject_non_zero_protocol_id() {
        let bytes: [u8; 7] = [
            0x00, 0x01, // TI
            0x00, 0x02, // PI != 0
            0x00, 0x01, // Length
            0x01, // Unit
        ];
        let err = MBAP::try_from(bytes.as_slice()).unwrap_err();
        assert_eq!(err, ModbusTcpError::InvalidProtocolIdentifier { got: 2 });
    }

    #[test]
    fn reject_truncated_buffer() {
        // length=6 => total attendu = 12, mais on donne moins
        let bytes: [u8; 10] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0xFF, 0x04, 0x00, 0x00];
        let err = MBAP::try_from(bytes.as_slice()).unwrap_err();
        assert_eq!(
            err,
            ModbusTcpError::LengthMismatch {
                expected: 12,
                actual: 10
            }
        );
    }

    #[test]
    fn parse_large_response_header_only_shape() {
        // Frame 3 first ADU: TI=31998 (0x7CFE), PI=0, Length=201 (0x00C9), Unit=255
        // PDU: function=4, byte_count=198, +198 bytes data => PDU len=200 => length=201 OK.
        let mut bytes = vec![
            0x7C, 0xFE, // TI
            0x00, 0x00, // PI
            0x00, 0xC9, // length=201
            0xFF, // unit
            0x04, // function
            0xC6, // byte_count=198
        ];
        bytes.extend(core::iter::repeat_n(0u8, 198));

        let pkt = MBAP::try_from(bytes.as_slice()).unwrap();
        assert_eq!(pkt.transaction_identifier, 0x7CFE);
        assert_eq!(pkt.length, 201);

        // assert_eq!(pkt.modbus_data.pdu_data.len(), 200); // PDU len = length-1
        // assert_eq!(pkt.modbus_data.pdu_data[0], 0x04);
        // assert_eq!(pkt.modbus_data.pdu_data[1], 0xC6);
    }

    #[test]
    fn parse_request() {
        // A MODBUS Request is the message sent on the network by the Client to initiate a transaction,
    }

    #[test]
    fn parse_response() {
        // A MODBUS Response is the Response message sent by the Server,
    }

    #[test]
    fn parse_configuration() {
        // A MODBUS Confirmation is the Response Message received on the Client side
    }

    #[test]
    fn parse_indication() {
        // is the Request message received on the Server side,
    }

    #[test]
    fn parse_multi_adu_is_ok() {
        let hex_str = "02b4000000c9ff04c600000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000004000000000000000000000000000001db000001d600004a380000000000000000000000000000000000000000000000000000000000006461696d006e000000000000000000000000000030310030000000000000000000000000000000000000000000000000000000000000000000000000000002b500000007ff04040004000002b60000002fff042c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002b700000007ff0404a00045a3";

        // Convert hex string to bytes
        let bytes = hex::decode(hex_str).expect("Failed to decode hex string");

        // Try to parse as S7Comm packet
        let result = ModbusTcpPacket::try_from(&bytes[..]);

        // Check if parsing succeeded
        assert!(result.is_ok());
        // Check if the result contain 4 MBAPs
        let pkt = result.unwrap();
        assert_eq!(pkt.mbaps.len(), 4);
    }

    /// pcaps_exemple/The-Ultimate-PCAP.pcapng trame 40032 : un bindRequest
    /// LDAP vers TCP 389 — `30 84 00 00 00 4a`, une longueur BER sur quatre
    /// octets, a exactement la forme d'une enveloppe MBAP (#167).
    const LDAP_BIND_REQUEST: &str = concat!(
        "30840000004a0201086084000000410201030400a38400000036040a4753532d",
        "53504e45474f04284e544c4d5353500001000000b78208e20000000000000000",
        "00000000000000000a00614a0000000f",
    );

    /// Corpus de tests nDPI (`ntop/nDPI` 5915c399,
    /// `tests/cfgs/default/pcap/elasticsearch.pcap`), trame 6 : une reponse du
    /// transport d'Elasticsearch (`ES`, longueur sur quatre octets).
    const ELASTICSEARCH_RESPONSE: &str = "455300000013000000000000000109005cc6630000cbf6ae03";

    /// pcaps_exemple/protocols/modbus/Modbus.pcap, trames 1 et 2.
    const READ_HOLDING_REGISTERS: &str = "00d100000006010300010001";
    const READ_HOLDING_REGISTERS_RESPONSE: &str = "00d1000000050103020000";

    /// Des en-tetes qui restent des PDU Modbus valides (revue de #171) :
    /// l'unbindRequest(2) d'Active Directory de la trame 3627 de
    /// `NEWYORK.cap` (OTRF Security-Datasets, apt29), un abandonRequest de
    /// la meme forme (lu comme une lecture de 382 bobines), et un
    /// A-ASSOCIATE-RJ de DICOM dont la source est l'utilisateur.
    const AD_UNBIND_REQUEST: &str = "3084000000050201024200";
    const AD_ABANDON_REQUEST: &str = "30840000000602010350017e";
    const DICOM_ASSOCIATE_REJECT: &str = "03000000000400010103";

    #[test]
    fn test_blind_probe_refuses_valid_looking_ldap_and_dicom() {
        for hex_payload in [
            AD_UNBIND_REQUEST,
            AD_ABANDON_REQUEST,
            DICOM_ASSOCIATE_REJECT,
        ] {
            let payload = hex::decode(hex_payload).unwrap();
            let packet = ModbusTcpPacket::try_from(payload.as_slice()).expect("forme MBAP");
            let mbap = &packet.mbaps[0];
            assert!(
                is_plausible_pdu(mbap.pdu.function_code, mbap.pdu.pdu_data),
                "{hex_payload} : une PDU Modbus valide"
            );
            assert!(
                !ModbusTcpPacket::is_blind_tcp_match(&payload),
                "{hex_payload}"
            );
        }
        // Une unite ou un code fonction de plus, et ce ne sont plus ces
        // en-tetes : la sonde juge la PDU seule.
        let payload = hex::decode("3084000000050301020000").unwrap();
        assert!(ModbusTcpPacket::is_blind_tcp_match(&payload));
    }

    #[test]
    fn test_blind_probe_keeps_modbus_and_refuses_lookalikes() {
        for hex_payload in [READ_HOLDING_REGISTERS, READ_HOLDING_REGISTERS_RESPONSE] {
            let payload = hex::decode(hex_payload).unwrap();
            assert!(
                ModbusTcpPacket::is_blind_tcp_match(&payload),
                "{hex_payload}"
            );
        }
        for hex_payload in [LDAP_BIND_REQUEST, ELASTICSEARCH_RESPONSE] {
            let payload = hex::decode(hex_payload).unwrap();
            // Le decodeur tolerant du port 502 les accepte...
            assert!(ModbusTcpPacket::try_from(payload.as_slice()).is_ok());
            // ... la sonde aveugle, non.
            assert!(!ModbusTcpPacket::is_blind_tcp_match(&payload));
        }
    }
}
