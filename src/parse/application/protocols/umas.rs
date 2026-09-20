// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! UMAS, le protocole proprietaire de Schneider Electric pour piloter les
//! automates Modicon (M340, M580, Quantum, Premium).
//!
//! UMAS n'a pas de specification publique. Il est transporte par Modbus/TCP
//! sous le code fonction **0x5A**, reserve au constructeur : l'enveloppe est
//! donc du Modbus standard, et seul le PDU est proprietaire.
//!
//! Ce module decode l'en-tete — identifiant de session et code fonction — et
//! rend les donnees brutes. Il ne nomme que ce qu'une trame reelle du depot
//! atteste : voir [`UmasFunction`].

use core::convert::TryFrom;

use crate::{
    checks::application::umas::{extract_umas_header, validate_umas_function_code},
    errors::application::umas::UmasError,
    parse::application::protocols::modbus_tcp::MBAP,
};

/// Deuxieme octet du PDU UMAS : code fonction d'une requete, ou statut d'une
/// reponse — les deux occupent la meme position, et un parseur sans etat ne
/// connait pas le sens de la conversation.
///
/// UMAS etant sans specification publique, les noms qui circulent pour les
/// codes de requete viennent de retro-ingenierie et ne sont pas verifiables
/// depuis une capture. Seul `Reply` est nomme : les 90 reponses de
/// `pcaps_exemple/protocols/umas/umas.pcap`, toutes emises par l'automate,
/// portent 0xFE. Les autres valeurs sont exposees brutes.
///
/// L'enum est `#[non_exhaustive]` : chaque nouveau nom pourra arriver en
/// version mineure, le jour ou une trame le justifie.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum UmasFunction {
    /// 0xFE — reponse de l'automate.
    Reply,
    /// Code de requete, ou statut de reponse qu'aucune trame du depot
    /// n'atteste.
    Other(u8),
}

/// Valeur portee par [`UmasFunction::Reply`].
pub const UMAS_REPLY: u8 = 0xFE;

impl UmasFunction {
    /// L'octet tel qu'il est sur le wire.
    pub const fn code(self) -> u8 {
        match self {
            UmasFunction::Reply => UMAS_REPLY,
            UmasFunction::Other(code) => code,
        }
    }
}

impl From<u8> for UmasFunction {
    fn from(code: u8) -> Self {
        match code {
            UMAS_REPLY => UmasFunction::Reply,
            other => UmasFunction::Other(other),
        }
    }
}

/// UMAS Packet
///
/// ```mermaid
/// ---
/// title: UmasPacket
/// ---
/// packet-beta
/// 0-15: "Transaction Identifier u16"
/// 16-31: "Protocol Identifier u16"
/// 32-47: "Length u16"
/// 48-55: "Unit Identifier u8"
/// 56-63: "Modbus Function Code u8 (0x5A)"
/// 64-71: "UMAS Session Id u8"
/// 72-79: "UMAS Function u8"
/// 80-143: "UMAS Data variable"
/// ```
// `MBAP` ne derive pas `PartialEq` : meme forme que `ModbusTcpPacket`.
#[derive(Debug)]
#[non_exhaustive]
pub struct UmasPacket<'a> {
    /// Enveloppe Modbus/TCP porteuse, validee (identifiant de protocole nul,
    /// longueur declaree coherente) et dont le code fonction vaut 0x5A.
    pub mbap: MBAP<'a>,
    /// Identifiant de session UMAS, attribue par l'automate.
    pub session_id: u8,
    pub function: UmasFunction,
    /// Charge utile UMAS, non decodee (zero-copie).
    pub data: &'a [u8],
}

impl<'a> TryFrom<&'a [u8]> for UmasPacket<'a> {
    type Error = UmasError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        // L'enveloppe Modbus/TCP est validee par son propre parseur : rien
        // n'est redecode ici.
        let mbap = MBAP::try_from(value)?;
        validate_umas_function_code(mbap.pdu.function_code)?;

        let (session_id, function_code, data) = extract_umas_header(mbap.pdu.pdu_data)?;

        Ok(UmasPacket {
            mbap,
            session_id,
            function: UmasFunction::from(function_code),
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MBAP synthetique : transaction, protocole 0, longueur, unite 0, puis
    /// le PDU fourni. Octets construits pour les cas d'erreur et de limite,
    /// les trames reelles vivant dans `tests/umas_golden.rs`.
    fn modbus_frame(pdu: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x00, 0x01, 0x00, 0x00];
        frame.extend_from_slice(&((pdu.len() + 1) as u16).to_be_bytes());
        frame.push(0x00);
        frame.extend_from_slice(pdu);
        frame
    }

    #[test]
    fn test_umas_function_maps_only_the_attested_code() {
        assert_eq!(UmasFunction::from(0xFE), UmasFunction::Reply);
        assert_eq!(UmasFunction::Reply.code(), 0xFE);
        for code in [0x00, 0x01, 0x02, 0x34, 0xFD, 0xFF] {
            assert_eq!(UmasFunction::from(code), UmasFunction::Other(code));
            assert_eq!(UmasFunction::Other(code).code(), code);
        }
    }

    #[test]
    fn test_parse_umas_request_without_data() {
        let frame = modbus_frame(&[0x5A, 0x01, 0x34]);
        let packet = UmasPacket::try_from(frame.as_slice()).expect("PDU UMAS valide");

        assert_eq!(packet.mbap.transaction_identifier, 1);
        assert_eq!(packet.mbap.unit_identifier, 0);
        assert_eq!(packet.session_id, 0x01);
        assert_eq!(packet.function, UmasFunction::Other(0x34));
        assert!(packet.data.is_empty());
    }

    #[test]
    fn test_parse_umas_reply_borrows_its_data() {
        let frame = modbus_frame(&[0x5A, 0x01, 0xFE, 0xAA, 0xBB]);
        let packet = UmasPacket::try_from(frame.as_slice()).expect("PDU UMAS valide");

        assert_eq!(packet.function, UmasFunction::Reply);
        assert_eq!(packet.data, &[0xAA, 0xBB]);
        // Zero-copie : la tranche pointe dans le buffer d'origine.
        assert!(frame.as_ptr_range().contains(&packet.data.as_ptr()));
    }

    #[test]
    fn test_reject_other_modbus_function_codes() {
        // 0x03 (Read Holding Registers) : du Modbus valide, pas de l'UMAS.
        let frame = modbus_frame(&[0x03, 0x00, 0x00, 0x00, 0x01]);
        assert!(matches!(
            UmasPacket::try_from(frame.as_slice()),
            Err(UmasError::NotUmas { got: 0x03 })
        ));
    }

    #[test]
    fn test_reject_truncated_umas_pdu() {
        // Code fonction 0x5A, mais pas de place pour session + fonction.
        for pdu in [&[0x5A][..], &[0x5A, 0x00][..]] {
            let frame = modbus_frame(pdu);
            assert!(
                matches!(
                    UmasPacket::try_from(frame.as_slice()),
                    Err(UmasError::PduTooSmall { needed: 2, .. })
                ),
                "PDU {pdu:02x?} accepte a tort"
            );
        }
    }

    #[test]
    fn test_reject_invalid_modbus_envelope() {
        // Identifiant de protocole non nul : ce n'est pas du Modbus/TCP.
        let mut frame = modbus_frame(&[0x5A, 0x00, 0x02]);
        frame[2] = 0x01;
        assert!(matches!(
            UmasPacket::try_from(frame.as_slice()),
            Err(UmasError::InvalidEnvelope(_))
        ));

        assert!(matches!(
            UmasPacket::try_from(&[][..]),
            Err(UmasError::InvalidEnvelope(_))
        ));
    }
}
