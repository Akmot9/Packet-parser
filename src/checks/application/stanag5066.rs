// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use crate::errors::application::stanag5066::Stanag5066ParseError;

/// En-tete d'un S_PDU : preambule (2), version (1), taille de la primitive
/// (2, type compris).
pub const SIS_HEADER_LENGTH: usize = 5;

pub const SIS_SYNC_PREAMBLE: [u8; 2] = [0x90, 0xeb];

/// Seule version definie.
pub const SIS_VERSION: u8 = 0;

/// Types de S_PDU (annexe A, §A.2).
pub const SIS_BIND_REQUEST: u8 = 1;
pub const SIS_UNBIND_REQUEST: u8 = 2;
pub const SIS_BIND_ACCEPTED: u8 = 3;
pub const SIS_BIND_REJECTED: u8 = 4;
pub const SIS_UNBIND_INDICATION: u8 = 5;
pub const SIS_HARD_LINK_ESTABLISH: u8 = 6;
pub const SIS_HARD_LINK_TERMINATE: u8 = 7;
pub const SIS_HARD_LINK_ESTABLISHED: u8 = 8;
pub const SIS_HARD_LINK_REJECTED: u8 = 9;
pub const SIS_HARD_LINK_TERMINATED: u8 = 10;
pub const SIS_HARD_LINK_INDICATION: u8 = 11;
pub const SIS_HARD_LINK_ACCEPT: u8 = 12;
pub const SIS_HARD_LINK_REJECT: u8 = 13;
pub const SIS_SUBNET_AVAILABILITY: u8 = 14;
pub const SIS_DATAFLOW_ON: u8 = 15;
pub const SIS_DATAFLOW_OFF: u8 = 16;
pub const SIS_KEEP_ALIVE: u8 = 17;
pub const SIS_MANAGEMENT_MESSAGE_REQUEST: u8 = 18;
pub const SIS_MANAGEMENT_MESSAGE_INDICATION: u8 = 19;
pub const SIS_UNIDATA_REQUEST: u8 = 20;
pub const SIS_UNIDATA_INDICATION: u8 = 21;
pub const SIS_UNIDATA_REQUEST_CONFIRM: u8 = 22;
pub const SIS_UNIDATA_REQUEST_REJECTED: u8 = 23;
pub const SIS_EXPEDITED_UNIDATA_REQUEST: u8 = 24;
pub const SIS_EXPEDITED_UNIDATA_INDICATION: u8 = 25;
pub const SIS_EXPEDITED_UNIDATA_REQUEST_CONFIRM: u8 = 26;
pub const SIS_EXPEDITED_UNIDATA_REQUEST_REJECTED: u8 = 27;

/// Longueur d'une adresse de noeud sur le wire : taille (3 bits), groupe
/// (1 bit) et 28 bits d'adresse, lus sur quatre octets comme tshark.
pub const SIS_NODE_ADDRESS_LENGTH: usize = 4;

pub fn ensure_len(buf: &[u8], needed: usize) -> Result<(), Stanag5066ParseError> {
    if buf.len() < needed {
        return Err(Stanag5066ParseError::Truncated {
            expected: needed,
            actual: buf.len(),
        });
    }
    Ok(())
}

/// Le preambule `90 EB`.
pub fn validate_preamble(bytes: [u8; 2]) -> Result<(), Stanag5066ParseError> {
    if bytes != SIS_SYNC_PREAMBLE {
        return Err(Stanag5066ParseError::InvalidPreamble(bytes));
    }
    Ok(())
}

pub fn extract_version(byte: u8) -> Result<u8, Stanag5066ParseError> {
    if byte != SIS_VERSION {
        return Err(Stanag5066ParseError::UnsupportedVersion(byte));
    }
    Ok(byte)
}

/// `S_Primitive size`, type compris : au moins 1.
pub fn extract_primitive_size(bytes: [u8; 2]) -> Result<u16, Stanag5066ParseError> {
    let size = u16::from_be_bytes(bytes);
    if size == 0 {
        return Err(Stanag5066ParseError::EmptyPrimitive);
    }
    Ok(size)
}

/// Un type de S_PDU de 1 a 27.
pub fn extract_pdu_type(byte: u8) -> Result<u8, Stanag5066ParseError> {
    if !(SIS_BIND_REQUEST..=SIS_EXPEDITED_UNIDATA_REQUEST_REJECTED).contains(&byte) {
        return Err(Stanag5066ParseError::ReservedPduType(byte));
    }
    Ok(byte)
}

/// Les champs fixes d'une primitive, type exclu, en octets (annexe A, §A.2).
/// Zero pour les primitives sans corps.
pub const fn fixed_primitive_length(pdu_type: u8) -> usize {
    match pdu_type {
        SIS_BIND_REQUEST => 3,
        SIS_BIND_ACCEPTED => 3,
        SIS_BIND_REJECTED | SIS_UNBIND_INDICATION => 1,
        SIS_HARD_LINK_ESTABLISH | SIS_HARD_LINK_ACCEPT => 1 + SIS_NODE_ADDRESS_LENGTH,
        SIS_HARD_LINK_TERMINATE => SIS_NODE_ADDRESS_LENGTH,
        SIS_HARD_LINK_ESTABLISHED
        | SIS_HARD_LINK_REJECTED
        | SIS_HARD_LINK_TERMINATED
        | SIS_HARD_LINK_INDICATION
        | SIS_HARD_LINK_REJECT => 2 + SIS_NODE_ADDRESS_LENGTH,
        SIS_SUBNET_AVAILABILITY => 2,
        SIS_MANAGEMENT_MESSAGE_REQUEST | SIS_MANAGEMENT_MESSAGE_INDICATION => 1,
        // priorite/SAP, adresse, type de service, TTL, taille.
        SIS_UNIDATA_REQUEST | SIS_EXPEDITED_UNIDATA_REQUEST => {
            1 + SIS_NODE_ADDRESS_LENGTH + 1 + 3 + 2
        }
        // priorite/SAP, adresse destination, mode/SAP source, adresse source, taille.
        SIS_UNIDATA_INDICATION | SIS_EXPEDITED_UNIDATA_INDICATION => {
            1 + SIS_NODE_ADDRESS_LENGTH + 1 + SIS_NODE_ADDRESS_LENGTH + 2
        }
        // inutilise ou motif/SAP, adresse, taille.
        SIS_UNIDATA_REQUEST_CONFIRM
        | SIS_UNIDATA_REQUEST_REJECTED
        | SIS_EXPEDITED_UNIDATA_REQUEST_CONFIRM
        | SIS_EXPEDITED_UNIDATA_REQUEST_REJECTED => 1 + SIS_NODE_ADDRESS_LENGTH + 2,
        _ => 0,
    }
}

/// Les champs fixes du type doivent etre presents dans la primitive.
pub fn validate_primitive_length(pdu_type: u8, actual: usize) -> Result<(), Stanag5066ParseError> {
    let expected = fixed_primitive_length(pdu_type);
    if actual < expected {
        return Err(Stanag5066ParseError::PrimitiveTooShort {
            pdu_type,
            expected,
            actual,
        });
    }
    Ok(())
}

/// Ce qui suit un S_PDU complet doit etre vide ou commencer un S_PDU :
/// autant du preambule `90 EB 00` qu'il reste d'octets.
pub fn validate_trailer(trailer: &[u8]) -> Result<(), Stanag5066ParseError> {
    let expected = [SIS_SYNC_PREAMBLE[0], SIS_SYNC_PREAMBLE[1], SIS_VERSION];
    let checked = trailer.len().min(expected.len());
    if trailer[..checked] != expected[..checked] {
        return Err(Stanag5066ParseError::UnexpectedTrailingBytes {
            trailing: trailer.len(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_fields() {
        assert_eq!(validate_preamble([0x90, 0xeb]), Ok(()));
        assert_eq!(
            validate_preamble([0x90, 0xec]),
            Err(Stanag5066ParseError::InvalidPreamble([0x90, 0xec]))
        );
        assert_eq!(extract_version(0), Ok(0));
        assert_eq!(
            extract_version(1),
            Err(Stanag5066ParseError::UnsupportedVersion(1))
        );
        assert_eq!(extract_primitive_size([0x00, 0x04]), Ok(4));
        assert_eq!(
            extract_primitive_size([0, 0]),
            Err(Stanag5066ParseError::EmptyPrimitive)
        );
        assert_eq!(extract_pdu_type(1), Ok(1));
        assert_eq!(extract_pdu_type(27), Ok(27));
        for byte in [0, 28, 0xff] {
            assert_eq!(
                extract_pdu_type(byte),
                Err(Stanag5066ParseError::ReservedPduType(byte))
            );
        }
    }

    #[test]
    fn test_fixed_lengths_and_trailer() {
        assert_eq!(fixed_primitive_length(SIS_UNIDATA_REQUEST), 11);
        assert_eq!(fixed_primitive_length(SIS_UNIDATA_INDICATION), 12);
        assert_eq!(fixed_primitive_length(SIS_KEEP_ALIVE), 0);
        assert_eq!(validate_primitive_length(SIS_BIND_REQUEST, 3), Ok(()));
        assert_eq!(
            validate_primitive_length(SIS_BIND_REQUEST, 2),
            Err(Stanag5066ParseError::PrimitiveTooShort {
                pdu_type: 1,
                expected: 3,
                actual: 2
            })
        );
        assert_eq!(validate_trailer(&[]), Ok(()));
        assert_eq!(validate_trailer(&[0x90]), Ok(()));
        assert_eq!(validate_trailer(&[0x90, 0xeb, 0x00, 0x00, 0x04]), Ok(()));
        assert_eq!(
            validate_trailer(&[0x90, 0xeb, 0x01]),
            Err(Stanag5066ParseError::UnexpectedTrailingBytes { trailing: 3 })
        );
        assert_eq!(
            validate_trailer(b"<0> Hello"),
            Err(Stanag5066ParseError::UnexpectedTrailingBytes { trailing: 9 })
        );
    }
}
