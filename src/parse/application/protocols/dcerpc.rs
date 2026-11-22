// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! DCE/RPC oriente connexion (DCE 1.1: RPC, C706 §12.6, #356), le RPC de
//! Microsoft (MSRPC, DCOM) sur TCP : l'en-tete commun de seize octets, puis,
//! pour une requete, l'indice d'allocation, le contexte de presentation et
//! le numero d'operation. Le corps (liaison, souches NDR, verificateur
//! d'authentification) est emprunte au segment, sans etre decode.
//!
//! DCE/RPC n'a pas de port fixe : le port 135 ne sert qu'a l'annuaire, les
//! services ecoutent sur des ports dynamiques. L'en-tete commun porte assez
//! d'octets contraints pour une sonde aveugle : version 5.0 ou 5.1, un type
//! de PDU oriente connexion, une etiquette de representation des donnees
//! dont deux octets sont nuls, et une longueur de fragment coherente.
//!
//! Limites, sans etat : un fragment plus long que le segment est coupe
//! (`DceRpcPdu::is_truncated`) et les segments de suite restent `Unknown` ;
//! seul le premier PDU d'un segment est lu (`DceRpcPdu::rest` rend la
//! suite). La variante sans connexion (version 4, sur UDP) et DCE/RPC dans
//! un tube nomme SMB ne sont pas lus.

use std::convert::TryFrom;

use crate::errors::application::dcerpc::DceRpcError;

/// Length of the common header of a connection-oriented PDU.
pub const DCERPC_COMMON_HEADER_LENGTH: usize = 16;

/// Type of a connection-oriented PDU (C706 §12.6.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DceRpcPduType {
    /// 0
    Request,
    /// 2
    Response,
    /// 3
    Fault,
    /// 11
    Bind,
    /// 12
    BindAck,
    /// 13
    BindNak,
    /// 14
    AlterContext,
    /// 15
    AlterContextResponse,
    /// 16, a Microsoft extension ([MS-RPCE] §2.2.2.11)
    Auth3,
    /// 17
    Shutdown,
    /// 18
    CoCancel,
    /// 19
    Orphaned,
}

impl DceRpcPduType {
    /// The PTYPE byte.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Request => 0,
            Self::Response => 2,
            Self::Fault => 3,
            Self::Bind => 11,
            Self::BindAck => 12,
            Self::BindNak => 13,
            Self::AlterContext => 14,
            Self::AlterContextResponse => 15,
            Self::Auth3 => 16,
            Self::Shutdown => 17,
            Self::CoCancel => 18,
            Self::Orphaned => 19,
        }
    }
}

/// Fields that follow the common header of a Request PDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DceRpcRequest {
    /// Size of the whole request body, as a hint to the receiver.
    pub alloc_hint: u32,
    /// Presentation context, as negotiated by the Bind.
    pub context_id: u16,
    /// Operation number within the interface.
    pub opnum: u16,
}

/// The first connection-oriented DCE/RPC PDU of a TCP segment.
///
/// ```mermaid
/// ---
/// title: DceRpcPdu (common header)
/// ---
/// packet-beta
/// 0-7: "rpc_vers = 5"
/// 8-15: "rpc_vers_minor"
/// 16-23: "PTYPE"
/// 24-31: "pfc_flags"
/// 32-63: "drep (byte order, charset, float, reserved)"
/// 64-79: "frag_length u16"
/// 80-95: "auth_length u16"
/// 96-127: "call_id u32"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DceRpcPdu<'a> {
    /// Minor version: 0 or 1.
    pub version_minor: u8,
    /// The PDU type.
    pub pdu_type: DceRpcPduType,
    /// The `pfc_flags` byte: first and last fragment, object UUID present...
    pub flags: u8,
    /// `true` when integers are little-endian, as the first byte of the
    /// data representation label says.
    pub little_endian: bool,
    /// The data representation label, as received.
    pub data_representation: [u8; 4],
    /// Length of the whole fragment, header and authentication included.
    pub frag_length: u16,
    /// Length of the authentication value that ends the fragment.
    pub auth_length: u16,
    /// Identifier that ties the fragments and the reply of one call.
    pub call_id: u32,
    /// What follows the common header, up to the end of the fragment or of
    /// the segment, whichever comes first.
    pub body: &'a [u8],
    rest: &'a [u8],
}

impl<'a> DceRpcPdu<'a> {
    /// First fragment of a call (`PFC_FIRST_FRAG`).
    pub fn is_first_fragment(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// Last fragment of a call (`PFC_LAST_FRAG`).
    pub fn is_last_fragment(&self) -> bool {
        self.flags & 0x02 != 0
    }

    /// `true` when the fragment goes on in the next TCP segment.
    pub fn is_truncated(&self) -> bool {
        DCERPC_COMMON_HEADER_LENGTH + self.body.len() < usize::from(self.frag_length)
    }

    /// The bytes of the segment that follow this fragment: another PDU, or
    /// nothing.
    pub fn rest(&self) -> &'a [u8] {
        self.rest
    }

    /// The fields of a Request PDU; `None` for another type or when the
    /// segment stops before them.
    pub fn request(&self) -> Option<DceRpcRequest> {
        if self.pdu_type != DceRpcPduType::Request {
            return None;
        }
        let [a0, a1, a2, a3, c0, c1, o0, o1, ..] = *self.body else {
            return None;
        };
        let (alloc_hint, context_id, opnum) = if self.little_endian {
            (
                u32::from_le_bytes([a0, a1, a2, a3]),
                u16::from_le_bytes([c0, c1]),
                u16::from_le_bytes([o0, o1]),
            )
        } else {
            (
                u32::from_be_bytes([a0, a1, a2, a3]),
                u16::from_be_bytes([c0, c1]),
                u16::from_be_bytes([o0, o1]),
            )
        };
        Some(DceRpcRequest {
            alloc_hint,
            context_id,
            opnum,
        })
    }

    /// Sonde aveugle : un PDU bien forme dont le fragment tient dans le
    /// segment ou le remplit, et, quand d'autres octets suivent, un second
    /// PDU bien forme (voir la doc du module).
    pub(crate) fn is_blind_match(payload: &'a [u8]) -> bool {
        DceRpcPdu::try_from(payload)
            .is_ok_and(|pdu| pdu.rest.is_empty() || DceRpcPdu::try_from(pdu.rest).is_ok())
    }
}

impl<'a> TryFrom<&'a [u8]> for DceRpcPdu<'a> {
    type Error = DceRpcError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let Some((header, after)) = bytes.split_first_chunk::<DCERPC_COMMON_HEADER_LENGTH>() else {
            return Err(DceRpcError::TooShort {
                expected: DCERPC_COMMON_HEADER_LENGTH,
                actual: bytes.len(),
            });
        };
        let [
            major,
            minor,
            ptype,
            flags,
            d0,
            d1,
            d2,
            d3,
            f0,
            f1,
            a0,
            a1,
            c0,
            c1,
            c2,
            c3,
        ] = *header;
        checks::version(major, minor)?;
        let pdu_type = checks::pdu_type(ptype)?;
        let data_representation = [d0, d1, d2, d3];
        let little_endian = checks::data_representation(data_representation)?;
        let (frag_length, auth_length, call_id) = if little_endian {
            (
                u16::from_le_bytes([f0, f1]),
                u16::from_le_bytes([a0, a1]),
                u32::from_le_bytes([c0, c1, c2, c3]),
            )
        } else {
            (
                u16::from_be_bytes([f0, f1]),
                u16::from_be_bytes([a0, a1]),
                u32::from_be_bytes([c0, c1, c2, c3]),
            )
        };
        checks::lengths(pdu_type, frag_length, auth_length)?;
        let body_length = (usize::from(frag_length) - DCERPC_COMMON_HEADER_LENGTH).min(after.len());
        let (body, rest) = after.split_at(body_length);
        Ok(Self {
            version_minor: minor,
            pdu_type,
            flags,
            little_endian,
            data_representation,
            frag_length,
            auth_length,
            call_id,
            body,
            rest,
        })
    }
}

mod checks {
    use super::{DCERPC_COMMON_HEADER_LENGTH, DceRpcError, DceRpcPduType};

    pub(super) fn version(major: u8, minor: u8) -> Result<(), DceRpcError> {
        if major == 5 && minor <= 1 {
            Ok(())
        } else {
            Err(DceRpcError::UnsupportedVersion { major, minor })
        }
    }

    pub(super) fn pdu_type(ptype: u8) -> Result<DceRpcPduType, DceRpcError> {
        Ok(match ptype {
            0 => DceRpcPduType::Request,
            2 => DceRpcPduType::Response,
            3 => DceRpcPduType::Fault,
            11 => DceRpcPduType::Bind,
            12 => DceRpcPduType::BindAck,
            13 => DceRpcPduType::BindNak,
            14 => DceRpcPduType::AlterContext,
            15 => DceRpcPduType::AlterContextResponse,
            16 => DceRpcPduType::Auth3,
            17 => DceRpcPduType::Shutdown,
            18 => DceRpcPduType::CoCancel,
            19 => DceRpcPduType::Orphaned,
            other => return Err(DceRpcError::UnknownPduType(other)),
        })
    }

    /// C706 §14.1 : entiers gros ou petit-boutistes, caracteres ASCII ou
    /// EBCDIC, quatre formats de flottants, deux octets reserves a zero.
    /// Rend `true` pour le petit-boutisme.
    pub(super) fn data_representation(label: [u8; 4]) -> Result<bool, DceRpcError> {
        let [first, float, 0, 0] = label else {
            return Err(DceRpcError::InvalidDataRepresentation(label));
        };
        if first >> 4 > 1 || first & 0x0F > 1 || float > 3 {
            return Err(DceRpcError::InvalidDataRepresentation(label));
        }
        Ok(first >> 4 == 1)
    }

    /// Octets que le type impose apres l'en-tete commun (C706 §12.6.4) :
    /// huit pour une requete, une reponse ou une faute (seize pour celle-ci),
    /// huit pour une liaison ou sa modification.
    fn minimum_length(pdu_type: DceRpcPduType) -> usize {
        DCERPC_COMMON_HEADER_LENGTH
            + match pdu_type {
                DceRpcPduType::Request
                | DceRpcPduType::Response
                | DceRpcPduType::Bind
                | DceRpcPduType::BindAck
                | DceRpcPduType::AlterContext
                | DceRpcPduType::AlterContextResponse => 8,
                DceRpcPduType::Fault => 16,
                DceRpcPduType::BindNak
                | DceRpcPduType::Auth3
                | DceRpcPduType::Shutdown
                | DceRpcPduType::CoCancel
                | DceRpcPduType::Orphaned => 0,
            }
    }

    pub(super) fn lengths(
        pdu_type: DceRpcPduType,
        frag_length: u16,
        auth_length: u16,
    ) -> Result<(), DceRpcError> {
        let minimum = minimum_length(pdu_type);
        if usize::from(frag_length) < minimum {
            return Err(DceRpcError::FragmentTooShort {
                frag_length,
                minimum,
            });
        }
        // Une valeur d'authentification est precedee de huit octets
        // (sec_trailer) : type, niveau, bourrage, contexte.
        let needed = match auth_length {
            0 => 0,
            length => usize::from(length) + 8,
        };
        if minimum + needed > usize::from(frag_length) {
            return Err(DceRpcError::InvalidAuthLength {
                auth_length,
                frag_length,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bind reel : The-Ultimate-PCAP.pcapng, trame 40261 (160 octets).
    const BIND: &str = concat!(
        "05000b0310000000a000000002000000d016d016000000000300000000000100",
        "0883afe11f5dc91191a408002b14a0fa03000000045d888aeb1cc9119fe80800",
        "2b10486002000000010001000883afe11f5dc91191a408002b14a0fa03000000",
        "33057171babe37498319b5dbef9ccc3601000000020001000883afe11f5dc911",
        "91a408002b14a0fa030000002c1cb76c12984045030000000000000001000000",
    );

    /// Request reel : meme capture, trame 40263 (168 octets, opnum 3).
    const REQUEST: &str = concat!(
        "0500000310000000a80000000200000090000000010003000100000000000000",
        "0000000000000000000000000000000002000000000000004b00000000000000",
        "4b000000050013000d354251e3064bd111ab0400c04fc2dcd204000200000013",
        "000d045d888aeb1cc9119fe808002b10486002000200000001000b0200000001",
        "0007020000870100090400000000000000000000000000000000000000000000",
        "0000000004000000",
    );

    fn hex(text: &str) -> Vec<u8> {
        hex::decode(text).expect("hexa valide")
    }

    #[test]
    fn bind_header_is_read() {
        let bytes = hex(BIND);
        let pdu = DceRpcPdu::try_from(bytes.as_slice()).expect("Bind");
        assert_eq!(pdu.version_minor, 0);
        assert_eq!(pdu.pdu_type, DceRpcPduType::Bind);
        assert_eq!(pdu.pdu_type.as_u8(), 11);
        assert!(pdu.is_first_fragment() && pdu.is_last_fragment());
        assert!(pdu.little_endian);
        assert_eq!(pdu.data_representation, [0x10, 0, 0, 0]);
        assert_eq!(pdu.frag_length, 160);
        assert_eq!(pdu.auth_length, 0);
        assert_eq!(pdu.call_id, 2);
        assert_eq!(pdu.body.len(), 144);
        assert!(pdu.rest().is_empty());
        assert!(!pdu.is_truncated());
        assert_eq!(pdu.request(), None);
        assert!(DceRpcPdu::is_blind_match(&bytes));
    }

    #[test]
    fn request_fields_are_read() {
        let bytes = hex(REQUEST);
        let pdu = DceRpcPdu::try_from(bytes.as_slice()).expect("Request");
        assert_eq!(pdu.pdu_type, DceRpcPduType::Request);
        assert_eq!(pdu.frag_length, 168);
        assert_eq!(
            pdu.request(),
            Some(DceRpcRequest {
                alloc_hint: 144,
                context_id: 1,
                opnum: 3,
            })
        );
        assert!(DceRpcPdu::is_blind_match(&bytes));
    }

    #[test]
    fn a_segment_shorter_than_the_fragment_is_truncated() {
        // Le Request reel, coupe apres 40 octets comme par un segment TCP.
        let bytes = hex(REQUEST);
        let pdu = DceRpcPdu::try_from(&bytes[..40]).expect("Request coupe");
        assert!(pdu.is_truncated());
        assert_eq!(pdu.body.len(), 24);
        assert_eq!(pdu.request().map(|request| request.opnum), Some(3));
        // Coupe avant le numero d'operation : l'en-tete reste lisible.
        let pdu = DceRpcPdu::try_from(&bytes[..20]).expect("en-tete seul");
        assert_eq!(pdu.request(), None);
    }

    #[test]
    fn two_pdus_in_one_segment() {
        // Le Bind et le Request reels, mis bout a bout : la suite du premier
        // est le second. Une suite qui n'est pas un PDU refuse la sonde.
        let mut bytes = hex(BIND);
        bytes.extend(hex(REQUEST));
        let first = DceRpcPdu::try_from(bytes.as_slice()).unwrap();
        assert_eq!(first.rest().len(), 168);
        let second = DceRpcPdu::try_from(first.rest()).unwrap();
        assert_eq!(second.pdu_type, DceRpcPduType::Request);
        assert!(DceRpcPdu::is_blind_match(&bytes));
        bytes.truncate(160 + 4);
        assert!(!DceRpcPdu::is_blind_match(&bytes));
    }

    // Les tests qui suivent alterent des octets des trames reelles, ou en
    // ecrivent a la main, pour viser une branche precise.

    #[test]
    fn synthetic_big_endian_header() {
        // Shutdown, entiers gros-boutistes, caracteres EBCDIC.
        let bytes = hex("05011103010000000010000000000007");
        let pdu = DceRpcPdu::try_from(bytes.as_slice()).unwrap();
        assert_eq!(pdu.version_minor, 1);
        assert_eq!(pdu.pdu_type, DceRpcPduType::Shutdown);
        assert!(!pdu.little_endian);
        assert_eq!((pdu.frag_length, pdu.auth_length, pdu.call_id), (16, 0, 7));

        // Request gros-boutiste : alloc_hint 2, contexte 1, opnum 9.
        let bytes = hex("050000030000000000180000000000070000000200010009");
        let pdu = DceRpcPdu::try_from(bytes.as_slice()).unwrap();
        assert_eq!(
            pdu.request(),
            Some(DceRpcRequest {
                alloc_hint: 2,
                context_id: 1,
                opnum: 9,
            })
        );
    }

    #[test]
    fn synthetic_every_pdu_type_round_trips() {
        for ptype in [0u8, 2, 3, 11, 12, 13, 14, 15, 16, 17, 18, 19] {
            assert_eq!(checks::pdu_type(ptype).unwrap().as_u8(), ptype);
        }
        for ptype in [1u8, 4, 10, 20, 255] {
            assert_eq!(
                checks::pdu_type(ptype),
                Err(DceRpcError::UnknownPduType(ptype))
            );
        }
    }

    #[test]
    fn altered_headers_are_refused() {
        let alter = |index: usize, value: u8| {
            let mut bytes = hex(REQUEST);
            bytes[index] = value;
            DceRpcPdu::try_from(bytes.as_slice()).map(|_| ())
        };
        assert_eq!(
            alter(0, 4),
            Err(DceRpcError::UnsupportedVersion { major: 4, minor: 0 })
        );
        assert_eq!(
            alter(1, 2),
            Err(DceRpcError::UnsupportedVersion { major: 5, minor: 2 })
        );
        assert_eq!(alter(2, 1), Err(DceRpcError::UnknownPduType(1)));
        for (index, value) in [(4, 0x20), (4, 0x12), (5, 4), (6, 1), (7, 1)] {
            assert!(
                matches!(
                    alter(index, value),
                    Err(DceRpcError::InvalidDataRepresentation(_))
                ),
                "octet {index}"
            );
        }
        // frag_length 23 : sous les 24 octets d'une requete.
        assert_eq!(
            alter(8, 23),
            Err(DceRpcError::FragmentTooShort {
                frag_length: 23,
                minimum: 24
            })
        );
        // auth_length 200 dans un fragment de 168 octets.
        assert_eq!(
            alter(10, 200),
            Err(DceRpcError::InvalidAuthLength {
                auth_length: 200,
                frag_length: 168
            })
        );
        assert_eq!(
            DceRpcPdu::try_from(&hex(REQUEST)[..15]).map(|_| ()),
            Err(DceRpcError::TooShort {
                expected: 16,
                actual: 15
            })
        );
    }
}
