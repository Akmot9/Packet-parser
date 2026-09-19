// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Message GIOP Reply (CORBA formal/04-03-12 §15.4.3).

use std::convert::TryFrom;

use super::{ServiceContext, cursor::Cursor, ior::Ior, parse_service_context_list};
use crate::{
    checks::application::giop::validate_reply_status, errors::application::giop::GiopParseError,
};

/// `ReplyStatusType` (§15.4.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum GiopReplyStatus {
    NoException,
    UserException,
    SystemException,
    LocationForward,
    /// GIOP 1.2.
    LocationForwardPerm,
    /// GIOP 1.2.
    NeedsAddressingMode,
}

impl TryFrom<u32> for GiopReplyStatus {
    type Error = GiopParseError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        use GiopReplyStatus::*;
        // La regle de validation (0..=5) vit dans checks ; ce match ne fait
        // que typer une valeur deja validee.
        let value = validate_reply_status(value)?;
        Ok(match value {
            0 => NoException,
            1 => UserException,
            2 => SystemException,
            3 => LocationForward,
            4 => LocationForwardPerm,
            5 => NeedsAddressingMode,
            // Inatteignable : validate_reply_status garantit value <= 5.
            _ => return Err(GiopParseError::UnknownReplyStatus(value)),
        })
    }
}

/// Corps d'une exception systeme (§15.4.3.2) : commun a Reply
/// `SYSTEM_EXCEPTION` et a LocateReply `LOC_SYSTEM_EXCEPTION`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct GiopSystemException<'a> {
    /// Repository ID, par exemple `IDL:omg.org/CORBA/OBJECT_NOT_EXIST:1.0`.
    pub exception_id: &'a str,
    pub minor_code: u32,
    /// 0 = COMPLETED_YES, 1 = COMPLETED_NO, 2 = COMPLETED_MAYBE.
    pub completion_status: u32,
}

impl<'a> GiopSystemException<'a> {
    pub(super) fn parse(cur: &mut Cursor<'a>) -> Result<Self, GiopParseError> {
        Ok(GiopSystemException {
            exception_id: cur.read_str()?,
            minor_code: cur.read_u32()?,
            completion_status: cur.read_u32()?,
        })
    }
}

/// Lecture typee du body d'un Reply, selon son statut.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GiopReplyDetail<'a> {
    /// `NO_EXCEPTION` : le body porte les resultats de l'operation, dont le
    /// type depend de l'IDL — opaque pour un parseur sans IDL.
    Results,
    /// `USER_EXCEPTION` : Repository ID de l'exception, puis ses membres
    /// encodes en CDR — types par l'IDL, donc rendus bruts.
    UserException {
        exception_id: &'a str,
        members: &'a [u8],
    },
    SystemException(GiopSystemException<'a>),
    /// `LOCATION_FORWARD` et `LOCATION_FORWARD_PERM` : la reference vers
    /// laquelle le client doit reemettre sa requete.
    LocationForward(Ior<'a>),
    /// `NEEDS_ADDRESSING_MODE` : `GIOP::AddressingDisposition` attendue.
    NeedsAddressingMode(u16),
    /// Le body n'a pas pu etre lu selon son statut (message tronque par la
    /// segmentation TCP, ou malforme). `body` garde les octets bruts.
    Undecoded,
}

/// Message Reply decode.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct GiopReply<'a> {
    pub request_id: u32,
    pub reply_status: GiopReplyStatus,
    pub service_contexts: Vec<ServiceContext<'a>>,
    /// Body brut, padding d'alignement exclu (zero-copy).
    pub body: &'a [u8],
    pub detail: GiopReplyDetail<'a>,
}

impl<'a> GiopReply<'a> {
    /// Parse un Reply au layout GIOP 1.2 : request_id, reply_status, service
    /// contexts, puis body aligne sur 8 octets.
    pub fn parse(body: &'a [u8], little_endian: bool) -> Result<Self, GiopParseError> {
        let mut cur = Cursor::new(body, little_endian);

        let request_id = cur.read_u32()?;
        let reply_status = GiopReplyStatus::try_from(cur.read_u32()?)?;
        let service_contexts = parse_service_context_list(&mut cur)?;
        cur.align_body_1_2();

        Ok(Self::finish(
            request_id,
            reply_status,
            service_contexts,
            cur,
        ))
    }

    /// Parse un Reply au layout historique GIOP 1.0/1.1 : service contexts en
    /// tete, puis request_id et reply_status ; le body suit sans alignement
    /// sur 8.
    pub(super) fn parse_1_0_1_1(
        body: &'a [u8],
        little_endian: bool,
    ) -> Result<Self, GiopParseError> {
        let mut cur = Cursor::new(body, little_endian);

        let service_contexts = parse_service_context_list(&mut cur)?;
        let request_id = cur.read_u32()?;
        let reply_status = GiopReplyStatus::try_from(cur.read_u32()?)?;

        Ok(Self::finish(
            request_id,
            reply_status,
            service_contexts,
            cur,
        ))
    }

    fn finish(
        request_id: u32,
        reply_status: GiopReplyStatus,
        service_contexts: Vec<ServiceContext<'a>>,
        cur: Cursor<'a>,
    ) -> Self {
        let body = cur.rest();
        // Un detail illisible ne fait pas echouer le Reply : l'en-tete est
        // deja fiable, le body brut reste disponible.
        let detail = parse_detail(reply_status, cur).unwrap_or(GiopReplyDetail::Undecoded);
        GiopReply {
            request_id,
            reply_status,
            service_contexts,
            body,
            detail,
        }
    }
}

fn parse_detail<'a>(
    status: GiopReplyStatus,
    mut cur: Cursor<'a>,
) -> Result<GiopReplyDetail<'a>, GiopParseError> {
    Ok(match status {
        GiopReplyStatus::NoException => GiopReplyDetail::Results,
        GiopReplyStatus::UserException => GiopReplyDetail::UserException {
            exception_id: cur.read_str()?,
            members: cur.rest(),
        },
        GiopReplyStatus::SystemException => {
            GiopReplyDetail::SystemException(GiopSystemException::parse(&mut cur)?)
        }
        GiopReplyStatus::LocationForward | GiopReplyStatus::LocationForwardPerm => {
            GiopReplyDetail::LocationForward(Ior::parse(&mut cur)?)
        }
        GiopReplyStatus::NeedsAddressingMode => {
            GiopReplyDetail::NeedsAddressingMode(cur.read_u16()?)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_status_covers_the_six_spec_values() {
        for (raw, expected) in [
            (0u32, GiopReplyStatus::NoException),
            (1, GiopReplyStatus::UserException),
            (2, GiopReplyStatus::SystemException),
            (3, GiopReplyStatus::LocationForward),
            (4, GiopReplyStatus::LocationForwardPerm),
            (5, GiopReplyStatus::NeedsAddressingMode),
        ] {
            assert_eq!(GiopReplyStatus::try_from(raw), Ok(expected));
        }
        assert!(matches!(
            GiopReplyStatus::try_from(6),
            Err(GiopParseError::UnknownReplyStatus(6))
        ));
    }

    #[test]
    fn reply_1_2_skips_the_8_byte_body_padding() {
        // request_id 5, USER_EXCEPTION, 1 service context de 2 octets : le
        // curseur est a l'offset 22 du body = 34 du message, donc 6 octets
        // de padding avant le body.
        let mut body = Vec::new();
        body.extend_from_slice(&5u32.to_be_bytes());
        body.extend_from_slice(&1u32.to_be_bytes());
        body.extend_from_slice(&1u32.to_be_bytes()); // 1 service context
        body.extend_from_slice(&17u32.to_be_bytes());
        body.extend_from_slice(&2u32.to_be_bytes());
        body.extend_from_slice(&[0xAA, 0xBB]);
        body.extend_from_slice(&[0; 6]); // padding vers 8
        body.extend_from_slice(&6u32.to_be_bytes()); // exception_id "IDL:x" + NUL
        body.extend_from_slice(b"IDL:x\0");
        body.extend_from_slice(&[0xC0, 0xDE]); // membres de l'exception

        let reply = GiopReply::parse(&body, false).expect("reply valide");
        assert_eq!(reply.request_id, 5);
        assert_eq!(reply.reply_status, GiopReplyStatus::UserException);
        assert_eq!(reply.service_contexts.len(), 1);
        assert_eq!(reply.body.len(), 12);
        assert_eq!(
            reply.detail,
            GiopReplyDetail::UserException {
                exception_id: "IDL:x",
                members: &[0xC0, 0xDE],
            }
        );
    }

    #[test]
    fn reply_1_0_reads_contexts_first_and_a_system_exception() {
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes()); // 0 service context
        body.extend_from_slice(&9u32.to_le_bytes()); // request_id
        body.extend_from_slice(&2u32.to_le_bytes()); // SYSTEM_EXCEPTION
        body.extend_from_slice(&6u32.to_le_bytes());
        body.extend_from_slice(b"IDL:y\0");
        body.extend_from_slice(&[0, 0]); // padding vers 4
        body.extend_from_slice(&0x4f4d_0001u32.to_le_bytes()); // minor
        body.extend_from_slice(&1u32.to_le_bytes()); // COMPLETED_NO

        let reply = GiopReply::parse_1_0_1_1(&body, true).expect("reply 1.0 valide");
        assert_eq!(reply.request_id, 9);
        assert_eq!(reply.reply_status, GiopReplyStatus::SystemException);
        let GiopReplyDetail::SystemException(exception) = reply.detail else {
            panic!("attendu SystemException, obtenu {:?}", reply.detail);
        };
        assert_eq!(exception.exception_id, "IDL:y");
        assert_eq!(exception.minor_code, 0x4f4d_0001);
        assert_eq!(exception.completion_status, 1);
    }

    #[test]
    fn unreadable_detail_degrades_to_undecoded_and_keeps_the_header() {
        // LOCATION_FORWARD dont l'IOR est coupe : l'en-tete reste lisible.
        let mut body = Vec::new();
        body.extend_from_slice(&1u32.to_be_bytes());
        body.extend_from_slice(&3u32.to_be_bytes());
        body.extend_from_slice(&0u32.to_be_bytes());
        // Offset 12 du body = 24 du message : deja aligne sur 8, pas de padding.
        body.extend_from_slice(&100u32.to_be_bytes()); // type_id de 100 octets absent

        let reply = GiopReply::parse(&body, false).expect("en-tete lisible");
        assert_eq!(reply.reply_status, GiopReplyStatus::LocationForward);
        assert_eq!(reply.detail, GiopReplyDetail::Undecoded);
        assert_eq!(reply.body.len(), 4);
    }

    #[test]
    fn unknown_status_and_truncated_header_are_errors() {
        let mut body = Vec::new();
        body.extend_from_slice(&1u32.to_be_bytes());
        body.extend_from_slice(&9u32.to_be_bytes());
        assert!(matches!(
            GiopReply::parse(&body, false),
            Err(GiopParseError::UnknownReplyStatus(9))
        ));
        assert!(matches!(
            GiopReply::parse(&[0xDE, 0xAD], false),
            Err(GiopParseError::UnexpectedEof)
        ));
    }
}
