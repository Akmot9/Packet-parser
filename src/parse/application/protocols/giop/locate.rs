// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Messages GIOP LocateRequest / LocateReply (CORBA formal/04-03-12
//! §15.4.5 et §15.4.6), CancelRequest (§15.4.4) et Fragment (§15.4.9).

use super::{
    TargetAddress, cursor::Cursor, ior::Ior, parse_target_address, reply::GiopSystemException,
};
use crate::{
    checks::application::giop::validate_locate_status, errors::application::giop::GiopParseError,
};

/// Message CancelRequest : le client n'attend plus la reponse a
/// `request_id`. Meme layout dans les trois versions.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct GiopCancelRequest {
    pub request_id: u32,
}

impl GiopCancelRequest {
    pub fn parse(body: &[u8], little_endian: bool) -> Result<Self, GiopParseError> {
        let mut cur = Cursor::new(body, little_endian);
        Ok(GiopCancelRequest {
            request_id: cur.read_u32()?,
        })
    }
}

/// Message LocateRequest : « cet objet est-il servi ici ? ».
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct GiopLocateRequest<'a> {
    pub request_id: u32,
    /// GIOP 1.0/1.1 : toujours [`TargetAddress::KeyAddr`] (object_key).
    pub target: TargetAddress<'a>,
}

impl<'a> GiopLocateRequest<'a> {
    /// Layout GIOP 1.2 : request_id puis TargetAddress.
    pub fn parse(body: &'a [u8], little_endian: bool) -> Result<Self, GiopParseError> {
        let mut cur = Cursor::new(body, little_endian);
        let request_id = cur.read_u32()?;
        let target = parse_target_address(&mut cur)?;
        Ok(GiopLocateRequest { request_id, target })
    }

    /// Layout GIOP 1.0/1.1 : request_id puis object_key (`sequence<octet>`).
    pub(super) fn parse_1_0_1_1(
        body: &'a [u8],
        little_endian: bool,
    ) -> Result<Self, GiopParseError> {
        let mut cur = Cursor::new(body, little_endian);
        let request_id = cur.read_u32()?;
        let target = TargetAddress::KeyAddr(cur.read_octet_sequence()?);
        Ok(GiopLocateRequest { request_id, target })
    }
}

/// `LocateStatusType` (§15.4.6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum GiopLocateStatus {
    UnknownObject,
    ObjectHere,
    ObjectForward,
    /// GIOP 1.2.
    ObjectForwardPerm,
    /// GIOP 1.2.
    LocSystemException,
    /// GIOP 1.2.
    LocNeedsAddressingMode,
}

impl GiopLocateStatus {
    /// Type la valeur lue sur le wire pour un message GIOP 1.`minor_version`.
    /// La version est exigee : `ObjectForwardPerm`, `LocSystemException` et
    /// `LocNeedsAddressingMode` n'existent qu'en GIOP 1.2.
    pub fn from_wire(value: u32, minor_version: u8) -> Result<Self, GiopParseError> {
        use GiopLocateStatus::*;
        let value = validate_locate_status(value, minor_version)?;
        Ok(match value {
            0 => UnknownObject,
            1 => ObjectHere,
            2 => ObjectForward,
            3 => ObjectForwardPerm,
            4 => LocSystemException,
            5 => LocNeedsAddressingMode,
            // Inatteignable : validate_locate_status borne value.
            _ => {
                return Err(GiopParseError::UnknownLocateStatus {
                    status: value,
                    minor_version,
                });
            }
        })
    }
}

/// Lecture typee du body d'un LocateReply, selon son statut.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GiopLocateReplyDetail<'a> {
    /// `UNKNOWN_OBJECT` et `OBJECT_HERE` : pas de body.
    None,
    /// `OBJECT_FORWARD` et `OBJECT_FORWARD_PERM`.
    ObjectForward(Ior<'a>),
    SystemException(GiopSystemException<'a>),
    /// `LOC_NEEDS_ADDRESSING_MODE` : `GIOP::AddressingDisposition` attendue.
    NeedsAddressingMode(u16),
    /// Le body n'a pas pu etre lu selon son statut ; `body` garde les octets.
    Undecoded,
}

/// Message LocateReply. Meme en-tete dans les trois versions ; le body suit
/// **sans** alignement sur 8, y compris en GIOP 1.2 (§15.4.6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct GiopLocateReply<'a> {
    pub request_id: u32,
    pub locate_status: GiopLocateStatus,
    pub body: &'a [u8],
    pub detail: GiopLocateReplyDetail<'a>,
}

impl<'a> GiopLocateReply<'a> {
    pub fn parse(
        body: &'a [u8],
        little_endian: bool,
        minor_version: u8,
    ) -> Result<Self, GiopParseError> {
        let mut cur = Cursor::new(body, little_endian);
        let request_id = cur.read_u32()?;
        let locate_status = GiopLocateStatus::from_wire(cur.read_u32()?, minor_version)?;
        let rest = cur.rest();
        let detail =
            parse_locate_detail(locate_status, cur).unwrap_or(GiopLocateReplyDetail::Undecoded);
        Ok(GiopLocateReply {
            request_id,
            locate_status,
            body: rest,
            detail,
        })
    }
}

fn parse_locate_detail<'a>(
    status: GiopLocateStatus,
    mut cur: Cursor<'a>,
) -> Result<GiopLocateReplyDetail<'a>, GiopParseError> {
    Ok(match status {
        GiopLocateStatus::UnknownObject | GiopLocateStatus::ObjectHere => {
            GiopLocateReplyDetail::None
        }
        GiopLocateStatus::ObjectForward | GiopLocateStatus::ObjectForwardPerm => {
            GiopLocateReplyDetail::ObjectForward(Ior::parse(&mut cur)?)
        }
        GiopLocateStatus::LocSystemException => {
            GiopLocateReplyDetail::SystemException(GiopSystemException::parse(&mut cur)?)
        }
        GiopLocateStatus::LocNeedsAddressingMode => {
            GiopLocateReplyDetail::NeedsAddressingMode(cur.read_u16()?)
        }
    })
}

/// Message Fragment (GIOP 1.1+) : suite d'un message dont le header portait
/// le bit « more fragments ». Un parseur stateless ne reassemble pas : il
/// expose le fragment et l'identifiant qui permet a l'appelant de le faire.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct GiopFragment<'a> {
    /// GIOP 1.2 : identifiant de la requete fragmentee. `None` en GIOP 1.1,
    /// dont le Fragment n'a pas d'en-tete (la connexion ne porte alors qu'un
    /// message fragmente a la fois).
    pub request_id: Option<u32>,
    pub data: &'a [u8],
}

impl<'a> GiopFragment<'a> {
    pub(super) fn parse(
        body: &'a [u8],
        little_endian: bool,
        minor_version: u8,
    ) -> Result<Self, GiopParseError> {
        let mut cur = Cursor::new(body, little_endian);
        let request_id = if minor_version >= 2 {
            Some(cur.read_u32()?)
        } else {
            None
        };
        Ok(GiopFragment {
            request_id,
            data: cur.rest(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locate_status_covers_the_six_spec_values() {
        for (raw, expected) in [
            (0u32, GiopLocateStatus::UnknownObject),
            (1, GiopLocateStatus::ObjectHere),
            (2, GiopLocateStatus::ObjectForward),
            (3, GiopLocateStatus::ObjectForwardPerm),
            (4, GiopLocateStatus::LocSystemException),
            (5, GiopLocateStatus::LocNeedsAddressingMode),
        ] {
            assert_eq!(GiopLocateStatus::from_wire(raw, 2), Ok(expected));
        }
        assert!(matches!(
            GiopLocateStatus::from_wire(6, 2),
            Err(GiopParseError::UnknownLocateStatus { status: 6, .. })
        ));
    }

    /// Meme regle que pour le Reply : les statuts introduits par GIOP 1.2
    /// sont refuses sur un LocateReply 1.0 ou 1.1.
    #[test]
    fn legacy_locate_reply_rejects_the_statuses_introduced_by_giop_1_2() {
        for status in [3u32, 4, 5] {
            let mut body = Vec::new();
            body.extend_from_slice(&2u32.to_be_bytes()); // request_id
            body.extend_from_slice(&status.to_be_bytes());

            for minor in [0, 1] {
                assert!(
                    matches!(
                        GiopLocateReply::parse(&body, false, minor),
                        Err(GiopParseError::UnknownLocateStatus { status: s, .. }) if s == status
                    ),
                    "statut {status} accepte en GIOP 1.{minor}"
                );
            }
            assert!(GiopLocateReply::parse(&body, false, 2).is_ok());
        }
    }

    #[test]
    fn cancel_request_reads_the_request_id_in_both_byte_orders() {
        assert_eq!(
            GiopCancelRequest::parse(&7u32.to_be_bytes(), false),
            Ok(GiopCancelRequest { request_id: 7 })
        );
        assert_eq!(
            GiopCancelRequest::parse(&7u32.to_le_bytes(), true),
            Ok(GiopCancelRequest { request_id: 7 })
        );
        assert!(matches!(
            GiopCancelRequest::parse(&[0, 0], false),
            Err(GiopParseError::UnexpectedEof)
        ));
    }

    #[test]
    fn locate_request_1_0_carries_a_bare_object_key() {
        let mut body = Vec::new();
        body.extend_from_slice(&3u32.to_be_bytes());
        body.extend_from_slice(&3u32.to_be_bytes());
        body.extend_from_slice(b"key");

        let request = GiopLocateRequest::parse_1_0_1_1(&body, false).expect("locate 1.0");
        assert_eq!(request.request_id, 3);
        assert_eq!(request.target, TargetAddress::KeyAddr(b"key"));
    }

    #[test]
    fn locate_reply_needs_addressing_mode_and_truncated_forward() {
        let mut body = Vec::new();
        body.extend_from_slice(&4u32.to_be_bytes());
        body.extend_from_slice(&5u32.to_be_bytes());
        body.extend_from_slice(&2u16.to_be_bytes());
        let reply = GiopLocateReply::parse(&body, false, 2).expect("locate reply");
        assert_eq!(reply.detail, GiopLocateReplyDetail::NeedsAddressingMode(2));

        // OBJECT_FORWARD sans IOR : l'en-tete reste lisible.
        let mut body = Vec::new();
        body.extend_from_slice(&4u32.to_be_bytes());
        body.extend_from_slice(&2u32.to_be_bytes());
        let reply = GiopLocateReply::parse(&body, false, 2).expect("en-tete lisible");
        assert_eq!(reply.locate_status, GiopLocateStatus::ObjectForward);
        assert_eq!(reply.detail, GiopLocateReplyDetail::Undecoded);
    }

    #[test]
    fn fragment_has_a_request_id_only_from_giop_1_2() {
        let mut body = Vec::new();
        body.extend_from_slice(&9u32.to_be_bytes());
        body.extend_from_slice(&[1, 2, 3]);

        let fragment = GiopFragment::parse(&body, false, 2).expect("fragment 1.2");
        assert_eq!(fragment.request_id, Some(9));
        assert_eq!(fragment.data, &[1, 2, 3]);

        let fragment = GiopFragment::parse(&body, false, 1).expect("fragment 1.1");
        assert_eq!(fragment.request_id, None);
        assert_eq!(fragment.data.len(), 7);
    }
}
