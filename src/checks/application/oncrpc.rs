// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Verifications du decodeur ONC RPC.
//!
//! Le message vient de la RFC 5531 §9, en XDR (RFC 4506) : des entiers de
//! quatre octets gros-boutistes, des champs opaques precedes de leur
//! longueur et completes a un multiple de quatre octets. La marque de
//! fragment de TCP vient de la RFC 5531 §11.

use crate::errors::application::oncrpc::OncRpcError;
use crate::parse::application::protocols::oncrpc::{
    OncRpcAcceptStatus, OncRpcAcceptedReply, OncRpcAuth, OncRpcBody, OncRpcCall, OncRpcMessage,
    OncRpcReply,
};

/// Version du protocole qu'un appel annonce.
const ONC_RPC_VERSION: u32 = 2;
/// Longueur maximale du corps d'un `opaque_auth`.
const ONC_RPC_MAX_AUTH_LENGTH: u32 = 400;
/// Longueur de la marque de fragment de TCP.
pub const ONC_RPC_RECORD_MARK_LENGTH: usize = 4;
/// Bit du dernier fragment d'un enregistrement.
const ONC_RPC_LAST_FRAGMENT: u32 = 0x8000_0000;
/// Le plus court message : une reponse refusee pour son authentifiant, cinq
/// entiers (xid, type, etat de la reponse, cause du refus, `auth_stat`).
const ONC_RPC_MESSAGE_MIN_LENGTH: u32 = 20;
/// La plus courte reponse acceptee : xid, type, etat de la reponse, un
/// verifieur vide (deux entiers) et l'etat d'acceptation.
const ONC_RPC_ACCEPTED_MIN_LENGTH: usize = 24;
/// Le plus court appel : xid, type, version, programme, sa version, la
/// procedure, puis deux `opaque_auth` vides.
const ONC_RPC_CALL_MIN_LENGTH: usize = 40;

const MESSAGE_CALL: u32 = 0;
const MESSAGE_REPLY: u32 = 1;
const REPLY_ACCEPTED: u32 = 0;
const REPLY_DENIED: u32 = 1;
const REJECT_RPC_MISMATCH: u32 = 0;
const REJECT_AUTH_ERROR: u32 = 1;

/// Un entier XDR, et ce qui le suit.
pub fn extract_u32<'a>(
    field: &'static str,
    bytes: &'a [u8],
) -> Result<(u32, &'a [u8]), OncRpcError> {
    let Some((value, rest)) = bytes.split_first_chunk::<4>() else {
        return Err(OncRpcError::TooShort {
            field,
            expected: 4,
            actual: bytes.len(),
        });
    };
    Ok((u32::from_be_bytes(*value), rest))
}

/// Une saveur d'authentification est un numero attribue du registre IANA
/// « RPC Authentication Flavor Numbers » (RFC 5531 §13.4 et annexe C, RFC
/// 9289 pour `AUTH_TLS`) : 0 a 7, les numeros historiques de Sun, et les
/// pseudo-saveurs de 390000 a 390255.
///
/// Sans cette borne, un segment de suite passe pour une reponse : dans une
/// liste de repertoire de NFS, « une entree suit » (1), le haut d'un
/// identifiant de fichier (0), son bas et la longueur d'un nom tombent ou
/// une reponse acceptee porte son etat, la saveur de son verifieur et sa
/// longueur (`wireshark_getsetacl.cap`, trame 33).
pub fn validate_auth_flavor(field: &'static str, flavor: u32) -> Result<(), OncRpcError> {
    match flavor {
        0..=7
        | 30_001
        | 200_000
        | 200_004
        | 300_000..=300_002
        | 390_000..=390_255
        | 200_100_000 => Ok(()),
        flavor => Err(OncRpcError::UnknownAuthFlavor { field, flavor }),
    }
}

/// Un `opaque_auth` (RFC 5531 §8.2) : la saveur, puis un corps d'au plus 400
/// octets, complete a un multiple de quatre.
pub fn extract_auth<'a>(
    field: &'static str,
    bytes: &'a [u8],
) -> Result<(OncRpcAuth<'a>, &'a [u8]), OncRpcError> {
    let (flavor, rest) = extract_u32(field, bytes)?;
    validate_auth_flavor(field, flavor)?;
    let (length, rest) = extract_u32(field, rest)?;
    if length > ONC_RPC_MAX_AUTH_LENGTH {
        return Err(OncRpcError::AuthBodyTooLong { field, length });
    }
    // Au plus 400 : la conversion et l'arrondi ne debordent pas.
    let length = length as usize;
    let padded = length.next_multiple_of(4);
    if rest.len() < padded {
        return Err(OncRpcError::TooShort {
            field,
            expected: padded,
            actual: rest.len(),
        });
    }
    let auth = OncRpcAuth::new(flavor, &rest[..length]);
    Ok((auth, &rest[padded..]))
}

/// Une reponse sans resultat s'arrete a son etat : rien ne la suit, ni
/// dans l'entree (`rest`), ni dans les octets que son fragment annonce et
/// que l'entree ne porte pas (`missing`).
fn validate_end(rest: &[u8], missing: usize) -> Result<(), OncRpcError> {
    match rest.len().saturating_add(missing) {
        0 => Ok(()),
        trailing => Err(OncRpcError::TrailingBytes(trailing)),
    }
}

/// Le corps d'un appel (RFC 5531 §9, `call_body`).
fn extract_call(bytes: &[u8]) -> Result<OncRpcCall<'_>, OncRpcError> {
    let (rpc_version, rest) = extract_u32("RPC version", bytes)?;
    if rpc_version != ONC_RPC_VERSION {
        return Err(OncRpcError::UnsupportedVersion(rpc_version));
    }
    let (program, rest) = extract_u32("program", rest)?;
    let (version, rest) = extract_u32("program version", rest)?;
    let (procedure, rest) = extract_u32("procedure", rest)?;
    let (credentials, rest) = extract_auth("credentials", rest)?;
    let (verifier, arguments) = extract_auth("verifier", rest)?;
    Ok(OncRpcCall::new(
        [program, version, procedure],
        credentials,
        verifier,
        arguments,
    ))
}

/// `accepted_reply` : le verifieur du serveur, l'etat, puis les resultats
/// d'un succes ou les versions d'un `PROG_MISMATCH`.
fn extract_accepted(bytes: &[u8], missing: usize) -> Result<OncRpcReply<'_>, OncRpcError> {
    let (verifier, rest) = extract_auth("verifier", bytes)?;
    let (code, rest) = extract_u32("accept status", rest)?;
    let (status, results) = match code {
        0 => (OncRpcAcceptStatus::Success, rest),
        1 => (OncRpcAcceptStatus::ProgramUnavailable, rest),
        2 => {
            let (low, rest) = extract_u32("mismatch information", rest)?;
            let (high, rest) = extract_u32("mismatch information", rest)?;
            (OncRpcAcceptStatus::ProgramMismatch { low, high }, rest)
        }
        3 => (OncRpcAcceptStatus::ProcedureUnavailable, rest),
        4 => (OncRpcAcceptStatus::GarbageArguments, rest),
        5 => (OncRpcAcceptStatus::SystemError, rest),
        other => return Err(OncRpcError::UnknownAcceptStatus(other)),
    };
    if status != OncRpcAcceptStatus::Success {
        validate_end(results, missing)?;
    }
    Ok(OncRpcReply::Accepted(OncRpcAcceptedReply::new(
        verifier, status, results,
    )))
}

/// `rejected_reply` : les versions d'un `RPC_MISMATCH`, ou la cause d'un
/// `AUTH_ERROR`.
fn extract_denied(bytes: &[u8], missing: usize) -> Result<OncRpcReply<'_>, OncRpcError> {
    let (code, rest) = extract_u32("reject status", bytes)?;
    let (reply, rest) = match code {
        REJECT_RPC_MISMATCH => {
            let (low, rest) = extract_u32("mismatch information", rest)?;
            let (high, rest) = extract_u32("mismatch information", rest)?;
            (OncRpcReply::RpcMismatch { low, high }, rest)
        }
        REJECT_AUTH_ERROR => {
            let (status, rest) = extract_u32("authentication status", rest)?;
            (OncRpcReply::AuthError { status }, rest)
        }
        other => return Err(OncRpcError::UnknownRejectStatus(other)),
    };
    validate_end(rest, missing)?;
    Ok(reply)
}

/// Un message : l'identifiant de transaction, le type, puis l'appel ou la
/// reponse. `missing` compte les octets que le fragment annonce au-dela de
/// l'entree : zero pour un datagramme ou un fragment entier.
pub fn extract_message(bytes: &[u8], missing: usize) -> Result<OncRpcMessage<'_>, OncRpcError> {
    let (xid, rest) = extract_u32("xid", bytes)?;
    let (kind, rest) = extract_u32("message type", rest)?;
    let body = match kind {
        MESSAGE_CALL => OncRpcBody::Call(extract_call(rest)?),
        MESSAGE_REPLY => {
            let (status, rest) = extract_u32("reply status", rest)?;
            OncRpcBody::Reply(match status {
                REPLY_ACCEPTED => extract_accepted(rest, missing)?,
                REPLY_DENIED => extract_denied(rest, missing)?,
                other => return Err(OncRpcError::UnknownReplyStatus(other)),
            })
        }
        other => return Err(OncRpcError::UnknownMessageType(other)),
    };
    Ok(OncRpcMessage::new(xid, body))
}

/// Le moins d'octets qu'un message qui s'ouvre comme `bytes` peut tenir,
/// d'apres son type et l'etat de sa reponse, s'ils se lisent deja.
///
/// Sert a juger une marque de fragment contre son message des que possible :
/// un fragment de 24 octets qui s'ouvre sur un appel ne le portera jamais,
/// meme si le segment le coupe avant que l'en-tete montre son defaut.
pub fn minimum_message_length(bytes: &[u8]) -> usize {
    let word = |offset: usize| {
        bytes
            .get(offset..offset + 4)
            .and_then(|word| word.first_chunk::<4>())
            .map(|word| u32::from_be_bytes(*word))
    };
    match (word(4), word(8)) {
        (Some(MESSAGE_CALL), _) => ONC_RPC_CALL_MIN_LENGTH,
        (Some(MESSAGE_REPLY), Some(REPLY_ACCEPTED)) => ONC_RPC_ACCEPTED_MIN_LENGTH,
        _ => ONC_RPC_MESSAGE_MIN_LENGTH as usize,
    }
}

/// La marque du premier fragment d'un enregistrement : le bit du dernier
/// fragment et la longueur du fragment, sur 31 bits.
///
/// Ce fragment porte l'en-tete du message. Une marque entiere se juge
/// seule, avant que le message soit lu : elle annonce au moins le plus
/// court message. Seule une marque coupee est « trop courte ».
pub fn extract_record_mark(bytes: &[u8]) -> Result<(bool, u32), OncRpcError> {
    let (mark, _) = extract_u32("record mark", bytes)?;
    let length = mark & !ONC_RPC_LAST_FRAGMENT;
    if length < ONC_RPC_MESSAGE_MIN_LENGTH {
        return Err(OncRpcError::FragmentTooShort { length });
    }
    Ok((mark & ONC_RPC_LAST_FRAGMENT != 0, length))
}

/// Les fragments de suite d'un enregistrement, dans un segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OncRpcContinuation<'a> {
    /// Les fragments, marques comprises.
    pub fragments: &'a [u8],
    /// Ce qui suit le dernier fragment : un autre enregistrement, ou rien.
    pub rest: &'a [u8],
    /// `true` quand le dernier fragment est la, entier.
    pub is_complete: bool,
    /// Somme des longueurs que les marques lues annoncent.
    pub announced: usize,
}

impl<'a> OncRpcContinuation<'a> {
    /// Aucun fragment de suite : l'enregistrement finit avec son premier
    /// fragment, ou le segment coupe celui-ci.
    pub fn none(rest: &'a [u8], is_complete: bool) -> Self {
        Self {
            fragments: &rest[..0],
            rest,
            is_complete,
            announced: 0,
        }
    }
}

/// Les fragments de suite d'un enregistrement (RFC 5531 §11), au debut de
/// `bytes` : chacun a sa marque, puis de zero a 2^31 - 1 octets, et le
/// dernier porte le bit de fin. Si le segment s'arrete avant la fin du
/// dernier fragment, l'enregistrement continue dans le segment suivant, et
/// tout `bytes` lui revient.
pub fn extract_continuation(bytes: &[u8]) -> OncRpcContinuation<'_> {
    let mut offset = 0;
    let mut announced = 0usize;
    let cut = |announced| OncRpcContinuation {
        fragments: bytes,
        rest: &bytes[bytes.len()..],
        is_complete: false,
        announced,
    };
    loop {
        let Some(mark) = bytes[offset..].first_chunk::<ONC_RPC_RECORD_MARK_LENGTH>() else {
            return cut(announced);
        };
        let mark = u32::from_be_bytes(*mark);
        let length = usize::try_from(mark & !ONC_RPC_LAST_FRAGMENT).unwrap_or(usize::MAX);
        announced = announced.saturating_add(length);
        let after = offset + ONC_RPC_RECORD_MARK_LENGTH;
        let Some(end) = after.checked_add(length).filter(|end| *end <= bytes.len()) else {
            return cut(announced);
        };
        offset = end;
        if mark & ONC_RPC_LAST_FRAGMENT != 0 {
            let (fragments, rest) = bytes.split_at(offset);
            return OncRpcContinuation {
                fragments,
                rest,
                is_complete: true,
                announced,
            };
        }
    }
}

/// Une reponse sans resultat tient dans son premier fragment : les
/// fragments de suite de son enregistrement, s'il en a, sont vides.
pub fn validate_continuation(
    message: &OncRpcMessage<'_>,
    continuation: &OncRpcContinuation<'_>,
) -> Result<(), OncRpcError> {
    let has_no_results = match message.body {
        OncRpcBody::Call(_) => false,
        OncRpcBody::Reply(OncRpcReply::Accepted(reply)) => {
            reply.status != OncRpcAcceptStatus::Success
        }
        OncRpcBody::Reply(_) => true,
    };
    if has_no_results && continuation.announced != 0 {
        return Err(OncRpcError::TrailingBytes(continuation.announced));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_bodies_are_padded_to_four_bytes() {
        // AUTH_SYS, cinq octets de corps, trois de bourrage, puis la suite.
        let bytes = [0, 0, 0, 1, 0, 0, 0, 5, 1, 2, 3, 4, 5, 0, 0, 0, 9];
        let (auth, rest) = extract_auth("credentials", &bytes).expect("opaque_auth");
        assert_eq!(auth.flavor, 1);
        assert_eq!(auth.body, [1, 2, 3, 4, 5]);
        assert_eq!(rest, [9]);

        // Le bourrage manque.
        assert_eq!(
            extract_auth("credentials", &bytes[..14]).map(|_| ()),
            Err(OncRpcError::TooShort {
                field: "credentials",
                expected: 8,
                actual: 6
            })
        );
        // 401 octets : un de trop.
        assert_eq!(
            extract_auth("verifier", &[0, 0, 0, 0, 0, 0, 0x01, 0x91]).map(|_| ()),
            Err(OncRpcError::AuthBodyTooLong {
                field: "verifier",
                length: 401
            })
        );
        assert_eq!(
            extract_auth("verifier", &[0, 0, 0, 0, 0, 0]).map(|_| ()),
            Err(OncRpcError::TooShort {
                field: "verifier",
                expected: 4,
                actual: 2
            })
        );
    }

    #[test]
    fn minimum_length_follows_the_message_type() {
        // xid, puis le type : un appel fait 40 octets au moins.
        assert_eq!(minimum_message_length(&[9, 9, 9, 9, 0, 0, 0, 0]), 40);
        // Une reponse acceptee, 24 ; refusee, 20.
        let accepted = [9, 9, 9, 9, 0, 0, 0, 1, 0, 0, 0, 0];
        assert_eq!(minimum_message_length(&accepted), 24);
        let denied = [9, 9, 9, 9, 0, 0, 0, 1, 0, 0, 0, 1];
        assert_eq!(minimum_message_length(&denied), 20);
        // Tant que le type, ou l'etat d'une reponse, ne se lit pas : 20.
        for cut in [
            &accepted[..0],
            &accepted[..7],
            &accepted[..8],
            &accepted[..11],
        ] {
            assert_eq!(minimum_message_length(cut), 20, "{cut:02x?}");
        }
    }

    #[test]
    fn auth_flavors_are_those_of_the_registry() {
        // AUTH_NONE a AUTH_TLS, AUTH_NW, AUTH_SEC, AUTH_ESV, AUTH_NQNFS a
        // AUTH_ILU_UGEN, les pseudo-saveurs, NeXT.
        for flavor in [
            0,
            1,
            6,
            7,
            30_001,
            200_000,
            200_004,
            300_000,
            300_002,
            390_000,
            390_255,
            200_100_000,
        ] {
            assert_eq!(validate_auth_flavor("credentials", flavor), Ok(()));
        }
        // Les numeros non attribues, dont le bas d'un identifiant de
        // fichier (trame 33 de wireshark_getsetacl.cap).
        for flavor in [
            8,
            30_000,
            30_002,
            200_001,
            300_003,
            389_999,
            390_256,
            0x005b_c010,
            u32::MAX,
        ] {
            assert_eq!(
                validate_auth_flavor("verifier", flavor),
                Err(OncRpcError::UnknownAuthFlavor {
                    field: "verifier",
                    flavor
                })
            );
        }
    }

    /// Synthetique : aucune capture du corpus ne coupe un enregistrement en
    /// plusieurs fragments.
    #[test]
    fn continuation_fragments_run_to_the_last_one() {
        let parts = |bytes| {
            let continuation = extract_continuation(bytes);
            (
                continuation.fragments,
                continuation.rest,
                continuation.is_complete,
                continuation.announced,
            )
        };
        // Deux octets, puis un dernier fragment vide, puis la suite.
        let bytes = [0, 0, 0, 2, 0xaa, 0xbb, 0x80, 0, 0, 0, 9, 9];
        assert_eq!(parts(&bytes), (&bytes[..10], &[9, 9][..], true, 2));
        // Un seul fragment, le dernier.
        let last = [0x80, 0, 0, 1, 7];
        assert_eq!(parts(&last), (&last[..], &[][..], true, 1));
        // Le dernier fragment manque, sa marque est coupee, ou il est
        // coupe : l'enregistrement continue au segment suivant.
        let cuts: [(&[u8], usize); 4] = [
            (&bytes[..6], 2),
            (&bytes[..8], 2),
            (&[0x80, 0, 0, 5, 1], 5),
            (&[], 0),
        ];
        for (cut, announced) in cuts {
            assert_eq!(parts(cut), (cut, &[][..], false, announced), "{cut:02x?}");
        }
        // Une longueur de 2^31 - 1 ne deborde pas.
        let huge = [0x7f, 0xff, 0xff, 0xff, 1];
        assert_eq!(parts(&huge), (&huge[..], &[][..], false, 0x7fff_ffff));
    }

    #[test]
    fn record_mark_splits_its_bit_and_its_length() {
        assert_eq!(extract_record_mark(&[0x80, 0, 0, 0x8c, 1]), Ok((true, 140)));
        assert_eq!(extract_record_mark(&[0, 0, 0x10, 0]), Ok((false, 4096)));
        // Une marque entiere se juge seule : sous les vingt octets du plus
        // court message, elle n'ouvre aucun enregistrement.
        assert_eq!(extract_record_mark(&[0x80, 0, 0, 20]), Ok((true, 20)));
        for length in [0, 19] {
            assert_eq!(
                extract_record_mark(&[0x80, 0, 0, length]),
                Err(OncRpcError::FragmentTooShort {
                    length: u32::from(length)
                })
            );
        }
        assert_eq!(
            extract_record_mark(&[0x80, 0, 0]),
            Err(OncRpcError::TooShort {
                field: "record mark",
                expected: 4,
                actual: 3
            })
        );
    }
}
