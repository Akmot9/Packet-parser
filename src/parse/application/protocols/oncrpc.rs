// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! ONC RPC (RFC 5531, #381), l'appel de procedure distante de Sun : le
//! transport de NFS, du portmapper, de `mountd`, de NLM et de NIS.
//!
//! Un message est un appel ou une reponse, lies par un identifiant de
//! transaction. L'appel nomme un programme, sa version et une procedure, et
//! porte un authentifiant et un verifieur ; la reponse est acceptee, avec un
//! etat, ou refusee, avec sa cause. Les arguments et les resultats sont
//! empruntes sans etre decodes : leur format est celui de chaque programme.
//!
//! Sur UDP, un datagramme porte un message. Sur TCP, chaque message suit une
//! marque de fragment de quatre octets ([`OncRpcRecord`], RFC 5531 §11).
//!
//! Detection : regles a port sur 111 (portmapper) et 2049 (NFS), en UDP et
//! en TCP. Les autres programmes (`mountd`, `statd`, `lockd`) prennent un
//! port que le portmapper annonce : il se declare par Decode As. Pas de
//! sonde aveugle : un appel s'ouvre par huit octets presque tous nuls, une
//! reponse aussi, ce que bien d'autres formats font.
//!
//! Limites, sans etat : une reponse ne dit ni son programme ni sa procedure,
//! que seul l'appel porte. Un message plus long que son segment est coupe
//! ([`OncRpcRecord::is_truncated`]) et les segments de suite restent
//! `Unknown`. D'un enregistrement en plusieurs fragments, seul le premier,
//! qui porte l'en-tete, est lu ; les suivants sont rendus bruts
//! ([`OncRpcRecord::continuation`]).

use std::convert::TryFrom;

use crate::checks::application::oncrpc::{
    ONC_RPC_RECORD_MARK_LENGTH, OncRpcContinuation, extract_continuation, extract_message,
    extract_record_mark, minimum_message_length, validate_continuation,
};
use crate::errors::application::oncrpc::OncRpcError;

/// One ONC RPC message (RFC 5531 §9): a call or a reply.
///
/// ```mermaid
/// ---
/// title: OncRpcMessage, a call (XDR, big-endian)
/// ---
/// packet-beta
/// 0-31: "xid"
/// 32-63: "msg_type = 0 (call)"
/// 64-95: "rpcvers = 2"
/// 96-127: "program"
/// 128-159: "program version"
/// 160-191: "procedure"
/// 192-223: "credentials: flavor"
/// 224-255: "credentials: length (at most 400)"
/// 256-287: "credentials: body, padded to 4 bytes"
/// 288-319: "verifier: flavor"
/// 320-351: "verifier: length (at most 400)"
/// 352-383: "verifier: body, padded to 4 bytes"
/// 384-415: "arguments"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct OncRpcMessage<'a> {
    /// Transaction identifier: a reply carries that of its call.
    pub xid: u32,
    /// The call or the reply.
    pub body: OncRpcBody<'a>,
}

impl<'a> OncRpcMessage<'a> {
    pub(crate) fn new(xid: u32, body: OncRpcBody<'a>) -> Self {
        Self { xid, body }
    }
}

impl<'a> TryFrom<&'a [u8]> for OncRpcMessage<'a> {
    type Error = OncRpcError;

    /// Reads one whole message: a UDP datagram, or a record fragment
    /// without its mark.
    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        extract_message(bytes, 0)
    }
}

/// The body of an [`OncRpcMessage`], by its `msg_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OncRpcBody<'a> {
    /// `CALL` (0).
    Call(OncRpcCall<'a>),
    /// `REPLY` (1).
    Reply(OncRpcReply<'a>),
}

/// A call (RFC 5531 §9, `call_body`), of version 2 of the protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct OncRpcCall<'a> {
    /// Number of the remote program: 100000 is the portmapper, 100003 NFS,
    /// 100005 `mountd`.
    pub program: u32,
    /// Version of the program: 2, 3 or 4 for NFS.
    pub version: u32,
    /// Number of the procedure in the program; 0 is the null procedure.
    pub procedure: u32,
    /// Who calls.
    pub credentials: OncRpcAuth<'a>,
    /// The proof that goes with the credentials, often empty.
    pub verifier: OncRpcAuth<'a>,
    /// Arguments of the procedure, in the XDR of the program, up to the
    /// end of the input.
    pub arguments: &'a [u8],
}

impl<'a> OncRpcCall<'a> {
    pub(crate) fn new(
        [program, version, procedure]: [u32; 3],
        credentials: OncRpcAuth<'a>,
        verifier: OncRpcAuth<'a>,
        arguments: &'a [u8],
    ) -> Self {
        Self {
            program,
            version,
            procedure,
            credentials,
            verifier,
            arguments,
        }
    }

    /// The name of the program in the registry of RPC program numbers
    /// (the `/etc/rpc` of a Unix host), for the most common ones.
    pub fn program_name(&self) -> Option<&'static str> {
        Some(match self.program {
            100_000 => "portmapper",
            100_001 => "rstatd",
            100_002 => "rusersd",
            100_003 => "nfs",
            100_004 => "ypserv",
            100_005 => "mountd",
            100_007 => "ypbind",
            100_008 => "walld",
            100_009 => "yppasswdd",
            100_011 => "rquotad",
            100_012 => "sprayd",
            100_021 => "nlockmgr",
            100_024 => "status",
            100_227 => "nfs_acl",
            _ => return None,
        })
    }
}

/// An `opaque_auth` (RFC 5531 §8.2): credentials or a verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct OncRpcAuth<'a> {
    /// Authentication flavor: 0 `AUTH_NONE`, 1 `AUTH_SYS` (a Unix user and
    /// its groups), 2 `AUTH_SHORT`, 3 `AUTH_DH`, 6 `RPCSEC_GSS`.
    pub flavor: u32,
    /// Body of the flavor, at most 400 bytes, without its padding.
    pub body: &'a [u8],
}

impl<'a> OncRpcAuth<'a> {
    pub(crate) fn new(flavor: u32, body: &'a [u8]) -> Self {
        Self { flavor, body }
    }
}

/// A reply (RFC 5531 §9, `reply_body`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OncRpcReply<'a> {
    /// `MSG_ACCEPTED`: the server took the call, which may still fail.
    Accepted(OncRpcAcceptedReply<'a>),
    /// `MSG_DENIED`, `RPC_MISMATCH`: the server does not speak version 2;
    /// `low` and `high` are the versions it speaks.
    #[non_exhaustive]
    RpcMismatch { low: u32, high: u32 },
    /// `MSG_DENIED`, `AUTH_ERROR`: the server refuses the credentials;
    /// `status` is the `auth_stat` (1 `AUTH_BADCRED`, 5 `AUTH_TOOWEAK`).
    #[non_exhaustive]
    AuthError { status: u32 },
}

/// An accepted reply (RFC 5531 §9, `accepted_reply`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct OncRpcAcceptedReply<'a> {
    /// The proof of the server.
    pub verifier: OncRpcAuth<'a>,
    /// What became of the call.
    pub status: OncRpcAcceptStatus,
    /// Results of the procedure, in the XDR of the program, up to the end
    /// of the input; empty unless the status is a success.
    pub results: &'a [u8],
}

impl<'a> OncRpcAcceptedReply<'a> {
    pub(crate) fn new(
        verifier: OncRpcAuth<'a>,
        status: OncRpcAcceptStatus,
        results: &'a [u8],
    ) -> Self {
        Self {
            verifier,
            status,
            results,
        }
    }
}

/// The `accept_stat` of an accepted reply (RFC 5531 §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OncRpcAcceptStatus {
    /// `SUCCESS` (0): the procedure ran, its results follow.
    Success,
    /// `PROG_UNAVAIL` (1): the server does not export the program.
    ProgramUnavailable,
    /// `PROG_MISMATCH` (2): the server does not export this version;
    /// `low` and `high` are the versions it exports.
    #[non_exhaustive]
    ProgramMismatch { low: u32, high: u32 },
    /// `PROC_UNAVAIL` (3): the program has no such procedure.
    ProcedureUnavailable,
    /// `GARBAGE_ARGS` (4): the server could not decode the arguments.
    GarbageArguments,
    /// `SYSTEM_ERR` (5): an error of the server, such as a failed memory
    /// allocation.
    SystemError,
}

impl OncRpcAcceptStatus {
    /// The number of the status, from 0 to 5.
    pub fn code(&self) -> u32 {
        match self {
            Self::Success => 0,
            Self::ProgramUnavailable => 1,
            Self::ProgramMismatch { .. } => 2,
            Self::ProcedureUnavailable => 3,
            Self::GarbageArguments => 4,
            Self::SystemError => 5,
        }
    }
}

/// One record of ONC RPC over TCP (RFC 5531 §11), read from its first
/// fragment: four bytes of mark, then the message.
///
/// ```mermaid
/// ---
/// title: OncRpcRecord, its first fragment (big-endian)
/// ---
/// packet-beta
/// 0-0: "L"
/// 1-31: "length of the fragment (31 bits)"
/// 32-63: "OncRpcMessage (length bytes)"
/// ```
///
/// `L` is set on the last fragment of a record; nearly every record has
/// one fragment. The header of the message is read in the first fragment:
/// a first fragment that ends before it is refused, whether the segment
/// carries it whole or not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct OncRpcRecord<'a> {
    /// `true` when the first fragment is the last of its record.
    pub is_last_fragment: bool,
    /// Length of the first fragment, from its record mark.
    pub length: u32,
    /// The message, whose arguments or results stop where the first
    /// fragment, or the segment, stops.
    pub message: OncRpcMessage<'a>,
    continuation: &'a [u8],
    is_truncated: bool,
    rest: &'a [u8],
}

impl<'a> OncRpcRecord<'a> {
    /// `true` when the record goes on in the next TCP segment: the segment
    /// cuts its first fragment, or stops before its last one.
    pub fn is_truncated(&self) -> bool {
        self.is_truncated
    }

    /// The fragments that follow the first one in this segment, with their
    /// marks: the rest of the arguments or results, not reassembled. Empty
    /// for a record of one fragment.
    pub fn continuation(&self) -> &'a [u8] {
        self.continuation
    }

    /// The bytes of the segment that follow this record: another record,
    /// or nothing.
    pub fn rest(&self) -> &'a [u8] {
        self.rest
    }

    /// The records of a TCP segment, in order. The iterator stops after
    /// the first error, or after a record that its segment cuts.
    pub fn records(payload: &'a [u8]) -> OncRpcRecords<'a> {
        OncRpcRecords { rest: payload }
    }

    /// Sonde des regles a port de TCP : des enregistrements bien formes qui
    /// pavent le segment. Seul le dernier peut etre coupe. TCP coupe ou il
    /// veut : derriere un enregistrement entier, le suivant peut s'arreter
    /// dans sa marque ou dans l'en-tete de son message, trop tot pour etre
    /// lu. Ce reste ne retire rien a l'enregistrement qui le precede ;
    /// seul, il ne nomme rien, et un reste faux refuse le segment.
    pub(crate) fn is_port_match(payload: &'a [u8]) -> bool {
        let mut has_whole_record = false;
        for record in Self::records(payload) {
            match record {
                Ok(record) => has_whole_record |= !record.is_truncated(),
                Err(OncRpcError::TooShort { .. }) => return has_whole_record,
                Err(_) => return false,
            }
        }
        !payload.is_empty()
    }
}

impl<'a> TryFrom<&'a [u8]> for OncRpcRecord<'a> {
    type Error = OncRpcError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let (is_last_fragment, length) = extract_record_mark(bytes)?;
        let after = &bytes[ONC_RPC_RECORD_MARK_LENGTH..];
        let announced = usize::try_from(length).unwrap_or(usize::MAX);
        let (fragment, rest) = after.split_at(announced.min(after.len()));
        // Ce que le fragment annonce et que le segment ne porte pas.
        let missing = announced - fragment.len();
        // La marque se juge contre le message des qu'il se lit. « Trop
        // court » ne vaut que si le fragment peut tenir l'en-tete : s'il
        // annonce moins que le champ ou la lecture s'arrete, ou moins que
        // le plus court message de ce type, c'est la marque qui est fausse,
        // que le segment coupe le fragment ou non.
        let message = extract_message(fragment, missing).map_err(|error| match error {
            OncRpcError::TooShort {
                expected, actual, ..
            } if announced
                < (fragment.len() - actual + expected).max(minimum_message_length(fragment)) =>
            {
                OncRpcError::FragmentTooShort { length }
            }
            error => error,
        })?;
        let continuation = if is_last_fragment || missing != 0 {
            OncRpcContinuation::none(rest, missing == 0)
        } else {
            extract_continuation(rest)
        };
        validate_continuation(&message, &continuation)?;
        Ok(Self {
            is_last_fragment,
            length,
            message,
            continuation: continuation.fragments,
            is_truncated: !continuation.is_complete,
            rest: continuation.rest,
        })
    }
}

/// Iterator over the records of a TCP segment ([`OncRpcRecord::records`]).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct OncRpcRecords<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for OncRpcRecords<'a> {
    type Item = Result<OncRpcRecord<'a>, OncRpcError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let record = OncRpcRecord::try_from(self.rest);
        // Apres une erreur, la suite du segment n'a plus de frontiere.
        self.rest = record.as_ref().map_or(&[], OncRpcRecord::rest);
        Some(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Trames reelles de pcaps_exemple/protocols/oncrpc/.

    /// Appel au portmapper sur UDP 111 (rpcbind version 3, GETADDR) :
    /// ndpi_nfsv2.pcap, trame 1, 64 octets.
    const GETADDR_CALL: &str = "3841169f0000000000000002000186a0000000030000000300000000000000000000000000000000000186a50000000100000003756470000000000000000000";

    /// Sa reponse : meme capture, trame 2, 48 octets.
    const GETADDR_REPLY: &str = "3841169f0000000100000000000000000000000000000000000000123133392e32352e32322e3130322e342e32340000";

    /// Appel NFSv3 ACCESS sur TCP 2049, marque de fragment comprise :
    /// wireshark_getsetacl.cap, trame 1, 144 octets.
    const TCP_ACCESS_CALL: &str = "8000008c2a8d57520000000000000002000186a30000000300000004000000010000004802b007a70000000f7361686c626572672d6c6170746f7000000003e8000003e8000000090000000400000014000000180000002e00000069000000770000007a0000007b000003e8000000000000000000000014010006003643452cf67348ea92152c6c306413990000001f";

    /// Sa reponse : meme capture, trame 2, 124 octets.
    const TCP_ACCESS_REPLY: &str = "800000782a8d57520000000100000000000000000000000000000000000000000000000100000002000041ed000000090000000000000000000000000000100000000000000010000000000000000000735b17c6406956a400000000000000024cace632000000004cc91128000000004cc911280000000000000003";

    /// Les 96 premiers octets d'une reponse READDIRPLUS de 3 248 octets,
    /// que son segment coupe a 1 448 : meme capture, trame 30.
    const CUT_READDIRPLUS_REPLY: &str = "80000cb0328d57520000000100000000000000000000000000000000000000000000000100000002000041ed00000002000003e8000003e8000000000000100000000000000010000000000000000000735b17c6406956a400000000005bc002";

    /// Les 64 premiers octets du dernier segment de cette reponse, un
    /// segment de suite : meme capture, trame 33. Il s'ouvre au milieu
    /// d'une entree de repertoire, dont les mots ont la forme d'une
    /// reponse acceptee.
    const CONTINUATION_SEGMENT: &str = "55c05b0029e8641a0000000100000000005bc010000000164261726368657374657220546f776572732e646a76750000000000007f1c51b50000000100000001";

    fn hex(text: &str) -> Vec<u8> {
        hex::decode(text).expect("hexa valide")
    }

    fn call<'a>(message: &OncRpcMessage<'a>) -> OncRpcCall<'a> {
        match message.body {
            OncRpcBody::Call(call) => call,
            body => panic!("appel attendu : {body:?}"),
        }
    }

    fn accepted<'a>(message: &OncRpcMessage<'a>) -> OncRpcAcceptedReply<'a> {
        match message.body {
            OncRpcBody::Reply(OncRpcReply::Accepted(reply)) => reply,
            body => panic!("reponse acceptee attendue : {body:?}"),
        }
    }

    #[test]
    fn parses_a_captured_call() {
        let bytes = hex(GETADDR_CALL);
        let message = OncRpcMessage::try_from(bytes.as_slice()).expect("appel");

        assert_eq!(message.xid, 0x3841_169f);
        let call = call(&message);
        assert_eq!(
            [call.program, call.version, call.procedure],
            [100_000, 3, 3]
        );
        assert_eq!(call.program_name(), Some("portmapper"));
        // AUTH_NONE, sans corps, des deux cotes.
        assert_eq!(
            (call.credentials.flavor, call.credentials.body),
            (0, &[][..])
        );
        assert_eq!((call.verifier.flavor, call.verifier.body), (0, &[][..]));
        // Les arguments de GETADDR : le programme cherche (mountd, 100005),
        // sa version, puis le reseau « udp ».
        assert_eq!(call.arguments.len(), 24);
        assert_eq!(call.arguments[..4], 100_005u32.to_be_bytes());
        assert_eq!(&call.arguments[12..15], b"udp");
    }

    #[test]
    fn parses_a_captured_reply() {
        let bytes = hex(GETADDR_REPLY);
        let message = OncRpcMessage::try_from(bytes.as_slice()).expect("reponse");

        // L'identifiant de l'appel ; ni programme ni procedure.
        assert_eq!(message.xid, 0x3841_169f);
        let reply = accepted(&message);
        assert_eq!((reply.verifier.flavor, reply.verifier.body), (0, &[][..]));
        assert_eq!(reply.status, OncRpcAcceptStatus::Success);
        assert_eq!(reply.status.code(), 0);
        // L'adresse universelle de mountd, une chaine XDR de 18 octets.
        assert_eq!(reply.results[..4], 18u32.to_be_bytes());
        assert_eq!(&reply.results[4..22], b"139.25.22.102.4.24");
    }

    #[test]
    fn parses_a_captured_record() {
        let bytes = hex(TCP_ACCESS_CALL);
        let record = OncRpcRecord::try_from(bytes.as_slice()).expect("enregistrement");

        assert!(record.is_last_fragment);
        assert_eq!(record.length, 140);
        assert!(!record.is_truncated());
        assert!(record.continuation().is_empty());
        assert!(record.rest().is_empty());
        assert_eq!(record.message.xid, 0x2a8d_5752);
        let call = call(&record.message);
        assert_eq!(
            [call.program, call.version, call.procedure],
            [100_003, 3, 4]
        );
        assert_eq!(call.program_name(), Some("nfs"));
        // AUTH_SYS : 72 octets, dont le nom de la machine.
        assert_eq!(call.credentials.flavor, 1);
        assert_eq!(call.credentials.body.len(), 72);
        assert_eq!(&call.credentials.body[8..23], b"sahlberg-laptop");
        assert_eq!((call.verifier.flavor, call.verifier.body), (0, &[][..]));
        // Un descripteur de fichier de 20 octets, precede de sa longueur,
        // et le masque d'acces.
        assert_eq!(call.arguments.len(), 28);
        assert_eq!(call.arguments[..4], 20u32.to_be_bytes());

        // Sans sa marque, le fragment est un message.
        assert_eq!(OncRpcMessage::try_from(&bytes[4..]), Ok(record.message));
        // Une marque n'est pas un message, et l'inverse.
        assert!(OncRpcMessage::try_from(bytes.as_slice()).is_err());
        assert!(OncRpcRecord::try_from(&bytes[4..]).is_err());
    }

    /// Synthetique par l'assemblage : l'appel et la reponse des trames 1 et
    /// 2, mis bout a bout dans un meme segment.
    #[test]
    fn records_follow_each_other() {
        let mut bytes = hex(TCP_ACCESS_CALL);
        bytes.extend(hex(TCP_ACCESS_REPLY));

        let records: Vec<_> = OncRpcRecord::records(&bytes)
            .collect::<Result<_, _>>()
            .expect("deux enregistrements");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].rest().len(), 124);
        assert_eq!(records[1].length, 120);
        assert_eq!(accepted(&records[1].message).results.len(), 96);
        assert!(records[1].rest().is_empty());
        assert!(OncRpcRecord::is_port_match(&bytes));

        // Apres une erreur, l'iterateur s'arrete.
        bytes.extend([0x80, 0, 0, 24, 0, 0, 0, 1, 0, 0, 0, 7]);
        let records: Vec<_> = OncRpcRecord::records(&bytes).collect();
        assert_eq!(records.len(), 3);
        assert_eq!(records[2], Err(OncRpcError::UnknownMessageType(7)));
        assert!(!OncRpcRecord::is_port_match(&bytes));
    }

    #[test]
    fn a_record_longer_than_its_segment_is_cut() {
        let bytes = hex(CUT_READDIRPLUS_REPLY);
        let record = OncRpcRecord::try_from(bytes.as_slice()).expect("enregistrement coupe");

        assert!(record.is_last_fragment);
        assert_eq!(record.length, 3248);
        assert!(record.is_truncated());
        assert!(record.rest().is_empty());
        let reply = accepted(&record.message);
        assert_eq!(reply.status, OncRpcAcceptStatus::Success);
        // Les resultats s'arretent avec le segment.
        assert_eq!(reply.results.len(), bytes.len() - 28);
        assert!(OncRpcRecord::is_port_match(&bytes));
    }

    #[test]
    fn a_continuation_segment_is_refused() {
        let bytes = hex(CONTINUATION_SEGMENT);

        // La « marque » annonce 1,4 Go ; puis « une entree suit » (1) a la
        // place du type, le haut d'un identifiant de fichier (0) a celle de
        // l'etat, et son bas a celle de la saveur du verifieur.
        assert_eq!(
            OncRpcRecord::try_from(bytes.as_slice()),
            Err(OncRpcError::UnknownAuthFlavor {
                field: "verifier",
                flavor: 0x005b_c010
            })
        );
        assert!(!OncRpcRecord::is_port_match(&bytes));
    }

    /// TCP coupe ou il veut : derriere un enregistrement entier, le debut
    /// du suivant. Synthetique par l'assemblage, sur les octets des trames
    /// 1 et 2.
    #[test]
    fn a_record_start_behind_a_whole_record_keeps_the_probe() {
        let whole = hex(TCP_ACCESS_CALL);
        let next = hex(TCP_ACCESS_REPLY);
        let with = |tail: &[u8]| [whole.as_slice(), tail].concat();

        // La marque coupee, la marque seule, l'en-tete coupe.
        for cut in [1, 3, 4, 7, 12, 27] {
            let bytes = with(&next[..cut]);
            assert!(OncRpcRecord::is_port_match(&bytes), "{cut} octets");
            // Seul, ce debut ne nomme rien.
            assert!(!OncRpcRecord::is_port_match(&next[..cut]), "{cut} octets");
        }
        // A 28 octets l'en-tete de la reponse est entier : elle est coupee,
        // et nommee meme seule.
        assert!(OncRpcRecord::is_port_match(&with(&next[..28])));
        assert!(OncRpcRecord::is_port_match(&next[..28]));

        // Une marque entiere se juge seule : nulle ou trop petite, elle
        // refuse le segment. Un debut faux aussi.
        let refused: [&[u8]; 5] = [
            &[0, 0, 0, 0],
            &[0x80, 0, 0, 0],
            &[0x80, 0, 0, 19],
            &[0x80, 0, 0, 120, 0x2a, 0x8d, 0x57, 0x52, 0, 0, 0, 2],
            &[
                0x80, 0, 0, 120, 0x2a, 0x8d, 0x57, 0x52, 0, 0, 0, 0, 0, 0, 0, 3,
            ],
        ];
        for tail in refused {
            assert!(!OncRpcRecord::is_port_match(&with(tail)), "{tail:02x?}");
        }
    }

    /// Synthetique : la marque de la trame 1 reecrite pour annoncer moins
    /// que l'en-tete de son appel.
    #[test]
    fn a_fragment_that_ends_before_its_header_is_refused() {
        let whole = hex(TCP_ACCESS_CALL);
        let mut bytes = whole[..4 + 24].to_vec();
        bytes[..4].copy_from_slice(&[0x80, 0, 0, 24]);

        // Le fragment est entier : ce n'est pas le segment qui coupe.
        assert_eq!(
            OncRpcRecord::try_from(bytes.as_slice()),
            Err(OncRpcError::FragmentTooShort { length: 24 })
        );
        // Derriere un enregistrement entier, ce reste refuse le segment.
        assert!(!OncRpcRecord::is_port_match(
            &[whole.as_slice(), &bytes].concat()
        ));
        // Le meme appel sous sa vraie marque, coupe par le segment : trop
        // court, sans plus.
        assert!(matches!(
            OncRpcRecord::try_from(&whole[..4 + 24]),
            Err(OncRpcError::TooShort { .. })
        ));

        // La marque se juge contre le message des qu'il se lit, meme coupe.
        // Douze octets d'un appel annonce a 24 : un appel en fait 40.
        bytes.truncate(4 + 12);
        assert_eq!(
            OncRpcRecord::try_from(bytes.as_slice()),
            Err(OncRpcError::FragmentTooShort { length: 24 })
        );
        assert!(!OncRpcRecord::is_port_match(
            &[whole.as_slice(), &bytes].concat()
        ));
        // Une reponse acceptee annoncee a 20 octets : elle en fait 24.
        let reply = hex(TCP_ACCESS_REPLY);
        let mut short_reply = reply[..4 + 12].to_vec();
        short_reply[..4].copy_from_slice(&[0x80, 0, 0, 20]);
        assert_eq!(
            OncRpcRecord::try_from(short_reply.as_slice()),
            Err(OncRpcError::FragmentTooShort { length: 20 })
        );
        // Un authentifiant de 72 octets dans un fragment annonce a 60.
        let mut short_auth = whole[..4 + 40].to_vec();
        short_auth[..4].copy_from_slice(&[0x80, 0, 0, 60]);
        assert_eq!(
            OncRpcRecord::try_from(short_auth.as_slice()),
            Err(OncRpcError::FragmentTooShort { length: 60 })
        );
    }

    /// Synthetique : aucune capture du corpus ne coupe un enregistrement en
    /// plusieurs fragments. L'appel de la trame 1, dont les quatre derniers
    /// octets passent dans un second fragment.
    #[test]
    fn continuation_fragments_follow_the_first_one() {
        let whole = hex(TCP_ACCESS_CALL);
        let next = hex(TCP_ACCESS_REPLY);
        let mut bytes = vec![0, 0, 0, 136];
        bytes.extend(&whole[4..140]);
        bytes.extend([0x80, 0, 0, 4]);
        bytes.extend(&whole[140..]);
        let first = bytes.len();
        bytes.extend(&next);

        let record = OncRpcRecord::try_from(bytes.as_slice()).expect("deux fragments");
        assert!(!record.is_last_fragment);
        assert_eq!(record.length, 136);
        assert!(!record.is_truncated());
        // Le second fragment, marque comprise, puis l'enregistrement suivant.
        assert_eq!(record.continuation(), &bytes[140..first]);
        assert_eq!(record.rest(), next.as_slice());
        // Les arguments s'arretent avec le premier fragment.
        assert_eq!(call(&record.message).arguments.len(), 24);
        assert_eq!(OncRpcRecord::records(&bytes).count(), 2);
        assert!(OncRpcRecord::is_port_match(&bytes));

        // Le dernier fragment manque, ou le segment le coupe :
        // l'enregistrement continue, et prend le reste du segment.
        for end in [140, 142, 144, 146] {
            let record = OncRpcRecord::try_from(&bytes[..end]).expect("fragments coupes");
            assert!(record.is_truncated(), "{end} octets");
            assert_eq!(record.continuation(), &bytes[140..end]);
            assert!(record.rest().is_empty());
        }
    }

    /// Synthetique : aucune reponse du corpus n'est un refus ni une erreur.
    /// L'en-tete de la reponse de la trame 2 de ndpi_nfsv2.pcap, dont les
    /// etats sont reecrits.
    #[test]
    fn replies_without_results_end_with_their_status() {
        let reply = hex(GETADDR_REPLY);
        // xid, REPLY, MSG_ACCEPTED, verifieur AUTH_NONE vide.
        let accepted_with = |status: &[u32]| {
            let mut bytes = reply[..20].to_vec();
            bytes.extend(status.iter().flat_map(|word| word.to_be_bytes()));
            bytes
        };
        // xid, REPLY, MSG_DENIED.
        let denied_with = |status: &[u32]| {
            let mut bytes = reply[..8].to_vec();
            bytes.extend(1u32.to_be_bytes());
            bytes.extend(status.iter().flat_map(|word| word.to_be_bytes()));
            bytes
        };
        let status = |bytes: &[u8]| {
            let message = OncRpcMessage::try_from(bytes).expect("reponse");
            accepted(&message).status
        };

        assert_eq!(
            status(&accepted_with(&[1])),
            OncRpcAcceptStatus::ProgramUnavailable
        );
        assert_eq!(
            status(&accepted_with(&[2, 2, 4])),
            OncRpcAcceptStatus::ProgramMismatch { low: 2, high: 4 }
        );
        assert_eq!(
            status(&accepted_with(&[3])),
            OncRpcAcceptStatus::ProcedureUnavailable
        );
        assert_eq!(
            status(&accepted_with(&[4])),
            OncRpcAcceptStatus::GarbageArguments
        );
        assert_eq!(
            status(&accepted_with(&[5])),
            OncRpcAcceptStatus::SystemError
        );
        assert_eq!(status(&accepted_with(&[5])).code(), 5);
        fn denied(bytes: &[u8]) -> Result<OncRpcBody<'_>, OncRpcError> {
            OncRpcMessage::try_from(bytes).map(|message| message.body)
        }
        assert_eq!(
            denied(&denied_with(&[0, 2, 2])),
            Ok(OncRpcBody::Reply(OncRpcReply::RpcMismatch {
                low: 2,
                high: 2
            }))
        );
        // AUTH_TOOWEAK (5) : le plus court message, vingt octets.
        let too_weak = denied_with(&[1, 5]);
        assert_eq!(too_weak.len(), 20);
        assert_eq!(
            denied(&too_weak),
            Ok(OncRpcBody::Reply(OncRpcReply::AuthError { status: 5 }))
        );

        // Rien ne suit un etat sans resultat.
        for bytes in [
            accepted_with(&[1, 0]),
            accepted_with(&[2, 2, 4, 0]),
            denied_with(&[0, 2, 2, 0]),
            denied_with(&[1, 5, 0]),
        ] {
            assert_eq!(
                OncRpcMessage::try_from(bytes.as_slice()),
                Err(OncRpcError::TrailingBytes(4))
            );
        }
        // Les etats inconnus.
        assert_eq!(
            OncRpcMessage::try_from(accepted_with(&[6]).as_slice()),
            Err(OncRpcError::UnknownAcceptStatus(6))
        );
        assert_eq!(
            OncRpcMessage::try_from(denied_with(&[2]).as_slice()),
            Err(OncRpcError::UnknownRejectStatus(2))
        );
        let mut unknown = reply.clone();
        unknown[11] = 2;
        assert_eq!(
            OncRpcMessage::try_from(unknown.as_slice()),
            Err(OncRpcError::UnknownReplyStatus(2))
        );

        // Sur TCP, la marque annonce ce message et rien de plus : un refus
        // que son segment couperait porterait des octets apres son etat.
        let record_of = |mark: [u8; 4], message: &[u8]| [&mark[..], message].concat();
        assert!(OncRpcRecord::try_from(record_of([0x80, 0, 0, 20], &too_weak).as_slice()).is_ok());
        assert_eq!(
            OncRpcRecord::try_from(record_of([0x80, 0, 0, 28], &too_weak).as_slice()),
            Err(OncRpcError::TrailingBytes(8))
        );
        // Ses fragments de suite, s'il en a, sont vides.
        let fragments =
            |tail: &[u8]| [record_of([0, 0, 0, 20], &too_weak).as_slice(), tail].concat();
        let with_empty = fragments(&[0x80, 0, 0, 0]);
        let empty = OncRpcRecord::try_from(with_empty.as_slice()).expect("fragment de suite vide");
        assert!(!empty.is_truncated());
        assert_eq!(empty.continuation(), [0x80, 0, 0, 0]);
        assert_eq!(
            OncRpcRecord::try_from(fragments(&[0x80, 0, 0, 2, 1, 2]).as_slice()),
            Err(OncRpcError::TrailingBytes(2))
        );
    }

    #[test]
    fn rejects_what_is_not_a_message() {
        let bytes = hex(GETADDR_CALL);

        // Un type qui n'est ni appel ni reponse.
        let mut other_type = bytes.clone();
        other_type[7] = 2;
        assert_eq!(
            OncRpcMessage::try_from(other_type.as_slice()),
            Err(OncRpcError::UnknownMessageType(2))
        );
        // Une autre version du protocole que la 2.
        let mut other_version = bytes.clone();
        other_version[11] = 3;
        assert_eq!(
            OncRpcMessage::try_from(other_version.as_slice()),
            Err(OncRpcError::UnsupportedVersion(3))
        );
        // Une saveur hors du registre.
        let mut other_flavor = bytes.clone();
        other_flavor[27] = 8;
        assert_eq!(
            OncRpcMessage::try_from(other_flavor.as_slice()),
            Err(OncRpcError::UnknownAuthFlavor {
                field: "credentials",
                flavor: 8
            })
        );
        // Un authentifiant de plus de 400 octets.
        let mut long_auth = bytes.clone();
        long_auth[30..32].copy_from_slice(&[0x01, 0x91]);
        assert_eq!(
            OncRpcMessage::try_from(long_auth.as_slice()),
            Err(OncRpcError::AuthBodyTooLong {
                field: "credentials",
                length: 401
            })
        );
        // Un datagramme coupe dans son en-tete, et le datagramme vide.
        for end in [0, 3, 8, 23, 39] {
            assert!(
                matches!(
                    OncRpcMessage::try_from(&bytes[..end]),
                    Err(OncRpcError::TooShort { .. })
                ),
                "{end} octets"
            );
        }
        // A 40 octets l'appel est entier, sans argument.
        assert!(OncRpcMessage::try_from(&bytes[..40]).is_ok());
    }
}
