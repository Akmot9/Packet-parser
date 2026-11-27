// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! SIP, Session Initiation Protocol (RFC 3261, #342) : requetes et reponses,
//! sur UDP comme sur TCP (§18), sans reassemblage.
//!
//! Recouvrement avec HTTP : la syntaxe est celle de HTTP/1.1 (ligne de
//! depart, en-tetes `Nom: valeur`, ligne vide, corps), mais les deux sont
//! disjoints. La version est `SIP/2.0`, que le parseur HTTP refuse, et les
//! methodes sont celles du registre SIP de l'IANA ; `OPTIONS`, la seule
//! qu'ils partagent, porte alors `SIP/2.0`. SSDP, du HTTP sur UDP, emploie
//! `NOTIFY * HTTP/1.1` : ni l'URI ni la version ne sont celles de SIP.
//!
//! Ce qui fait un message SIP, et non un texte quelconque :
//! - une tete complete, jusqu'au premier `CRLF CRLF`, en UTF-8 ;
//! - les en-tetes Via, From, To, Call-ID et CSeq, en forme longue ou
//!   compacte (§8.1.1, §7.3.3) ;
//! - un CSeq dont la methode est celle de la requete (§8.1.1.5).
//!
//! Limites, sans etat : une tete coupee entre deux segments TCP n'est pas
//! reconnue, et un segment de continuation n'est pas du SIP pour la crate.
//! SIP sur TLS (port 5061) reste du TLS, et SIP sur WebSocket (RFC 7118) n'est
//! pas lu.

use std::convert::TryFrom;

use crate::{
    checks::application::sip::{
        SipCoreHeader, extract_sip_content_length, extract_sip_cseq, extract_sip_header_line,
        extract_sip_status_code, extract_sip_text, is_sip_version, known_sip_method,
        sip_core_header, sip_header_alias, sip_header_lines, split_sip_head, split_sip_header_line,
        split_sip_start_line, strip_status_line_version, validate_sip_request_uri,
    },
    errors::application::sip::SipError,
};

/// The SIP version, the methods of the IANA registry and the compact forms
/// of the header names, as the parser checks them.
pub use crate::checks::application::sip::{SIP_COMPACT_FORMS, SIP_METHODS, SIP_VERSION};

/// The start line of a [`SipMessage`] (RFC 3261 §7.1, §7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SipStartLine<'a> {
    /// `Method SP Request-URI SP SIP/2.0`.
    #[non_exhaustive]
    Request {
        /// One of [`SIP_METHODS`], `INVITE`, `REGISTER`...
        method: &'a str,
        /// `sip:bob@biloxi.com`, `tel:+33...`: a scheme, `:`, then visible
        /// ASCII.
        uri: &'a str,
    },
    /// `SIP/2.0 SP Status-Code SP Reason-Phrase`.
    #[non_exhaustive]
    Response {
        /// Three digits, from 100 to 699.
        status_code: u16,
        /// `OK`, `Ringing`, `Unauthorized`...; may be empty.
        reason: &'a str,
    },
}

/// The `CSeq` header of a [`SipMessage`] (RFC 3261 §20.16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipCseq<'a> {
    /// Below 2^31 (§8.1.1.5).
    pub sequence: u32,
    /// The method of the request; for a response, the method of the
    /// request it answers.
    pub method: &'a str,
}

/// SIP message (RFC 3261 §7): a request or a response, its header fields
/// and its body, as they fit in one datagram or one TCP segment.
///
/// ```mermaid
/// ---
/// title: SipMessage
/// ---
/// packet-beta
/// 0-63: "Start line (Method SP URI SP SIP/2.0 | SIP/2.0 SP Code SP Reason) CRLF"
/// 64-127: "Headers variable (Name: value CRLF), Via From To Call-ID CSeq required"
/// 128-143: "CRLF (empty line)"
/// 144-207: "Body variable (Content-Length bytes, SDP...)"
/// ```
///
/// All borrowed fields point into the payload: no byte is copied. The
/// mandatory headers are exposed as fields, whatever their form on the wire
/// (`Call-ID` or `i`); the others are in [`SipMessage::headers`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipMessage<'a> {
    pub start_line: SipStartLine<'a>,
    /// Every header field, as a validated view over the header block.
    pub headers: SipHeaders<'a>,
    /// The first `Via`: the transport and the address the response goes
    /// back to, `SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds`.
    pub via: &'a str,
    pub from: &'a str,
    pub to: &'a str,
    pub call_id: &'a str,
    pub cseq: SipCseq<'a>,
    /// `Content-Length`, when the message carries it; mandatory on TCP
    /// (§20.14), optional on UDP.
    pub content_length: Option<u32>,
    /// What follows the empty line: the first `Content-Length` bytes when
    /// the header is there, cut by the end of the payload; everything that
    /// follows otherwise. A second message in the same TCP segment is not
    /// part of it.
    pub body: &'a [u8],
}

impl<'a> SipMessage<'a> {
    pub fn is_request(&self) -> bool {
        matches!(self.start_line, SipStartLine::Request { .. })
    }

    /// The method of the request; for a response, the method of its CSeq,
    /// that of the request it answers.
    pub fn method(&self) -> &'a str {
        match self.start_line {
            SipStartLine::Request { method, .. } => method,
            SipStartLine::Response { .. } => self.cseq.method,
        }
    }

    /// The status code of a response; `None` for a request.
    pub fn status_code(&self) -> Option<u16> {
        match self.start_line {
            SipStartLine::Response { status_code, .. } => Some(status_code),
            SipStartLine::Request { .. } => None,
        }
    }
}

/// The header fields of a [`SipMessage`]: a borrowed view over the header
/// block, validated once while parsing; iterating cannot fail and does not
/// allocate.
///
/// A folded header (a line that starts with a space or a tab continues the
/// previous one, RFC 3261 §7.3.1) yields its value as carried, inner `CRLF`
/// and blanks included.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct SipHeaders<'a> {
    // Lignes d'en-tete, sans la ligne de depart ni la ligne vide finale.
    // Chaque ligne logique est passee par `split_sip_header_line` au
    // parsing.
    block: &'a str,
}

impl<'a> SipHeaders<'a> {
    /// The `(name, value)` pairs, in wire order; names as written on the
    /// wire, compact or long, values trimmed.
    pub fn iter(&self) -> impl Iterator<Item = (&'a str, &'a str)> + 'a {
        sip_header_lines(self.block)
            // Infaillible : chaque ligne a ete validee au parsing.
            .filter_map(|line| extract_sip_header_line(line).ok())
    }

    /// Value of the first header named `name`, compared case-insensitively
    /// (§7.3.1). A long name also finds its compact form and the other way
    /// round: `get("Call-ID")` finds `i: ...`.
    pub fn get(&self, name: &str) -> Option<&'a str> {
        let alias = sip_header_alias(name);
        self.iter()
            .find(|(header, _)| {
                header.eq_ignore_ascii_case(name)
                    || alias.is_some_and(|alias| header.eq_ignore_ascii_case(alias))
            })
            .map(|(_, value)| value)
    }

    /// Number of header fields.
    pub fn len(&self) -> usize {
        self.iter().count()
    }

    pub fn is_empty(&self) -> bool {
        self.iter().next().is_none()
    }
}

impl std::fmt::Debug for SipHeaders<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

/// La ligne de depart : `SIP/2.0 ` ouvre une reponse, une methode du
/// registre une requete.
fn parse_start_line(line: &str) -> Result<SipStartLine<'_>, SipError> {
    if let Some(status) = strip_status_line_version(line) {
        let (code, reason) = status.split_once(' ').unwrap_or((status, ""));
        let status_code = extract_sip_status_code(code)?;
        return Ok(SipStartLine::Response {
            status_code,
            reason,
        });
    }

    let mut parts = line.splitn(3, ' ');
    let method = parts.next().unwrap_or_default();
    if known_sip_method(method).is_none() {
        return Err(SipError::UnknownMethod);
    }
    let uri = parts.next().ok_or(SipError::InvalidRequestUri)?;
    validate_sip_request_uri(uri)?;
    if !parts.next().is_some_and(is_sip_version) {
        return Err(SipError::InvalidVersion);
    }
    Ok(SipStartLine::Request { method, uri })
}

impl<'a> TryFrom<&'a [u8]> for SipMessage<'a> {
    type Error = SipError;

    fn try_from(payload: &'a [u8]) -> Result<Self, SipError> {
        let (head, rest) = split_sip_head(payload)?;
        let head = extract_sip_text(head)?;
        let (start, block) = split_sip_start_line(head);
        let start_line = parse_start_line(start)?;

        let mut via = None;
        let mut from = None;
        let mut to = None;
        let mut call_id = None;
        let mut cseq = None;
        let mut content_length = None;
        for line in sip_header_lines(block) {
            let (name, value) = split_sip_header_line(line)?;
            // Les autres en-tetes sont valides, et lus par `headers`.
            let Some(header) = sip_core_header(name) else {
                continue;
            };
            let slot = match header {
                SipCoreHeader::Via => &mut via,
                SipCoreHeader::From => &mut from,
                SipCoreHeader::To => &mut to,
                SipCoreHeader::CallId => &mut call_id,
                SipCoreHeader::Cseq => &mut cseq,
                SipCoreHeader::ContentLength => &mut content_length,
            };
            // La premiere occurrence gagne : le Via du haut est celui du
            // dernier saut.
            if slot.is_none() {
                *slot = Some(value.trim());
            } else if header == SipCoreHeader::ContentLength {
                // Seul un champ a liste se repete (§7.3.1) ; deux
                // Content-Length laisseraient la fin du corps au hasard
                // (#383).
                return Err(SipError::DuplicateHeader("Content-Length"));
            }
        }

        let via = via.ok_or(SipError::MissingHeader("Via"))?;
        let from = from.ok_or(SipError::MissingHeader("From"))?;
        let to = to.ok_or(SipError::MissingHeader("To"))?;
        let call_id = call_id.ok_or(SipError::MissingHeader("Call-ID"))?;
        let (sequence, cseq_method) =
            extract_sip_cseq(cseq.ok_or(SipError::MissingHeader("CSeq"))?)?;
        if let SipStartLine::Request { method, .. } = start_line
            && method != cseq_method
        {
            // Les deux sont des methodes du registre : l'erreur nomme leurs
            // constantes, sans copier le payload.
            return Err(SipError::CseqMethodMismatch {
                request: known_sip_method(method).unwrap_or_default(),
                cseq: known_sip_method(cseq_method).unwrap_or_default(),
            });
        }
        let content_length = content_length.map(extract_sip_content_length).transpose()?;
        let body = match content_length {
            Some(length) => {
                let length = usize::try_from(length).unwrap_or(usize::MAX);
                &rest[..rest.len().min(length)]
            }
            None => rest,
        };

        Ok(SipMessage {
            start_line,
            headers: SipHeaders { block },
            via,
            from,
            to,
            call_id,
            cseq: SipCseq {
                sequence,
                method: cseq_method,
            },
            content_length,
            body,
        })
    }
}

/// Le decodeur tel qu'il lisait la tete : `CRLF CRLF` par fenetres, lignes
/// par `str::find`, chaque nom compare aux six en-tetes lus et a leur forme
/// compacte. La reference des tests differentiels, ici et dans ceux du
/// dispatch.
#[cfg(test)]
pub(crate) mod reference {
    use super::*;

    fn split_sip_head(payload: &[u8]) -> Result<(&[u8], &[u8]), SipError> {
        let index = payload
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .ok_or(SipError::MissingHeaderTerminator)?;
        Ok((&payload[..index], &payload[index + 4..]))
    }

    pub(crate) fn extract_sip_header_line(line: &str) -> Result<(&str, &str), SipError> {
        let (name, value) = line.split_once(':').ok_or(SipError::InvalidHeader)?;
        let name = name.trim_end_matches([' ', '\t']);
        let is_token = |byte: u8| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~'
                )
        };
        if name.is_empty() || !name.bytes().all(is_token) {
            return Err(SipError::InvalidHeader);
        }
        Ok((name, value.trim()))
    }

    pub(crate) fn sip_header_lines(block: &str) -> impl Iterator<Item = &str> {
        let mut rest = block;
        std::iter::from_fn(move || {
            if rest.is_empty() {
                return None;
            }
            let mut searched = 0;
            loop {
                let Some(offset) = rest[searched..].find("\r\n") else {
                    let line = rest;
                    rest = "";
                    return Some(line);
                };
                let end = searched + offset;
                let next = end + 2;
                if matches!(rest.as_bytes().get(next), Some(b' ' | b'\t')) {
                    searched = next;
                    continue;
                }
                let line = &rest[..end];
                rest = &rest[next..];
                return Some(line);
            }
        })
    }

    fn is_sip_header(name: &str, long: &str) -> bool {
        name.eq_ignore_ascii_case(long)
            || sip_header_alias(long).is_some_and(|alias| name.eq_ignore_ascii_case(alias))
    }

    pub(crate) fn parse(payload: &[u8]) -> Result<SipMessage<'_>, SipError> {
        let (head, rest) = split_sip_head(payload)?;
        let head = extract_sip_text(head)?;
        let (start, block) = head.split_once("\r\n").unwrap_or((head, ""));
        let start_line = parse_start_line(start)?;

        let mut via = None;
        let mut from = None;
        let mut to = None;
        let mut call_id = None;
        let mut cseq = None;
        let mut content_length = None;
        for line in sip_header_lines(block) {
            let (name, value) = extract_sip_header_line(line)?;
            let slot = match () {
                _ if is_sip_header(name, "Via") => &mut via,
                _ if is_sip_header(name, "From") => &mut from,
                _ if is_sip_header(name, "To") => &mut to,
                _ if is_sip_header(name, "Call-ID") => &mut call_id,
                _ if is_sip_header(name, "CSeq") => &mut cseq,
                _ if is_sip_header(name, "Content-Length") => &mut content_length,
                _ => continue,
            };
            if slot.is_none() {
                *slot = Some(value);
            } else if is_sip_header(name, "Content-Length") {
                return Err(SipError::DuplicateHeader("Content-Length"));
            }
        }

        let via = via.ok_or(SipError::MissingHeader("Via"))?;
        let from = from.ok_or(SipError::MissingHeader("From"))?;
        let to = to.ok_or(SipError::MissingHeader("To"))?;
        let call_id = call_id.ok_or(SipError::MissingHeader("Call-ID"))?;
        let (sequence, cseq_method) =
            extract_sip_cseq(cseq.ok_or(SipError::MissingHeader("CSeq"))?)?;
        if let SipStartLine::Request { method, .. } = start_line
            && method != cseq_method
        {
            return Err(SipError::CseqMethodMismatch {
                request: known_sip_method(method).unwrap_or_default(),
                cseq: known_sip_method(cseq_method).unwrap_or_default(),
            });
        }
        let content_length = content_length.map(extract_sip_content_length).transpose()?;
        let body = match content_length {
            Some(length) => {
                let length = usize::try_from(length).unwrap_or(usize::MAX);
                &rest[..rest.len().min(length)]
            }
            None => rest,
        };

        Ok(SipMessage {
            start_line,
            headers: SipHeaders { block },
            via,
            from,
            to,
            call_id,
            cseq: SipCseq {
                sequence,
                method: cseq_method,
            },
            content_length,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Le decodeur rend la valeur ou l'erreur de sa reference, et la vue
    /// sur les en-tetes les memes paires ; rend vrai pour un message decode.
    /// Les lignes logiques et leur lecture sont aussi comparees sur tout
    /// payload en UTF-8, decode ou non.
    fn agrees_with_the_reference(payload: &[u8]) -> bool {
        let decoded = SipMessage::try_from(payload);
        assert_eq!(decoded, reference::parse(payload), "{payload:?}");
        if let Ok(message) = &decoded {
            let expected: Vec<(&str, &str)> = reference::sip_header_lines(message.headers.block)
                .filter_map(|line| reference::extract_sip_header_line(line).ok())
                .collect();
            let pairs: Vec<(&str, &str)> = message.headers.iter().collect();
            assert_eq!(pairs, expected, "{payload:?}");
        }
        if let Ok(text) = std::str::from_utf8(payload) {
            let expected: Vec<&str> = reference::sip_header_lines(text).collect();
            let lines: Vec<&str> = sip_header_lines(text).collect();
            assert_eq!(lines, expected, "{payload:?}");
            for line in lines {
                assert_eq!(
                    extract_sip_header_line(line),
                    reference::extract_sip_header_line(line),
                    "{line:?}"
                );
            }
        }
        decoded.is_ok()
    }

    /// Sur les messages des RFC, un message a en-tetes replies et des refus,
    /// leurs troncatures, des fins de ligne et des blancs inseres a chaque
    /// position, et chaque octet remplace par les octets qui comptent pour
    /// la tete : le decodeur rend ce que rendait la lecture d'origine.
    #[test]
    fn test_decoder_agrees_with_the_reference() {
        let folded = replace(
            RFC_INVITE,
            "Max-Forwards: 70\r\n",
            "Subject: I know you're there,\r\n   pick up the phone\r\n\tand talk\r\nl : 3\r\n",
        );
        let seeds: [&[u8]; 7] = [
            RFC_INVITE,
            RFC_RINGING_COMPACT,
            &folded,
            b"OPTIONS sip:carol@chicago.com SIP/2.0\r\nv:a\r\nf:b\r\nt:c\r\ni:d\r\nCSeq:1 OPTIONS\r\n\r\n",
            b"sip/2.0 200 OK\r\nVIA: a\r\nfrom: b\r\nTO: c\r\ncall-id: d\r\ncseq: 7 BYE\r\nContent-Length: 0\r\ncontent-length: 0\r\n\r\n",
            b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNT: upnp:rootdevice\r\n\r\n",
            b"REGISTER sip:caf\xc3\xa9.example SIP/2.0\r\nVia: \xe2\x82\xac\r\nFrom: a\r\nTo: b\r\nCall-ID: c\r\nCSeq: 2 REGISTER\r\n\r\ncorps",
        ];
        let (mut accepted, mut checked) = (0, 0);
        let mut check = |payload: &[u8]| {
            accepted += usize::from(agrees_with_the_reference(payload));
            checked += 1;
        };
        check(b"");
        for seed in seeds {
            check(seed);
            let mut mutated = seed.to_vec();
            for position in 0..seed.len() {
                check(&seed[..position]);
                let original = seed[position];
                for value in [
                    b'\r',
                    b'\n',
                    b':',
                    b' ',
                    b'\t',
                    b'v',
                    b'L',
                    b'1',
                    0x00,
                    0x0c,
                    0x80,
                    original ^ 0x20,
                    original.wrapping_add(1),
                ] {
                    mutated[position] = value;
                    check(&mutated);
                }
                mutated[position] = original;
                for inserted in [&b"\r\n"[..], b"\r\n\r\n", b"\r\n ", b"\r", b":", b" "] {
                    let mut longer = seed[..position].to_vec();
                    longer.extend_from_slice(inserted);
                    longer.extend_from_slice(&seed[position..]);
                    check(&longer);
                }
            }
        }
        assert!(checked > 30_000, "{checked} payloads");
        assert!(accepted > 10_000, "{accepted} messages decodes");
    }

    /// Synthetique : l'INVITE d'exemple de RFC 3261 §24.2 (F1, Alice vers
    /// Bob). La RFC ne montre pas le SDP d'Alice : le corps de 128 octets
    /// est invente, et `Content-Length` le suit.
    const RFC_INVITE: &[u8] = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
        Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds8\r\n\
        Max-Forwards: 70\r\n\
        To: Bob <sip:bob@biloxi.com>\r\n\
        From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
        Call-ID: a84b4c76e66710\r\n\
        CSeq: 314159 INVITE\r\n\
        Contact: <sip:alice@pc33.atlanta.com>\r\n\
        Content-Type: application/sdp\r\n\
        Content-Length: 128\r\n\
        \r\n\
        v=0\r\n\
        o=alice 2890844526 2890844526 IN IP4 pc33.atlanta.com\r\n\
        s=-\r\n\
        c=IN IP4 pc33.atlanta.com\r\n\
        t=0 0\r\n\
        m=audio 3456 RTP/AVP 0 8 97\r\n";

    /// Synthetique : la reponse 180 Ringing de RFC 3261 §24.2 (F2), en
    /// formes compactes.
    const RFC_RINGING_COMPACT: &[u8] = b"SIP/2.0 180 Ringing\r\n\
        v: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds8;received=192.0.2.1\r\n\
        t: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
        f: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
        i: a84b4c76e66710\r\n\
        CSeq: 314159 INVITE\r\n\
        m: <sip:bob@192.0.2.4>\r\n\
        l: 0\r\n\
        \r\n";

    fn replace(message: &[u8], from: &str, to: &str) -> Vec<u8> {
        String::from_utf8(message.to_vec())
            .unwrap()
            .replacen(from, to, 1)
            .into_bytes()
    }

    #[test]
    fn parses_the_rfc_invite() {
        let message = SipMessage::try_from(RFC_INVITE).expect("INVITE de la RFC");
        assert_eq!(
            message.start_line,
            SipStartLine::Request {
                method: "INVITE",
                uri: "sip:bob@biloxi.com"
            }
        );
        assert!(message.is_request());
        assert_eq!(message.method(), "INVITE");
        assert_eq!(message.status_code(), None);
        assert_eq!(
            message.via,
            "SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds8"
        );
        assert_eq!(message.to, "Bob <sip:bob@biloxi.com>");
        assert_eq!(message.from, "Alice <sip:alice@atlanta.com>;tag=1928301774");
        assert_eq!(message.call_id, "a84b4c76e66710");
        assert_eq!(
            message.cseq,
            SipCseq {
                sequence: 314_159,
                method: "INVITE"
            }
        );
        assert_eq!(message.content_length, Some(128));
        assert_eq!(message.body.len(), 128);
        assert!(message.body.starts_with(b"v=0\r\n"));
        assert_eq!(message.headers.len(), 9);
        assert_eq!(message.headers.get("max-forwards"), Some("70"));
        assert_eq!(message.headers.get("c"), Some("application/sdp"));
        assert_eq!(message.headers.get("Absent"), None);
    }

    #[test]
    fn parses_a_response_in_compact_forms() {
        let message = SipMessage::try_from(RFC_RINGING_COMPACT).expect("180 compact");
        assert_eq!(
            message.start_line,
            SipStartLine::Response {
                status_code: 180,
                reason: "Ringing"
            }
        );
        assert!(!message.is_request());
        assert_eq!(message.method(), "INVITE");
        assert_eq!(message.status_code(), Some(180));
        assert_eq!(message.call_id, "a84b4c76e66710");
        assert_eq!(message.to, "Bob <sip:bob@biloxi.com>;tag=a6c85cf");
        assert_eq!(message.content_length, Some(0));
        assert_eq!(message.body, b"");
        // La forme longue trouve la compacte, et l'inverse.
        assert_eq!(message.headers.get("Contact"), Some("<sip:bob@192.0.2.4>"));
        assert_eq!(message.headers.get("CALL-ID"), Some("a84b4c76e66710"));
        let long = SipMessage::try_from(RFC_INVITE).unwrap();
        assert_eq!(long.headers.get("i"), Some("a84b4c76e66710"));
        assert_eq!(long.headers.get("m"), Some("<sip:alice@pc33.atlanta.com>"));
    }

    #[test]
    fn is_zero_copy() {
        let message = SipMessage::try_from(RFC_INVITE).unwrap();
        let range = RFC_INVITE.as_ptr_range();
        let SipStartLine::Request { method, uri } = message.start_line else {
            panic!("requete attendue");
        };
        for field in [
            method,
            uri,
            message.via,
            message.from,
            message.to,
            message.call_id,
            message.cseq.method,
        ] {
            assert!(range.contains(&field.as_ptr()), "{field}");
        }
        assert!(range.contains(&message.body.as_ptr()));
        for (name, value) in message.headers.iter() {
            assert!(range.contains(&name.as_ptr()) && range.contains(&value.as_ptr()));
        }
    }

    /// Synthetique : deux messages dans un meme segment TCP. Le corps
    /// s'arrete a Content-Length ; un Content-Length plus long que le reste
    /// prend ce qui reste.
    #[test]
    fn content_length_bounds_the_body() {
        let mut segment = RFC_INVITE.to_vec();
        segment.extend_from_slice(RFC_RINGING_COMPACT);
        let message = SipMessage::try_from(segment.as_slice()).unwrap();
        assert_eq!(message.body.len(), 128);
        assert!(!message.body.windows(7).any(|window| window == b"SIP/2.0"));

        let cut = &RFC_INVITE[..RFC_INVITE.len() - 40];
        assert_eq!(SipMessage::try_from(cut).unwrap().body.len(), 88);

        let no_length = replace(RFC_INVITE, "Content-Length: 128\r\n", "");
        let message = SipMessage::try_from(no_length.as_slice()).unwrap();
        assert_eq!(message.content_length, None);
        assert_eq!(message.body.len(), 128);
    }

    /// Synthetique : un en-tete replie (§7.3.1) garde sa valeur brute.
    #[test]
    fn accepts_folded_headers() {
        let folded = replace(
            RFC_INVITE,
            "Max-Forwards: 70\r\n",
            "Subject: I know you're there,\r\n   pick up the phone\r\n",
        );
        let message = SipMessage::try_from(folded.as_slice()).unwrap();
        assert_eq!(
            message.headers.get("s"),
            Some("I know you're there,\r\n   pick up the phone")
        );
        let folded_to = replace(RFC_INVITE, "To: Bob ", "To: Bob\r\n\t");
        let message = SipMessage::try_from(folded_to.as_slice()).unwrap();
        assert_eq!(message.to, "Bob\r\n\t<sip:bob@biloxi.com>");
    }

    /// Synthetique : la version est sans casse, la methode avec (§7.1).
    #[test]
    fn version_ignores_case_method_does_not() {
        let lower = replace(RFC_INVITE, " SIP/2.0\r\n", " sip/2.0\r\n");
        assert!(SipMessage::try_from(lower.as_slice()).is_ok());
        let response = replace(RFC_RINGING_COMPACT, "SIP/2.0 180", "Sip/2.0 180");
        assert!(SipMessage::try_from(response.as_slice()).is_ok());
        let method = replace(RFC_INVITE, "INVITE sip:", "invite sip:");
        assert_eq!(
            SipMessage::try_from(method.as_slice()),
            Err(SipError::UnknownMethod)
        );
    }

    #[test]
    fn rejects_what_is_not_sip() {
        let cases: [(Vec<u8>, SipError); 16] = [
            (
                RFC_INVITE[..200].to_vec(),
                SipError::MissingHeaderTerminator,
            ),
            (
                {
                    let mut bytes = RFC_INVITE.to_vec();
                    bytes[40] = 0xff;
                    bytes
                },
                SipError::InvalidUtf8,
            ),
            (
                b"GET / HTTP/1.1\r\nHost: a\r\n\r\n".to_vec(),
                SipError::UnknownMethod,
            ),
            (
                replace(RFC_INVITE, "sip:bob@biloxi.com SIP", "bob@biloxi.com SIP"),
                SipError::InvalidRequestUri,
            ),
            (
                replace(RFC_INVITE, " SIP/2.0\r\nVia", " SIP/3.0\r\nVia"),
                SipError::InvalidVersion,
            ),
            (
                b"OPTIONS * HTTP/1.1\r\n\r\n".to_vec(),
                SipError::InvalidRequestUri,
            ),
            (
                replace(RFC_RINGING_COMPACT, "180 Ringing", "18 Ringing"),
                SipError::InvalidStatusCode,
            ),
            (
                replace(RFC_RINGING_COMPACT, "180 Ringing", "700 Ringing"),
                SipError::InvalidStatusCode,
            ),
            (
                replace(RFC_INVITE, "Max-Forwards: 70", "Max Forwards: 70"),
                SipError::InvalidHeader,
            ),
            (
                replace(RFC_INVITE, "SIP/2.0\r\nVia", "SIP/2.0\r\n Via"),
                SipError::InvalidHeader,
            ),
            (
                replace(RFC_INVITE, "Call-ID: a84b4c76e66710\r\n", ""),
                SipError::MissingHeader("Call-ID"),
            ),
            (
                replace(RFC_INVITE, "CSeq: 314159 INVITE", "CSeq: INVITE"),
                SipError::InvalidCseq,
            ),
            (
                replace(RFC_INVITE, "CSeq: 314159 INVITE", "CSeq: 314159 BYE"),
                SipError::CseqMethodMismatch {
                    request: "INVITE",
                    cseq: "BYE",
                },
            ),
            (
                replace(RFC_INVITE, "Content-Length: 128", "Content-Length: many"),
                SipError::InvalidContentLength,
            ),
            // Deux Content-Length, de valeurs differentes ou egales, en
            // forme longue ou compacte (§7.3.1, #383).
            (
                replace(
                    RFC_INVITE,
                    "Content-Length: 128",
                    "Content-Length: 0\r\nContent-Length: 128",
                ),
                SipError::DuplicateHeader("Content-Length"),
            ),
            (
                replace(
                    RFC_INVITE,
                    "Content-Length: 128",
                    "Content-Length: 128\r\nl: 128",
                ),
                SipError::DuplicateHeader("Content-Length"),
            ),
        ];
        for (payload, error) in cases {
            assert_eq!(
                SipMessage::try_from(payload.as_slice()),
                Err(error),
                "{}",
                String::from_utf8_lossy(&payload)
            );
        }
        for header in ["Via", "From", "To", "CSeq"] {
            let line_start = format!("\r\n{header}: ");
            let text = String::from_utf8(RFC_INVITE.to_vec()).unwrap();
            let start = text.find(&line_start).unwrap() + 2;
            let end = start + text[start..].find("\r\n").unwrap() + 2;
            let without = format!("{}{}", &text[..start], &text[end..]);
            assert_eq!(
                SipMessage::try_from(without.as_bytes()),
                Err(SipError::MissingHeader(header)),
                "{header}"
            );
        }
    }
}
