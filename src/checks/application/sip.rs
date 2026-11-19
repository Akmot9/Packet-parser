// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Controles des messages SIP (RFC 3261 §7, #342).
//!
//! La syntaxe est celle de HTTP/1.1, mais ce qui fait un message SIP est
//! verrouille ici : la version `SIP/2.0`, une methode du registre IANA, un
//! Request-URI avec un schema, un code de statut de 100 a 699, des noms
//! d'en-tete qui sont des tokens, et un CSeq `numero methode` avec un numero
//! sous 2^31 (§8.1.1.5).

use crate::errors::application::sip::SipError;

/// La seule version de SIP (RFC 3261 §7.1), comparee sans la casse.
pub const SIP_VERSION: &str = "SIP/2.0";

/// Les methodes du registre IANA « Session Initiation Protocol (SIP)
/// Parameters / Methods and Response Codes » : les six de RFC 3261, puis
/// PRACK (RFC 3262), SUBSCRIBE et NOTIFY (RFC 6665), PUBLISH (RFC 3903),
/// INFO (RFC 6086), REFER (RFC 3515), MESSAGE (RFC 3428) et UPDATE
/// (RFC 3311). Les noms de methode sont sensibles a la casse (§7.1).
pub const SIP_METHODS: [&str; 14] = [
    "INVITE",
    "ACK",
    "OPTIONS",
    "BYE",
    "CANCEL",
    "REGISTER",
    "PRACK",
    "SUBSCRIBE",
    "NOTIFY",
    "PUBLISH",
    "INFO",
    "REFER",
    "MESSAGE",
    "UPDATE",
];

/// Les formes compactes des en-tetes, `(compacte, longue)` : celles de
/// RFC 3261 §7.3.3 (`c`, `e`, `f`, `i`, `k`, `l`, `m`, `s`, `t`, `v`) et
/// celles du registre IANA des en-tetes : `a`, `d` et `j` (RFC 3841), `b`
/// (RFC 3892), `o` et `u` (RFC 6665), `r` (RFC 3515), `x` (RFC 4028), `y`
/// (RFC 8224) et `n` (RFC 4474, retire par RFC 8224 mais encore emis).
pub const SIP_COMPACT_FORMS: [(&str, &str); 20] = [
    ("a", "Accept-Contact"),
    ("b", "Referred-By"),
    ("c", "Content-Type"),
    ("d", "Request-Disposition"),
    ("e", "Content-Encoding"),
    ("f", "From"),
    ("i", "Call-ID"),
    ("j", "Reject-Contact"),
    ("k", "Supported"),
    ("l", "Content-Length"),
    ("m", "Contact"),
    ("n", "Identity-Info"),
    ("o", "Event"),
    ("r", "Refer-To"),
    ("s", "Subject"),
    ("t", "To"),
    ("u", "Allow-Events"),
    ("v", "Via"),
    ("x", "Session-Expires"),
    ("y", "Identity"),
];

/// Separateur entre la tete et le corps.
const HEAD_TERMINATOR: &[u8] = b"\r\n\r\n";

/// Plus grand numero de CSeq, exclu (RFC 3261 §8.1.1.5).
const CSEQ_LIMIT: u32 = 1 << 31;

/// Garde a cout constant, avant le decodeur : le payload commence par
/// `SIP/2.0 ` (casse ignoree) ou par une methode suivie d'un espace. Sans
/// elle, chaque payload TCP et UDP non reconnu paierait la recherche du
/// `CRLF CRLF` et la validation UTF-8.
pub fn may_start_sip(payload: &[u8]) -> bool {
    let version = SIP_VERSION.len();
    let is_status_line = payload.len() > version
        && payload[..version].eq_ignore_ascii_case(SIP_VERSION.as_bytes())
        && payload[version] == b' ';
    is_status_line
        || SIP_METHODS.iter().any(|method| {
            payload.starts_with(method.as_bytes()) && payload.get(method.len()) == Some(&b' ')
        })
}

/// Coupe le payload apres la tete : la tete, sans le `CRLF CRLF`, et ce qui
/// le suit. Le separateur est obligatoire : un datagramme porte le message
/// entier, et sur TCP une tete coupee par le segment ne prouve pas SIP.
pub fn split_sip_head(payload: &[u8]) -> Result<(&[u8], &[u8]), SipError> {
    let index = payload
        .windows(HEAD_TERMINATOR.len())
        .position(|window| window == HEAD_TERMINATOR)
        .ok_or(SipError::MissingHeaderTerminator)?;
    Ok((&payload[..index], &payload[index + HEAD_TERMINATOR.len()..]))
}

/// La tete est du texte UTF-8 (RFC 3261 §7 : `TEXT-UTF8`).
pub fn extract_sip_text(head: &[u8]) -> Result<&str, SipError> {
    std::str::from_utf8(head).map_err(|_| SipError::InvalidUtf8)
}

/// La methode du registre, sous sa forme statique.
pub fn known_sip_method(token: &str) -> Option<&'static str> {
    SIP_METHODS.iter().copied().find(|method| *method == token)
}

/// Vrai pour la version `SIP/2.0`, casse ignoree (§7.1).
pub fn is_sip_version(token: &str) -> bool {
    token.eq_ignore_ascii_case(SIP_VERSION)
}

/// Le reste d'une ligne de statut apres `SIP/2.0 `, ou `None` pour une
/// ligne de requete.
pub fn strip_status_line_version(line: &str) -> Option<&str> {
    let version = SIP_VERSION.len();
    let prefix = line.get(..version)?;
    if !is_sip_version(prefix) {
        return None;
    }
    line[version..].strip_prefix(' ')
}

/// Code de statut : trois chiffres, de 100 a 699 (§7.2, §21).
pub fn extract_sip_status_code(token: &str) -> Result<u16, SipError> {
    if token.len() != 3 || !token.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(SipError::InvalidStatusCode);
    }
    let code: u16 = token.parse().map_err(|_| SipError::InvalidStatusCode)?;
    if !(100..=699).contains(&code) {
        return Err(SipError::InvalidStatusCode);
    }
    Ok(code)
}

/// Request-URI : un schema (`ALPHA *(ALPHA / DIGIT / "+" / "-" / ".")`),
/// `:`, puis au moins un caractere ASCII visible (RFC 3261 §25.1,
/// `absoluteURI` de RFC 2396). `sip:`, `sips:`, `tel:` et `urn:` passent.
pub fn validate_sip_request_uri(uri: &str) -> Result<(), SipError> {
    let (scheme, rest) = uri.split_once(':').ok_or(SipError::InvalidRequestUri)?;
    let mut scheme_bytes = scheme.bytes();
    let starts_with_alpha = scheme_bytes.next().is_some_and(|b| b.is_ascii_alphabetic());
    let scheme_is_valid = starts_with_alpha
        && scheme_bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'));
    let rest_is_valid = !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_graphic());
    if scheme_is_valid && rest_is_valid {
        Ok(())
    } else {
        Err(SipError::InvalidRequestUri)
    }
}

/// Caracteres d'un `token` (RFC 3261 §25.1).
fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~'
        )
}

/// Une ligne d'en-tete logique, repli compris : `token *(SP / HTAB) ":"`
/// puis la valeur, blancs peripheriques exclus. La valeur d'un en-tete
/// replie garde ses `CRLF` et ses blancs interieurs.
pub fn extract_sip_header_line(line: &str) -> Result<(&str, &str), SipError> {
    let (name, value) = line.split_once(':').ok_or(SipError::InvalidHeader)?;
    let name = name.trim_end_matches([' ', '\t']);
    if name.is_empty() || !name.bytes().all(is_token_byte) {
        return Err(SipError::InvalidHeader);
    }
    Ok((name, value.trim()))
}

/// Les lignes logiques du bloc d'en-tetes : une ligne qui commence par un
/// espace ou une tabulation continue la precedente (§7.3.1). Chaque element
/// emprunte au bloc, `CRLF` interieurs des replis compris.
pub fn sip_header_lines(block: &str) -> impl Iterator<Item = &str> {
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

/// L'autre forme d'un nom d'en-tete, compacte pour un nom long et longue
/// pour un nom compact ; `None` pour un en-tete sans forme compacte.
pub fn sip_header_alias(name: &str) -> Option<&'static str> {
    SIP_COMPACT_FORMS.iter().find_map(|(compact, long)| {
        if name.eq_ignore_ascii_case(compact) {
            Some(*long)
        } else if name.eq_ignore_ascii_case(long) {
            Some(*compact)
        } else {
            None
        }
    })
}

/// Vrai si `name`, lu sur le fil, designe l'en-tete `long` ou sa forme
/// compacte. Les noms sont insensibles a la casse (§7.3.1).
pub fn is_sip_header(name: &str, long: &str) -> bool {
    name.eq_ignore_ascii_case(long)
        || sip_header_alias(long).is_some_and(|alias| name.eq_ignore_ascii_case(alias))
}

/// CSeq : `1*DIGIT LWS Method` (§20.16), numero sous 2^31 (§8.1.1.5) et
/// methode du registre, empruntee a la valeur.
pub fn extract_sip_cseq(value: &str) -> Result<(u32, &str), SipError> {
    let mut parts = value.split_ascii_whitespace();
    let (Some(number), Some(method), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(SipError::InvalidCseq);
    };
    if !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(SipError::InvalidCseq);
    }
    let sequence: u32 = number.parse().map_err(|_| SipError::InvalidCseq)?;
    if sequence >= CSEQ_LIMIT {
        return Err(SipError::InvalidCseq);
    }
    if known_sip_method(method).is_none() {
        return Err(SipError::InvalidCseq);
    }
    Ok((sequence, method))
}

/// Content-Length : des chiffres decimaux, sur 32 bits (§20.14).
pub fn extract_sip_content_length(value: &str) -> Result<u32, SipError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(SipError::InvalidContentLength);
    }
    value.parse().map_err(|_| SipError::InvalidContentLength)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_method_is_a_token_and_every_compact_form_one_letter() {
        for method in SIP_METHODS {
            assert!(method.bytes().all(is_token_byte), "{method}");
            assert_eq!(known_sip_method(method), Some(method));
        }
        for (compact, long) in SIP_COMPACT_FORMS {
            assert_eq!(compact.len(), 1, "{compact}");
            assert_eq!(sip_header_alias(compact), Some(long));
            assert_eq!(sip_header_alias(long), Some(compact));
            assert_eq!(sip_header_alias(&long.to_ascii_uppercase()), Some(compact));
        }
        assert_eq!(sip_header_alias("Max-Forwards"), None);
    }

    #[test]
    fn guard_wants_a_version_or_a_method_then_a_space() {
        assert!(may_start_sip(b"SIP/2.0 200 OK\r\n"));
        assert!(may_start_sip(b"sip/2.0 200 OK\r\n"));
        assert!(may_start_sip(b"INVITE sip:bob@biloxi.com SIP/2.0\r\n"));
        assert!(!may_start_sip(b"SIP/2.0"));
        assert!(!may_start_sip(b"SIP/2.0\r\n"));
        assert!(!may_start_sip(b"invite sip:bob@biloxi.com SIP/2.0\r\n"));
        assert!(!may_start_sip(b"INVITE"));
        assert!(!may_start_sip(b"GET / HTTP/1.1\r\n"));
        assert!(!may_start_sip(b""));
    }

    #[test]
    fn folded_lines_continue_the_previous_header() {
        let block = "Subject: I know you're there,\r\n   pick up the phone\r\n\tand talk\r\nTo: <sip:bob@biloxi.com>";
        let lines: Vec<&str> = sip_header_lines(block).collect();
        assert_eq!(
            lines,
            [
                "Subject: I know you're there,\r\n   pick up the phone\r\n\tand talk",
                "To: <sip:bob@biloxi.com>"
            ]
        );
        let (name, value) = extract_sip_header_line(lines[0]).unwrap();
        assert_eq!(name, "Subject");
        assert_eq!(
            value,
            "I know you're there,\r\n   pick up the phone\r\n\tand talk"
        );
    }

    #[test]
    fn header_names_are_tokens_followed_by_optional_blanks() {
        assert_eq!(extract_sip_header_line("Via :x"), Ok(("Via", "x")));
        assert_eq!(extract_sip_header_line("i:abc"), Ok(("i", "abc")));
        assert_eq!(
            extract_sip_header_line("No Colon"),
            Err(SipError::InvalidHeader)
        );
        assert_eq!(extract_sip_header_line(": x"), Err(SipError::InvalidHeader));
        assert_eq!(
            extract_sip_header_line("Bad Name: x"),
            Err(SipError::InvalidHeader)
        );
        assert_eq!(
            extract_sip_header_line(" Via: x"),
            Err(SipError::InvalidHeader)
        );
    }

    #[test]
    fn cseq_is_a_number_below_two_to_the_31_and_a_method() {
        assert_eq!(extract_sip_cseq("314159 INVITE"), Ok((314_159, "INVITE")));
        assert_eq!(extract_sip_cseq("1\t ACK"), Ok((1, "ACK")));
        assert_eq!(
            extract_sip_cseq("2147483647 BYE"),
            Ok((2_147_483_647, "BYE"))
        );
        for value in [
            "2147483648 BYE",
            "99999999999 BYE",
            "+1 BYE",
            "1",
            "1 invite",
            "1 FOO",
            "1 BYE extra",
            "",
        ] {
            assert_eq!(
                extract_sip_cseq(value),
                Err(SipError::InvalidCseq),
                "{value}"
            );
        }
    }

    #[test]
    fn status_codes_and_uris() {
        assert_eq!(extract_sip_status_code("100"), Ok(100));
        assert_eq!(extract_sip_status_code("699"), Ok(699));
        for token in ["099", "700", "20", "2000", "+20", "abc", ""] {
            assert_eq!(
                extract_sip_status_code(token),
                Err(SipError::InvalidStatusCode)
            );
        }
        for uri in [
            "sip:bob@biloxi.com",
            "sips:a@b",
            "tel:+33123",
            "urn:service:sos",
        ] {
            assert_eq!(validate_sip_request_uri(uri), Ok(()), "{uri}");
        }
        for uri in [
            "bob@biloxi.com",
            "sip:",
            ":x",
            "1sip:x",
            "s p:x",
            "sip:\u{e9}",
        ] {
            assert_eq!(
                validate_sip_request_uri(uri),
                Err(SipError::InvalidRequestUri),
                "{uri}"
            );
        }
    }

    #[test]
    fn content_length_is_decimal() {
        assert_eq!(extract_sip_content_length("0"), Ok(0));
        assert_eq!(extract_sip_content_length("142"), Ok(142));
        for value in ["", "-1", "1 2", "0x10", "4294967296"] {
            assert_eq!(
                extract_sip_content_length(value),
                Err(SipError::InvalidContentLength),
                "{value}"
            );
        }
    }
}
