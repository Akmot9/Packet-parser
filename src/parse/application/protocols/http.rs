// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! HTTP/1.x (RFC 9112) : requetes ([`HttpRequest`]) et reponses
//! ([`HttpResponse`]), tels qu'ils tiennent dans un segment TCP, sans
//! reassemblage. La tete — ligne de depart et en-tetes, jusqu'au premier
//! `CRLF CRLF` — est validee en UTF-8 et ligne par ligne ; le corps est pris
//! tel quel, binaire compris (#176). Zero copie : tout emprunte au payload.

use std::convert::TryFrom;

use crate::{
    checks::application::http::{
        extract_header_line, find_byte, find_crlf, parse_payload_as_utf8, require_method,
        require_status_code, require_uri, require_version, split_head_body_bytes,
    },
    errors::application::http::HttpParseError,
};

/// HTTP Request
///
/// ```mermaid
/// ---
/// title: HttpRequest
/// ---
/// packet-beta
/// 0-63: "Request Line variable (Method SP URI SP Version CRLF)"
/// 64-127: "Headers variable (Name: Value CRLF)"
/// 128-143: "CRLF separator"
/// 144-207: "Body variable"
/// ```
///
/// The `HttpRequest` struct represents a parsed HTTP request.
///
/// All variable-length fields are zero-copy borrows into the original
/// packet payload: no packet bytes are copied during parsing.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct HttpRequest<'a> {
    pub method: &'a str,
    pub uri: &'a str,
    pub version: &'a str,
    /// Header fields, as a zero-copy view over the header block: every line
    /// is validated once while parsing, none is collected (#63). A `Vec`
    /// here cost ~18 % of the whole `parse()` of a real HTTP request, paid by
    /// every HTTP packet just to be recognized.
    pub headers: HttpHeaders<'a>,
    /// The body as text, when it is valid UTF-8; empty otherwise, the bytes
    /// being in [`HttpRequest::body_bytes`]. Until 11.6.0 a request whose
    /// body was not UTF-8 was rejected as a whole (#176).
    pub body: &'a str,
    /// The body, as carried: what follows the first `CRLF CRLF`, possibly
    /// binary or cut by the segment.
    pub body_bytes: &'a [u8],
}

/// HTTP response (RFC 9112 §4): status line, headers and body, as they fit
/// in one TCP segment.
///
/// ```mermaid
/// ---
/// title: HttpResponse
/// ---
/// packet-beta
/// 0-63: "Status Line variable (Version SP Code SP Reason CRLF)"
/// 64-127: "Headers variable (Name: Value CRLF)"
/// 128-143: "CRLF separator"
/// 144-207: "Body variable (bytes)"
/// ```
///
/// The head (status line and headers) is validated as UTF-8 and line by
/// line; the body is borrowed as bytes, binary (images, gzip) or cut by the
/// segment (`Transfer-Encoding: chunked` runs over several segments).
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct HttpResponse<'a> {
    /// `HTTP/1.1`, `HTTP/1.0`...
    pub version: &'a str,
    /// Three digits, `200`, `301`, `404`...
    pub status_code: u16,
    /// Reason phrase, `OK`, `Moved Permanently`; may be empty (RFC 9112 §4).
    pub reason: &'a str,
    pub headers: HttpHeaders<'a>,
    pub body: &'a [u8],
}

impl<'a> TryFrom<&'a [u8]> for HttpResponse<'a> {
    type Error = HttpParseError;

    fn try_from(payload: &'a [u8]) -> Result<Self, Self::Error> {
        parse_http_response(payload)
    }
}

/// Parses an HTTP response from a payload without copying packet bytes: the
/// status line `HTTP-version SP status-code SP [reason-phrase]` (RFC 9112
/// §4, the reason phrase keeps its spaces), then headers validated once.
/// The strict version and the three-digit code keep arbitrary text out of
/// HTTP.
pub fn parse_http_response(payload: &[u8]) -> Result<HttpResponse<'_>, HttpParseError> {
    let (head, body) = split_head_body_bytes(payload);
    let head = parse_payload_as_utf8(head)?;
    let (status_line, headers) = split_start_line(head)?;

    let mut parts = status_line.splitn(3, ' ');
    let version = require_version(parts.next().filter(|part| !part.is_empty()))?;
    let status_code = require_status_code(parts.next())?;
    let reason = parts.next().unwrap_or_default();

    Ok(HttpResponse {
        version,
        status_code,
        reason,
        headers,
        body,
    })
}

/// La ligne de depart d'une tete, et la vue sur ses en-tetes, chacun valide
/// une fois.
fn split_start_line(head: &str) -> Result<(&str, HttpHeaders<'_>), HttpParseError> {
    // La premiere ligne existe structurellement, meme sur une chaine vide :
    // sans `CRLF`, c'est toute la tete, et une ligne vide echoue ensuite sur
    // son premier jeton.
    let (start_line, block) = match find_crlf(head.as_bytes()) {
        Some(end) => (
            head.get(..end).unwrap_or_default(),
            head.get(end + 2..).unwrap_or_default(),
        ),
        None => (head, ""),
    };

    // Les headers sont valides ici, une fois, et exposes comme une vue sur
    // leur bloc : rien n'est collecte. Une ligne est valide quand elle porte
    // un `:` (`extract_header_line`) ; la lecture s'arrete a la ligne vide.
    let mut rest = block.as_bytes();
    loop {
        let (line, after) = match find_crlf(rest) {
            Some(end) => (rest.get(..end), rest.get(end + 2..)),
            None => (Some(rest), None),
        };
        let line = line.unwrap_or_default();
        if line.is_empty() {
            break;
        }
        if find_byte(line, b':').is_none() {
            return Err(HttpParseError::InvalidHeader);
        }
        let Some(after) = after else { break };
        rest = after;
    }
    Ok((start_line, HttpHeaders { block }))
}

/// The header fields of an [`HttpRequest`] or an [`HttpResponse`]: a
/// borrowed view over the header block, already validated — iterating
/// cannot fail and does not allocate.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct HttpHeaders<'a> {
    // Lignes de headers, sans la request line ni la ligne vide finale. Chaque
    // ligne est passee par `extract_header_line` au parsing.
    block: &'a str,
}

impl<'a> HttpHeaders<'a> {
    /// The `(name, value)` pairs, in wire order, both trimmed.
    pub fn iter(&self) -> impl Iterator<Item = (&'a str, &'a str)> + 'a {
        self.block
            .split("\r\n")
            .take_while(|line| !line.is_empty())
            // Infaillible : chaque ligne a ete validee au parsing.
            .filter_map(|line| extract_header_line(line).ok())
    }

    /// Value of the first header named `name`, compared case-insensitively
    /// (RFC 9110 §5.1).
    pub fn get(&self, name: &str) -> Option<&'a str> {
        self.iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
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

impl std::fmt::Debug for HttpHeaders<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<'a> TryFrom<&'a [u8]> for HttpRequest<'a> {
    type Error = HttpParseError;

    fn try_from(payload: &'a [u8]) -> Result<Self, Self::Error> {
        parse_http_request(payload)
    }
}

/// Parses an HTTP request from a given payload without copying packet bytes.
///
/// There is deliberately no up-front length pre-check: `HttpParseError` has
/// no "empty payload" variant, and every access below is bounded (`find`,
/// `split`, `split_whitespace` — no indexing), so an empty payload safely
/// flows through the chain and fails with `MissingMethod`.
pub fn parse_http_request(payload: &[u8]) -> Result<HttpRequest<'_>, HttpParseError> {
    let (head, body_bytes) = split_head_body_bytes(payload);
    let head = parse_payload_as_utf8(head)?;
    let (request_line, headers) = split_start_line(head)?;

    let mut request_parts = request_line.split_whitespace();
    let method = require_method(request_parts.next())?;
    let uri = require_uri(request_parts.next())?;
    let version = require_version(request_parts.next())?;

    Ok(HttpRequest {
        method,
        uri,
        version,
        headers,
        body: std::str::from_utf8(body_bytes).unwrap_or_default(),
        body_bytes,
    })
}

/// Les decodeurs tels qu'ils lisaient la tete par les chercheurs de `str`
/// (`windows`, `split("\r\n")`, `splitn(2, ':')`) : la reference des tests
/// differentiels, ici et dans ceux du dispatch.
#[cfg(test)]
pub(crate) mod reference {
    use super::*;

    fn split_head_body_bytes(payload: &[u8]) -> (&[u8], &[u8]) {
        match payload.windows(4).position(|window| window == b"\r\n\r\n") {
            Some(index) => (&payload[..index], &payload[index + 4..]),
            None => (payload, &[]),
        }
    }

    fn split_start_line(head: &str) -> Result<(&str, HttpHeaders<'_>), HttpParseError> {
        let mut lines = head.split("\r\n");
        let start_line = lines.next().unwrap_or_default();
        let block = head.get(start_line.len()..).unwrap_or_default();
        let block = block.strip_prefix("\r\n").unwrap_or(block);
        for line in lines {
            if line.is_empty() {
                break;
            }
            extract_header_line(line)?;
        }
        Ok((start_line, HttpHeaders { block }))
    }

    pub(crate) fn parse_http_request(payload: &[u8]) -> Result<HttpRequest<'_>, HttpParseError> {
        let (head, body_bytes) = split_head_body_bytes(payload);
        let head = parse_payload_as_utf8(head)?;
        let (request_line, headers) = split_start_line(head)?;

        let mut request_parts = request_line.split_whitespace();
        let method = require_method(request_parts.next())?;
        let uri = require_uri(request_parts.next())?;
        let version = require_version(request_parts.next())?;

        Ok(HttpRequest {
            method,
            uri,
            version,
            headers,
            body: std::str::from_utf8(body_bytes).unwrap_or_default(),
            body_bytes,
        })
    }

    pub(crate) fn parse_http_response(payload: &[u8]) -> Result<HttpResponse<'_>, HttpParseError> {
        let (head, body) = split_head_body_bytes(payload);
        let head = parse_payload_as_utf8(head)?;
        let (status_line, headers) = split_start_line(head)?;

        let mut parts = status_line.splitn(3, ' ');
        let version = require_version(parts.next().filter(|part| !part.is_empty()))?;
        let status_code = require_status_code(parts.next())?;
        let reason = parts.next().unwrap_or_default();

        Ok(HttpResponse {
            version,
            status_code,
            reason,
            headers,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Requetes et reponses du corpus (`The-Ultimate-PCAP.pcapng`, trames
    /// 1515 et 1517, corps abrege) et synthetiques : les graines du test
    /// differentiel.
    const DIFFERENTIAL_SEEDS: [&[u8]; 10] = [
        b"GET / HTTP/1.1\r\nHost: ip.webernetz.net\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; \
          WOW64; rv:26.0) Gecko/20100101 Firefox/26.0\r\nAccept: text/html,application/xhtml+xml,\
          application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\
          \r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nDate: Tue, 21 Jan 2014 11:28:16 GMT\r\nServer: Apache\r\n\
          Content-Length: 1328\r\nKeep-Alive: timeout=5, max=100\r\nConnection: Keep-Alive\r\n\
          Content-Type: text/html\r\n\r\n<table border=\"1\">\n\t<tr><td>caf\xc3\xa9</td></tr>\r\n\r\n",
        b"POST /submit HTTP/1.0\r\nContent-Length: 2\r\n\r\nok",
        b"POST /upload HTTP/1.1\r\nHost: a\r\nContent-Type: image/png\r\n\r\n\x89PNG\r\n\x1a\n\xff",
        b"OPTIONS * HTTP/2",
        b" \t\r\n GET  /espaces\t HTTP/1.1 \r\nX-Empty:\r\n:\r\n",
        b"CONNECT example.com:443 HTTP/1.1\r\n\r\n",
        b"HTTP/1.0 404 Not Found",
        b"HTTP/1.1 204 \r\nServer: x\r\nNotAHeader\r\n\r\n",
        b"GET /caf\xc3\xa9 HTTP/1.1\r\nX-Nom: \xe2\x82\xac\r\n\r\n",
    ];

    /// Les deux decodeurs rendent ce que rend leur reference, valeur ou
    /// erreur. Rend le nombre de succes.
    fn agrees_with_the_reference(payload: &[u8]) -> usize {
        let request = parse_http_request(payload);
        assert_eq!(
            request,
            reference::parse_http_request(payload),
            "{payload:?}"
        );
        let response = parse_http_response(payload);
        assert_eq!(
            response,
            reference::parse_http_response(payload),
            "{payload:?}"
        );
        usize::from(request.is_ok()) + usize::from(response.is_ok())
    }

    /// La tete lue par mots de huit octets donne, pour tout payload, le
    /// resultat de la lecture par les chercheurs de `str` : sur les graines,
    /// leurs troncatures, des fins de ligne inserees a chaque position et
    /// chaque octet remplace par les octets qui comptent pour la tete.
    #[test]
    fn test_decoders_agree_with_the_reference() {
        let (mut accepted, mut checked) = (0, 0);
        let mut check = |payload: &[u8]| {
            accepted += agrees_with_the_reference(payload);
            checked += 1;
        };
        check(b"");
        for seed in DIFFERENTIAL_SEEDS {
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
                    b'/',
                    b'.',
                    b'1',
                    0x00,
                    0x0c,
                    0x80,
                    0xff,
                    original ^ 0x20,
                    original.wrapping_add(1),
                ] {
                    mutated[position] = value;
                    check(&mutated);
                }
                mutated[position] = original;
                for inserted in [&b"\r\n"[..], b"\r\n\r\n", b"\r", b"\n", b":"] {
                    let mut longer = seed[..position].to_vec();
                    longer.extend_from_slice(inserted);
                    longer.extend_from_slice(&seed[position..]);
                    check(&longer);
                }
            }
        }
        assert!(checked > 15_000, "{checked} payloads");
        assert!(accepted > 8_000, "{accepted} decodages reussis");
    }

    #[test]
    fn test_headers_view_is_zero_copy_case_insensitive_and_validated_once() {
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Empty:\r\n\r\nbody";
        let request = HttpRequest::try_from(&payload[..]).expect("requete valide");

        assert_eq!(request.headers.len(), 2);
        assert_eq!(request.headers.get("host"), Some("example.com"));
        assert_eq!(request.headers.get("X-EMPTY"), Some(""));
        assert_eq!(request.headers.get("absent"), None);
        assert_eq!(request.body, "body");
        // Zero copie : les valeurs pointent dans le payload d'origine.
        let host = request.headers.get("Host").expect("header Host");
        assert!(payload.as_ptr_range().contains(&host.as_ptr()));
        assert_eq!(
            format!("{:?}", request.headers),
            r#"[("Host", "example.com"), ("X-Empty", "")]"#
        );

        // Une ligne de header invalide fait toujours echouer le parsing.
        assert!(HttpRequest::try_from(&b"GET / HTTP/1.1\r\nno-colon\r\n\r\n"[..]).is_err());
        // Sans header : vue vide.
        let bare = HttpRequest::try_from(&b"GET / HTTP/1.1\r\n\r\n"[..]).expect("requete valide");
        assert!(bare.headers.is_empty());
    }

    #[test]
    fn test_parse_http_request() {
        let http_payload = b"GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: curl/7.68.0\r\nAccept: */*\r\n\r\n";
        match HttpRequest::try_from(&http_payload[..]) {
            Ok(request) => {
                assert_eq!(request.method, "GET");
                assert_eq!(request.uri, "/index.html");
                assert_eq!(request.version, "HTTP/1.1");
                assert_eq!(request.headers.len(), 3);
                assert_eq!(
                    request.headers.iter().next().expect("header present"),
                    ("Host", "www.example.com")
                );
                assert_eq!(
                    request.headers.iter().nth(1).expect("header present"),
                    ("User-Agent", "curl/7.68.0")
                );
                assert_eq!(
                    request.headers.iter().nth(2).expect("header present"),
                    ("Accept", "*/*")
                );
                assert_eq!(request.body, "");
            }
            Err(_) => panic!("Expected HTTP request"),
        }
    }

    #[test]
    fn test_parse_http_request_with_body() {
        let http_payload = b"POST /submit HTTP/1.1\r\nHost: www.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 13\r\n\r\nfield1=value1";
        match HttpRequest::try_from(&http_payload[..]) {
            Ok(request) => {
                assert_eq!(request.method, "POST");
                assert_eq!(request.uri, "/submit");
                assert_eq!(request.version, "HTTP/1.1");
                assert_eq!(request.headers.len(), 3);
                assert_eq!(
                    request.headers.iter().next().expect("header present"),
                    ("Host", "www.example.com")
                );
                assert_eq!(
                    request.headers.iter().nth(1).expect("header present"),
                    ("Content-Type", "application/x-www-form-urlencoded")
                );
                assert_eq!(
                    request.headers.iter().nth(2).expect("header present"),
                    ("Content-Length", "13")
                );
                assert_eq!(request.body, "field1=value1");
            }
            Err(_) => panic!("Expected HTTP request with body"),
        }
    }

    #[test]
    fn test_parse_http_request_invalid() {
        let http_payload = b"INVALID REQUEST\r\n\r\n";
        match HttpRequest::try_from(&http_payload[..]) {
            Ok(_) => panic!("Expected invalid HTTP request"),
            Err(err) => assert_eq!(err, HttpParseError::InvalidMethod("INVALID".to_string())),
        }
    }

    #[test]
    fn test_parse_http_request_rejects_non_http_version() {
        let http_payload = b"GET something else\r\n\r\n";
        match HttpRequest::try_from(&http_payload[..]) {
            Ok(_) => panic!("Expected invalid HTTP request"),
            Err(err) => assert_eq!(err, HttpParseError::InvalidVersion("else".to_string())),
        }
    }

    #[test]
    fn test_parse_http_request_is_zero_copy() {
        let http_payload = b"GET /index.html HTTP/1.1\r\nHost: www.example.com\r\n\r\nbody";
        let request = HttpRequest::try_from(&http_payload[..]).expect("valid request");

        // Every borrowed field must point inside the original payload.
        let range = http_payload.as_ptr_range();
        for s in [
            request.method,
            request.uri,
            request.version,
            request.headers.iter().next().expect("header present").0,
            request.headers.iter().next().expect("header present").1,
            request.body,
        ] {
            let ptr = s.as_ptr();
            assert!(range.contains(&ptr), "field does not borrow from payload");
        }
        assert_eq!(request.body, "body");
    }

    #[test]
    fn test_parse_http_request_truncated_request_line() {
        // Request line cut after the URI: no version token.
        let http_payload = b"GET /index.html";
        match HttpRequest::try_from(&http_payload[..]) {
            Ok(_) => panic!("Expected truncated request line to fail"),
            Err(err) => assert_eq!(err, HttpParseError::MissingVersion),
        }
    }

    #[test]
    fn test_parse_http_request_missing_method_tokens() {
        // Empty payload: the request line exists but has no tokens.
        let http_payload = b"";
        match HttpRequest::try_from(&http_payload[..]) {
            Ok(_) => panic!("Expected empty payload to fail"),
            Err(err) => assert_eq!(err, HttpParseError::MissingMethod),
        }
    }

    #[test]
    fn test_parse_http_request_missing_crlf() {
        // No CRLF at all: the whole payload is the request line, no headers, no body.
        let http_payload = b"GET /index.html HTTP/1.1";
        let request = HttpRequest::try_from(&http_payload[..]).expect("valid bare request line");
        assert_eq!(request.method, "GET");
        assert_eq!(request.uri, "/index.html");
        assert_eq!(request.version, "HTTP/1.1");
        assert!(request.headers.is_empty());
        assert_eq!(request.body, "");
    }

    #[test]
    fn test_parse_http_request_invalid_header() {
        // Header line without a colon separator.
        let http_payload = b"GET / HTTP/1.1\r\nNotAHeader\r\n\r\n";
        match HttpRequest::try_from(&http_payload[..]) {
            Ok(_) => panic!("Expected invalid header to fail"),
            Err(err) => assert_eq!(err, HttpParseError::InvalidHeader),
        }
    }

    #[test]
    fn test_parse_http_request_non_utf8() {
        let http_payload = b"GET / HTTP/1.1\r\n\xFF\xFE\r\n\r\n";
        match HttpRequest::try_from(&http_payload[..]) {
            Ok(_) => panic!("Expected non-UTF-8 payload to fail"),
            Err(err) => assert_eq!(err, HttpParseError::InvalidUtf8),
        }
    }

    /// #176 : seule la tete est validee en UTF-8 ; un corps binaire dans le
    /// meme segment ne refuse plus la requete.
    #[test]
    fn test_parse_http_request_with_binary_body() {
        let http_payload =
            b"POST /upload HTTP/1.1\r\nHost: a\r\nContent-Type: image/png\r\n\r\n\x89PNG\r\n\x1a\n\xff";
        let request = HttpRequest::try_from(&http_payload[..]).expect("requete valide");
        assert_eq!(request.method, "POST");
        assert_eq!(request.headers.len(), 2);
        assert_eq!(request.body, "");
        assert_eq!(request.body_bytes, b"\x89PNG\r\n\x1a\n\xff");
        assert!(
            http_payload
                .as_ptr_range()
                .contains(&request.body_bytes.as_ptr())
        );
        // Un corps texte reste expose dans les deux champs.
        let text = HttpRequest::try_from(&b"POST / HTTP/1.1\r\n\r\nabc"[..]).unwrap();
        assert_eq!((text.body, text.body_bytes), ("abc", &b"abc"[..]));
    }

    /// #176 : les reponses, d'apres des tetes reelles du corpus.
    #[test]
    fn test_parse_http_response() {
        let payload = b"HTTP/1.1 301 Moved Permanently\r\nDate: Tue, 23 Jul 2024 09:00:00 GMT\r\nServer: Apache\r\nLocation: http://www.example.com/\r\nContent-Length: 2\r\nContent-Type: text/html; charset=iso-8859-1\r\n\r\n\xe9\xe0";
        let response = HttpResponse::try_from(&payload[..]).expect("reponse valide");
        assert_eq!(response.version, "HTTP/1.1");
        assert_eq!(response.status_code, 301);
        assert_eq!(response.reason, "Moved Permanently");
        assert_eq!(response.headers.len(), 5);
        assert_eq!(
            response.headers.get("location"),
            Some("http://www.example.com/")
        );
        assert_eq!(response.body, b"\xe9\xe0");
        let range = payload.as_ptr_range();
        for s in [response.version, response.reason] {
            assert!(range.contains(&s.as_ptr()));
        }
        assert!(range.contains(&response.body.as_ptr()));

        // Reponse en morceaux : la tete d'un serveur d'automate, deux-points
        // sans espace, corps `chunked` qui continue dans un autre segment.
        let chunked = HttpResponse::try_from(
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding:chunked\r\nContent-Type:application/json\r\n\r\n1f\r\n{\"a\":"[..],
        )
        .expect("reponse valide");
        assert_eq!((chunked.status_code, chunked.reason), (200, "OK"));
        assert_eq!(chunked.headers.get("Transfer-Encoding"), Some("chunked"));
        assert_eq!(chunked.body, b"1f\r\n{\"a\":");

        // Sans corps, sans CRLF final, avec un code sans phrase, en HTTP/1.0.
        let bare = HttpResponse::try_from(&b"HTTP/1.0 204 "[..]).expect("reponse valide");
        assert_eq!(
            (bare.version, bare.status_code, bare.reason),
            ("HTTP/1.0", 204, "")
        );
        assert!(bare.headers.is_empty());
        assert_eq!(bare.body, b"");
        let no_phrase = HttpResponse::try_from(&b"HTTP/1.1 204\r\n\r\n"[..]).expect("valide");
        assert_eq!((no_phrase.status_code, no_phrase.reason), (204, ""));
    }

    #[test]
    fn test_parse_http_response_rejects_what_is_not_a_status_line() {
        for (payload, error) in [
            (&b""[..], HttpParseError::MissingVersion),
            (&b"HTTP/1.1"[..], HttpParseError::MissingStatusCode),
            (
                &b"HTTP/1.1 20 OK"[..],
                HttpParseError::InvalidStatusCode("20".to_string()),
            ),
            (
                &b"HTTP/1.1 abc OK"[..],
                HttpParseError::InvalidStatusCode("abc".to_string()),
            ),
            (
                &b"HTTP/1.1  200 OK"[..],
                HttpParseError::InvalidStatusCode(String::new()),
            ),
            (
                &b"HTTP/zzz 200 OK"[..],
                HttpParseError::InvalidVersion("HTTP/zzz".to_string()),
            ),
            (
                &b"GET / HTTP/1.1\r\n\r\n"[..],
                HttpParseError::InvalidVersion("GET".to_string()),
            ),
            (
                &b"HTTP/1.1 200 OK\r\nno-colon\r\n\r\n"[..],
                HttpParseError::InvalidHeader,
            ),
            (
                &b"HTTP/1.1 200 OK\r\nX: \xff\r\n\r\n"[..],
                HttpParseError::InvalidUtf8,
            ),
        ] {
            assert_eq!(
                HttpResponse::try_from(payload),
                Err(error),
                "{}",
                String::from_utf8_lossy(payload)
            );
        }
        // Une requete n'est pas une reponse, et reciproquement.
        assert!(HttpRequest::try_from(&b"HTTP/1.1 200 OK\r\n\r\n"[..]).is_err());
    }

    #[test]
    fn test_parse_http_request_empty_body() {
        let http_payload = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
        let request = HttpRequest::try_from(&http_payload[..]).expect("valid request");
        assert_eq!(request.body, "");
    }

    #[test]
    fn test_parse_http_request_multiline_body() {
        let http_payload = b"POST / HTTP/1.1\r\nHost: a\r\n\r\nline1\r\nline2";
        let request = HttpRequest::try_from(&http_payload[..]).expect("valid request");
        assert_eq!(request.body, "line1\r\nline2");
    }
}
