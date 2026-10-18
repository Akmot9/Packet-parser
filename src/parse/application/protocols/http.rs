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
        extract_header_line, parse_payload_as_utf8, require_method, require_status_code,
        require_uri, require_version, split_head_body_bytes,
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
    let mut lines = head.split("\r\n");

    // `split("\r\n")` produit toujours au moins un element, meme sur une
    // chaine vide : la premiere ligne existe donc structurellement, et une
    // ligne vide echoue ensuite sur son premier jeton.
    let start_line = lines.next().unwrap_or_default();

    // Les headers sont valides ici, une fois, et exposes comme une vue sur
    // leur bloc : rien n'est collecte.
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

#[cfg(test)]
mod tests {
    use super::*;

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
