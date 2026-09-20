// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Module for parsing HTTP packets.

use std::convert::TryFrom;

use crate::{
    checks::application::http::{
        extract_header_line, parse_payload_as_utf8, require_method, require_uri, require_version,
        split_head_body,
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
    pub body: &'a str,
}

/// The header fields of an [`HttpRequest`]: a borrowed view over the header
/// block, already validated — iterating cannot fail and does not allocate.
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
    let payload_str = parse_payload_as_utf8(payload)?;

    let (head, body) = split_head_body(payload_str);

    let mut lines = head.split("\r\n");

    // `split("\r\n")` produit toujours au moins un element, meme sur une
    // chaine vide : la premiere ligne existe donc structurellement, et une
    // ligne vide echoue ensuite en MissingMethod.
    let request_line = lines.next().unwrap_or_default();

    let mut request_parts = request_line.split_whitespace();
    let method = require_method(request_parts.next())?;
    let uri = require_uri(request_parts.next())?;
    let version = require_version(request_parts.next())?;

    // Les headers sont valides ici, une fois, et exposes comme une vue sur
    // leur bloc : rien n'est collecte.
    let block = head.get(request_line.len()..).unwrap_or_default();
    let block = block.strip_prefix("\r\n").unwrap_or(block);
    for line in lines {
        if line.is_empty() {
            break;
        }
        extract_header_line(line)?;
    }
    let headers = HttpHeaders { block };

    Ok(HttpRequest {
        method,
        uri,
        version,
        headers,
        body,
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
                    request.headers.iter().nth(0).expect("header present"),
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
                    request.headers.iter().nth(0).expect("header present"),
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
            request.headers.iter().nth(0).expect("header present").0,
            request.headers.iter().nth(0).expect("header present").1,
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
