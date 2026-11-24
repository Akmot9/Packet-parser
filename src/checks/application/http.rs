// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use crate::errors::application::http::HttpParseError;

/// Separator between the head (start line + headers) and the body.
const HEAD_BODY_SEPARATOR: &str = "\r\n\r\n";

/// Validates that the payload is UTF-8 and returns it as a borrowed `&str`.
///
/// The validation is done once with `std::str::from_utf8`: no allocation,
/// no lossy replacement of invalid bytes.
pub fn parse_payload_as_utf8(payload: &[u8]) -> Result<&str, HttpParseError> {
    std::str::from_utf8(payload).map_err(|_| HttpParseError::InvalidUtf8)
}

/// L'octet de poids faible, puis de poids fort, de chaque octet d'un mot.
const LOW_BITS: u64 = 0x0101_0101_0101_0101;
const HIGH_BITS: u64 = 0x8080_8080_8080_8080;

/// Indice du premier octet `needle` de `haystack`, lu par mots de huit
/// octets : une instruction par octet, la ou une boucle octet par octet,
/// `windows` ou le `find` de `str` en coutent de cinq a dix sur les lignes
/// d'une tete HTTP.
///
/// `word ^ pattern` annule les octets egaux a `needle` ; `(x - LOW_BITS) &
/// !x & HIGH_BITS` leve alors le bit fort de chaque octet nul. Une retenue
/// peut le lever a tort sur un octet valant 1, mais seulement au-dessus d'un
/// octet nul : le bit leve le plus bas designe toujours le premier octet
/// egal, et lui seul est lu.
pub(crate) fn find_byte(haystack: &[u8], needle: u8) -> Option<usize> {
    let pattern = LOW_BITS * u64::from(needle);
    let mut rest = haystack;
    let mut index = 0;
    while let Some((word, after)) = rest.split_first_chunk::<8>() {
        let x = u64::from_le_bytes(*word) ^ pattern;
        let found = x.wrapping_sub(LOW_BITS) & !x & HIGH_BITS;
        if found != 0 {
            return Some(index + (found.trailing_zeros() / 8) as usize);
        }
        rest = after;
        index += 8;
    }
    rest.iter()
        .position(|byte| *byte == needle)
        .map(|position| index + position)
}

/// Indice du premier `CRLF` de `text` : ce que rend `str::find("\r\n")`
/// sur du texte, sans le chercheur de sous-chaine de la bibliotheque.
pub(crate) fn find_crlf(text: &[u8]) -> Option<usize> {
    let mut from = 0;
    loop {
        let carriage_return = from + find_byte(text.get(from..)?, b'\r')?;
        if text.get(carriage_return + 1) == Some(&b'\n') {
            return Some(carriage_return);
        }
        from = carriage_return + 1;
    }
}

/// Indice du premier `CRLF CRLF` de `payload`, la fin d'une tete HTTP, SIP
/// ou SSDP. Un `CRLF` que ne suit pas un second ne peut en ouvrir un autre
/// avant deux octets : la recherche reprend apres lui.
pub(crate) fn find_head_end(payload: &[u8]) -> Option<usize> {
    let mut from = 0;
    loop {
        let line_end = from + find_crlf(payload.get(from..)?)?;
        if payload.get(line_end + 2..line_end + 4) == Some(b"\r\n") {
            return Some(line_end);
        }
        from = line_end + 2;
    }
}

/// Coupe le payload autour du premier `CRLF CRLF` : la tete (ligne de depart
/// et en-tetes) et le corps, en octets. Sans separateur, tout le payload est
/// la tete et le corps est vide. Seule la tete est ensuite validee en UTF-8
/// (#176) : le corps peut etre binaire (image, gzip).
pub fn split_head_body_bytes(payload: &[u8]) -> (&[u8], &[u8]) {
    match find_head_end(payload) {
        Some(index) => (
            &payload[..index],
            &payload[index + HEAD_BODY_SEPARATOR.len()..],
        ),
        None => (payload, &[]),
    }
}

/// Exige un code de statut de trois chiffres (RFC 9112 §4 : `status-code =
/// 3DIGIT`), et le rend. Trois chiffres exactement, et pas une version
/// stricte seule, gardent un texte quelconque commencant par `HTTP/1.1 `
/// hors de HTTP.
pub fn require_status_code(part: Option<&str>) -> Result<u16, HttpParseError> {
    let code = part.ok_or(HttpParseError::MissingStatusCode)?;
    if code.len() != 3 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(HttpParseError::InvalidStatusCode(code.to_string()));
    }
    code.parse()
        .map_err(|_| HttpParseError::InvalidStatusCode(code.to_string()))
}

/// Standard HTTP request methods (RFC 9110) accepted by the parser.
const HTTP_METHODS: [&str; 9] = [
    "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
];

/// Requires the HTTP method token to be present and to be a standard HTTP
/// method, then returns it borrowed. Rejecting unknown methods keeps random
/// text payloads from being classified as HTTP.
pub fn require_method(part: Option<&str>) -> Result<&str, HttpParseError> {
    let method = part.ok_or(HttpParseError::MissingMethod)?;
    if !HTTP_METHODS.contains(&method) {
        return Err(HttpParseError::InvalidMethod(method.to_string()));
    }
    Ok(method)
}

/// Requires the URI token to be present and returns it borrowed.
pub fn require_uri(part: Option<&str>) -> Result<&str, HttpParseError> {
    part.ok_or(HttpParseError::MissingUri)
}

/// Requires the HTTP version token to be present and shaped like `HTTP/x.y`,
/// then returns it borrowed.
///
/// The digits are checked, not just the `HTTP/` prefix: accepting `HTTP/zzz`
/// let arbitrary text be classified as an HTTP request line.
pub fn require_version(part: Option<&str>) -> Result<&str, HttpParseError> {
    let version = part.ok_or(HttpParseError::MissingVersion)?;
    let invalid = || HttpParseError::InvalidVersion(version.to_string());

    let digits = version.strip_prefix("HTTP/").ok_or_else(invalid)?;
    let (major, minor) = match digits.split_once('.') {
        Some((major, minor)) => (major, Some(minor)),
        None => (digits, None),
    };

    let is_single_digit =
        |part: &str| part.len() == 1 && part.starts_with(|c: char| c.is_ascii_digit());
    if !is_single_digit(major) || minor.is_some_and(|minor| !is_single_digit(minor)) {
        return Err(invalid());
    }
    Ok(version)
}

/// Garde a cout constant de la sonde HTTP (#249) : ce payload peut-il
/// commencer une requete ? Le decodeur exige que le premier jeton de la
/// premiere ligne soit une methode standard, et `split_whitespace` saute
/// les blancs qui le precedent. La garde saute donc les memes blancs, puis
/// compare le debut aux methodes.
///
/// Elle ne refuse que ce que `parse_http_request` refuserait. Sans elle, le
/// decodeur cherche `CRLF CRLF` dans tout le payload puis valide la tete en
/// UTF-8 avant de regarder la methode : chaque segment TCP non reconnu
/// payait deux parcours complets (1,2 µs pour 1 208 octets).
pub fn may_start_request(payload: &[u8]) -> bool {
    let start = skip_leading_whitespace(payload);
    HTTP_METHODS
        .iter()
        .any(|method| start.starts_with(method.as_bytes()))
}

/// Garde a cout constant de la sonde HTTP (#249) : ce payload peut-il
/// commencer une reponse ? Le decodeur exige une version `HTTP/x.y` en
/// premier jeton de la ligne de statut, sans blanc devant.
pub fn may_start_response(payload: &[u8]) -> bool {
    payload.starts_with(b"HTTP/")
}

/// Le payload sans ses blancs de tete, au sens de [`char::is_whitespace`]
/// (celui de `split_whitespace`), lus directement dans leur encodage UTF-8.
/// Un octet qui ne commence pas un blanc arrete la lecture : le cout est
/// constant sur tout payload qui ne commence pas par un blanc.
fn skip_leading_whitespace(mut bytes: &[u8]) -> &[u8] {
    loop {
        let width = match bytes {
            // U+0009 a U+000D, U+0020.
            [b'\t'..=b'\r' | b' ', ..] => 1,
            // U+0085, U+00A0.
            [0xC2, 0x85 | 0xA0, ..] => 2,
            // U+1680.
            [0xE1, 0x9A, 0x80, ..]
            // U+2000 a U+200A, U+2028, U+2029, U+202F.
            | [0xE2, 0x80, 0x80..=0x8A | 0xA8 | 0xA9 | 0xAF, ..]
            // U+205F.
            | [0xE2, 0x81, 0x9F, ..]
            // U+3000.
            | [0xE3, 0x80, 0x80, ..] => 3,
            _ => return bytes,
        };
        bytes = bytes.get(width..).unwrap_or_default();
    }
}

/// Requires a header name or value part to be present and returns it borrowed.
pub fn require_header_part(part: Option<&str>) -> Result<&str, HttpParseError> {
    part.ok_or(HttpParseError::InvalidHeader)
}

/// Checks that a header line contains a `:` separator and returns the
/// borrowed `(name, value)` pair, both trimmed of surrounding whitespace.
/// A line without a `:` yields `InvalidHeader`.
pub fn extract_header_line(line: &str) -> Result<(&str, &str), HttpParseError> {
    let mut header_parts = line.splitn(2, ':');
    let name = require_header_part(header_parts.next())?.trim();
    let value = require_header_part(header_parts.next())?.trim();
    Ok((name, value))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// La table de `skip_leading_whitespace` est exactement
    /// `char::is_whitespace` : un blanc oublie ferait refuser par la garde
    /// une requete que le decodeur accepte.
    #[test]
    fn skip_leading_whitespace_matches_char_is_whitespace() {
        let mut buffer = [0u8; 4];
        for character in (0..=u32::from(char::MAX)).filter_map(char::from_u32) {
            let encoded = character.encode_utf8(&mut buffer).as_bytes();
            assert_eq!(
                skip_leading_whitespace(encoded).is_empty(),
                character.is_whitespace(),
                "U+{:04X}",
                u32::from(character)
            );
        }
    }

    #[test]
    fn request_guard_skips_whitespace_and_wants_a_method() {
        assert!(may_start_request(b"GET / HTTP/1.1\r\n\r\n"));
        assert!(may_start_request(b" \t\nPATCH /x HTTP/1.1"));
        assert!(may_start_request(
            "\u{a0}\u{2003}\u{3000}DELETE /".as_bytes()
        ));
        assert!(!may_start_request(b""));
        assert!(!may_start_request(b"   "));
        assert!(!may_start_request(b"get / HTTP/1.1"));
        assert!(!may_start_request(b"INVALID REQUEST"));
        assert!(!may_start_request(b"HTTP/1.1 200 OK"));
        assert!(!may_start_request(&[0x17, 0x03, 0x03, 0x00, 0x20]));
    }

    #[test]
    fn response_guard_wants_the_version_first() {
        assert!(may_start_response(b"HTTP/1.1 200 OK\r\n\r\n"));
        assert!(!may_start_response(b" HTTP/1.1 200 OK"));
        assert!(!may_start_response(b"HTTP"));
        assert!(!may_start_response(b"GET / HTTP/1.1"));
    }

    #[test]
    fn test_parse_payload_as_utf8_valid() {
        let payload = b"GET / HTTP/1.1";
        let result = parse_payload_as_utf8(payload).expect("valid UTF-8");
        assert_eq!(result, "GET / HTTP/1.1");
        // Zero-copy: the returned str borrows the input bytes.
        assert_eq!(result.as_ptr(), payload.as_ptr());
    }

    #[test]
    fn test_parse_payload_as_utf8_invalid() {
        let payload = [0x47, 0x45, 0x54, 0xFF, 0xFE];
        assert_eq!(
            parse_payload_as_utf8(&payload),
            Err(HttpParseError::InvalidUtf8)
        );
    }

    #[test]
    fn test_split_head_body_bytes() {
        assert_eq!(
            split_head_body_bytes(b"HTTP/1.1 200 OK\r\nA: b\r\n\r\n\xff\xfe"),
            (&b"HTTP/1.1 200 OK\r\nA: b"[..], &b"\xff\xfe"[..])
        );
        assert_eq!(
            split_head_body_bytes(b"HTTP/1.1 200 OK\r\n"),
            (&b"HTTP/1.1 200 OK\r\n"[..], &b""[..])
        );
    }

    /// Chaque sequence de `length` octets pris dans `alphabet`.
    fn sequences(alphabet: &[u8], length: usize, visit: &mut impl FnMut(&[u8])) {
        let mut digits = vec![0; length];
        let mut sequence = vec![alphabet[0]; length];
        loop {
            visit(&sequence);
            let mut position = 0;
            loop {
                let Some(digit) = digits.get_mut(position) else {
                    return;
                };
                *digit = (*digit + 1) % alphabet.len();
                sequence[position] = alphabet[*digit];
                if *digit != 0 {
                    break;
                }
                position += 1;
            }
        }
    }

    /// La recherche par mots rend l'indice de `position`, sur toutes les
    /// sequences courtes d'un alphabet qui porte l'octet cherche et ceux
    /// qu'une retenue pourrait confondre avec lui (`needle ^ 1`, `needle ^
    /// 0x80`), puis autour des frontieres de mots.
    #[test]
    fn find_byte_is_the_position_of_the_first_equal_byte() {
        for needle in [b'\r', b':', 0x00, 0x01, 0x7f, 0x80, 0xff] {
            let alphabet = [
                needle,
                needle ^ 1,
                needle ^ 0x80,
                b'a',
                needle.wrapping_add(1),
            ];
            let mut checked = 0;
            for length in 0..=7 {
                sequences(&alphabet, length, &mut |haystack| {
                    assert_eq!(
                        find_byte(haystack, needle),
                        haystack.iter().position(|byte| *byte == needle),
                        "{needle:#04x} dans {haystack:02x?}"
                    );
                    checked += 1;
                });
            }
            assert!(checked > 90_000, "{checked} sequences");

            // Un octet cherche, puis deux, a chaque position de 40 octets de
            // chaque octet de remplissage.
            for filler in alphabet.into_iter().skip(1) {
                for length in 0..40 {
                    let mut haystack = vec![filler; length];
                    assert_eq!(find_byte(&haystack, needle), None);
                    for first in 0..length {
                        haystack[first] = needle;
                        assert_eq!(find_byte(&haystack, needle), Some(first));
                        for second in first + 1..length {
                            haystack[second] = needle;
                            assert_eq!(find_byte(&haystack, needle), Some(first));
                            haystack[second] = filler;
                        }
                        haystack[first] = filler;
                    }
                }
            }
        }
    }

    /// `find_crlf` et `find_head_end` rendent l'indice de la premiere
    /// occurrence, comme la recherche par fenetres qu'ils remplacent : sur
    /// toutes les sequences de CR, de LF et de texte jusqu'a dix octets, puis
    /// sur des lignes plus longues qu'un mot.
    #[test]
    fn line_end_searches_are_the_first_occurrence() {
        fn first(haystack: &[u8], needle: &[u8]) -> Option<usize> {
            haystack
                .windows(needle.len())
                .position(|window| window == needle)
        }
        fn check(text: &[u8]) {
            assert_eq!(find_crlf(text), first(text, b"\r\n"), "{text:?}");
            assert_eq!(find_head_end(text), first(text, b"\r\n\r\n"), "{text:?}");
            let (head, body) = split_head_body_bytes(text);
            match first(text, b"\r\n\r\n") {
                Some(index) => assert_eq!((head, body), (&text[..index], &text[index + 4..])),
                None => assert_eq!((head, body), (text, &b""[..])),
            }
        }
        let mut checked = 0;
        for length in 0..=10 {
            sequences(b"\r\na", length, &mut |text| {
                check(text);
                checked += 1;
            });
        }
        assert!(checked > 80_000, "{checked} sequences");

        // Des fins de ligne a chaque position de lignes de 0 a 20 octets.
        for line in 0..=20 {
            for ending in [
                &b"\r\n"[..],
                b"\r\n\r\n",
                b"\r",
                b"\n",
                b"\r\r\n",
                b"\r\n\r",
                b"\n\r\n",
            ] {
                for lines in 1..=3 {
                    let mut text = Vec::new();
                    for _ in 0..lines {
                        text.resize(text.len() + line, b'x');
                        text.extend_from_slice(ending);
                    }
                    check(&text);
                    text.extend_from_slice(b"\r\n\r\nbody");
                    check(&text);
                }
            }
        }
    }

    #[test]
    fn test_require_status_code() {
        assert_eq!(require_status_code(Some("200")), Ok(200));
        assert_eq!(require_status_code(Some("404")), Ok(404));
        assert_eq!(
            require_status_code(None),
            Err(HttpParseError::MissingStatusCode)
        );
        for code in ["20", "2000", "abc", "20a", " 200", "٢٠٠"] {
            assert_eq!(
                require_status_code(Some(code)),
                Err(HttpParseError::InvalidStatusCode(code.to_string())),
                "{code}"
            );
        }
    }

    #[test]
    fn test_require_method() {
        assert_eq!(require_method(Some("GET")), Ok("GET"));
        assert_eq!(require_method(None), Err(HttpParseError::MissingMethod));
    }

    #[test]
    fn test_require_uri() {
        assert_eq!(require_uri(Some("/index.html")), Ok("/index.html"));
        assert_eq!(require_uri(None), Err(HttpParseError::MissingUri));
    }

    #[test]
    fn test_require_version() {
        assert_eq!(require_version(Some("HTTP/1.1")), Ok("HTTP/1.1"));
        assert_eq!(require_version(None), Err(HttpParseError::MissingVersion));
    }

    #[test]
    fn test_require_version_accepts_digit_forms() {
        for version in ["HTTP/0.9", "HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/3"] {
            assert_eq!(require_version(Some(version)), Ok(version));
        }
    }

    #[test]
    fn test_require_version_rejects_malformed_forms() {
        // Le préfixe seul ne suffit pas : ce qui suit doit être un chiffre,
        // éventuellement suivi d'un point et d'un second chiffre.
        for version in [
            "HTTP/zzz",
            "HTTP/",
            "HTTP/1.",
            "HTTP/.1",
            "HTTP/11",
            "HTTP/1.1.1",
            "HTTP/1x",
            "HTTP/ 1",
        ] {
            assert_eq!(
                require_version(Some(version)),
                Err(HttpParseError::InvalidVersion(version.to_string())),
                "{version} devrait être rejeté"
            );
        }
    }

    #[test]
    fn test_require_header_part() {
        assert_eq!(require_header_part(Some("Host")), Ok("Host"));
        assert_eq!(
            require_header_part(None),
            Err(HttpParseError::InvalidHeader)
        );
    }

    #[test]
    fn test_extract_header_line_valid() {
        assert_eq!(
            extract_header_line("Host: www.example.com"),
            Ok(("Host", "www.example.com"))
        );
        // No space after the colon, and surrounding whitespace is trimmed.
        assert_eq!(extract_header_line("Accept:*/*"), Ok(("Accept", "*/*")));
        assert_eq!(extract_header_line("  Host :  a  "), Ok(("Host", "a")));
    }

    #[test]
    fn test_extract_header_line_keeps_extra_colons_in_value() {
        assert_eq!(
            extract_header_line("Referer: http://example.com/"),
            Ok(("Referer", "http://example.com/"))
        );
    }

    #[test]
    fn test_extract_header_line_missing_colon() {
        assert_eq!(
            extract_header_line("NotAHeader"),
            Err(HttpParseError::InvalidHeader)
        );
    }
}
