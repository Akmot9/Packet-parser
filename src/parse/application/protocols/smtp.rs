// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Module for parsing SMTP messages (RFC 5321).

use std::convert::TryFrom;

use crate::{
    checks::application::smtp::{
        looks_like_reply, parse_payload_as_utf8, parse_reply_code, require_known_command,
        split_first_line, validate_command_syntax, validate_payload_characters,
    },
    errors::application::smtp::SmtpParseError,
};

/// A parsed SMTP message: either a client command or a server reply.
///
/// ```mermaid
/// ---
/// title: SMTP command or reply line
/// ---
/// packet-beta
/// 0-31: "Command verb or reply code"
/// 32-95: "Optional arguments or reply text"
/// 96-111: "CRLF"
/// ```
///
/// All borrowed fields are zero-copy views into the original packet payload.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SmtpMessage<'a> {
    /// A client command, e.g. `MAIL FROM:<a@b.com>`.
    Command {
        verb: &'a str,
        args: Option<&'a str>,
    },
    /// A server reply, e.g. `250 OK` or a multi-line `250-...`/`250 HELP`
    /// reply. `lines` holds the text of every line after its code/separator,
    /// in order; a single-line reply has exactly one entry.
    Reply { code: u16, lines: Vec<&'a str> },
}

impl<'a> TryFrom<&'a [u8]> for SmtpMessage<'a> {
    type Error = SmtpParseError;

    fn try_from(payload: &'a [u8]) -> Result<Self, Self::Error> {
        parse_smtp_message(payload)
    }
}

/// Parses an SMTP message from a given payload without copying packet bytes.
pub fn parse_smtp_message(payload: &[u8]) -> Result<SmtpMessage<'_>, SmtpParseError> {
    if payload.is_empty() {
        return Err(SmtpParseError::EmptyPayload);
    }

    let payload_str = parse_payload_as_utf8(payload)?;
    validate_payload_characters(payload_str)?;
    let (first_line, rest) = split_first_line(payload_str)?;

    if looks_like_reply(first_line) {
        let (code, separator, text) = parse_reply_code(first_line)?;
        return parse_reply(code, separator, text, rest);
    }

    let mut parts = first_line.splitn(2, ' ');
    let verb = require_known_command(parts.next().unwrap_or(""))?;
    let args = parts.next().map(str::trim).filter(|s| !s.is_empty());
    validate_command_syntax(verb, args, first_line)?;

    Ok(SmtpMessage::Command { verb, args })
}

/// Builds a `Reply` from its already-parsed first line. A single space
/// separator means a one-line reply; a dash starts a multi-line reply, whose
/// continuation lines are read from `rest` until a terminator line
/// (`{code} ...`) is found.
fn parse_reply<'a>(
    code: u16,
    separator: Option<u8>,
    text: &'a str,
    rest: &'a str,
) -> Result<SmtpMessage<'a>, SmtpParseError> {
    if separator != Some(b'-') {
        return Ok(SmtpMessage::Reply {
            code,
            lines: vec![text],
        });
    }

    let mut lines = vec![text];
    let mut remainder = rest;
    while !remainder.is_empty() {
        let (line, next) = split_first_line(remainder)?;
        remainder = next;
        match parse_reply_code(line) {
            // The final line repeats the same code and uses either a space or
            // the RFC-permitted bare-code form.
            Ok((line_code, Some(b' ') | None, line_text)) if line_code == code => {
                lines.push(line_text);
                return Ok(SmtpMessage::Reply { code, lines });
            }
            // Every non-final SMTP line must repeat the initial code followed
            // by a hyphen (RFC 5321 section 4.2.1).
            Ok((line_code, Some(b'-'), line_text)) if line_code == code => {
                lines.push(line_text);
            }
            _ => {
                return Err(SmtpParseError::InvalidMultilineReply(line.to_string()));
            }
        }
    }

    Err(SmtpParseError::MissingReplyTerminator)
}

/// Le decodeur tel qu'il coupait les lignes par `str::find` : la reference
/// des tests differentiels, ici et dans ceux du dispatch.
#[cfg(test)]
pub(crate) mod reference {
    use super::*;

    fn split_first_line(payload: &str) -> Result<(&str, &str), SmtpParseError> {
        match payload.find("\r\n") {
            Some(index) => Ok((&payload[..index], &payload[index + 2..])),
            None => Err(SmtpParseError::IncompleteLine),
        }
    }

    fn parse_reply_code(line: &str) -> Result<(u16, Option<u8>, &str), SmtpParseError> {
        let bytes = line.as_bytes();
        if bytes.len() < 3 || !bytes[..3].iter().all(u8::is_ascii_digit) {
            return Err(SmtpParseError::InvalidReplyCode(line.to_string()));
        }
        let code: u16 = line[..3].parse().expect("validated ASCII digits");
        if !(200..=599).contains(&code) {
            return Err(SmtpParseError::InvalidReplyCode(line.to_string()));
        }
        match bytes.get(3).copied() {
            None => Ok((code, None, "")),
            Some(separator @ (b' ' | b'-')) => Ok((code, Some(separator), &line[4..])),
            Some(_) => Err(SmtpParseError::InvalidReplyCode(line.to_string())),
        }
    }

    pub(crate) fn parse_smtp_message(payload: &[u8]) -> Result<SmtpMessage<'_>, SmtpParseError> {
        if payload.is_empty() {
            return Err(SmtpParseError::EmptyPayload);
        }

        let payload_str = parse_payload_as_utf8(payload)?;
        validate_payload_characters(payload_str)?;
        let (first_line, rest) = split_first_line(payload_str)?;

        if looks_like_reply(first_line) {
            let (code, separator, text) = parse_reply_code(first_line)?;
            if separator != Some(b'-') {
                return Ok(SmtpMessage::Reply {
                    code,
                    lines: vec![text],
                });
            }

            let mut lines = vec![text];
            let mut remainder = rest;
            while !remainder.is_empty() {
                let (line, next) = split_first_line(remainder)?;
                remainder = next;
                match parse_reply_code(line) {
                    Ok((line_code, Some(b' ') | None, line_text)) if line_code == code => {
                        lines.push(line_text);
                        return Ok(SmtpMessage::Reply { code, lines });
                    }
                    Ok((line_code, Some(b'-'), line_text)) if line_code == code => {
                        lines.push(line_text);
                    }
                    _ => {
                        return Err(SmtpParseError::InvalidMultilineReply(line.to_string()));
                    }
                }
            }
            return Err(SmtpParseError::MissingReplyTerminator);
        }

        let mut parts = first_line.splitn(2, ' ');
        let verb = require_known_command(parts.next().unwrap_or(""))?;
        let args = parts.next().map(str::trim).filter(|s| !s.is_empty());
        validate_command_syntax(verb, args, first_line)?;

        Ok(SmtpMessage::Command { verb, args })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Le decodeur rend le message ou l'erreur de sa reference : sur les
    /// trames du corpus et des commandes, leurs troncatures, des fins de
    /// ligne inserees a chaque position et chaque octet remplace par les
    /// octets qui comptent pour une ligne de commande ou de reponse.
    #[test]
    fn test_decoder_agrees_with_the_reference() {
        let seeds: [&[u8]; 9] = [
            BANNER_REPLY,
            EHLO_COMMAND,
            EHLO_REPLY,
            MAIL_FROM_COMMAND,
            RCPT_TO_COMMAND,
            DATA_REPLY,
            b"250\r\n",
            b"250-a\r\n250\r\n250 trop\r\n",
            b"quit\r\nNOOP\r\n",
        ];
        let (mut accepted, mut checked) = (0, 0);
        let mut check = |payload: &[u8]| {
            let decoded = parse_smtp_message(payload);
            assert_eq!(
                decoded,
                reference::parse_smtp_message(payload),
                "{payload:?}"
            );
            accepted += usize::from(decoded.is_ok());
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
                    b' ',
                    b'-',
                    b'\t',
                    b'2',
                    b'9',
                    b'<',
                    0x00,
                    0x80,
                    original ^ 0x20,
                    original.wrapping_add(1),
                ] {
                    mutated[position] = value;
                    check(&mutated);
                }
                mutated[position] = original;
                for inserted in [&b"\r\n"[..], b"\r", b"250 ", b"250-", b" "] {
                    let mut longer = seed[..position].to_vec();
                    longer.extend_from_slice(inserted);
                    longer.extend_from_slice(&seed[position..]);
                    check(&longer);
                }
            }
        }
        assert!(checked > 5_000, "{checked} payloads");
        assert!(accepted > 1_000, "{accepted} messages decodes");
    }

    // Trames reelles :
    // pcaps_exemple/protocols/smtp/smtp_control.pcapng. Les numeros originaux
    // du sample Wireshark sont documentes dans SOURCE.md.

    /// Trame 1 (originale 6) : banniere multi-lignes du serveur.
    const BANNER_REPLY: &[u8] = b"220-xc90.websitewelcome.com ESMTP Exim 4.69 #1 Mon, 05 Oct 2009 01:05:54 -0500 \r\n220-We do not authorize the use of this system to transport unsolicited, \r\n220 and/or bulk e-mail.\r\n";
    /// Trame 2 (originale 7) : commande EHLO.
    const EHLO_COMMAND: &[u8] = b"EHLO GP\r\n";
    /// Trame 3 (originale 9) : reponse EHLO multi-lignes avec les extensions.
    const EHLO_REPLY: &[u8] = b"250-xc90.websitewelcome.com Hello GP [122.162.143.157]\r\n250-SIZE 52428800\r\n250-PIPELINING\r\n250-AUTH PLAIN LOGIN\r\n250-STARTTLS\r\n250 HELP\r\n";
    // Fixtures de syntaxe anonymisees ; elles ne sont pas des golden tests.
    const MAIL_FROM_COMMAND: &[u8] = b"MAIL FROM:<alice@example.test>\r\n";
    const RCPT_TO_COMMAND: &[u8] = b"RCPT TO:<bob@example.test>\r\n";
    /// Trame 6 (originale 21) : invitation a saisir le corps du message.
    const DATA_REPLY: &[u8] = b"354 Enter message, ending with \".\" on a line by itself\r\n";

    #[test]
    fn test_parse_multiline_banner_reply() {
        let message = SmtpMessage::try_from(BANNER_REPLY).expect("valid multi-line reply");
        assert_eq!(
            message,
            SmtpMessage::Reply {
                code: 220,
                lines: vec![
                    "xc90.websitewelcome.com ESMTP Exim 4.69 #1 Mon, 05 Oct 2009 01:05:54 -0500 ",
                    "We do not authorize the use of this system to transport unsolicited, ",
                    "and/or bulk e-mail.",
                ],
            }
        );
    }

    #[test]
    fn test_parse_ehlo_command() {
        let message = SmtpMessage::try_from(EHLO_COMMAND).expect("valid command");
        assert_eq!(
            message,
            SmtpMessage::Command {
                verb: "EHLO",
                args: Some("GP"),
            }
        );
    }

    #[test]
    fn test_parse_ehlo_reply_extensions() {
        let message = SmtpMessage::try_from(EHLO_REPLY).expect("valid multi-line reply");
        assert_eq!(
            message,
            SmtpMessage::Reply {
                code: 250,
                lines: vec![
                    "xc90.websitewelcome.com Hello GP [122.162.143.157]",
                    "SIZE 52428800",
                    "PIPELINING",
                    "AUTH PLAIN LOGIN",
                    "STARTTLS",
                    "HELP",
                ],
            }
        );
    }

    #[test]
    fn test_parse_mail_from_command() {
        let message = SmtpMessage::try_from(MAIL_FROM_COMMAND).expect("valid command");
        assert_eq!(
            message,
            SmtpMessage::Command {
                verb: "MAIL",
                args: Some("FROM:<alice@example.test>"),
            }
        );
    }

    #[test]
    fn test_parse_rcpt_to_command() {
        let message = SmtpMessage::try_from(RCPT_TO_COMMAND).expect("valid command");
        assert_eq!(
            message,
            SmtpMessage::Command {
                verb: "RCPT",
                args: Some("TO:<bob@example.test>"),
            }
        );
    }

    #[test]
    fn test_parse_data_reply() {
        let message = SmtpMessage::try_from(DATA_REPLY).expect("valid reply");
        assert_eq!(
            message,
            SmtpMessage::Reply {
                code: 354,
                lines: vec!["Enter message, ending with \".\" on a line by itself"],
            }
        );
    }

    #[test]
    fn test_parse_command_without_args() {
        let message = SmtpMessage::try_from(&b"QUIT\r\n"[..]).expect("valid command");
        assert_eq!(
            message,
            SmtpMessage::Command {
                verb: "QUIT",
                args: None,
            }
        );
    }

    #[test]
    fn test_command_verbs_are_case_insensitive_and_zero_copy() {
        let payload = b"ehlo example.test\r\n";
        let message = SmtpMessage::try_from(&payload[..]).expect("valid lower-case command");
        assert_eq!(
            message,
            SmtpMessage::Command {
                verb: "ehlo",
                args: Some("example.test"),
            }
        );
        let range = payload.as_ptr_range();
        match message {
            SmtpMessage::Command { verb, args } => {
                assert!(range.contains(&verb.as_ptr()));
                assert!(range.contains(&args.expect("args").as_ptr()));
            }
            other => panic!("expected Command, got {other:?}"),
        }
    }

    #[test]
    fn test_bare_reply_code_is_accepted() {
        assert_eq!(
            SmtpMessage::try_from(&b"250\r\n"[..]),
            Ok(SmtpMessage::Reply {
                code: 250,
                lines: vec![""],
            })
        );
        assert_eq!(
            SmtpMessage::try_from(&b"250-first\r\n250\r\n"[..]),
            Ok(SmtpMessage::Reply {
                code: 250,
                lines: vec!["first", ""],
            })
        );
    }

    #[test]
    fn test_parse_is_zero_copy() {
        let message = SmtpMessage::try_from(EHLO_COMMAND).expect("valid command");
        let range = EHLO_COMMAND.as_ptr_range();
        match message {
            SmtpMessage::Command { verb, args } => {
                assert!(range.contains(&verb.as_ptr()));
                assert!(range.contains(&args.expect("args").as_ptr()));
            }
            other => panic!("expected Command, got {other:?}"),
        }
    }

    #[test]
    fn test_empty_payload_is_an_error() {
        assert_eq!(
            SmtpMessage::try_from(&[][..]),
            Err(SmtpParseError::EmptyPayload)
        );
    }

    #[test]
    fn test_unknown_command_is_rejected() {
        let payload = b"BONJOUR tout le monde\r\n";
        assert_eq!(
            SmtpMessage::try_from(&payload[..]),
            Err(SmtpParseError::UnknownCommand("BONJOUR".to_string()))
        );
    }

    #[test]
    fn test_multiline_reply_missing_terminator_is_an_error() {
        let payload = b"250-SIZE 52428800\r\n";
        assert_eq!(
            SmtpMessage::try_from(&payload[..]),
            Err(SmtpParseError::MissingReplyTerminator)
        );
    }

    #[test]
    fn test_multiline_reply_requires_same_code_on_every_line() {
        for payload in [
            &b"250-first\r\ntext without code\r\n250 last\r\n"[..],
            &b"250-first\r\n550 wrong code\r\n"[..],
            &b"250-first\r\n550-wrong code\r\n250 last\r\n"[..],
        ] {
            assert!(
                matches!(
                    SmtpMessage::try_from(payload),
                    Err(SmtpParseError::InvalidMultilineReply(_))
                ),
                "payload: {payload:?}"
            );
        }
    }

    #[test]
    fn test_line_without_crlf_is_incomplete() {
        assert_eq!(
            SmtpMessage::try_from(&b"EHLO example.test"[..]),
            Err(SmtpParseError::IncompleteLine)
        );
        assert_eq!(
            SmtpMessage::try_from(&b"250-first\r\n250 last"[..]),
            Err(SmtpParseError::IncompleteLine)
        );
    }

    #[test]
    fn test_invalid_reply_range_and_command_syntax_are_rejected() {
        assert_eq!(
            SmtpMessage::try_from(&b"199 preliminary\r\n"[..]),
            Err(SmtpParseError::InvalidReplyCode(
                "199 preliminary".to_string()
            ))
        );
        assert_eq!(
            SmtpMessage::try_from(&b"DATA unexpected\r\n"[..]),
            Err(SmtpParseError::InvalidCommandSyntax(
                "DATA unexpected".to_string()
            ))
        );
        assert_eq!(
            SmtpMessage::try_from(&b"MAIL user@example.test\r\n"[..]),
            Err(SmtpParseError::InvalidCommandSyntax(
                "MAIL user@example.test".to_string()
            ))
        );
        assert_eq!(
            SmtpMessage::try_from(&b"BDAT 4\r\ntest"[..]),
            Err(SmtpParseError::UnknownCommand("BDAT".to_string()))
        );
    }

    #[test]
    fn test_non_utf8_payload_is_an_error() {
        let payload = [0xFFu8, 0xFE, 0xFD];
        assert_eq!(
            SmtpMessage::try_from(&payload[..]),
            Err(SmtpParseError::InvalidUtf8)
        );
    }

    /// Issue #109 : un CR ou un LF nu (RFC 5321 §2.3.8) et tout caractere de
    /// controle autre que TAB sont refuses, dans la commande comme apres
    /// elle. Octets synthetiques.
    #[test]
    fn test_bare_line_breaks_and_control_characters_are_rejected() {
        assert_eq!(
            SmtpMessage::try_from(&b"MAIL FROM:<a\nb@c.example>\r\n"[..]),
            Err(SmtpParseError::BareLineBreak { offset: 12 })
        );
        assert_eq!(
            SmtpMessage::try_from(&b"RCPT TO:<a\rb@c.example>\r\n"[..]),
            Err(SmtpParseError::BareLineBreak { offset: 10 })
        );
        assert_eq!(
            SmtpMessage::try_from(&b"EHLO host\x00\r\n"[..]),
            Err(SmtpParseError::ControlCharacter {
                offset: 9,
                byte: 0x00
            })
        );
        assert_eq!(
            SmtpMessage::try_from(&b"MAIL FROM:<a@b.example>\r\n\x17\x15\x00"[..]),
            Err(SmtpParseError::ControlCharacter {
                offset: 25,
                byte: 0x17
            })
        );
        assert_eq!(
            SmtpMessage::try_from(&b"220 mail.example ESMTP\x1b[0m\r\n"[..]),
            Err(SmtpParseError::ControlCharacter {
                offset: 22,
                byte: 0x1B
            })
        );
    }
}
