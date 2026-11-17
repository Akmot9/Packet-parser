// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Parsers declared in a TOML file instead of code (issue #325), with the
//! `rules` feature.
//!
//! A rule file names a protocol the crate does not decode, such as a
//! proprietary or in-house protocol, from the bytes that recognize it, and
//! describes fields to show. It runs no code: it cannot use the network,
//! read a file or crash the application, and it reads the same way in a
//! review as it runs. Each label of the file becomes an
//! [`ApplicationParser`] registered with
//! [`ParseConfig::with_rules`](crate::ParseConfig::with_rules), with the
//! guarantees of [`custom`](super::custom): it runs after the built-in
//! table, only on a TCP or UDP payload the table left `Unknown`, and never
//! takes a payload from the crate.
//!
//! ```
//! use packet_parser::{
//!     ParseConfig, PayloadContext, RuleSet, TransportProtocol, classify_payload_with,
//! };
//!
//! let rules = RuleSet::from_toml(
//!     r#"
//! version = 1
//!
//! [[rule]]
//! label = "ACME"  # made up for this example
//! transport = "udp"
//! ports = [47000]
//!
//! [[rule.pattern]]
//! offset = 0
//! bytes = "41 43 4D 45"
//!
//! [[rule.field]]
//! name = "type"
//! offset = 5
//! type = "u8"
//! values = { 1 = "request", 2 = "response" }
//! "#,
//! )?;
//! let config = ParseConfig::new().with_rules(&rules)?;
//!
//! let payload = b"ACME\x01\x02\x00\x10";
//! let application =
//!     classify_payload_with(TransportProtocol::Udp, Some(40_000), Some(47_000), payload, &config);
//! assert_eq!(application.map(|application| application.protocol.label()), Some("ACME"));
//!
//! let context = PayloadContext::new(TransportProtocol::Udp, Some(40_000), Some(47_000));
//! let parser = config.parser("ACME").expect("registered");
//! assert_eq!(
//!     parser.fields(payload, &context),
//!     [("type".to_string(), "response (2)".to_string())]
//! );
//!
//! // A mistake is refused with its place in the file.
//! let error = RuleSet::from_toml("version = 1\n[[rule]]\nlabel = \"ACME\"\nport = [1]\n")
//!     .expect_err("unknown key");
//! assert_eq!(error.line(), Some(4));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## The format, version 1
//!
//! A file starts with `version = 1`, then has one `[[rule]]` table per
//! rule. An unknown key is refused, so that a typo does not silently drop a
//! condition.
//!
//! | Key of `[[rule]]` | Meaning |
//! |---|---|
//! | `label` | The label written for the payloads it recognizes. The rules of [`ApplicationParser::label`] apply. |
//! | `transport` | `"tcp"`, `"udp"` or `"tcp+udp"`, the default. |
//! | `ports` | Read only when the source or the destination port is one of them. Empty or absent: any port. |
//! | `min_length` | Shortest payload, in bytes. Default and minimum: the end of the last pattern. |
//! | `max_length` | Longest payload, in bytes. No limit by default. |
//! | `[[rule.pattern]]` | At least one: `offset`, `bytes` in hexadecimal (`"41 43 4D 45"`, spaces allowed) and an optional `mask` of the same length. |
//! | `[[rule.field]]` | Fields to show: `name`, `offset`, `type`, and `length`, `mask` or `values` depending on the type. |
//!
//! A rule recognizes a payload when every condition holds: transport, port,
//! lengths, and each pattern, which holds when
//! `payload[offset + i] & mask[i] == bytes[i]`. Its patterns must check at
//! least [`MIN_SIGNATURE_BITS`] bits in all: a rule on a port alone, or on
//! one byte, would label random payloads.
//!
//! Several rules with the same label are variants of one protocol, such as
//! a request and a response: the label goes to a payload that any of them
//! recognizes, and the fields are those of the first that does.
//!
//! A field has a `type`:
//!
//! - `u8`, `u16be`, `u16le`, `u32be`, `u32le`, `u64be`, `u64le`: an
//!   unsigned integer, shown in decimal. An optional `mask`, written in
//!   hexadecimal most significant byte first with as many bytes as the
//!   type, keeps some bits and shifts them down. Optional `values` name
//!   some values, keyed in decimal or `0x` hexadecimal:
//!   `values = { 1 = "request", 0x10 = "error" }` shows `request (1)`.
//! - `hex`, with a `length`: the bytes in hexadecimal, `41 43 4D 45`.
//! - `text`, with a `length`: the bytes up to the first NUL, the
//!   printable ASCII as is and any other byte as `\xNN`.
//!
//! A field that does not fit in the payload is not shown.
//!
//! What a rule cannot express is left to a decoder in the crate: a
//! position read from the payload (a length, a TLV), a repetition, a
//! protocol carried by something other than TCP or UDP, or a message split
//! across TCP segments, of which only the first segment is recognized.

mod format;
mod matcher;

use std::collections::BTreeSet;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use crate::parse::application::custom::ApplicationParser;
use matcher::RuleParser;

/// The only version of the format, the value of `version`.
pub const FORMAT_VERSION: i64 = 1;
/// The fewest bits the patterns of a rule must check, in all: a random
/// payload matches them at most once in 65 536.
pub const MIN_SIGNATURE_BITS: u32 = 16;
/// The highest `offset` of a pattern or a field.
pub const MAX_OFFSET: usize = 65_535;
/// The longest `bytes` of a pattern.
pub const MAX_PATTERN_LENGTH: usize = 64;
/// The most rules in a file.
pub const MAX_RULES: usize = 256;
/// The most ports of a rule.
pub const MAX_PORTS: usize = 256;
/// The most fields of a rule.
pub const MAX_FIELDS: usize = 64;
/// The longest `length` of a `hex` or `text` field.
pub const MAX_FIELD_LENGTH: usize = 256;
/// The most named `values` of a field.
pub const MAX_VALUES: usize = 256;
/// The longest name of a field or of a value, in bytes.
pub const MAX_NAME_LENGTH: usize = 64;

/// The parsers of a rule file, one per label, ready to register with
/// [`ParseConfig::add_rules`](crate::ParseConfig::add_rules).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RuleSet {
    parsers: Vec<Arc<RuleParser>>,
}

impl RuleSet {
    /// Reads and checks a rule file. Nothing is registered yet.
    ///
    /// # Errors
    ///
    /// [`RulesError`] at the first mistake, with its line and column: TOML
    /// syntax, unknown key, wrong type, unknown `version`, invalid
    /// hexadecimal, weak signature, bound exceeded, or a label refused by
    /// the rules of [`ApplicationParser::label`]
    /// (the duplicates of a configuration are only known at registration).
    pub fn from_toml(text: &str) -> Result<Self, RulesError> {
        let parsers = format::read(text)?;
        Ok(Self {
            parsers: parsers.into_iter().map(Arc::new).collect(),
        })
    }

    /// The labels of the file, in the order of their first rule, which is
    /// the order they run in.
    pub fn labels(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.parsers.iter().map(|parser| parser.label)
    }

    /// The number of labels: several rules with one label count once.
    pub fn len(&self) -> usize {
        self.parsers.len()
    }

    /// Whether the file has no rule.
    pub fn is_empty(&self) -> bool {
        self.parsers.is_empty()
    }

    /// Un parseur par etiquette, pour `ParseConfig::add_rules`.
    pub(crate) fn parsers(&self) -> impl Iterator<Item = Arc<dyn ApplicationParser>> + '_ {
        self.parsers
            .iter()
            .map(|parser| Arc::clone(parser) as Arc<dyn ApplicationParser>)
    }
}

/// Why [`RuleSet::from_toml`] refused a file.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RulesError {
    line: Option<usize>,
    column: Option<usize>,
    message: String,
}

impl RulesError {
    /// L'erreur placee a l'octet `offset` du texte, ligne et colonne
    /// comptees a partir de 1, la colonne en caracteres.
    fn at(text: &str, offset: usize, message: impl Into<String>) -> Self {
        let mut line = 1;
        let mut column = 1;
        for (index, character) in text.char_indices() {
            if index >= offset {
                break;
            }
            if character == '\n' {
                line += 1;
                column = 1;
            } else {
                column += 1;
            }
        }
        Self {
            line: Some(line),
            column: Some(column),
            message: message.into(),
        }
    }

    /// Une erreur sans position.
    fn whole(message: impl Into<String>) -> Self {
        Self {
            line: None,
            column: None,
            message: message.into(),
        }
    }

    /// The line of the mistake, from 1, when it has one.
    pub fn line(&self) -> Option<usize> {
        self.line
    }

    /// The column of the mistake, from 1, in characters.
    pub fn column(&self) -> Option<usize> {
        self.column
    }

    /// What is wrong, without the position.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for RulesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.line, self.column) {
            (Some(line), Some(column)) => {
                write!(f, "ligne {line}, colonne {column} : {}", self.message)
            }
            (Some(line), None) => write!(f, "ligne {line} : {}", self.message),
            _ => f.write_str(&self.message),
        }
    }
}

impl std::error::Error for RulesError {}

/// L'etiquette en `&'static str`, comme l'exige `ApplicationParser::label`.
/// Chaque texte distinct n'est fui qu'une fois : relire le meme fichier,
/// ou un autre qui reprend ses etiquettes, ne fait pas grossir la memoire.
fn intern(label: &str) -> &'static str {
    static LABELS: Mutex<BTreeSet<&'static str>> = Mutex::new(BTreeSet::new());
    // Un verrou empoisonne garde un ensemble coherent : l'insertion est la
    // derniere operation sous le verrou.
    let mut labels = LABELS.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(known) = labels.get(label) {
        return known;
    }
    let leaked: &'static str = Box::leak(label.to_owned().into_boxed_str());
    labels.insert(leaked);
    leaked
}

#[cfg(test)]
mod tests;
