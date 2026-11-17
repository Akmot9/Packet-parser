// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! # packet_parser_plugin
//!
//! Parsers for [`packet_parser`], loaded at run time from native libraries
//! (issue #319).
//!
//! A protocol that `packet_parser` does not decode, such as a proprietary
//! format, gets its own parser: a type that implements [`ApplicationParser`].
//! An application can register it directly with
//! [`ParseConfig::with_parser`](packet_parser::ParseConfig::with_parser).
//! This kit lets that parser live in its own library, built apart, and
//! loaded by an application that is already compiled, for instance behind an
//! "Import parsers" button.
//!
//! ## Writing a plugin
//!
//! A crate of type `cdylib`, with one parser and one call to
//! [`export_parser!`]:
//!
//! ```toml
//! [lib]
//! crate-type = ["cdylib"]
//!
//! [dependencies]
//! packet_parser_plugin = { git = "https://github.com/Akmot9/Packet-parser" }
//! ```
//!
//! ```ignore
//! use packet_parser_plugin::{ApplicationParser, CustomTransports, PayloadContext, export_parser};
//!
//! struct Acme;
//!
//! impl ApplicationParser for Acme {
//!     fn label(&self) -> &'static str {
//!         "ACME"
//!     }
//!     fn transports(&self) -> CustomTransports {
//!         CustomTransports::Udp
//!     }
//!     fn matches(&self, payload: &[u8], _context: &PayloadContext) -> bool {
//!         payload.starts_with(b"ACME")
//!     }
//! }
//!
//! export_parser!(Acme);
//! ```
//!
//! `cargo build --release` then gives `libacme.so` on Linux,
//! `libacme.dylib` on macOS and `acme.dll` on Windows. A library is built
//! for one operating system and one architecture.
//!
//! ## Loading it
//!
//! ```no_run
//! use packet_parser::{LinkType, ParseConfig, parse_with};
//! use packet_parser_plugin::load_parser;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // SAFETY: a library whose origin was checked beforehand.
//! let parser = unsafe { load_parser("plugins/libacme.so") }?;
//! let config = ParseConfig::new().with_parser(parser)?;
//!
//! # let frame: Vec<u8> = Vec::new();
//! let flow = parse_with(LinkType::ETHERNET, &frame, &config)?;
//! if let Some(fields) = config.custom_fields(&flow) {
//!     for (name, value) in fields {
//!         println!("{name}: {value}");
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## What the kit guarantees, and what it does not
//!
//! - The plugin and its host only exchange C types ([`abi`]): they may be
//!   built by different versions of rustc and of `packet_parser`.
//! - The loader checks what the plugin declares: version of the ABI, label,
//!   transports, ports.
//! - A panic of the parser is caught in the plugin: the payload is not
//!   recognized, and the host goes on. The plugin must be built with
//!   `panic = "unwind"`, the default.
//! - A plugin is native code, not a sandbox. It runs with every right of the
//!   host, can read its memory, and can crash it by a fault other than a
//!   panic. [`load_parser`] is `unsafe` for that reason: load only a file
//!   whose origin you checked.

pub mod abi;
#[doc(hidden)]
pub mod export;
mod load;

pub use load::{PluginLoadError, load_parser};
pub use packet_parser;
pub use packet_parser::{ApplicationParser, CustomTransports, PayloadContext};
