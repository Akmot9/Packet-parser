// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! A plugin for a toy protocol, DEMO: the model of a plugin.
//!
//! DEMO is made up for this example: no real traffic carries it. Its
//! datagrams go to or from UDP port 47000:
//!
//! | Offset | Size | Field |
//! |---|---|---|
//! | 0 | 4 | magic `DEMO` |
//! | 4 | 1 | version, 1 |
//! | 5 | 1 | kind: 1 hello, 2 data |
//! | 6 | 2 | body length, big-endian |
//! | 8 | n | body |
//!
//! Built as a `cdylib` (see `[[example]]` in `Cargo.toml`):
//!
//! ```text
//! cargo build --release --example demo_parser
//! ```
//!
//! gives `target/release/examples/libdemo_parser.so` on Linux, and
//! `libdemo_parser.dylib` on macOS.

use packet_parser_plugin::{ApplicationParser, CustomTransports, PayloadContext, export_parser};

const MAGIC: &[u8; 4] = b"DEMO";
const HEADER_LENGTH: usize = 8;

struct Demo;

impl Demo {
    /// The header and the body, when the payload is a whole DEMO message.
    fn split(payload: &[u8]) -> Option<(u8, u8, &[u8])> {
        let (header, body) = payload.split_first_chunk::<HEADER_LENGTH>()?;
        let [m0, m1, m2, m3, version, kind, l0, l1] = *header;
        let length = usize::from(u16::from_be_bytes([l0, l1]));
        ([m0, m1, m2, m3] == *MAGIC && version == 1 && length == body.len())
            .then_some((version, kind, body))
    }
}

impl ApplicationParser for Demo {
    fn label(&self) -> &'static str {
        "DEMO"
    }

    fn transports(&self) -> CustomTransports {
        CustomTransports::Udp
    }

    fn ports(&self) -> &[u16] {
        &[47_000]
    }

    fn matches(&self, payload: &[u8], _context: &PayloadContext) -> bool {
        Self::split(payload).is_some()
    }

    fn fields(&self, payload: &[u8], _context: &PayloadContext) -> Vec<(String, String)> {
        let Some((version, kind, body)) = Self::split(payload) else {
            return Vec::new();
        };
        let kind = match kind {
            1 => "hello".to_string(),
            2 => "data".to_string(),
            other => format!("unknown ({other})"),
        };
        vec![
            ("version".to_string(), version.to_string()),
            ("kind".to_string(), kind),
            (
                "body".to_string(),
                String::from_utf8_lossy(body).into_owned(),
            ),
        ]
    }
}

export_parser!(Demo);
