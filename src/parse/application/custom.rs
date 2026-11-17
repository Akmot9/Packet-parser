// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Parsers added by the caller (issue #319).
//!
//! A protocol this crate does not decode, such as a proprietary format or an
//! in-house protocol, can still be named. Implement [`ApplicationParser`] and
//! register it with [`ParseConfig::with_parser`](crate::ParseConfig::with_parser):
//! [`parse_with`](crate::parse_with) and
//! [`classify_payload_with`](crate::classify_payload_with) then label the
//! payloads it recognizes [`ApplicationProtocol::Custom`].
//!
//! An added parser never takes a payload from the crate. It runs after the
//! built-in table, only on a non-empty TCP or UDP payload that the table left
//! `Unknown`. The parsers run in the order they were registered, and the
//! first one that accepts the payload names it.
//!
//! The parser can live in the application, or in a native library loaded at
//! run time: the `packet_parser_plugin` kit, in the `plugin/` folder of the
//! repository, exports an [`ApplicationParser`] from a `.so`, `.dylib` or
//! `.dll` and loads it back.

use std::fmt;
use std::sync::Arc;

use crate::parse::application::protocol::ApplicationProtocol;
use crate::parse::transport::Transport;
use crate::parse::transport::protocols::TransportProtocol;

/// Longest label an [`ApplicationParser`] may have, in bytes.
pub const MAX_LABEL_LENGTH: usize = 64;

/// A parser for a protocol this crate does not decode.
///
/// It is called on payloads the crate left `Unknown`, and must be cheap and
/// deterministic on any input. [`matches`](Self::matches) gives the same
/// answer for the same payload and context, never panics, and reads nothing
/// but its arguments: no file, no network, no clock.
///
/// ```
/// use std::sync::Arc;
///
/// use packet_parser::{
///     ApplicationParser, CustomTransports, ParseConfig, PayloadContext, TransportProtocol,
///     classify_payload_with,
/// };
///
/// /// A toy protocol, made up for this example: UDP datagrams that start
/// /// with `DEMO`, then a version byte.
/// struct Demo;
///
/// impl ApplicationParser for Demo {
///     fn label(&self) -> &'static str {
///         "DEMO"
///     }
///     fn transports(&self) -> CustomTransports {
///         CustomTransports::Udp
///     }
///     fn matches(&self, payload: &[u8], _context: &PayloadContext) -> bool {
///         payload.len() > 4 && payload.starts_with(b"DEMO")
///     }
///     fn fields(&self, payload: &[u8], _context: &PayloadContext) -> Vec<(String, String)> {
///         payload
///             .get(4)
///             .map(|version| vec![("version".to_string(), version.to_string())])
///             .unwrap_or_default()
///     }
/// }
///
/// let config = ParseConfig::new().with_parser(Arc::new(Demo))?;
/// let label = |protocol, payload: &[u8]| {
///     classify_payload_with(protocol, Some(40_000), Some(40_001), payload, &config)
///         .map(|application| application.protocol.label())
/// };
///
/// assert_eq!(label(TransportProtocol::Udp, b"DEMO\x01"), Some("DEMO"));
/// // The parser declared UDP only.
/// assert_eq!(label(TransportProtocol::Tcp, b"DEMO\x01"), Some("Unknown"));
/// // Nothing the parser accepts: the payload stays unknown.
/// assert_eq!(label(TransportProtocol::Udp, b"OTHER"), Some("Unknown"));
///
/// let parser = config.parser("DEMO").expect("registered");
/// let context = PayloadContext::new(TransportProtocol::Udp, Some(40_000), Some(40_001));
/// assert_eq!(parser.fields(b"DEMO\x01", &context), [("version".to_string(), "1".to_string())]);
/// # Ok::<(), packet_parser::ParserRegistrationError>(())
/// ```
pub trait ApplicationParser: Send + Sync {
    /// The label written for the payloads this parser recognizes: in
    /// [`ApplicationProtocol::Custom`], [`ApplicationProtocol::label`] and
    /// the JSON output.
    ///
    /// Registration refuses an empty label, one longer than
    /// [`MAX_LABEL_LENGTH`] bytes, one with a control character or with
    /// spaces around it, the label of a built-in protocol, and the label of
    /// a parser already registered. The last two comparisons ignore ASCII
    /// case: `"dns"` is refused because of `"DNS"`. The label is read once,
    /// at registration.
    fn label(&self) -> &'static str;

    /// The transports this parser reads. Both TCP and UDP by default.
    fn transports(&self) -> CustomTransports {
        CustomTransports::TcpAndUdp
    }

    /// The ports this parser reads: it is only called when the source or the
    /// destination port is one of them. Empty by default, which means any
    /// port, and payloads without a known port.
    fn ports(&self) -> &[u16] {
        &[]
    }

    /// Whether this payload is the protocol of this parser.
    fn matches(&self, payload: &[u8], context: &PayloadContext) -> bool;

    /// The decoded fields of a payload this parser recognized, as name and
    /// value, in display order. Parsing never calls it: an application calls
    /// it to show one packet, through [`ParseConfig::parser`](crate::ParseConfig::parser)
    /// or [`ParseConfig::custom_fields`](crate::ParseConfig::custom_fields).
    /// Empty by default.
    fn fields(&self, payload: &[u8], context: &PayloadContext) -> Vec<(String, String)> {
        let _ = (payload, context);
        Vec::new()
    }
}

/// The transports an [`ApplicationParser`] reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CustomTransports {
    /// TCP segments only.
    Tcp,
    /// UDP datagrams only.
    Udp,
    /// Both.
    TcpAndUdp,
}

impl CustomTransports {
    /// Whether a payload carried by `protocol` is read. Only TCP and UDP
    /// ever are.
    pub const fn admits(self, protocol: TransportProtocol) -> bool {
        matches!(
            (self, protocol),
            (Self::Tcp | Self::TcpAndUdp, TransportProtocol::Tcp)
                | (Self::Udp | Self::TcpAndUdp, TransportProtocol::Udp)
        )
    }
}

/// What an [`ApplicationParser`] knows of a payload besides its bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct PayloadContext {
    /// TCP or UDP.
    pub transport: TransportProtocol,
    /// The source port, when known.
    pub source_port: Option<u16>,
    /// The destination port, when known.
    pub destination_port: Option<u16>,
}

impl PayloadContext {
    /// The context of a payload carried by `transport` between these ports.
    pub const fn new(
        transport: TransportProtocol,
        source_port: Option<u16>,
        destination_port: Option<u16>,
    ) -> Self {
        Self {
            transport,
            source_port,
            destination_port,
        }
    }

    /// Whether the source or the destination port is `port`.
    pub fn has_port(&self, port: u16) -> bool {
        self.source_port == Some(port) || self.destination_port == Some(port)
    }

    pub(crate) fn of(transport: &Transport<'_>) -> Self {
        Self::new(
            transport.protocol,
            transport.source_port,
            transport.destination_port,
        )
    }
}

/// Why [`ParseConfig::with_parser`](crate::ParseConfig::with_parser) refused
/// a parser.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ParserRegistrationError {
    /// The label is empty, longer than [`MAX_LABEL_LENGTH`] bytes, has a
    /// control character, or starts or ends with a space.
    #[error("etiquette de parseur invalide : {label:?}")]
    InvalidLabel {
        /// The refused label.
        label: String,
    },
    /// A built-in protocol has this label, ignoring ASCII case.
    #[error("etiquette d'un protocole de la crate : {label:?}")]
    BuiltInLabel {
        /// The refused label.
        label: String,
    },
    /// A parser already registered has this label, ignoring ASCII case.
    #[error("etiquette deja enregistree : {label:?}")]
    DuplicateLabel {
        /// The refused label.
        label: String,
    },
}

/// A parser and the label it gave at registration.
#[derive(Clone)]
pub(crate) struct RegisteredParser {
    pub(crate) label: &'static str,
    pub(crate) parser: Arc<dyn ApplicationParser>,
}

// `ParseConfig` etait `UnwindSafe` et `RefUnwindSafe` en 12.x, et doit le
// rester : un `Arc<dyn ApplicationParser>` ne l'est pas de lui-meme. La
// crate n'appelle un parseur que par `&self` et ne modifie pas la
// configuration pendant le parsing : une panique d'un parseur la laisse
// intacte. L'etat interne du parseur, s'il en a, est l'affaire de celui qui
// rattrape la panique.
impl std::panic::UnwindSafe for RegisteredParser {}
impl std::panic::RefUnwindSafe for RegisteredParser {}

impl fmt::Debug for RegisteredParser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label)
    }
}

impl RegisteredParser {
    /// Checks the label of `parser` against the built-in protocols and the
    /// parsers already in `registered`.
    pub(crate) fn new(
        parser: Arc<dyn ApplicationParser>,
        registered: &[RegisteredParser],
    ) -> Result<Self, ParserRegistrationError> {
        let label = parser.label();
        let refused = || label.to_string();
        if label.is_empty()
            || label.len() > MAX_LABEL_LENGTH
            || label.chars().any(char::is_control)
            || label.trim() != label
        {
            return Err(ParserRegistrationError::InvalidLabel { label: refused() });
        }
        if ApplicationProtocol::ALL
            .iter()
            .any(|protocol| protocol.label().eq_ignore_ascii_case(label))
        {
            return Err(ParserRegistrationError::BuiltInLabel { label: refused() });
        }
        if registered
            .iter()
            .any(|other| other.label.eq_ignore_ascii_case(label))
        {
            return Err(ParserRegistrationError::DuplicateLabel { label: refused() });
        }
        Ok(Self { label, parser })
    }

    fn reads(&self, payload: &[u8], context: &PayloadContext) -> bool {
        let ports = self.parser.ports();
        self.parser.transports().admits(context.transport)
            && (ports.is_empty() || ports.iter().any(|port| context.has_port(*port)))
            && self.parser.matches(payload, context)
    }
}

/// Le premier parseur ajoute qui reconnait le payload d'un transport que la
/// table a laisse `Unknown`.
pub(crate) fn classify(
    parsers: &[RegisteredParser],
    transport: &Transport<'_>,
) -> Option<ApplicationProtocol> {
    let payload = transport.payload.filter(|payload| !payload.is_empty())?;
    let context = PayloadContext::of(transport);
    parsers
        .iter()
        .find(|registered| registered.reads(payload, &context))
        .map(|registered| ApplicationProtocol::Custom(registered.label))
}
