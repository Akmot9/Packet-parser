// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Les regles compilees : la reconnaissance, sans allocation, et le
//! decodage des champs, a la demande.

use crate::parse::application::custom::{ApplicationParser, CustomTransports, PayloadContext};
use crate::parse::transport::protocols::TransportProtocol;

/// Les regles d'une etiquette : ses variantes, dans l'ordre du fichier.
#[derive(Debug)]
pub(crate) struct RuleParser {
    pub(super) label: &'static str,
    transports: CustomTransports,
    /// Union des ports des variantes ; vide des qu'une variante lit tout
    /// port. Chaque variante revérifie les siens.
    ports: Vec<u16>,
    variants: Vec<Rule>,
}

impl RuleParser {
    /// `variants` n'est jamais vide : une etiquette vient d'au moins une
    /// regle.
    pub(super) fn new(label: &'static str, variants: Vec<Rule>) -> Self {
        let tcp = variants
            .iter()
            .any(|rule| rule.transports.admits(TransportProtocol::Tcp));
        let udp = variants
            .iter()
            .any(|rule| rule.transports.admits(TransportProtocol::Udp));
        let transports = match (tcp, udp) {
            (true, false) => CustomTransports::Tcp,
            (false, true) => CustomTransports::Udp,
            _ => CustomTransports::TcpAndUdp,
        };
        let ports = if variants.iter().any(|rule| rule.ports.is_empty()) {
            Vec::new()
        } else {
            let mut ports: Vec<u16> = variants
                .iter()
                .flat_map(|rule| rule.ports.iter().copied())
                .collect();
            ports.sort_unstable();
            ports.dedup();
            ports
        };
        Self {
            label,
            transports,
            ports,
            variants,
        }
    }

    fn recognizing(&self, payload: &[u8], context: &PayloadContext) -> Option<&Rule> {
        self.variants
            .iter()
            .find(|rule| rule.matches(payload, context))
    }
}

impl ApplicationParser for RuleParser {
    fn label(&self) -> &'static str {
        self.label
    }

    fn transports(&self) -> CustomTransports {
        self.transports
    }

    fn ports(&self) -> &[u16] {
        &self.ports
    }

    fn matches(&self, payload: &[u8], context: &PayloadContext) -> bool {
        self.recognizing(payload, context).is_some()
    }

    fn fields(&self, payload: &[u8], context: &PayloadContext) -> Vec<(String, String)> {
        self.recognizing(payload, context)
            .map(|rule| rule.fields(payload))
            .unwrap_or_default()
    }
}

/// Une regle : ses conditions, puis ses champs.
#[derive(Debug)]
pub(super) struct Rule {
    pub(super) transports: CustomTransports,
    /// Tries, sans doublon ; vide : tout port.
    pub(super) ports: Vec<u16>,
    pub(super) min_length: usize,
    pub(super) max_length: Option<usize>,
    /// L'octet le plus selectif des motifs, range dans la regle : il ecarte
    /// presque toute charge sans aller lire les motifs.
    pub(super) anchor: Anchor,
    pub(super) patterns: Vec<Pattern>,
    pub(super) fields: Vec<Field>,
}

/// Un octet des motifs, sous son masque (non nul).
#[derive(Debug, Clone, Copy)]
pub(super) struct Anchor {
    pub(super) offset: usize,
    pub(super) value: u8,
    pub(super) mask: u8,
}

impl Rule {
    /// Les conditions les moins cheres d'abord : longueur et ancre ecartent
    /// la quasi-totalite des charges d'un autre protocole.
    fn matches(&self, payload: &[u8], context: &PayloadContext) -> bool {
        payload.len() >= self.min_length
            && self.max_length.is_none_or(|max| payload.len() <= max)
            && payload
                .get(self.anchor.offset)
                .is_some_and(|byte| byte & self.anchor.mask == self.anchor.value)
            && self.patterns.iter().all(|pattern| pattern.matches(payload))
            && self.transports.admits(context.transport)
            && (self.ports.is_empty() || self.ports.iter().any(|port| context.has_port(*port)))
    }

    fn fields(&self, payload: &[u8]) -> Vec<(String, String)> {
        self.fields
            .iter()
            .filter_map(|field| Some((field.name.clone(), field.read(payload)?)))
            .collect()
    }
}

/// Des octets a une position, sous un masque (`FF` par defaut).
#[derive(Debug)]
pub(super) struct Pattern {
    pub(super) offset: usize,
    pub(super) bytes: Vec<u8>,
    /// De la longueur de `bytes` ; `bytes` n'a aucun bit hors du masque.
    pub(super) mask: Vec<u8>,
    /// Masque plein : une comparaison d'octets suffit.
    pub(super) exact: bool,
}

impl Pattern {
    fn matches(&self, payload: &[u8]) -> bool {
        let Some(window) = payload
            .get(self.offset..)
            .and_then(|rest| rest.get(..self.bytes.len()))
        else {
            return false;
        };
        if self.exact {
            return window == self.bytes.as_slice();
        }
        window
            .iter()
            .zip(&self.bytes)
            .zip(&self.mask)
            .all(|((byte, wanted), mask)| byte & mask == *wanted)
    }
}

/// Un champ a afficher.
#[derive(Debug)]
pub(super) struct Field {
    pub(super) name: String,
    pub(super) offset: usize,
    pub(super) kind: FieldKind,
}

#[derive(Debug)]
pub(super) enum FieldKind {
    /// Un entier non signe de `width` octets (1, 2, 4 ou 8).
    Integer {
        width: usize,
        little_endian: bool,
        /// Le masque et le decalage qui ramene ses bits en bas.
        mask: Option<(u64, u32)>,
        /// Tries par valeur, sans doublon.
        values: Vec<(u64, String)>,
    },
    /// Les octets en hexadecimal.
    Hex { length: usize },
    /// Les octets jusqu'au premier NUL, en ASCII echappe.
    Text { length: usize },
}

impl Field {
    /// `None` quand le champ deborde de la charge : rien n'est invente.
    fn read(&self, payload: &[u8]) -> Option<String> {
        let rest = payload.get(self.offset..)?;
        match &self.kind {
            FieldKind::Integer {
                width,
                little_endian,
                mask,
                values,
            } => {
                let bytes = rest.get(..*width)?;
                let fold = |value: u64, byte: &u8| (value << 8) | u64::from(*byte);
                let raw = if *little_endian {
                    bytes.iter().rev().fold(0, fold)
                } else {
                    bytes.iter().fold(0, fold)
                };
                let value = mask.map_or(raw, |(mask, shift)| (raw & mask) >> shift);
                Some(
                    match values.binary_search_by_key(&value, |(known, _)| *known) {
                        Ok(index) => values.get(index).map_or_else(
                            || value.to_string(),
                            |(_, name)| format!("{name} ({value})"),
                        ),
                        Err(_) => value.to_string(),
                    },
                )
            }
            FieldKind::Hex { length } => Some(
                rest.get(..*length)?
                    .iter()
                    .map(|byte| format!("{byte:02X}"))
                    .collect::<Vec<_>>()
                    .join(" "),
            ),
            FieldKind::Text { length } => {
                let bytes = rest.get(..*length)?;
                let end = bytes
                    .iter()
                    .position(|byte| *byte == 0)
                    .unwrap_or(bytes.len());
                Some(escape(bytes.get(..end).unwrap_or(bytes)))
            }
        }
    }
}

/// L'ASCII imprimable tel quel, `\` double, tout autre octet en `\xNN`.
fn escape(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len());
    for byte in bytes {
        match byte {
            b'\\' => text.push_str("\\\\"),
            b' '..=b'~' => text.push(char::from(*byte)),
            _ => text.push_str(&format!("\\x{byte:02X}")),
        }
    }
    text
}
