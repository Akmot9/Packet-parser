// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Le fichier de regles, version 1 : sa forme brute (`serde`), puis sa
//! validation, qui place chaque refus a sa ligne et sa colonne.

use std::collections::BTreeMap;
use std::ops::Range;

use serde::Deserialize;
use toml::Spanned;

use super::matcher::{Anchor, Field, FieldKind, Pattern, Rule, RuleParser};
use super::{
    FORMAT_VERSION, MAX_FIELD_LENGTH, MAX_FIELDS, MAX_NAME_LENGTH, MAX_OFFSET, MAX_PATTERN_LENGTH,
    MAX_PATTERNS, MAX_PORTS, MAX_RULES, MAX_VALUES, MIN_SIGNATURE_BITS, RulesError, intern,
};
use crate::parse::application::custom::{CustomTransports, check_label};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    version: Spanned<i64>,
    #[serde(default)]
    rule: Vec<Spanned<RawRule>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    label: Spanned<String>,
    #[serde(default)]
    transport: Option<Spanned<String>>,
    #[serde(default)]
    ports: Option<Spanned<Vec<u16>>>,
    #[serde(default)]
    min_length: Option<Spanned<u64>>,
    #[serde(default)]
    max_length: Option<Spanned<u64>>,
    #[serde(default)]
    pattern: Vec<Spanned<RawPattern>>,
    #[serde(default)]
    field: Vec<Spanned<RawField>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPattern {
    offset: Spanned<u64>,
    bytes: Spanned<String>,
    #[serde(default)]
    mask: Option<Spanned<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawField {
    name: Spanned<String>,
    offset: Spanned<u64>,
    #[serde(rename = "type")]
    kind: Spanned<String>,
    #[serde(default)]
    length: Option<Spanned<u64>>,
    #[serde(default)]
    mask: Option<Spanned<String>>,
    #[serde(default)]
    values: Option<Spanned<BTreeMap<String, String>>>,
}

/// Lit le fichier et le valide en entier ; les etiquettes ne sont
/// internees qu'ensuite, pour un fichier accepte.
pub(super) fn read(text: &str) -> Result<Vec<RuleParser>, RulesError> {
    let file: RawFile = toml::from_str(text).map_err(|error| match error.span() {
        Some(span) => RulesError::at(text, span.start, error.message()),
        None => RulesError::whole(error.message()),
    })?;
    let at = Locator { text };

    let version = *file.version.get_ref();
    if version != FORMAT_VERSION {
        return Err(at.error(
            &file.version.span(),
            format!(
                "version de format {version} inconnue : seule la version {FORMAT_VERSION} existe"
            ),
        ));
    }
    if let Some(extra) = file.rule.get(MAX_RULES) {
        return Err(at.error(
            &extra.span(),
            format!("plus de {MAX_RULES} regles dans le fichier"),
        ));
    }

    let mut groups: Vec<(String, Vec<Rule>)> = Vec::new();
    for raw in file.rule {
        let span = raw.span();
        let raw = raw.into_inner();
        let label_span = raw.label.span();
        let label = raw.label.get_ref().clone();
        check_label(&label).map_err(|error| at.error(&label_span, error.to_string()))?;
        let rule = compile(raw, &span, &at)?;
        match groups
            .iter_mut()
            .find(|(known, _)| known.eq_ignore_ascii_case(&label))
        {
            Some((known, variants)) if *known == label => variants.push(rule),
            Some((known, _)) => {
                return Err(at.error(
                    &label_span,
                    format!("l'etiquette {label:?} ne differe de {known:?} que par la casse"),
                ));
            }
            None => groups.push((label, vec![rule])),
        }
    }
    Ok(groups
        .into_iter()
        .map(|(label, variants)| RuleParser::new(intern(&label), variants))
        .collect())
}

/// Place une erreur dans le texte.
struct Locator<'a> {
    text: &'a str,
}

impl Locator<'_> {
    fn error(&self, span: &Range<usize>, message: impl Into<String>) -> RulesError {
        RulesError::at(self.text, span.start, message)
    }

    /// Un entier du fichier, borne et converti.
    fn bounded(&self, value: &Spanned<u64>, key: &str, max: usize) -> Result<usize, RulesError> {
        usize::try_from(*value.get_ref())
            .ok()
            .filter(|value| *value <= max)
            .ok_or_else(|| {
                self.error(
                    &value.span(),
                    format!("{key} = {} depasse la borne {max}", value.get_ref()),
                )
            })
    }

    /// Des octets ecrits en hexadecimal, deux chiffres par octet, espaces
    /// permis.
    fn hex(&self, value: &Spanned<String>, key: &str) -> Result<Vec<u8>, RulesError> {
        let invalid = || {
            self.error(
                &value.span(),
                format!(
                    "{key} = {:?} : hexadecimal invalide, deux chiffres par octet, espaces permis",
                    value.get_ref()
                ),
            )
        };
        let digits: Vec<u8> = value
            .get_ref()
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect();
        let (pairs, rest) = digits.as_chunks::<2>();
        if pairs.is_empty() || !rest.is_empty() {
            return Err(invalid());
        }
        let digit = |byte: u8| {
            char::from(byte)
                .to_digit(16)
                .and_then(|value| u8::try_from(value).ok())
        };
        pairs
            .iter()
            .map(|[high, low]| Some((digit(*high)? << 4) | digit(*low)?))
            .collect::<Option<Vec<u8>>>()
            .ok_or_else(invalid)
    }

    /// Le nom d'un champ ou d'une valeur.
    fn name(&self, span: &Range<usize>, name: &str, what: &str) -> Result<(), RulesError> {
        if name.is_empty()
            || name.len() > MAX_NAME_LENGTH
            || name.chars().any(char::is_control)
            || name.trim() != name
        {
            return Err(self.error(
                span,
                format!(
                    "{what} {name:?} invalide : de 1 a {MAX_NAME_LENGTH} octets, sans caractere de controle ni espace autour"
                ),
            ));
        }
        Ok(())
    }
}

fn compile(raw: RawRule, span: &Range<usize>, at: &Locator<'_>) -> Result<Rule, RulesError> {
    let transports = match &raw.transport {
        None => CustomTransports::TcpAndUdp,
        Some(transport) => match transport.get_ref().as_str() {
            "tcp" => CustomTransports::Tcp,
            "udp" => CustomTransports::Udp,
            "tcp+udp" => CustomTransports::TcpAndUdp,
            other => {
                return Err(at.error(
                    &transport.span(),
                    format!("transport {other:?} inconnu : \"tcp\", \"udp\" ou \"tcp+udp\""),
                ));
            }
        },
    };

    let mut ports = match &raw.ports {
        None => Vec::new(),
        Some(ports) if ports.get_ref().len() > MAX_PORTS => {
            return Err(at.error(
                &ports.span(),
                format!("plus de {MAX_PORTS} ports dans la regle"),
            ));
        }
        Some(ports) => ports.get_ref().clone(),
    };
    ports.sort_unstable();
    ports.dedup();

    if raw.pattern.is_empty() {
        return Err(at.error(
            span,
            "une regle demande au moins un motif ([[rule.pattern]])",
        ));
    }
    // Tous les motifs sont gardes et compares a chaque payload : leur
    // nombre est borne comme celui des champs (#383).
    if let Some(extra) = raw.pattern.get(MAX_PATTERNS) {
        return Err(at.error(
            &extra.span(),
            format!("plus de {MAX_PATTERNS} motifs dans la regle"),
        ));
    }
    let patterns = raw
        .pattern
        .iter()
        .map(|pattern| compile_pattern(pattern, at))
        .collect::<Result<Vec<_>, _>>()?;
    // Chaque bit du payload compte une fois : deux motifs qui se recouvrent
    // ne verifient pas deux fois le meme bit (#383).
    let mut checked: BTreeMap<usize, u8> = BTreeMap::new();
    for pattern in &patterns {
        for (index, mask) in pattern.mask.iter().enumerate() {
            *checked.entry(pattern.offset + index).or_default() |= mask;
        }
    }
    let bits: u32 = checked.values().map(|mask| mask.count_ones()).sum();
    if bits < MIN_SIGNATURE_BITS {
        return Err(at.error(
            span,
            format!(
                "signature trop faible : {bits} bits verifies par les motifs, il en faut au moins {MIN_SIGNATURE_BITS}"
            ),
        ));
    }
    // L'octet qui verifie le plus de bits ; a egalite, le premier.
    let anchor = patterns
        .iter()
        .flat_map(|pattern| {
            pattern
                .bytes
                .iter()
                .zip(&pattern.mask)
                .enumerate()
                .map(|(index, (value, mask))| Anchor {
                    offset: pattern.offset + index,
                    value: *value,
                    mask: *mask,
                })
        })
        .filter(|anchor| anchor.mask != 0)
        .max_by_key(|anchor| (anchor.mask.count_ones(), std::cmp::Reverse(anchor.offset)))
        .ok_or_else(|| at.error(span, "motif sans bit verifie : son masque est nul"))?;
    let end = patterns
        .iter()
        .map(|pattern| pattern.offset + pattern.bytes.len())
        .max()
        .unwrap_or(0);

    let min_length = match &raw.min_length {
        None => end,
        Some(min) => {
            let value = at.bounded(min, "min_length", usize::MAX)?;
            if value < end {
                return Err(at.error(
                    &min.span(),
                    format!("min_length = {value} est sous la fin du dernier motif ({end})"),
                ));
            }
            value
        }
    };
    let max_length = match &raw.max_length {
        None => None,
        Some(max) => {
            let value = at.bounded(max, "max_length", usize::MAX)?;
            if value < min_length {
                return Err(at.error(
                    &max.span(),
                    format!("max_length = {value} est sous la longueur minimale ({min_length})"),
                ));
            }
            Some(value)
        }
    };

    if let Some(extra) = raw.field.get(MAX_FIELDS) {
        return Err(at.error(
            &extra.span(),
            format!("plus de {MAX_FIELDS} champs dans la regle"),
        ));
    }
    let mut fields: Vec<Field> = Vec::with_capacity(raw.field.len());
    for field in &raw.field {
        let field = field.get_ref();
        let compiled = compile_field(field, at)?;
        if fields.iter().any(|known| known.name == compiled.name) {
            return Err(at.error(
                &field.name.span(),
                format!("champ {:?} declare deux fois dans la regle", compiled.name),
            ));
        }
        fields.push(compiled);
    }

    Ok(Rule {
        transports,
        ports,
        min_length,
        max_length,
        anchor,
        patterns,
        fields,
    })
}

fn compile_pattern(raw: &Spanned<RawPattern>, at: &Locator<'_>) -> Result<Pattern, RulesError> {
    let pattern = raw.get_ref();
    let offset = at.bounded(&pattern.offset, "offset", MAX_OFFSET)?;
    let bytes = at.hex(&pattern.bytes, "bytes")?;
    if bytes.len() > MAX_PATTERN_LENGTH {
        return Err(at.error(
            &pattern.bytes.span(),
            format!(
                "motif de {} octets : {MAX_PATTERN_LENGTH} au plus",
                bytes.len()
            ),
        ));
    }
    let mask = match &pattern.mask {
        None => vec![0xFF; bytes.len()],
        Some(mask_text) => {
            let mask = at.hex(mask_text, "mask")?;
            if mask.len() != bytes.len() {
                return Err(at.error(
                    &mask_text.span(),
                    format!(
                        "mask a {} octets, bytes en a {} : il en faut autant",
                        mask.len(),
                        bytes.len()
                    ),
                ));
            }
            mask
        }
    };
    if bytes
        .iter()
        .zip(&mask)
        .any(|(byte, mask)| byte & !mask != 0)
    {
        return Err(at.error(
            &pattern.bytes.span(),
            "un octet de bytes a des bits hors de son masque : il ne pourrait jamais correspondre",
        ));
    }
    if mask.iter().all(|mask| *mask == 0) {
        return Err(at.error(&raw.span(), "motif sans bit verifie : son masque est nul"));
    }
    let exact = mask.iter().all(|mask| *mask == 0xFF);
    Ok(Pattern {
        offset,
        bytes,
        mask,
        exact,
    })
}

fn compile_field(field: &RawField, at: &Locator<'_>) -> Result<Field, RulesError> {
    let name = field.name.get_ref().clone();
    at.name(&field.name.span(), &name, "nom de champ")?;
    let offset = at.bounded(&field.offset, "offset", MAX_OFFSET)?;

    let integer = match field.kind.get_ref().as_str() {
        "u8" => Some((1, false)),
        "u16be" => Some((2, false)),
        "u16le" => Some((2, true)),
        "u32be" => Some((4, false)),
        "u32le" => Some((4, true)),
        "u64be" => Some((8, false)),
        "u64le" => Some((8, true)),
        "hex" | "text" => None,
        other => {
            return Err(at.error(
                &field.kind.span(),
                format!(
                    "type de champ {other:?} inconnu : u8, u16be, u16le, u32be, u32le, u64be, u64le, hex ou text"
                ),
            ));
        }
    };

    let kind = match integer {
        Some((width, little_endian)) => {
            if let Some(length) = &field.length {
                return Err(at.error(
                    &length.span(),
                    "length ne s'applique qu'aux champs hex et text",
                ));
            }
            let (mask, max) = match &field.mask {
                None => (None, max_of(width)),
                Some(mask_text) => {
                    let bytes = at.hex(mask_text, "mask")?;
                    if bytes.len() != width {
                        return Err(at.error(
                            &mask_text.span(),
                            format!(
                                "mask a {} octets, le type {} en a {width}",
                                bytes.len(),
                                field.kind.get_ref()
                            ),
                        ));
                    }
                    let mask = bytes
                        .iter()
                        .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte));
                    if mask == 0 {
                        return Err(
                            at.error(&mask_text.span(), "mask nul : le champ vaudrait toujours 0")
                        );
                    }
                    let shift = mask.trailing_zeros();
                    (Some((mask, shift)), mask >> shift)
                }
            };
            let values = match &field.values {
                None => Vec::new(),
                Some(values) => compile_values(values, max, at)?,
            };
            FieldKind::Integer {
                width,
                little_endian,
                mask,
                values,
            }
        }
        None => {
            for (present, key) in [
                (field.mask.as_ref().map(Spanned::span), "mask"),
                (field.values.as_ref().map(Spanned::span), "values"),
            ] {
                if let Some(span) = present {
                    return Err(
                        at.error(&span, format!("{key} ne s'applique qu'aux champs entiers"))
                    );
                }
            }
            let Some(length) = &field.length else {
                return Err(at.error(
                    &field.kind.span(),
                    format!("un champ {} demande length", field.kind.get_ref()),
                ));
            };
            let length = at.bounded(length, "length", MAX_FIELD_LENGTH)?;
            if length == 0 {
                return Err(at.error(
                    &field
                        .length
                        .as_ref()
                        .map_or(field.kind.span(), Spanned::span),
                    "length = 0 : le champ serait toujours vide",
                ));
            }
            if field.kind.get_ref() == "hex" {
                FieldKind::Hex { length }
            } else {
                FieldKind::Text { length }
            }
        }
    };
    Ok(Field { name, offset, kind })
}

/// La plus grande valeur d'un entier de `width` octets.
fn max_of(width: usize) -> u64 {
    u32::try_from(width * 8)
        .ok()
        .and_then(|bits| 1_u64.checked_shl(bits))
        .map_or(u64::MAX, |limit| limit - 1)
}

/// Les noms de valeurs, cles en decimal ou en hexadecimal `0x`.
fn compile_values(
    values: &Spanned<BTreeMap<String, String>>,
    max: u64,
    at: &Locator<'_>,
) -> Result<Vec<(u64, String)>, RulesError> {
    let span = values.span();
    if values.get_ref().len() > MAX_VALUES {
        return Err(at.error(&span, format!("plus de {MAX_VALUES} valeurs nommees")));
    }
    let mut compiled: Vec<(u64, String)> = Vec::with_capacity(values.get_ref().len());
    for (key, name) in values.get_ref() {
        let value = match key.strip_prefix("0x").or_else(|| key.strip_prefix("0X")) {
            Some(hex) if !hex.is_empty() => u64::from_str_radix(hex, 16).ok(),
            Some(_) => None,
            None => key.parse::<u64>().ok(),
        }
        .ok_or_else(|| {
            at.error(
                &span,
                format!("cle de values {key:?} : un entier en decimal ou en hexadecimal 0x"),
            )
        })?;
        if value > max {
            return Err(at.error(
                &span,
                format!(
                    "cle de values {key:?} : {value} depasse la valeur maximale du champ ({max})"
                ),
            ));
        }
        at.name(&span, name, "nom de valeur")?;
        if compiled.iter().any(|(known, _)| *known == value) {
            return Err(at.error(&span, format!("la valeur {value} est nommee deux fois")));
        }
        compiled.push((value, name.clone()));
    }
    compiled.sort_unstable_by_key(|(value, _)| *value);
    Ok(compiled)
}
