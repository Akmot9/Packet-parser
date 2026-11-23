// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Verifications du decodeur Kerberos V5.
//!
//! Les messages viennent de la RFC 4120 §5 et de son annexe A : du DER,
//! longueurs definies seulement. Chaque message est un element
//! `[APPLICATION n]` qui porte une SEQUENCE de champs `[n]` explicites ; les
//! deux premiers sont `pvno` et `msg-type`. L'enregistrement de TCP vient de
//! la RFC 4120 §7.2.2 : quatre octets de longueur, bit de poids fort nul.
//!
//! Un segment TCP peut couper un message : `extract_element` rend alors le
//! contenu present, et `DerElement::is_truncated` le dit.

use crate::errors::application::kerberos::KerberosError;
use crate::parse::application::protocols::kerberos::{KerberosMessageType, KerberosPrincipalName};

pub const DER_INTEGER: u8 = 0x02;
pub const DER_GENERAL_STRING: u8 = 0x1b;
pub const DER_SEQUENCE: u8 = 0x30;
/// Classe de contexte, forme construite : le champ `[n]` d'une SEQUENCE.
const DER_CONTEXT: u8 = 0xa0;
/// Classe d'application, forme construite : l'etiquette d'un message.
const DER_APPLICATION: u8 = 0x60;
/// `Ticket ::= [APPLICATION 1] SEQUENCE` (RFC 4120 §5.3).
const KERBEROS_TICKET_TAG: u8 = 0x61;
/// `pvno` : la version 5 du protocole.
const KERBEROS_VERSION: u8 = 5;
/// Octets de longueur lus en forme longue.
const MAX_LENGTH_OCTETS: usize = 4;
/// Plus grande longueur lue : celle qu'un enregistrement de TCP peut
/// annoncer, sur 31 bits.
const DER_MAX_LENGTH: u64 = 0x7fff_ffff;
/// Longueur de la marque d'enregistrement de TCP.
pub const KERBEROS_RECORD_MARK_LENGTH: usize = 4;
/// Bit reserve de la marque d'enregistrement.
const KERBEROS_RECORD_RESERVED_BIT: u32 = 0x8000_0000;
/// Le plus court message que le decodeur accepte : l'etiquette du message
/// et sa longueur (2), celles de la SEQUENCE (2), `pvno` (5) et `msg-type`
/// (5).
const KERBEROS_MESSAGE_MIN_LENGTH: u32 = 14;

/// Un element DER : son etiquette, sa longueur annoncee, et ce que l'entree
/// en porte.
#[derive(Debug, Clone, Copy)]
pub struct DerElement<'a> {
    pub tag: u8,
    /// Longueur annoncee du contenu.
    pub length: usize,
    /// Le contenu, coupe a la fin de l'entree s'il la depasse.
    pub contents: &'a [u8],
    /// Ce qui suit l'element ; vide quand le contenu est coupe.
    pub rest: &'a [u8],
    /// Octets de l'etiquette et de la longueur.
    pub header_length: usize,
}

impl DerElement<'_> {
    pub fn is_truncated(&self) -> bool {
        self.length > self.contents.len()
    }

    /// Octets annonces par l'element, en-tete compris.
    pub fn total_length(&self) -> usize {
        self.header_length + self.length
    }
}

/// Le type d'un message, lu a son etiquette `[APPLICATION n]`.
pub fn extract_message_type(bytes: &[u8]) -> Result<KerberosMessageType, KerberosError> {
    let Some(tag) = bytes.first() else {
        return Err(KerberosError::TooShort {
            field: "message",
            expected: 2,
            actual: 0,
        });
    };
    KerberosMessageType::ALL
        .into_iter()
        .find(|kind| DER_APPLICATION | kind.code() == *tag)
        .ok_or(KerberosError::UnknownMessageTag(*tag))
}

/// Lit l'etiquette et la longueur d'un element, en forme courte ou longue.
pub fn extract_element<'a>(
    field: &'static str,
    bytes: &'a [u8],
) -> Result<DerElement<'a>, KerberosError> {
    let [tag, first, after @ ..] = bytes else {
        return Err(KerberosError::TooShort {
            field,
            expected: 2,
            actual: bytes.len(),
        });
    };
    let (length, header_length) = if *first < 0x80 {
        (usize::from(*first), 2)
    } else {
        let count = usize::from(*first & 0x7f);
        // 0x80 : forme indefinie, que DER interdit.
        if count == 0 || count > MAX_LENGTH_OCTETS {
            return Err(KerberosError::InvalidLength { field });
        }
        let Some(octets) = after.get(..count) else {
            return Err(KerberosError::TooShort {
                field,
                expected: 2 + count,
                actual: bytes.len(),
            });
        };
        let length = octets
            .iter()
            .fold(0u64, |length, octet| (length << 8) | u64::from(*octet));
        if length > DER_MAX_LENGTH {
            return Err(KerberosError::InvalidLength { field });
        }
        let Ok(length) = usize::try_from(length) else {
            return Err(KerberosError::InvalidLength { field });
        };
        (length, 2 + count)
    };
    let after_header = &bytes[header_length..];
    let (contents, rest) = after_header.split_at(length.min(after_header.len()));
    Ok(DerElement {
        tag: *tag,
        length,
        contents,
        rest,
        header_length,
    })
}

/// Lit un element d'un conteneur et verifie son etiquette. Quand le
/// conteneur est entier, un element qui en deborde est une erreur de
/// longueur, pas une entree trop courte.
pub fn extract_inner<'a>(
    field: &'static str,
    container: &'a [u8],
    container_is_truncated: bool,
    expected_tag: u8,
) -> Result<DerElement<'a>, KerberosError> {
    if let Some(tag) = container.first()
        && *tag != expected_tag
    {
        return Err(KerberosError::UnexpectedTag {
            field,
            expected: expected_tag,
            actual: *tag,
        });
    }
    let element = match extract_element(field, container) {
        Err(KerberosError::TooShort {
            expected, actual, ..
        }) if !container_is_truncated => {
            return Err(KerberosError::LengthOverflow {
                field,
                length: expected,
                available: actual,
            });
        }
        element => element?,
    };
    if element.is_truncated() && !container_is_truncated {
        return Err(KerberosError::LengthOverflow {
            field,
            length: element.total_length(),
            available: container.len(),
        });
    }
    Ok(element)
}

/// La SEQUENCE d'un message : elle remplit l'element `[APPLICATION n]`.
pub fn extract_sequence<'a>(message: &DerElement<'a>) -> Result<DerElement<'a>, KerberosError> {
    let sequence = extract_inner(
        "sequence",
        message.contents,
        message.is_truncated(),
        DER_SEQUENCE,
    )?;
    if sequence.total_length() != message.length {
        return Err(KerberosError::SequenceLengthMismatch {
            message: message.length,
            sequence: sequence.total_length(),
        });
    }
    Ok(sequence)
}

/// Un champ d'en-tete entier : une entree qui s'arrete avant sa fin est trop
/// courte pour etre nommee.
fn extract_header_field<'a>(
    field: &'static str,
    container: &'a [u8],
    container_is_truncated: bool,
    number: u8,
) -> Result<DerElement<'a>, KerberosError> {
    let element = extract_inner(
        field,
        container,
        container_is_truncated,
        DER_CONTEXT | number,
    )?;
    if element.is_truncated() {
        return Err(KerberosError::TooShort {
            field,
            expected: element.total_length(),
            actual: element.header_length + element.contents.len(),
        });
    }
    Ok(element)
}

/// Verifie `pvno` et `msg-type`, les deux premiers champs de la SEQUENCE :
/// `[1]` et `[2]` dans un KDC-REQ, `[0]` et `[1]` dans les autres messages
/// (RFC 4120 §5.4.1 et suivants). `pvno` vaut 5, `msg-type` le numero de
/// l'etiquette du message.
pub fn validate_header(
    sequence: &DerElement<'_>,
    message_type: KerberosMessageType,
) -> Result<(), KerberosError> {
    let is_cut = sequence.is_truncated();
    let first = u8::from(message_type.is_kdc_request());
    let version = extract_header_field("pvno", sequence.contents, is_cut, first)?;
    if version.contents != [DER_INTEGER, 1, KERBEROS_VERSION] {
        return Err(KerberosError::InvalidProtocolVersion);
    }
    let kind = extract_header_field("msg-type", version.rest, is_cut, first + 1)?;
    if kind.contents != [DER_INTEGER, 1, message_type.code()] {
        return Err(KerberosError::MessageTypeMismatch {
            expected: message_type.code(),
        });
    }
    Ok(())
}

/// La marque d'enregistrement de TCP : la longueur du message qui suit. Le
/// bit de poids fort est reserve et nul (RFC 4120 §7.2.2).
///
/// Une marque entiere se juge seule, avant que le message soit lu : son
/// bit reserve, ou une longueur sous celle du plus court message, la
/// refuse. Seule une marque coupee est « trop courte » (#382).
pub fn extract_record_length(bytes: &[u8]) -> Result<u32, KerberosError> {
    let Some(mark) = bytes.first_chunk::<KERBEROS_RECORD_MARK_LENGTH>() else {
        return Err(KerberosError::TooShort {
            field: "record mark",
            expected: KERBEROS_RECORD_MARK_LENGTH,
            actual: bytes.len(),
        });
    };
    let record = u32::from_be_bytes(*mark);
    if record & KERBEROS_RECORD_RESERVED_BIT != 0 || record < KERBEROS_MESSAGE_MIN_LENGTH {
        return Err(KerberosError::InvalidRecordMark(record));
    }
    Ok(record)
}

/// La marque annonce exactement le message qu'elle precede : la longueur
/// que donne son etiquette DER, en-tete compris.
pub fn validate_record_length(record: u32, message: usize) -> Result<(), KerberosError> {
    if usize::try_from(record) != Ok(message) {
        return Err(KerberosError::RecordLengthMismatch { record, message });
    }
    Ok(())
}

/// Le contenu d'un element, et s'il est coupe par la fin de l'entree.
#[derive(Debug, Clone, Copy)]
pub struct DerContents<'a> {
    pub bytes: &'a [u8],
    pub is_cut: bool,
}

/// Lit un element d'un contenu. Il ne peut etre coupe que si son conteneur
/// l'est.
fn extract_from<'a>(container: DerContents<'a>) -> Option<DerElement<'a>> {
    let element = extract_element("field", container.bytes).ok()?;
    (container.is_cut || !element.is_truncated()).then_some(element)
}

/// Le contenu du champ `[number]` d'une SEQUENCE de champs explicites. Les
/// champs se suivent par numeros croissants ; le dernier que l'entree porte
/// peut etre coupe.
pub fn extract_field(mut fields: DerContents<'_>, number: u8) -> Option<DerContents<'_>> {
    while let Some(tag) = fields.bytes.first() {
        if tag & 0xe0 != DER_CONTEXT || tag & 0x1f > number {
            return None;
        }
        let element = extract_from(fields)?;
        if tag & 0x1f == number {
            return Some(DerContents {
                bytes: element.contents,
                is_cut: element.is_truncated(),
            });
        }
        fields.bytes = element.rest;
    }
    None
}

/// Le contenu d'un champ qui ne porte qu'un element construit de
/// l'etiquette donnee, coupe ou non.
fn extract_nested(contents: DerContents<'_>, tag: u8) -> Option<DerContents<'_>> {
    let element = extract_from(contents)?;
    (element.tag == tag && element.rest.is_empty()).then_some(DerContents {
        bytes: element.contents,
        is_cut: element.is_truncated(),
    })
}

/// Le contenu d'un champ qui ne porte qu'un element primitif de l'etiquette
/// donnee, entier.
fn extract_primitive(contents: DerContents<'_>, tag: u8) -> Option<&[u8]> {
    let element = extract_nested(contents, tag)?;
    (!element.is_cut).then_some(element.bytes)
}

/// Un INTEGER signe d'un a quatre octets (`Int32`, RFC 4120 §5.2.4).
pub fn extract_integer(contents: DerContents<'_>) -> Option<i32> {
    let value = extract_primitive(contents, DER_INTEGER)?;
    let first = *value.first()?;
    if value.len() > 4 {
        return None;
    }
    let sign = if first & 0x80 == 0 { 0 } else { -1 };
    Some(
        value
            .iter()
            .fold(sign, |number, octet| (number << 8) | i32::from(*octet)),
    )
}

/// Une `KerberosString` (RFC 4120 §5.2.1) : une GeneralString.
pub fn extract_string(contents: DerContents<'_>) -> Option<&[u8]> {
    extract_primitive(contents, DER_GENERAL_STRING)
}

/// Les champs d'une SEQUENCE seule dans son champ.
pub fn extract_sequence_fields(contents: DerContents<'_>) -> Option<DerContents<'_>> {
    extract_nested(contents, DER_SEQUENCE)
}

/// Les champs d'un `Ticket` : `[APPLICATION 1] SEQUENCE`.
pub fn extract_ticket(contents: DerContents<'_>) -> Option<DerContents<'_>> {
    extract_sequence_fields(extract_nested(contents, KERBEROS_TICKET_TAG)?)
}

/// `PrincipalName ::= SEQUENCE { name-type [0] Int32, name-string [1]
/// SEQUENCE OF KerberosString }` (RFC 4120 §5.2.2).
pub fn extract_principal_name(contents: DerContents<'_>) -> Option<KerberosPrincipalName<'_>> {
    let fields = extract_sequence_fields(contents)?;
    let name_type = extract_integer(extract_field(fields, 0)?)?;
    let strings = extract_sequence_fields(extract_field(fields, 1)?)?;
    Some(KerberosPrincipalName::new(name_type, strings.bytes))
}

/// La premiere chaine d'une suite de `KerberosString`, et ce qui la suit.
/// Une chaine coupee ne se lit pas.
pub fn extract_name_string(strings: &[u8]) -> Option<(&[u8], &[u8])> {
    let element = extract_element("name-string", strings).ok()?;
    (element.tag == DER_GENERAL_STRING && !element.is_truncated())
        .then_some((element.contents, element.rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn whole(bytes: &[u8]) -> DerContents<'_> {
        DerContents {
            bytes,
            is_cut: false,
        }
    }

    fn cut(bytes: &[u8]) -> DerContents<'_> {
        DerContents {
            bytes,
            is_cut: true,
        }
    }

    #[test]
    fn lengths_are_read_in_both_forms() {
        let short = extract_element("field", &[0x04, 0x02, 1, 2, 3]).expect("forme courte");
        assert_eq!((short.tag, short.length, short.header_length), (4, 2, 2));
        assert_eq!((short.contents, short.rest), (&[1u8, 2][..], &[3u8][..]));
        assert_eq!(short.total_length(), 4);

        let long = extract_element("field", &[0x04, 0x82, 0x01, 0x00, 9]).expect("forme longue");
        assert_eq!((long.length, long.header_length), (256, 4));
        assert!(long.is_truncated());
        assert_eq!((long.contents, long.rest), (&[9u8][..], &[][..]));

        // Forme indefinie, plus de quatre octets, plus de 31 bits.
        for bytes in [
            &[0x04u8, 0x80][..],
            &[0x04, 0x85, 0, 0, 0, 0, 1],
            &[0x04, 0x84, 0x80, 0, 0, 0],
        ] {
            assert_eq!(
                extract_element("field", bytes).map(|_| ()),
                Err(KerberosError::InvalidLength { field: "field" })
            );
        }
        assert_eq!(
            extract_element("field", &[0x04, 0x82, 0x01]).map(|_| ()),
            Err(KerberosError::TooShort {
                field: "field",
                expected: 4,
                actual: 3
            })
        );
    }

    #[test]
    fn integers_are_signed() {
        let integer = |bytes: &[u8]| extract_integer(whole(bytes));
        assert_eq!(integer(&[0x02, 0x01, 0x19]), Some(25));
        assert_eq!(integer(&[0x02, 0x01, 0x80]), Some(-128));
        assert_eq!(integer(&[0x02, 0x02, 0x00, 0x80]), Some(128));
        assert_eq!(
            integer(&[0x02, 0x04, 0x7f, 0xff, 0xff, 0xff]),
            Some(i32::MAX)
        );
        assert_eq!(integer(&[0x02, 0x04, 0x80, 0, 0, 0]), Some(i32::MIN));
        // Vide, trop long, suivi d'un octet, ou d'une autre etiquette.
        for bytes in [
            &[0x02u8, 0x00][..],
            &[0x02, 0x05, 0, 0, 0, 0, 1],
            &[0x02, 0x01, 0x19, 0x00],
            &[0x04, 0x01, 0x19],
        ] {
            assert_eq!(integer(bytes), None);
        }
        // Coupe : pas de valeur, meme dans un conteneur coupe.
        assert_eq!(extract_integer(cut(&[0x02, 0x02, 0x00])), None);
    }

    #[test]
    fn fields_are_found_by_number() {
        // [0] INTEGER 1, [2] GeneralString "ab".
        let fields = [
            0xa0, 0x03, 0x02, 0x01, 0x01, 0xa2, 0x04, 0x1b, 0x02, b'a', b'b',
        ];
        let field = |bytes, number| extract_field(whole(bytes), number);
        assert_eq!(field(&fields, 0).and_then(extract_integer), Some(1));
        assert_eq!(field(&fields, 2).and_then(extract_string), Some(&b"ab"[..]));
        // Absent, ou derriere un champ de numero plus grand.
        assert!(field(&fields, 1).is_none());
        assert!(field(&fields, 3).is_none());
        // Une etiquette qui n'est pas un champ explicite arrete la lecture.
        assert!(field(&[0x30, 0x00, 0xa1, 0x00], 1).is_none());

        // Un champ qui deborde d'un conteneur entier ne se lit pas ; dans un
        // conteneur coupe, il se lit, mais pas la chaine qu'il coupe.
        assert!(field(&fields[..10], 2).is_none());
        let last = extract_field(cut(&fields[..10]), 2).expect("champ coupe");
        assert!(last.is_cut);
        assert_eq!(last.bytes, [0x1b, 0x02, b'a']);
        assert_eq!(extract_string(last), None);
        // Ce qui precede la coupure se lit toujours.
        assert_eq!(
            extract_field(cut(&fields[..10]), 0).and_then(extract_integer),
            Some(1)
        );
    }

    #[test]
    fn principal_names_are_read() {
        // name-type 2, name-string { "krbtgt", "EX" }.
        let name = [
            0x30, 0x15, 0xa0, 0x03, 0x02, 0x01, 0x02, 0xa1, 0x0e, 0x30, 0x0c, 0x1b, 0x06, b'k',
            b'r', b'b', b't', b'g', b't', 0x1b, 0x02, b'E', b'X',
        ];
        let principal = extract_principal_name(whole(&name)).expect("nom");
        assert_eq!(principal.name_type, 2);
        assert_eq!(
            principal.components().collect::<Vec<_>>(),
            [&b"krbtgt"[..], b"EX"]
        );
        // Coupe dans la seconde chaine : la premiere reste lisible.
        let principal = extract_principal_name(cut(&name[..21])).expect("nom coupe");
        assert_eq!(principal.components().collect::<Vec<_>>(), [b"krbtgt"]);
        assert!(extract_principal_name(whole(&name[..21])).is_none());
    }
}
