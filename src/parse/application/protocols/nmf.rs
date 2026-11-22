// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! .NET Message Framing ([MC-NMF], #352) : le tramage des liaisons WCF
//! `net.tcp`. Un segment TCP porte une suite d'enregistrements : un octet de
//! type, puis rien, un octet, ou une taille a longueur variable et son
//! contenu. Le decodeur les enumere sans copie ; le contenu d'une enveloppe
//! (un message SOAP, le plus souvent en XML binaire [MC-NBFSE]) est emprunte
//! au segment, sans etre decode.
//!
//! NMF n'a pas de port. Deux formes ont une signature assez longue pour une
//! sonde aveugle (`NmfSegment::is_blind_match`) :
//! - le preambule : Version 1.0, Mode, puis Via (`00 01 00 01 mm 02`) et une
//!   URI en UTF-8 ;
//! - une enveloppe a taille dont le contenu commence comme [MC-NBFSE] : une
//!   table de chaines bien formee, puis `s:Envelope` du dictionnaire
//!   statique et la declaration de son prefixe (`56 02 0B 01 73`).
//!
//! Sur un port declare par Decode As, tout segment qui se decoupe en
//! enregistrements est accepte, y compris l'accuse de preambule ou la fin de
//! session, qui tiennent en un octet.
//!
//! Limites, sans etat : une enveloppe plus longue qu'un segment est coupee
//! (`NmfRecord::SizedEnvelope` garde la taille annoncee et ce que le
//! segment contient), et les segments de suite, qui commencent au milieu
//! d'un message, restent `Unknown`. Les enveloppes en SOAP texte ou en XML
//! binaire sans dictionnaire de session, et les flux passes sous TLS apres
//! un Upgrade, ne se reconnaissent que sur un port declare : aucune trame
//! reelle ne les couvre.

use std::convert::TryFrom;

use crate::errors::application::nmf::NmfError;

/// Communication mode of a Mode record ([MC-NMF] §2.2.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NmfMode {
    /// 1: one message each way, the request of unknown size.
    SingletonUnsized,
    /// 2: a session with messages in both directions.
    Duplex,
    /// 3: a session with messages from the initiator only.
    Simplex,
    /// 4: one message of known size, no reply expected on the framing.
    SingletonSized,
}

/// One record of a framing stream ([MC-NMF] §2.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NmfRecord<'a> {
    /// `0x00`: the version of the framing, always 1.0.
    Version { major: u8, minor: u8 },
    /// `0x01`: the communication mode.
    Mode(NmfMode),
    /// `0x02`: the URI the messages are bound to.
    Via(&'a str),
    /// `0x03`: one of the well-known message encodings, by number.
    KnownEncoding(u8),
    /// `0x04`: a message encoding named by its MIME content type.
    ExtensibleEncoding(&'a str),
    /// `0x05`: start of a message sent as chunks. The chunks, up to the
    /// end of the segment, are borrowed as they are.
    UnsizedEnvelope { chunks: &'a [u8] },
    /// `0x06`: a message of known size.
    SizedEnvelope {
        /// Size of the message, as the record states it.
        declared_length: u32,
        /// The bytes of the message this segment holds: fewer than
        /// `declared_length` when the message goes on in the next segment.
        payload: &'a [u8],
    },
    /// `0x07`: end of the session.
    End,
    /// `0x08`: a fault, named by a URI.
    Fault(&'a str),
    /// `0x09`: a request to upgrade the stream (TLS, Negotiate), by name.
    UpgradeRequest(&'a str),
    /// `0x0A`: the upgrade is accepted.
    UpgradeResponse,
    /// `0x0B`: the preamble is accepted.
    PreambleAck,
    /// `0x0C`: end of the preamble.
    PreambleEnd,
}

impl NmfRecord<'_> {
    /// The record type byte.
    pub fn record_type(&self) -> u8 {
        match self {
            Self::Version { .. } => 0x00,
            Self::Mode(_) => 0x01,
            Self::Via(_) => 0x02,
            Self::KnownEncoding(_) => 0x03,
            Self::ExtensibleEncoding(_) => 0x04,
            Self::UnsizedEnvelope { .. } => 0x05,
            Self::SizedEnvelope { .. } => 0x06,
            Self::End => 0x07,
            Self::Fault(_) => 0x08,
            Self::UpgradeRequest(_) => 0x09,
            Self::UpgradeResponse => 0x0A,
            Self::PreambleAck => 0x0B,
            Self::PreambleEnd => 0x0C,
        }
    }

    /// `true` for a sized envelope that the segment cuts short.
    pub fn is_truncated(&self) -> bool {
        matches!(
            self,
            Self::SizedEnvelope { declared_length, payload }
                if payload.len() < *declared_length as usize
        )
    }
}

/// The framing records of one TCP segment.
///
/// ```mermaid
/// ---
/// title: NmfRecord (sized envelope)
/// ---
/// packet-beta
/// 0-7: "Record type = 0x06"
/// 8-15: "Size (1 to 5 bytes, 7 bits each, low first)"
/// 16-63: "Payload (Size bytes)"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct NmfSegment<'a> {
    bytes: &'a [u8],
}

impl<'a> NmfSegment<'a> {
    /// The records, in wire order.
    pub fn records(&self) -> NmfRecords<'a> {
        NmfRecords { rest: self.bytes }
    }

    /// The segment, as received.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Sonde aveugle : un preambule (Version 1.0, Mode, Via) ou une
    /// enveloppe a taille qui s'ouvre comme [MC-NBFSE] (voir la doc du
    /// module).
    pub(crate) fn is_blind_match(payload: &'a [u8]) -> bool {
        let Ok(segment) = NmfSegment::try_from(payload) else {
            return false;
        };
        let mut records = segment.records();
        match records.next() {
            Some(NmfRecord::Version { .. }) => {
                matches!(records.next(), Some(NmfRecord::Mode(_)))
                    && matches!(records.next(), Some(NmfRecord::Via(via)) if via.contains("://"))
            }
            Some(NmfRecord::SizedEnvelope { payload, .. }) => checks::opens_as_nbfse(payload),
            _ => false,
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for NmfSegment<'a> {
    type Error = NmfError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        if bytes.is_empty() {
            return Err(NmfError::Empty);
        }
        let mut rest = bytes;
        while !rest.is_empty() {
            let (_, consumed) = checks::record(rest)?;
            rest = &rest[consumed..];
        }
        Ok(Self { bytes })
    }
}

/// Iterator over the records of an [`NmfSegment`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NmfRecords<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for NmfRecords<'a> {
    type Item = NmfRecord<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // Le segment a ete valide par `try_from` : chaque enregistrement se
        // relit sans erreur.
        let (record, consumed) = checks::record(self.rest).ok()?;
        self.rest = &self.rest[consumed..];
        Some(record)
    }
}

mod checks {
    use super::{NmfError, NmfMode, NmfRecord};

    /// `s:Envelope` du dictionnaire statique [MC-NBFS], puis la declaration
    /// du prefixe `s` : le debut de tout message SOAP en XML binaire.
    const NBFS_ENVELOPE: [u8; 5] = [0x56, 0x02, 0x0B, 0x01, 0x73];

    /// Une taille [MC-NMF] §2.2.2 : sept bits par octet, poids faible
    /// d'abord, cinq octets au plus, 32 bits au plus. Rend la valeur et le
    /// nombre d'octets lus.
    pub(super) fn size(bytes: &[u8]) -> Option<(u32, usize)> {
        let mut value: u32 = 0;
        for (index, byte) in bytes.iter().take(5).enumerate() {
            let bits = u32::from(byte & 0x7F);
            if index == 4 && bits > 0x0F {
                return None;
            }
            value |= bits << (7 * index);
            if byte & 0x80 == 0 {
                return Some((value, index + 1));
            }
        }
        None
    }

    fn truncated(record_type: u8, expected: usize, actual: usize) -> NmfError {
        NmfError::TruncatedRecord {
            record_type,
            expected,
            actual,
        }
    }

    /// Une taille puis autant d'octets, apres l'octet de type : rend le
    /// contenu et la longueur totale de l'enregistrement.
    fn sized(bytes: &[u8]) -> Result<(u32, &[u8], usize), NmfError> {
        let (length, width) = size(&bytes[1..]).ok_or(NmfError::MalformedSize)?;
        let start = 1 + width;
        let end = start.saturating_add(length as usize);
        let content = &bytes[start..end.min(bytes.len())];
        Ok((length, content, start + content.len()))
    }

    fn string(bytes: &[u8]) -> Result<(&str, usize), NmfError> {
        let record_type = bytes[0];
        let (length, content, consumed) = sized(bytes)?;
        if content.len() < length as usize {
            return Err(truncated(
                record_type,
                consumed + length as usize - content.len(),
                bytes.len(),
            ));
        }
        let text =
            std::str::from_utf8(content).map_err(|_| NmfError::InvalidString { record_type })?;
        Ok((text, consumed))
    }

    /// Le premier enregistrement de `bytes`, non vide, et sa longueur.
    pub(super) fn record(bytes: &[u8]) -> Result<(NmfRecord<'_>, usize), NmfError> {
        let Some(&record_type) = bytes.first() else {
            return Err(NmfError::Empty);
        };
        match record_type {
            0x00 => {
                let [_, major, minor, ..] = *bytes else {
                    return Err(truncated(record_type, 3, bytes.len()));
                };
                if (major, minor) != (1, 0) {
                    return Err(NmfError::UnsupportedVersion { major, minor });
                }
                Ok((NmfRecord::Version { major, minor }, 3))
            }
            0x01 => {
                let [_, mode, ..] = *bytes else {
                    return Err(truncated(record_type, 2, bytes.len()));
                };
                let mode = match mode {
                    1 => NmfMode::SingletonUnsized,
                    2 => NmfMode::Duplex,
                    3 => NmfMode::Simplex,
                    4 => NmfMode::SingletonSized,
                    other => return Err(NmfError::InvalidMode(other)),
                };
                Ok((NmfRecord::Mode(mode), 2))
            }
            0x03 => {
                let [_, encoding, ..] = *bytes else {
                    return Err(truncated(record_type, 2, bytes.len()));
                };
                Ok((NmfRecord::KnownEncoding(encoding), 2))
            }
            0x02 => string(bytes).map(|(text, used)| (NmfRecord::Via(text), used)),
            0x04 => string(bytes).map(|(text, used)| (NmfRecord::ExtensibleEncoding(text), used)),
            0x08 => string(bytes).map(|(text, used)| (NmfRecord::Fault(text), used)),
            0x09 => string(bytes).map(|(text, used)| (NmfRecord::UpgradeRequest(text), used)),
            0x05 => Ok((
                NmfRecord::UnsizedEnvelope {
                    chunks: &bytes[1..],
                },
                bytes.len(),
            )),
            0x06 => {
                let (declared_length, payload, consumed) = sized(bytes)?;
                Ok((
                    NmfRecord::SizedEnvelope {
                        declared_length,
                        payload,
                    },
                    consumed,
                ))
            }
            0x07 => Ok((NmfRecord::End, 1)),
            0x0A => Ok((NmfRecord::UpgradeResponse, 1)),
            0x0B => Ok((NmfRecord::PreambleAck, 1)),
            0x0C => Ok((NmfRecord::PreambleEnd, 1)),
            other => Err(NmfError::UnknownRecordType(other)),
        }
    }

    /// Le contenu d'une enveloppe commence-t-il comme [MC-NBFSE] : la
    /// taille de la table de chaines, des chaines UTF-8 prefixees de leur
    /// longueur qui la remplissent exactement, puis `s:Envelope` ?
    pub(super) fn opens_as_nbfse(payload: &[u8]) -> bool {
        let Some((table, width)) = size(payload) else {
            return false;
        };
        let Some(end) = width.checked_add(table as usize) else {
            return false;
        };
        let Some(strings) = payload.get(width..end) else {
            return false;
        };
        let mut rest = strings;
        while !rest.is_empty() {
            let Some((length, width)) = size(rest) else {
                return false;
            };
            let Some(next) = width.checked_add(length as usize) else {
                return false;
            };
            let Some(text) = rest.get(width..next) else {
                return false;
            };
            if std::str::from_utf8(text).is_err() {
                return false;
            }
            rest = &rest[next..];
        }
        payload[end..].starts_with(&NBFS_ENVELOPE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Preambule reel : trame 4 de
    /// `pcaps_exemple/protocols/nmf/terrain_nmf_censure.pcap` (URI censuree).
    const PREAMBLE: &str = "000100010202296e65742e7463703a2f2f686f73742f787878787878787878787878787878787878787878787878787803080c";

    fn hex(text: &str) -> Vec<u8> {
        let digits: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        hex::decode(digits).expect("hexa valide")
    }

    #[test]
    fn preamble_lists_its_five_records() {
        let bytes = hex(PREAMBLE);
        let segment = NmfSegment::try_from(bytes.as_slice()).expect("preambule");
        let records: Vec<_> = segment.records().collect();
        assert_eq!(records.len(), 5);
        assert_eq!(records[0], NmfRecord::Version { major: 1, minor: 0 });
        assert_eq!(records[1], NmfRecord::Mode(NmfMode::Duplex));
        assert!(matches!(records[2], NmfRecord::Via(via) if via.len() == 41));
        assert_eq!(records[3], NmfRecord::KnownEncoding(8));
        assert_eq!(records[4], NmfRecord::PreambleEnd);
        assert!(NmfSegment::is_blind_match(&bytes));
        assert_eq!(segment.as_bytes(), bytes.as_slice());
    }

    // Les tests qui suivent portent sur des octets ecrits a la main, pour
    // viser une branche precise ; les trames reelles sont dans
    // `tests/nmf_golden.rs`.

    #[test]
    fn synthetic_sized_envelope_with_string_table() {
        // Taille 12 ; table de 4 octets : une chaine "abc" ; s:Envelope.
        let bytes = hex("06 0c 04 03 616263 56020b0173 0401");
        let segment = NmfSegment::try_from(bytes.as_slice()).unwrap();
        let record = segment.records().next().unwrap();
        assert_eq!(record.record_type(), 0x06);
        assert!(!record.is_truncated());
        assert!(
            matches!(record, NmfRecord::SizedEnvelope { declared_length: 12, payload } if payload.len() == 12)
        );
        assert!(NmfSegment::is_blind_match(&bytes));
    }

    #[test]
    fn synthetic_truncated_envelope_keeps_what_the_segment_holds() {
        // Taille annoncee 300 (ac 02), six octets presents.
        let bytes = hex("06 ac02 00 56020b0173");
        let segment = NmfSegment::try_from(bytes.as_slice()).unwrap();
        let record = segment.records().next().unwrap();
        assert!(record.is_truncated());
        assert!(
            matches!(record, NmfRecord::SizedEnvelope { declared_length: 300, payload } if payload.len() == 6)
        );
        assert!(NmfSegment::is_blind_match(&bytes));
    }

    #[test]
    fn synthetic_single_byte_records_decode_but_do_not_match_blind() {
        for (byte, record) in [
            (0x07, NmfRecord::End),
            (0x0A, NmfRecord::UpgradeResponse),
            (0x0B, NmfRecord::PreambleAck),
            (0x0C, NmfRecord::PreambleEnd),
        ] {
            let bytes = [byte];
            let segment = NmfSegment::try_from(&bytes[..]).unwrap();
            assert_eq!(segment.records().collect::<Vec<_>>(), [record]);
            assert!(!NmfSegment::is_blind_match(&bytes));
        }
    }

    #[test]
    fn synthetic_envelope_without_nbfse_opening_is_not_a_blind_match() {
        // Une enveloppe bien formee dont le contenu n'est pas du XML binaire.
        let bytes = hex("06 04 3c733a45");
        assert!(NmfSegment::try_from(bytes.as_slice()).is_ok());
        assert!(!NmfSegment::is_blind_match(&bytes));
        // Table de chaines qui deborde du segment.
        assert!(!NmfSegment::is_blind_match(&hex("06 0a 7f 56020b0173")));
        // Chaine de la table qui n'est pas de l'UTF-8.
        assert!(!NmfSegment::is_blind_match(&hex(
            "06 0a 03 02 ffff 56020b0173"
        )));
    }

    #[test]
    fn synthetic_other_records() {
        let bytes = hex("04 03 612f62 09 03 746c73 08 01 66 05 0261620000");
        let records: Vec<_> = NmfSegment::try_from(bytes.as_slice())
            .unwrap()
            .records()
            .collect();
        assert_eq!(records[0], NmfRecord::ExtensibleEncoding("a/b"));
        assert_eq!(records[1], NmfRecord::UpgradeRequest("tls"));
        assert_eq!(records[2], NmfRecord::Fault("f"));
        assert!(matches!(records[3], NmfRecord::UnsizedEnvelope { chunks } if chunks.len() == 5));
        assert_eq!(
            records
                .iter()
                .map(NmfRecord::record_type)
                .collect::<Vec<_>>(),
            [0x04, 0x09, 0x08, 0x05]
        );
    }

    #[test]
    fn synthetic_errors() {
        let parse = |text: &str| NmfSegment::try_from(hex(text).as_slice()).map(|_| ());
        assert_eq!(NmfSegment::try_from(&[][..]), Err(NmfError::Empty));
        assert_eq!(parse("0d"), Err(NmfError::UnknownRecordType(0x0D)));
        assert_eq!(
            parse("0001"),
            Err(NmfError::TruncatedRecord {
                record_type: 0,
                expected: 3,
                actual: 2
            })
        );
        assert_eq!(
            parse("000000"),
            Err(NmfError::UnsupportedVersion { major: 0, minor: 0 })
        );
        assert_eq!(parse("0105"), Err(NmfError::InvalidMode(5)));
        assert_eq!(
            parse("01"),
            Err(NmfError::TruncatedRecord {
                record_type: 1,
                expected: 2,
                actual: 1
            })
        );
        assert_eq!(
            parse("03"),
            Err(NmfError::TruncatedRecord {
                record_type: 3,
                expected: 2,
                actual: 1
            })
        );
        assert_eq!(parse("06"), Err(NmfError::MalformedSize));
        assert_eq!(parse("06 8080808080"), Err(NmfError::MalformedSize));
        assert_eq!(parse("06 ffffffff1f 00"), Err(NmfError::MalformedSize));
        assert_eq!(
            parse("02 05 6162"),
            Err(NmfError::TruncatedRecord {
                record_type: 2,
                expected: 7,
                actual: 4
            })
        );
        assert_eq!(
            parse("02 02 ffff"),
            Err(NmfError::InvalidString { record_type: 2 })
        );
    }

    #[test]
    fn synthetic_size_reads_up_to_32_bits() {
        assert_eq!(checks::size(&[0x00]), Some((0, 1)));
        assert_eq!(checks::size(&[0xD2, 0x08]), Some((1106, 2)));
        assert_eq!(
            checks::size(&[0xFF, 0xFF, 0xFF, 0xFF, 0x0F]),
            Some((u32::MAX, 5))
        );
        assert_eq!(checks::size(&[]), None);
    }
}
