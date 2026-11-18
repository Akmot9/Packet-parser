// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use crate::{
    errors::application::quic::QuicError,
    parse::application::protocols::quic::{ConnectionId, QuicLongHeader, QuicPacketType},
};

/// QUIC v1 version number (RFC 9000).
pub const QUIC_V1: u32 = 1;

/// La version d'un paquet Version Negotiation (RFC 9000 §17.2.1, RFC 8999
/// §6) : aucune version ne la porte.
pub const QUIC_VERSION_NEGOTIATION: u32 = 0;

/// Longueur maximale d'un Connection ID en QUIC v1. RFC 9000 §17.2 :
/// « Endpoints that receive a version 1 long header with a value larger
/// than 20 MUST drop the packet. » Les invariants (RFC 8999 §5.1) en
/// permettent 255 pour les autres versions.
pub const QUIC_V1_MAX_CID_LEN: u8 = 20;

/// Taille du Retry Integrity Tag (RFC 9001 §5.8) : tag AEAD de 128 bits
/// place a la fin de tout paquet Retry.
pub const QUIC_RETRY_INTEGRITY_TAG_LEN: usize = 16;

/// Taille minimale plausible d'un paquet Short Header (RFC 9001 §5.4.2) :
/// 1 octet de flags + DCID (peut être vide) + au moins 20 octets après le
/// DCID — la protection d'en-tête exige un échantillon de 16 octets pris
/// 4 octets après le début du Packet Number, donc l'émetteur padde toujours
/// à cette taille.
pub const QUIC_SHORT_HEADER_MIN_LEN: usize = 21;

/// Heuristique stateless pour un paquet 1-RTT à Short Header (RFC 9000 §17.3).
///
/// Le Short Header est volontairement opaque : pas de version, pas de
/// longueur de DCID encodée. Les seuls invariants observables sont
/// Header Form = 0 et Fixed Bit = 1 (`b0 & 0xC0 == 0x40`), plus la taille
/// minimale imposée par l'échantillonnage de la protection d'en-tête.
/// Signature faible : à n'utiliser que derrière un garde-fou de port.
pub fn is_plausible_short_header(payload: &[u8]) -> bool {
    payload.len() >= QUIC_SHORT_HEADER_MIN_LEN && payload[0] & 0b1100_0000 == 0b0100_0000
}

/// Les invariants d'un en-tete long (RFC 8999 §5.1), communs a toutes les
/// versions : le bit de forme a 1, la version sur 4 octets, puis deux
/// Connection IDs, chacun precede de sa longueur, dans le datagramme. Le
/// reste de l'en-tete, le Fixed Bit compris, est propre a la version.
/// Signature faible : a n'utiliser que derriere un garde-fou de port.
pub fn is_invariant_long_header(payload: &[u8]) -> bool {
    let mut cur = QuicCursor::new(payload);
    cur.take_u8().is_ok_and(|b0| b0 & 0b1000_0000 != 0)
        && cur.take(4).is_ok()
        && read_cid(&mut cur).is_ok()
        && read_cid(&mut cur).is_ok()
}

/// Bounds-checked cursor over a QUIC packet slice.
///
/// Controlled-extraction helper: every read validates the remaining length
/// before slicing, so the parser never indexes out of bounds and stays
/// zero-copy (all reads return sub-slices of the original packet).
#[derive(Debug, Clone, Copy)]
pub struct QuicCursor<'a> {
    buf: &'a [u8],
    offset: usize,
}

impl<'a> QuicCursor<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, offset: 0 }
    }

    /// Number of bytes left to read.
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.offset)
    }

    /// Take `n` bytes as a borrowed sub-slice, validating bounds first.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], QuicError> {
        if self.remaining() < n {
            return Err(QuicError::Truncated {
                needed: n,
                remaining: self.remaining(),
            });
        }
        let slice = &self.buf[self.offset..self.offset + n];
        self.offset += n;
        Ok(slice)
    }

    /// Take a single byte, validating bounds first.
    pub fn take_u8(&mut self) -> Result<u8, QuicError> {
        let slice = self.take(1)?;
        Ok(slice[0])
    }

    /// Take all remaining bytes as a borrowed sub-slice.
    pub fn take_rest(&mut self) -> &'a [u8] {
        let slice = &self.buf[self.offset..];
        self.offset = self.buf.len();
        slice
    }

    /// Read a QUIC variable-length integer (RFC 9000 §16) with bounds checking.
    ///
    /// The two most significant bits of the first byte encode the total
    /// length (1, 2, 4 or 8 bytes); the remaining 6 bits plus the
    /// continuation bytes form the big-endian value.
    pub fn read_varint(&mut self) -> Result<u64, QuicError> {
        let first = self.take_u8()?;
        let total_len = 1usize << (first >> 6); // 1, 2, 4 or 8
        let mut value = (first & 0b0011_1111) as u64;

        let continuation = total_len - 1;
        if self.remaining() < continuation {
            return Err(QuicError::TruncatedVarint {
                needed: continuation,
                remaining: self.remaining(),
            });
        }
        for &byte in self.take(continuation)? {
            value = (value << 8) | (byte as u64);
        }
        Ok(value)
    }
}

/// The header form bit must be 1 for a Long Header packet (RFC 9000 §17.2).
pub fn validate_long_header(header_form_long: bool) -> Result<(), QuicError> {
    if !header_form_long {
        return Err(QuicError::NotLongHeader);
    }
    Ok(())
}

/// The fixed bit must be 1 (RFC 9000 §17.2).
pub fn validate_fixed_bit(fixed_bit: bool) -> Result<(), QuicError> {
    if !fixed_bit {
        return Err(QuicError::FixedBitNotSet);
    }
    Ok(())
}

/// Checks the Long Header bits of the first byte (RFC 9000 §17.2) and
/// returns the packet type together with the raw Packet Number Length bits
/// plus one (1..=4).
///
/// Ces deux bits, comme les deux bits reserves, sont masques par la
/// protection d'en-tete (RFC 9001 §5.4.1) dans un Initial, un 0-RTT ou un
/// Handshake : sans les cles, la valeur rendue n'est pas la longueur du
/// numero de paquet (#293).
///
/// `NotLongHeader` is checked before `FixedBitNotSet` to preserve the
/// historical error precedence on a byte failing both checks.
pub fn extract_first_byte(b0: u8) -> Result<(QuicPacketType, u8), QuicError> {
    let header_form_long = (b0 & 0b1000_0000) != 0;
    validate_long_header(header_form_long)?;

    let fixed_bit = (b0 & 0b0100_0000) != 0;
    validate_fixed_bit(fixed_bit)?;

    let lptype = (b0 >> 4) & 0b11; // Long Packet Type (2 bits)
    // Bits 2-3 (reserved) and 0-1 (Packet Number Length) are protected by
    // header protection : read as is, never validated.
    let pn_len_code = b0 & 0b11; // PN length code, protected
    let pn_length = pn_len_code + 1; // 1..=4

    // Le masque 0b11 borne lptype a 0..=3 : les quatre valeurs sont nommees.
    let packet_type = match lptype {
        0 => QuicPacketType::Initial,
        1 => QuicPacketType::ZeroRtt,
        2 => QuicPacketType::Handshake,
        _ => QuicPacketType::Retry,
    };

    Ok((packet_type, pn_length))
}

/// Only QUIC v1 is accepted.
pub fn validate_version(version: u32) -> Result<(), QuicError> {
    if version != QUIC_V1 {
        return Err(QuicError::UnsupportedVersion(version));
    }
    Ok(())
}

/// Reads the 4-byte Version field and checks that it is QUIC v1.
///
/// Error order is preserved from the historical inline extraction:
/// `Truncated` if fewer than 4 bytes remain, then `UnsupportedVersion`.
pub fn extract_version(cur: &mut QuicCursor<'_>) -> Result<u32, QuicError> {
    let ver_bytes = cur.take(4)?;
    let version = u32::from_be_bytes([ver_bytes[0], ver_bytes[1], ver_bytes[2], ver_bytes[3]]);
    validate_version(version)?;
    Ok(version)
}

/// The announced payload length must fit in the remaining bytes.
pub fn validate_payload_available(available: usize, expected: usize) -> Result<(), QuicError> {
    if available < expected {
        return Err(QuicError::PayloadTooShort {
            expected,
            available,
        });
    }
    Ok(())
}

/// Une longueur lue dans un varint (jusqu'a 2^62 - 1, RFC 9000 §16) ramenee
/// a `usize` sans troncature. Sur une cible 32 bits, une valeur qui n'y
/// tient pas sature : le controle de bornes qui suit la refuse, au lieu de
/// lire moins d'octets que la longueur annoncee (#273).
pub fn varint_to_len(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

/// Longueur minimale du champ Length d'un paquet protege : l'echantillon
/// de la protection d'en-tete commence 4 octets apres le debut du numero de
/// paquet et fait 16 octets pour tous les AEAD de QUIC v1 (RFC 9001
/// §5.4.2, « An endpoint MUST discard packets that are not long enough to
/// contain a complete sample »).
pub const QUIC_MIN_PROTECTED_LENGTH: u64 = 4 + 16;

/// The Length field covers the protected Packet Number and payload. It must
/// leave room for the header protection sample ([`QUIC_MIN_PROTECTED_LENGTH`]).
/// Returns the length to read after the field.
pub fn validate_length_field(length_field: u64) -> Result<usize, QuicError> {
    if length_field < QUIC_MIN_PROTECTED_LENGTH {
        return Err(QuicError::LengthFieldTooSmall {
            length_field,
            min: QUIC_MIN_PROTECTED_LENGTH,
        });
    }
    Ok(varint_to_len(length_field))
}

/// Separe le Retry Token du Retry Integrity Tag (RFC 9000 §17.2.5).
///
/// Apres l'en-tete long, un paquet Retry porte un Token de longueur libre
/// puis un tag d'integrite de 16 octets (RFC 9001 §5.8) : le tag occupe les
/// 16 derniers octets, le token tout ce qui precede. Un reste trop court
/// pour porter le tag est refuse avec `Truncated`.
///
/// Un token vide est accepte : l'obligation de rejet d'un Retry a token vide
/// (RFC 9000 §17.2.5) s'adresse au client qui consomme le paquet, pas a un
/// parseur stateless — meme logique que les bits reserves proteges, observes
/// mais non valides.
pub(crate) fn split_retry_token_and_tag(
    rest: &[u8],
) -> Result<(&[u8], &[u8; QUIC_RETRY_INTEGRITY_TAG_LEN]), QuicError> {
    rest.split_last_chunk::<QUIC_RETRY_INTEGRITY_TAG_LEN>()
        .ok_or(QuicError::Truncated {
            needed: QUIC_RETRY_INTEGRITY_TAG_LEN,
            remaining: rest.len(),
        })
}

/// Lit un Connection ID (longueur u8 + octets) sans copie, en vérifiant
/// les bornes avant chaque lecture. Toute longueur est lue : c'est la
/// forme des invariants (RFC 8999 §5.1), et d'un Version Negotiation.
pub(crate) fn read_cid<'a>(cur: &mut QuicCursor<'a>) -> Result<ConnectionId<'a>, QuicError> {
    let len = cur.take_u8()?;
    let bytes = cur.take(len as usize)?;
    Ok(ConnectionId { len, bytes })
}

/// Un Connection ID de QUIC v1 tient en [`QUIC_V1_MAX_CID_LEN`] octets
/// (RFC 9000 §17.2, #299).
pub fn validate_v1_cid_length(length: u8) -> Result<(), QuicError> {
    if length > QUIC_V1_MAX_CID_LEN {
        return Err(QuicError::ConnectionIdTooLong {
            length,
            max: QUIC_V1_MAX_CID_LEN,
        });
    }
    Ok(())
}

/// Comme [`read_cid`], pour un en-tete long de QUIC v1 : la longueur est
/// verifiee avant que les octets soient lus.
pub(crate) fn read_v1_cid<'a>(cur: &mut QuicCursor<'a>) -> Result<ConnectionId<'a>, QuicError> {
    let len = cur.take_u8()?;
    validate_v1_cid_length(len)?;
    let bytes = cur.take(len as usize)?;
    Ok(ConnectionId { len, bytes })
}

/// La liste des versions d'un Version Negotiation (RFC 8999 §6) : des
/// blocs de 4 octets jusqu'a la fin du datagramme. Un bloc incomplet est
/// refuse avec `Truncated`. Une liste vide reste lisible : la notation
/// `Supported Version (32) ...` admet zero repetition (RFC 9000 §1.3).
pub fn validate_supported_versions(versions: &[u8]) -> Result<(), QuicError> {
    let partial = versions.len() % 4;
    if partial != 0 {
        return Err(QuicError::Truncated {
            needed: 4,
            remaining: partial,
        });
    }
    Ok(())
}

/// Lit Length (varint) puis les `Length` octets qui le suivent : le numéro
/// de paquet et la charge, protégés ensemble (RFC 9001 §5.4).
///
/// Sans les clés, la longueur du numéro de paquet est inconnue : la charge
/// rendue commence au numéro de paquet, et `packet_number` reste `None`
/// (#293). `length_field` n'est placé dans le header qu'après la dernière
/// validation (« check puis place »).
pub(crate) fn read_length_and_payload<'a>(
    cur: &mut QuicCursor<'a>,
    header: &mut QuicLongHeader<'a>,
) -> Result<&'a [u8], QuicError> {
    let length_field = cur.read_varint()?;
    let protected_len = validate_length_field(length_field)?;
    validate_payload_available(cur.remaining(), protected_len)?;
    let payload = cur.take(protected_len)?;

    // Toutes les validations ont réussi : on place la valeur.
    header.length_field = length_field;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cursor_take_within_bounds() {
        let data = [1u8, 2, 3, 4];
        let mut cur = QuicCursor::new(&data);
        assert_eq!(cur.take(2).unwrap(), &[1, 2]);
        assert_eq!(cur.remaining(), 2);
        assert_eq!(cur.take(2).unwrap(), &[3, 4]);
        assert_eq!(cur.remaining(), 0);
    }

    #[test]
    fn test_cursor_take_out_of_bounds() {
        let data = [1u8, 2];
        let mut cur = QuicCursor::new(&data);
        assert_eq!(
            cur.take(3),
            Err(QuicError::Truncated {
                needed: 3,
                remaining: 2
            })
        );
        // A failed take must not advance the cursor.
        assert_eq!(cur.remaining(), 2);
    }

    #[test]
    fn test_cursor_take_u8() {
        let data = [0xABu8];
        let mut cur = QuicCursor::new(&data);
        assert_eq!(cur.take_u8(), Ok(0xAB));
        assert_eq!(
            cur.take_u8(),
            Err(QuicError::Truncated {
                needed: 1,
                remaining: 0
            })
        );
    }

    #[test]
    fn test_cursor_take_rest() {
        let data = [1u8, 2, 3];
        let mut cur = QuicCursor::new(&data);
        cur.take_u8().unwrap();
        assert_eq!(cur.take_rest(), &[2, 3]);
        assert_eq!(cur.remaining(), 0);
        assert_eq!(cur.take_rest(), &[] as &[u8]);
    }

    #[test]
    fn test_read_varint_all_lengths() {
        // 1 byte: 0x25 = 37
        let mut cur = QuicCursor::new(&[0x25]);
        assert_eq!(cur.read_varint(), Ok(37));

        // 2 bytes: 0x7BBD = 15293 (RFC 9000 §A.1 example)
        let mut cur = QuicCursor::new(&[0x7B, 0xBD]);
        assert_eq!(cur.read_varint(), Ok(15293));

        // 4 bytes: 0x9D7F3E7D = 494878333 (RFC 9000 §A.1 example)
        let mut cur = QuicCursor::new(&[0x9D, 0x7F, 0x3E, 0x7D]);
        assert_eq!(cur.read_varint(), Ok(494_878_333));

        // 8 bytes: 0xC2197C5EFF14E88C = 151288809941952652 (RFC 9000 §A.1 example)
        let mut cur = QuicCursor::new(&[0xC2, 0x19, 0x7C, 0x5E, 0xFF, 0x14, 0xE8, 0x8C]);
        assert_eq!(cur.read_varint(), Ok(151_288_809_941_952_652));
    }

    #[test]
    fn test_read_varint_truncated() {
        // Empty buffer: not even the first byte.
        let mut cur = QuicCursor::new(&[]);
        assert_eq!(
            cur.read_varint(),
            Err(QuicError::Truncated {
                needed: 1,
                remaining: 0
            })
        );

        // Prefix announces 2 bytes but no continuation byte follows.
        let mut cur = QuicCursor::new(&[0x40]);
        assert_eq!(
            cur.read_varint(),
            Err(QuicError::TruncatedVarint {
                needed: 1,
                remaining: 0
            })
        );

        // Prefix announces 8 bytes but only 3 continuation bytes follow.
        let mut cur = QuicCursor::new(&[0xC0, 0x01, 0x02, 0x03]);
        assert_eq!(
            cur.read_varint(),
            Err(QuicError::TruncatedVarint {
                needed: 7,
                remaining: 3
            })
        );
    }

    #[test]
    fn test_is_plausible_short_header() {
        // Premier octet valide (form=0, fixed=1) et taille suffisante.
        let mut packet = vec![0x4C];
        packet.extend_from_slice(&[0u8; QUIC_SHORT_HEADER_MIN_LEN - 1]);
        assert!(is_plausible_short_header(&packet));

        // Trop court d'un octet.
        assert!(!is_plausible_short_header(
            &packet[..QUIC_SHORT_HEADER_MIN_LEN - 1]
        ));

        // Long Header (form=1) : pas un Short Header.
        packet[0] = 0xC0;
        assert!(!is_plausible_short_header(&packet));

        // Fixed bit absent.
        packet[0] = 0x0C;
        assert!(!is_plausible_short_header(&packet));

        // Buffer vide.
        assert!(!is_plausible_short_header(&[]));
    }

    #[test]
    fn test_validate_long_header() {
        assert_eq!(validate_long_header(true), Ok(()));
        assert_eq!(validate_long_header(false), Err(QuicError::NotLongHeader));
    }

    #[test]
    fn test_validate_fixed_bit() {
        assert_eq!(validate_fixed_bit(true), Ok(()));
        assert_eq!(validate_fixed_bit(false), Err(QuicError::FixedBitNotSet));
    }

    #[test]
    fn a_v1_connection_id_holds_twenty_bytes() {
        assert_eq!(validate_v1_cid_length(0), Ok(()));
        assert_eq!(validate_v1_cid_length(20), Ok(()));
        assert_eq!(
            validate_v1_cid_length(21),
            Err(QuicError::ConnectionIdTooLong {
                length: 21,
                max: 20
            })
        );
        // La longueur est refusee avant la lecture des octets : un CID de
        // 21 octets tronque donne la meme erreur.
        let mut cur = QuicCursor::new(&[21, 0xAA]);
        assert_eq!(
            read_v1_cid(&mut cur),
            Err(QuicError::ConnectionIdTooLong {
                length: 21,
                max: 20
            })
        );
        let mut cur = QuicCursor::new(&[21; 22]);
        assert_eq!(read_cid(&mut cur).map(|cid| cid.len), Ok(21));
    }

    #[test]
    fn supported_versions_come_in_blocks_of_four_bytes() {
        assert_eq!(validate_supported_versions(&[]), Ok(()));
        assert_eq!(validate_supported_versions(&[0, 0, 0, 1]), Ok(()));
        assert_eq!(
            validate_supported_versions(&[0, 0, 0, 1, 0xFF]),
            Err(QuicError::Truncated {
                needed: 4,
                remaining: 1
            })
        );
    }

    #[test]
    fn test_validate_version() {
        assert_eq!(validate_version(QUIC_V1), Ok(()));
        assert_eq!(
            validate_version(0xff00_001d),
            Err(QuicError::UnsupportedVersion(0xff00_001d))
        );
    }

    #[test]
    fn test_validate_payload_available() {
        assert_eq!(validate_payload_available(10, 10), Ok(()));
        assert_eq!(validate_payload_available(10, 4), Ok(()));
        assert_eq!(
            validate_payload_available(3, 10),
            Err(QuicError::PayloadTooShort {
                expected: 10,
                available: 3
            })
        );
    }

    #[test]
    fn test_validate_length_field() {
        assert_eq!(validate_length_field(22), Ok(22));
        assert_eq!(validate_length_field(20), Ok(20));
        assert_eq!(
            validate_length_field(19),
            Err(QuicError::LengthFieldTooSmall {
                length_field: 19,
                min: 20
            })
        );
    }

    /// #273 : une longueur de 2^32 ou plus n'est pas tronquee. Sur 64 bits
    /// elle est rendue telle quelle ; sur 32 bits elle sature, la ou le cast
    /// `as usize` n'en gardait que les 32 bits bas (ici 5, donc 4 octets de
    /// payload acceptes).
    #[test]
    fn test_validate_length_field_keeps_a_wide_varint_whole() {
        let wide = (1u64 << 32) + 5;

        assert_eq!(varint_to_len(u64::MAX), usize::MAX);
        assert!(varint_to_len(wide) > 5);
        assert_eq!(validate_length_field(wide), Ok(varint_to_len(wide)));
    }

    #[test]
    fn test_extract_first_byte_valid_types() {
        // 0xC3 : Long=1, Fixed=1, Initial (00), PN len code=3 -> 4 octets.
        assert_eq!(extract_first_byte(0xC3), Ok((QuicPacketType::Initial, 4)));
        // 0xD0 : 0-RTT, PN len 1.
        assert_eq!(extract_first_byte(0xD0), Ok((QuicPacketType::ZeroRtt, 1)));
        // 0xE1 : Handshake, PN len 2.
        assert_eq!(extract_first_byte(0xE1), Ok((QuicPacketType::Handshake, 2)));
        // 0xF2 : Retry, PN len 3.
        assert_eq!(extract_first_byte(0xF2), Ok((QuicPacketType::Retry, 3)));
    }

    /// Les deux bits du Long Packet Type couvrent exactement les quatre types
    /// de QUIC v1 (RFC 9000 §17.2) : chaque octet a Long Header valide donne
    /// l'un d'eux. Verrouille la suppression de l'ancienne variante
    /// `QuicPacketType::Unknown`, jamais construite (#48).
    #[test]
    fn test_extract_first_byte_maps_every_long_header_to_a_named_type() {
        for b0 in 0u8..=u8::MAX {
            let Ok((packet_type, pn_length)) = extract_first_byte(b0) else {
                continue;
            };
            let expected = match (b0 >> 4) & 0b11 {
                0 => QuicPacketType::Initial,
                1 => QuicPacketType::ZeroRtt,
                2 => QuicPacketType::Handshake,
                _ => QuicPacketType::Retry,
            };
            assert_eq!(packet_type, expected, "b0={b0:#04x}");
            assert_eq!(pn_length, (b0 & 0b11) + 1);
        }
    }

    #[test]
    fn test_extract_first_byte_error_precedence() {
        // form=0 et fixed=0 : NotLongHeader doit primer sur FixedBitNotSet.
        assert_eq!(extract_first_byte(0x00), Err(QuicError::NotLongHeader));
        // form=0, fixed=1 : Short Header.
        assert_eq!(extract_first_byte(0x40), Err(QuicError::NotLongHeader));
        // form=1, fixed=0.
        assert_eq!(extract_first_byte(0x80), Err(QuicError::FixedBitNotSet));
    }

    #[test]
    fn test_extract_version() {
        // Version v1, le curseur ne consomme que les 4 octets du champ.
        let mut cur = QuicCursor::new(&[0x00, 0x00, 0x00, 0x01, 0xFF]);
        assert_eq!(extract_version(&mut cur), Ok(1));
        assert_eq!(cur.remaining(), 1);

        // Version inconnue.
        let mut cur = QuicCursor::new(&[0x00, 0x00, 0x00, 0x02]);
        assert_eq!(
            extract_version(&mut cur),
            Err(QuicError::UnsupportedVersion(2))
        );

        // Tronqué : Truncated prime sur UnsupportedVersion.
        let mut cur = QuicCursor::new(&[0x00, 0x00]);
        assert_eq!(
            extract_version(&mut cur),
            Err(QuicError::Truncated {
                needed: 4,
                remaining: 2
            })
        );
    }

    #[test]
    fn test_read_cid() {
        let mut cur = QuicCursor::new(&[0x02, 0xAA, 0xBB, 0xCC]);
        let cid = read_cid(&mut cur).expect("CID valide");
        assert_eq!(cid.len, 2);
        assert_eq!(cid.bytes, &[0xAA, 0xBB]);
        assert_eq!(cur.remaining(), 1);

        let mut cur = QuicCursor::new(&[0x05, 0x01]);
        assert!(matches!(
            read_cid(&mut cur),
            Err(QuicError::Truncated {
                needed: 5,
                remaining: 1
            })
        ));
    }

    #[test]
    fn test_split_retry_token_and_tag() {
        // Octets synthetiques : token de 4 octets suivi d'un tag de 16.
        let mut rest = vec![0xAA, 0xBB, 0xCC, 0xDD];
        rest.extend_from_slice(&[0x11; QUIC_RETRY_INTEGRITY_TAG_LEN]);
        let (token, tag) = split_retry_token_and_tag(&rest).expect("Retry valide");
        assert_eq!(token, &[0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(tag, &[0x11; QUIC_RETRY_INTEGRITY_TAG_LEN]);
    }

    #[test]
    fn test_split_retry_empty_token_accepted() {
        // Exactement 16 octets : tag seul, token vide accepte (choix documente).
        let rest = [0x22u8; QUIC_RETRY_INTEGRITY_TAG_LEN];
        let (token, tag) = split_retry_token_and_tag(&rest).expect("token vide accepte");
        assert!(token.is_empty());
        assert_eq!(tag, &rest);
    }

    #[test]
    fn test_split_retry_too_short_rejected() {
        // 15 octets : impossible de porter le tag de 16 octets.
        let rest = [0u8; QUIC_RETRY_INTEGRITY_TAG_LEN - 1];
        assert_eq!(
            split_retry_token_and_tag(&rest),
            Err(QuicError::Truncated {
                needed: QUIC_RETRY_INTEGRITY_TAG_LEN,
                remaining: 15
            })
        );
    }

    /// En-tête factice pour tester `read_length_and_payload` isolément.
    fn dummy_header<'a>(pn_length: u8) -> QuicLongHeader<'a> {
        QuicLongHeader {
            header_form_long: true,
            fixed_bit: true,
            packet_type: QuicPacketType::Handshake,
            version: QUIC_V1,
            dcid: ConnectionId { len: 0, bytes: &[] },
            scid: ConnectionId { len: 0, bytes: &[] },
            pn_length,
            length_field: 0,
            packet_number: None,
        }
    }

    #[test]
    fn test_read_length_and_payload_places_after_checks() {
        // length = 20 : numéro de paquet protégé et charge, ensemble, puis
        // un octet hors du paquet.
        let mut data = vec![0x14];
        data.extend(1..=21u8);
        let mut cur = QuicCursor::new(&data);
        let mut header = dummy_header(1);
        let payload = read_length_and_payload(&mut cur, &mut header).expect("valide");
        assert_eq!(payload, &data[1..21]);
        assert_eq!(cur.remaining(), 1);
        assert_eq!(header.length_field, 20);
        assert_eq!(header.packet_number, None);
    }

    #[test]
    fn test_read_length_and_payload_failure_leaves_header_untouched() {
        // length = 30 mais vingt octets seulement.
        let mut data = vec![0x1E];
        data.extend([0u8; 20]);
        let mut cur = QuicCursor::new(&data);
        let mut header = dummy_header(1);
        assert!(matches!(
            read_length_and_payload(&mut cur, &mut header),
            Err(QuicError::PayloadTooShort {
                expected: 30,
                available: 20
            })
        ));
        assert_eq!(header.length_field, 0);
    }
}
