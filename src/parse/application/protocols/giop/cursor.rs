// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use crate::{
    checks::application::giop::{GIOP_HEADER_LEN, ensure_available, parse_cdr_string},
    errors::application::giop::GiopParseError,
};

/// Curseur CDR : les primitives sont alignees sur leur taille naturelle
/// (CORBA formal/04-03-12 §15.3.1.1), comptee depuis le debut du **flux
/// CDR**. Pour un body GIOP, ce flux est le message entier : l'offset 0 est
/// le premier octet du header de 12 octets, d'ou `base = 12`. Pour les
/// alignements 2 et 4 la base est neutre (12 est multiple de 4) ; elle
/// compte pour l'alignement sur 8 des bodies GIOP 1.2. Pour une
/// encapsulation (profil IIOP), le flux repart de zero a l'octet
/// d'endianness : `base = 0`.
///
/// Les tests sur trames reelles (tests/giop_golden.rs) verrouillent ces
/// paddings : sans eux, aucun Request 1.2 reel ne se decode.
#[derive(Clone)]
pub(super) struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
    base: usize,
    little_endian: bool,
}

impl<'a> Cursor<'a> {
    /// Curseur sur le body d'un message GIOP (apres le header de 12 octets).
    pub(super) fn new(buf: &'a [u8], little_endian: bool) -> Self {
        Self {
            buf,
            pos: 0,
            base: GIOP_HEADER_LEN,
            little_endian,
        }
    }

    /// Curseur sur une encapsulation CDR (§15.3.3) : le premier octet porte
    /// l'endianness de l'encapsulation, independante de celle du message, et
    /// l'alignement repart de cet octet.
    pub(super) fn encapsulation(buf: &'a [u8]) -> Result<Self, GiopParseError> {
        let mut cur = Self {
            buf,
            pos: 0,
            base: 0,
            little_endian: false,
        };
        cur.little_endian = cur.read_u8()? & 0x01 != 0;
        Ok(cur)
    }

    pub(super) fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Octets non encore lus, sans avancer.
    pub(super) fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos.min(self.buf.len())..]
    }

    #[cfg(test)]
    pub(super) fn position(&self) -> usize {
        self.pos
    }

    /// Avance jusqu'au prochain multiple de `boundary` (padding CDR). Le
    /// padding n'existe que devant une donnee : il est borne par les octets
    /// restants, la lecture qui suit rapportant l'EOF le cas echeant.
    pub(super) fn align(&mut self, boundary: usize) {
        let rem = (self.base + self.pos) % boundary;
        if rem != 0 {
            self.pos += (boundary - rem).min(self.remaining());
        }
    }

    /// GIOP 1.2 (§15.4.2.2, §15.4.3.2) : le body d'un Request ou d'un Reply
    /// est aligne sur 8 octets depuis le debut du message. Le padding
    /// n'existe que s'il y a un body.
    pub(super) fn align_body_1_2(&mut self) {
        if self.remaining() > 0 {
            self.align(8);
        }
    }

    pub(super) fn read_u8(&mut self) -> Result<u8, GiopParseError> {
        ensure_available(self.remaining(), 1)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub(super) fn read_u16(&mut self) -> Result<u16, GiopParseError> {
        self.align(2);
        ensure_available(self.remaining(), 2)?;
        let bytes = [self.buf[self.pos], self.buf[self.pos + 1]];
        self.pos += 2;
        Ok(if self.little_endian {
            u16::from_le_bytes(bytes)
        } else {
            u16::from_be_bytes(bytes)
        })
    }

    pub(super) fn read_u32(&mut self) -> Result<u32, GiopParseError> {
        self.align(4);
        ensure_available(self.remaining(), 4)?;
        let bytes = [
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ];
        self.pos += 4;
        Ok(if self.little_endian {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        })
    }

    pub(super) fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], GiopParseError> {
        ensure_available(self.remaining(), len)?;
        let slice = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    /// `sequence<octet>` : ulong length, puis les octets.
    pub(super) fn read_octet_sequence(&mut self) -> Result<&'a [u8], GiopParseError> {
        let len = self.read_u32()? as usize;
        self.read_bytes(len)
    }

    /// String CDR : ulong length, puis bytes (souvent termines par 0).
    pub(super) fn read_str(&mut self) -> Result<&'a str, GiopParseError> {
        let bytes = self.read_octet_sequence()?;
        parse_cdr_string(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_alignment_on_8_counts_from_the_message_start() {
        // pos 4 dans le body = offset 16 du message : deja multiple de 8.
        let buf = [0u8; 16];
        let mut cur = Cursor::new(&buf, false);
        cur.read_u32().expect("4 octets");
        cur.align_body_1_2();
        assert_eq!(cur.position(), 4);

        // pos 8 dans le body = offset 20 du message : 4 octets de padding.
        cur.read_u32().expect("4 octets");
        cur.align_body_1_2();
        assert_eq!(cur.position(), 12);
    }

    #[test]
    fn body_alignment_is_skipped_when_no_body_follows() {
        let buf = [0u8; 8];
        let mut cur = Cursor::new(&buf, false);
        cur.read_u32().expect("4 octets");
        cur.read_u32().expect("4 octets");
        cur.align_body_1_2();
        assert_eq!(cur.position(), 8);
        assert!(cur.rest().is_empty());
    }

    #[test]
    fn alignment_padding_never_runs_past_the_buffer() {
        // 1 octet lu, 1 octet restant : l'alignement sur 4 demanderait 3
        // octets de padding. Il est borne, et la lecture rapporte l'EOF.
        let buf = [0u8; 2];
        let mut cur = Cursor::new(&buf, false);
        cur.read_u8().expect("1 octet");
        assert!(matches!(cur.read_u32(), Err(GiopParseError::UnexpectedEof)));
        assert_eq!(cur.remaining(), 0);
    }

    #[test]
    fn encapsulation_carries_its_own_endianness_and_alignment_origin() {
        // Octet d'endianness 1 (little-endian), padding jusqu'a 4, ulong 7.
        let buf = [0x01, 0, 0, 0, 7, 0, 0, 0];
        let mut cur = Cursor::encapsulation(&buf).expect("encapsulation");
        assert_eq!(cur.read_u32(), Ok(7));

        assert!(matches!(
            Cursor::encapsulation(&[]),
            Err(GiopParseError::UnexpectedEof)
        ));
    }
}
