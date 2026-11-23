// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Skinny (SCCP, Skinny Client Control Protocol, #370), la signalisation
//! des telephones IP Cisco vers leur serveur d'appel, sur TCP 2000 : a ne
//! pas confondre avec le SCCP de SS7. Le poste envoie des evenements
//! (decroche, touche), le serveur des ordres (sonnerie, affichage, ouverture
//! de la voix, qui passe en RTP).
//!
//! Chaque message s'ouvre par douze octets petit-boutistes : une longueur,
//! une version d'en-tete et un identifiant de message. Un segment TCP porte
//! un ou plusieurs messages a la suite ([`SkinnyMessage::messages`]). Le
//! corps, une structure propre a chaque identifiant, est emprunte au
//! segment, sans etre decode.
//!
//! Le protocole est proprietaire et sans specification publique : la
//! reference de fait est le dissecteur de Wireshark, d'ou viennent les
//! versions d'en-tete admises et la plage des identifiants.
//!
//! Detection : regle a port sur TCP 2000. Douze octets surtout nuls ne font
//! pas une sonde aveugle, et 2000 est aussi un port ephemere : la sonde
//! exige des messages qui pavent le segment, d'identifiant plausible.
//!
//! Limites, sans etat : un message plus long que son segment est coupe
//! ([`SkinnyMessage::is_truncated`]) et les segments de suite restent
//! `Unknown`. La signalisation chiffree (TLS sur TCP 2443) est du TLS.

use std::convert::TryFrom;

use crate::errors::application::skinny::SkinnyError;

/// Length of the header of a message: data length, header version and
/// message identifier.
pub const SKINNY_HEADER_LENGTH: usize = 12;

/// One Skinny message, the first of the bytes it is read from.
///
/// ```mermaid
/// ---
/// title: SkinnyMessage (little-endian)
/// ---
/// packet-beta
/// 0-31: "data_length u32 (message_id + body)"
/// 32-63: "header_version u32"
/// 64-95: "message_id u32"
/// 96-127: "body (data_length - 4 bytes)"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SkinnyMessage<'a> {
    /// Number of bytes that follow the header version: the message
    /// identifier, four bytes, and the body.
    pub data_length: u32,
    /// Version of the header, which follows the version of the protocol:
    /// 0 for the basic header, then 10, 11 and 15 to 22.
    pub header_version: u32,
    /// Identifier of the message, which gives the structure of the body.
    pub message_id: u32,
    /// What follows the header, up to the end of the message or of the
    /// segment, whichever comes first.
    pub body: &'a [u8],
    rest: &'a [u8],
}

impl<'a> SkinnyMessage<'a> {
    /// `true` when the message goes on in the next TCP segment.
    pub fn is_truncated(&self) -> bool {
        checks::body_length(self.data_length) > self.body.len()
    }

    /// The bytes of the segment that follow this message: another message,
    /// or nothing.
    pub fn rest(&self) -> &'a [u8] {
        self.rest
    }

    /// The messages of a TCP segment, in order. The iterator stops after
    /// the first error, or after a message that its segment cuts.
    pub fn messages(payload: &'a [u8]) -> SkinnyMessages<'a> {
        SkinnyMessages { rest: payload }
    }

    /// Sonde de la regle a port : des messages bien formes qui pavent le
    /// segment, d'identifiant plausible. Seul le dernier peut etre coupe par
    /// le segment, et sa longueur doit alors rester plausible.
    pub(crate) fn is_port_match(payload: &'a [u8]) -> bool {
        let mut rest = payload;
        loop {
            let Ok(message) = SkinnyMessage::try_from(rest) else {
                return false;
            };
            if !checks::is_plausible_message_id(message.message_id) {
                return false;
            }
            if message.is_truncated() {
                return message.data_length <= checks::MAX_CUT_DATA_LENGTH;
            }
            if message.rest.is_empty() {
                return true;
            }
            rest = message.rest;
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for SkinnyMessage<'a> {
    type Error = SkinnyError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let Some((header, after)) = bytes.split_first_chunk::<SKINNY_HEADER_LENGTH>() else {
            return Err(SkinnyError::TooShort {
                expected: SKINNY_HEADER_LENGTH,
                actual: bytes.len(),
            });
        };
        let [l0, l1, l2, l3, v0, v1, v2, v3, m0, m1, m2, m3] = *header;
        let data_length = checks::data_length(u32::from_le_bytes([l0, l1, l2, l3]))?;
        let header_version = checks::header_version(u32::from_le_bytes([v0, v1, v2, v3]))?;
        let message_id = u32::from_le_bytes([m0, m1, m2, m3]);
        let (body, rest) = after.split_at(checks::body_length(data_length).min(after.len()));
        Ok(Self {
            data_length,
            header_version,
            message_id,
            body,
            rest,
        })
    }
}

/// Iterator over the messages of a TCP segment
/// ([`SkinnyMessage::messages`]).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SkinnyMessages<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for SkinnyMessages<'a> {
    type Item = Result<SkinnyMessage<'a>, SkinnyError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let message = SkinnyMessage::try_from(self.rest);
        // Apres une erreur, la suite du segment n'a plus de frontiere.
        self.rest = message.as_ref().map_or(&[], |message| message.rest);
        Some(message)
    }
}

mod checks {
    use super::SkinnyError;

    /// Octets de l'identifiant de message, que la longueur compte.
    const MESSAGE_ID_LENGTH: u32 = 4;

    /// Versions d'en-tete que connait le dissecteur de Wireshark : 0
    /// (« Basic »), puis la version du protocole, 10, 11 et 15 a 22.
    const HEADER_VERSIONS: [u32; 11] = [0, 10, 11, 15, 16, 17, 18, 19, 20, 21, 22];

    /// Longueur au-dela de laquelle un message coupe par son segment n'est
    /// plus retenu par la sonde. Garde-fou, pas une regle du protocole : le
    /// plus long message du corpus fait 2 124 octets.
    pub(super) const MAX_CUT_DATA_LENGTH: u32 = 0xFFFF;

    pub(super) fn data_length(length: u32) -> Result<u32, SkinnyError> {
        if length < MESSAGE_ID_LENGTH {
            return Err(SkinnyError::InvalidDataLength(length));
        }
        Ok(length)
    }

    pub(super) fn header_version(version: u32) -> Result<u32, SkinnyError> {
        if HEADER_VERSIONS.contains(&version) {
            Ok(version)
        } else {
            Err(SkinnyError::UnsupportedHeaderVersion(version))
        }
    }

    /// Longueur du corps qu'annonce `data_length`, une fois l'identifiant
    /// retire.
    pub(super) fn body_length(data_length: u32) -> usize {
        usize::try_from(data_length.saturating_sub(MESSAGE_ID_LENGTH)).unwrap_or(usize::MAX)
    }

    /// Les identifiants connus vont de 0x0000 a 0x0160, plus trois messages
    /// SPCP (jeton d'enregistrement) en 0x8000, 0x8100 et 0x8101.
    pub(super) fn is_plausible_message_id(message_id: u32) -> bool {
        message_id < 0x0200 || matches!(message_id, 0x8000 | 0x8100 | 0x8101)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RegisterAck reel, en-tete de base :
    /// pcaps_exemple/protocols/skinny/ndpi_sccp_hw_conf_register.pcapng,
    /// trame 8 (32 octets).
    const REGISTER_ACK: &str = "1800000000000000810000001e000000556e7573656400003c00000012008028";

    /// KeepAlive reel, version d'en-tete 0x13 :
    /// pcaps_exemple/protocols/skinny/wireshark_8805_packets.cap, trame 52.
    const KEEP_ALIVE: &str = "040000001300000000000000";

    /// KeepAliveAck reel, en-tete de base : meme capture, trame 54.
    const KEEP_ALIVE_ACK: &str = "040000000000000000010000";

    /// Deux messages reels dans un segment, version d'en-tete 0x12 :
    /// ndpi_sccp_hw_conf_register.pcapng, trame 13 (316 octets), un message
    /// sans corps (0x000f) puis un de 296 octets (0x0010).
    const TWO_MESSAGES: &str = concat!(
        "04000000120000000f00000028010000120000001000000009000000040000001e000000",
        "0000000000000000020000001e00000000000000000000000c0000003c00000000000000",
        "00000000100000003c00000000000000000000000b0000003c0000000000000000000000",
        "0f0000003c0000000000000000000000010100001e000000000000000000000003010000",
        "1e0000000000000000000000050100001e00000000000000000000000000000000000083",
        "ffffffff000000000070000000000101e200640201010000000000200000000000000000",
        "001b00000000000001e2000000000000000000000000000000200000000000000000001a",
        "00000000000003840000000000000000000000000000000c000000072ad69cec00000000",
        "000c7f8500887f850048000000000000000000000000000621000000",
    );

    fn hex(text: &str) -> Vec<u8> {
        hex::decode(text).expect("hexa valide")
    }

    #[test]
    fn register_ack_is_read() {
        let bytes = hex(REGISTER_ACK);
        let message = SkinnyMessage::try_from(bytes.as_slice()).expect("RegisterAck");
        assert_eq!(message.data_length, 24);
        assert_eq!(message.header_version, 0);
        assert_eq!(message.message_id, 0x0081);
        assert_eq!(message.body.len(), 20);
        assert!(message.rest().is_empty());
        assert!(!message.is_truncated());
        assert!(SkinnyMessage::is_port_match(&bytes));
    }

    #[test]
    fn keep_alives_have_no_body() {
        let bytes = hex(KEEP_ALIVE);
        let message = SkinnyMessage::try_from(bytes.as_slice()).expect("KeepAlive");
        assert_eq!(
            (
                message.data_length,
                message.header_version,
                message.message_id
            ),
            (4, 0x13, 0x0000)
        );
        assert!(message.body.is_empty() && !message.is_truncated());

        let bytes = hex(KEEP_ALIVE_ACK);
        let message = SkinnyMessage::try_from(bytes.as_slice()).expect("KeepAliveAck");
        assert_eq!((message.header_version, message.message_id), (0, 0x0100));
        assert!(SkinnyMessage::is_port_match(&bytes));
    }

    #[test]
    fn two_messages_in_one_segment() {
        let bytes = hex(TWO_MESSAGES);
        assert_eq!(bytes.len(), 316);
        let messages: Vec<_> = SkinnyMessage::messages(&bytes)
            .collect::<Result<_, _>>()
            .expect("deux messages");
        assert_eq!(messages.len(), 2);
        assert_eq!(
            (messages[0].message_id, messages[0].body.len()),
            (0x000f, 0)
        );
        assert_eq!(messages[0].rest().len(), 304);
        assert_eq!(
            (messages[1].message_id, messages[1].data_length),
            (0x0010, 296)
        );
        assert_eq!(messages[1].header_version, 0x12);
        assert_eq!(messages[1].body.len(), 292);
        assert!(messages[1].rest().is_empty());
        assert!(SkinnyMessage::is_port_match(&bytes));
    }

    // Les tests qui suivent coupent ou alterent des octets des trames
    // reelles, ou en ecrivent a la main, pour viser une branche precise.

    #[test]
    fn a_segment_shorter_than_the_message_is_truncated() {
        // Le RegisterAck reel, coupe apres 20 octets comme par un segment.
        let bytes = hex(REGISTER_ACK);
        let message = SkinnyMessage::try_from(&bytes[..20]).expect("message coupe");
        assert!(message.is_truncated());
        assert_eq!(message.body.len(), 8);
        assert!(message.rest().is_empty());
        assert!(SkinnyMessage::is_port_match(&bytes[..20]));
        // L'iterateur rend le message coupe, puis s'arrete.
        assert_eq!(SkinnyMessage::messages(&bytes[..20]).count(), 1);
    }

    #[test]
    fn synthetic_trailing_bytes_refuse_the_probe() {
        // Un message complet suivi d'octets qui ne sont pas un message.
        let mut bytes = hex(KEEP_ALIVE);
        bytes.extend([0xde, 0xad]);
        let message = SkinnyMessage::try_from(bytes.as_slice()).expect("premier message");
        assert_eq!(message.rest(), [0xde, 0xad]);
        assert!(!SkinnyMessage::is_port_match(&bytes));
        let results: Vec<_> = SkinnyMessage::messages(&bytes).collect();
        assert_eq!(results.len(), 2);
        assert_eq!(
            results[1],
            Err(SkinnyError::TooShort {
                expected: 12,
                actual: 2
            })
        );
        // Un second en-tete entier mais invalide.
        let mut bytes = hex(KEEP_ALIVE);
        bytes.extend(hex("040000000100000000000000"));
        assert!(!SkinnyMessage::is_port_match(&bytes));
    }

    #[test]
    fn altered_headers_are_refused() {
        let alter = |index: usize, value: u8| {
            let mut bytes = hex(REGISTER_ACK);
            bytes[index] = value;
            SkinnyMessage::try_from(bytes.as_slice()).map(|_| ())
        };
        // Longueur 3 : sous les quatre octets de l'identifiant.
        assert_eq!(alter(0, 3), Err(SkinnyError::InvalidDataLength(3)));
        // Versions d'en-tete hors de la liste : 1, 12, 23, et un octet haut.
        for (index, value, version) in [(4, 1, 1), (4, 12, 12), (4, 23, 23), (7, 1, 0x0100_0000)] {
            assert_eq!(
                alter(index, value),
                Err(SkinnyError::UnsupportedHeaderVersion(version)),
                "octet {index}"
            );
        }
        assert_eq!(
            SkinnyMessage::try_from(&hex(REGISTER_ACK)[..11]).map(|_| ()),
            Err(SkinnyError::TooShort {
                expected: 12,
                actual: 11
            })
        );
        assert_eq!(
            SkinnyMessage::try_from(&[][..]).map(|_| ()),
            Err(SkinnyError::TooShort {
                expected: 12,
                actual: 0
            })
        );
    }

    #[test]
    fn synthetic_every_header_version_is_read() {
        for version in [0u8, 10, 11, 15, 16, 17, 18, 19, 20, 21, 22] {
            let mut bytes = hex(KEEP_ALIVE);
            bytes[4] = version;
            let message = SkinnyMessage::try_from(bytes.as_slice()).expect("version connue");
            assert_eq!(message.header_version, u32::from(version));
        }
    }

    #[test]
    fn synthetic_probe_guards() {
        // Identifiant hors plage : le decodeur le lit, la sonde le refuse.
        let mut bytes = hex(KEEP_ALIVE);
        bytes[9] = 0x02;
        assert!(SkinnyMessage::try_from(bytes.as_slice()).is_ok());
        assert!(!SkinnyMessage::is_port_match(&bytes));
        // Les trois identifiants SPCP sont admis.
        for (low, high) in [(0x00, 0x80), (0x00, 0x81), (0x01, 0x81)] {
            let mut bytes = hex(KEEP_ALIVE);
            (bytes[8], bytes[9]) = (low, high);
            assert!(SkinnyMessage::is_port_match(&bytes), "{high:02x}{low:02x}");
        }
        // Message coupe dont la longueur depasse 65 535 octets.
        let mut bytes = hex(KEEP_ALIVE);
        bytes[2] = 0x01;
        let message = SkinnyMessage::try_from(bytes.as_slice()).expect("en-tete lisible");
        assert!(message.is_truncated());
        assert!(!SkinnyMessage::is_port_match(&bytes));
        // Segment vide.
        assert!(!SkinnyMessage::is_port_match(&[]));
    }
}
