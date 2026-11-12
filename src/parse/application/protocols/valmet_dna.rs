// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Valmet DNA (Metso DNA), le reseau de process d'un systeme de controle
//! distribue : protocole proprietaire, sans specification ni dissecteur
//! public. Ce decodeur est construit sur la seule observation du trafic — une
//! capture sur le port miroir d'un reseau en exploitation, anonymisee dans
//! `pcaps_exemple/protocols/valmet_dna/` — sans code ni documentation du
//! fournisseur. Il lit, ne reconstruit aucune logique de controle et n'emet
//! rien. Les noms des champs sont ceux de l'observation, pas ceux du
//! fournisseur.
//!
//! Ce qui circule : des datagrammes UDP 2517 -> 2517 vers le groupe
//! multicast 239.0.171.1, dont la charge commence par la magie `AB 01` (les
//! deux derniers octets du groupe), l'identifiant du noeud source
//! (`0x80NN`), une destination (`0x00FF` sur toutes les trames observees :
//! « tous les noeuds », vraisemblablement), une longueur egale au datagramme
//! moins deux, puis une famille de message sur quatre octets. Deux familles
//! sont connues :
//!
//! - `0x00000FFF`, le **telegramme d'etat** ([`StatusTelegram`]) : 126
//!   octets, emis par chaque noeud toutes les 640 ms, qui porte l'adresse
//!   IPv4 du noeud (celle de l'en-tete IP), une horloge BCD de dix octets
//!   ([`DnaClock`]), le numero du noeud (l'octet bas de son identifiant), le
//!   groupe multicast, et deux compteurs de 32 bits dont le second repete le
//!   premier du telegramme precedent et qui avancent de 640 000 par periode
//!   de 640 ms : des microsecondes ;
//! - `0x001E00D0`, le **message a etiquette** ([`TagMessage`]) : un en-tete
//!   fixe de 72 octets, dont la longueur de l'etiquette ecrite deux fois
//!   (offsets 28 et 70), puis l'etiquette, qui pave exactement le
//!   datagramme. Les etiquettes lisibles ont la forme `:e:<classe>:<chemin>`,
//!   la classe sur deux lettres (`di`, `pr`, `li`, `hw`, `sn` observees) ;
//!   certaines, de dix octets, ne sont pas du texte.
//!
//! Les autres familles sont acceptees avec leur corps en octets
//! ([`ValmetDnaMessage::Unknown`]) sur les ports du protocole, et refusees
//! par la sonde aveugle. Les champs qui ne sont pas nommes ici restent dans
//! [`ValmetDnaPacket::body`], tels quels.
//!
//! Sur UDP 4516 -> 4517, vers le meme groupe, un noeud emet toutes les 30 s
//! une **balise** de 42 octets ([`TimeBeacon`]) : quatre octets nuls,
//! `AB CC`, un code, un compteur, la meme horloge BCD et l'adresse du noeud.
//! Elle n'est reconnue que sur ses ports.

use std::{convert::TryFrom, net::Ipv4Addr};

use crate::{
    checks::application::valmet_dna::{
        BEACON_CLOCK_OFFSET, BEACON_CODE_OFFSET, BEACON_COUNTER_OFFSET, BEACON_NODE_IP_OFFSET,
        CLOCK_LENGTH, STATUS_CLOCK_OFFSET, STATUS_GROUP_OFFSET, STATUS_KIND, STATUS_NODE_IP_OFFSET,
        STATUS_NODE_NUMBER_OFFSET, STATUS_PREVIOUS_TICK_OFFSET, STATUS_TICK_OFFSET, TAG_KIND,
        TAG_LENGTH_ECHO_OFFSET, TAG_LENGTH_OFFSET, TAG_MESSAGE_HEADER_LENGTH,
        VALMET_DNA_HEADER_LENGTH, bcd, ensure_len, validate_beacon_frame, validate_length,
        validate_magic, validate_status_length, validate_tag_length,
    },
    errors::application::valmet_dna::ValmetDnaParseError,
};

/// Familles de message connues (quatre octets a l'offset 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MessageKind {
    /// `0x00000FFF` : telegramme d'etat periodique, 126 octets.
    Status,
    /// `0x001E00D0` : message a etiquette.
    Tag,
}

impl MessageKind {
    pub fn from_code(code: u32) -> Option<Self> {
        Some(match code {
            STATUS_KIND => Self::Status,
            TAG_KIND => Self::Tag,
            _ => return None,
        })
    }
}

/// L'horloge BCD de dix octets des telegrammes d'etat et des balises.
///
/// ```mermaid
/// ---
/// title: DnaClock
/// ---
/// packet-beta
/// 0-15: "Fraction (BCD, mot little-endian, 100 us)"
/// 16-23: "Second (BCD)"
/// 24-31: "Minute (BCD)"
/// 32-39: "Hour (BCD)"
/// 40-47: "Weekday (BCD)"
/// 48-55: "Day (BCD)"
/// 56-63: "Month (BCD)"
/// 64-79: "Year (BCD, mot little-endian)"
/// ```
///
/// L'ordre des champs est etabli sur la capture d'origine : les secondes
/// passent de 59 a 00 avec report sur les minutes, la fraction avance de
/// 6 400 par telegramme (640 ms), l'heure et le jour de la semaine sont ceux
/// du jour de la capture. L'horloge des noeuds n'etait pas calee sur
/// l'heure legale (vingt-neuf minutes d'ecart, identiques sur tous les
/// noeuds) : elle date les echanges entre eux, pas le monde exterieur.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct DnaClock {
    /// Fraction de seconde, en unites de 100 µs (0 a 9999).
    pub fraction: u16,
    pub second: u8,
    pub minute: u8,
    pub hour: u8,
    /// Jour de la semaine : `2` observe un mardi, soit lundi = 1 (ISO 8601)
    /// ou dimanche = 0 — un seul jour observe, les deux conventions y
    /// coincident. Toujours entre 0 et 7.
    pub weekday: u8,
    pub day: u8,
    pub month: u8,
    pub year: u16,
}

impl DnaClock {
    /// Lit les dix premiers octets de `bytes` ; `None` si un quartet n'est
    /// pas un chiffre ou si un champ sort de sa plage (secondes et minutes
    /// jusqu'a 59, heure jusqu'a 23, jour de la semaine jusqu'a 7, jour de
    /// 1 a 31, mois de 1 a 12) — une horloge non reglee, pas une erreur de
    /// decodage.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let digits = bytes.first_chunk::<CLOCK_LENGTH>()?;
        let mut values = [0u8; CLOCK_LENGTH];
        for (value, byte) in values.iter_mut().zip(digits) {
            *value = bcd(*byte)?;
        }
        let [
            fraction_low,
            fraction_high,
            second,
            minute,
            hour,
            weekday,
            day,
            month,
            year_low,
            year_high,
        ] = values;
        if second > 59
            || minute > 59
            || hour > 23
            || weekday > 7
            || !(1..=31).contains(&day)
            || !(1..=12).contains(&month)
        {
            return None;
        }
        Some(Self {
            fraction: u16::from(fraction_high) * 100 + u16::from(fraction_low),
            second,
            minute,
            hour,
            weekday,
            day,
            month,
            year: u16::from(year_high) * 100 + u16::from(year_low),
        })
    }

    /// Microsecondes ecoulees depuis minuit, pour comparer deux horloges du
    /// meme jour.
    pub fn microseconds_of_day(&self) -> u64 {
        let seconds =
            u64::from(self.hour) * 3600 + u64::from(self.minute) * 60 + u64::from(self.second);
        seconds * 1_000_000 + u64::from(self.fraction) * 100
    }
}

/// Le telegramme d'etat (famille `0x00000FFF`, 126 octets) : les champs
/// identifies, offsets depuis le debut du datagramme.
///
/// ```mermaid
/// ---
/// title: StatusTelegram
/// ---
/// packet-beta
/// 0-95: "En-tete Valmet DNA (12 octets)"
/// 96-287: "Non identifie (24 octets)"
/// 288-319: "Node IPv4 address"
/// 320-335: "Non identifie"
/// 336-415: "DnaClock (10 octets)"
/// 416-463: "Non identifie (6 octets)"
/// 464-471: "Node number"
/// 472-559: "Non identifie (11 octets)"
/// 560-591: "Multicast group IPv4"
/// 592-847: "Non identifie (32 octets)"
/// 848-879: "Tick (us)"
/// 880-911: "Previous tick (us)"
/// 912-1007: "Non identifie (12 octets)"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct StatusTelegram {
    /// Adresse IPv4 du noeud : celle de la source IP du datagramme sur
    /// toutes les trames observees.
    pub node_ip: Ipv4Addr,
    /// L'horloge du noeud, quand ses dix octets forment une date valide.
    pub clock: Option<DnaClock>,
    /// Numero du noeud : l'octet bas de [`ValmetDnaPacket::source_node`]
    /// sur toutes les trames observees.
    pub node_number: u8,
    /// Le groupe multicast du reseau : la destination IP du datagramme.
    pub multicast_group: Ipv4Addr,
    /// Compteur de 32 bits qui avance d'environ 640 000 entre deux
    /// telegrammes espaces de 640 ms : des microsecondes, modulo 2^32. Sur la
    /// capture, les 302 ecarts vont de 639 111 a 642 481 (#235).
    pub tick: u32,
    /// Le `tick` du telegramme precedent du meme noeud.
    pub previous_tick: u32,
}

impl StatusTelegram {
    fn parse(payload: &[u8]) -> Result<Self, ValmetDnaParseError> {
        validate_status_length(payload.len())?;
        Ok(Self {
            node_ip: ipv4_at(payload, STATUS_NODE_IP_OFFSET),
            clock: DnaClock::from_bytes(&payload[STATUS_CLOCK_OFFSET..]),
            node_number: payload[STATUS_NODE_NUMBER_OFFSET],
            multicast_group: ipv4_at(payload, STATUS_GROUP_OFFSET),
            tick: u32_at(payload, STATUS_TICK_OFFSET),
            previous_tick: u32_at(payload, STATUS_PREVIOUS_TICK_OFFSET),
        })
    }
}

/// Le message a etiquette (famille `0x001E00D0`) : l'etiquette, empruntee
/// au datagramme, dont la longueur est ecrite aux offsets 28 et 70 et qui
/// commence a l'offset 72.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct TagMessage<'a> {
    /// Longueur declaree de l'etiquette, egale a `tag.len()`.
    pub tag_length: u16,
    /// L'etiquette, telle quelle : `:e:<classe>:<chemin>` quand elle est
    /// lisible, dix octets qui ne sont pas du texte sinon.
    pub tag: &'a [u8],
}

impl<'a> TagMessage<'a> {
    fn parse(payload: &'a [u8]) -> Result<Self, ValmetDnaParseError> {
        ensure_len(payload, TAG_MESSAGE_HEADER_LENGTH)?;
        let declared = u16_at(payload, TAG_LENGTH_OFFSET);
        let echo = u16_at(payload, TAG_LENGTH_ECHO_OFFSET);
        let tag_length = validate_tag_length(declared, echo, payload.len())?;
        Ok(Self {
            tag_length: declared,
            tag: &payload[TAG_MESSAGE_HEADER_LENGTH..TAG_MESSAGE_HEADER_LENGTH + tag_length],
        })
    }

    /// L'etiquette en texte, quand elle est de l'UTF-8 valide.
    pub fn tag_text(&self) -> Option<&'a str> {
        std::str::from_utf8(self.tag).ok()
    }

    /// Les deux parties de la forme `:e:<classe>:<chemin>`.
    fn split(&self) -> Option<(&'a str, &'a str)> {
        let (class, path) = self.tag_text()?.strip_prefix(":e:")?.split_once(':')?;
        (!class.is_empty()).then_some((class, path))
    }

    /// La classe d'une etiquette `:e:<classe>:<chemin>` (`di`, `pr`, `li`,
    /// `hw`, `sn` observees).
    pub fn class(&self) -> Option<&'a str> {
        self.split().map(|(class, _)| class)
    }

    /// Le chemin d'une etiquette `:e:<classe>:<chemin>`.
    pub fn path(&self) -> Option<&'a str> {
        self.split().map(|(_, path)| path)
    }
}

/// Le corps decode d'un message, selon sa famille.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ValmetDnaMessage<'a> {
    Status(StatusTelegram),
    Tag(TagMessage<'a>),
    /// Famille inconnue : le corps est dans [`ValmetDnaPacket::body`].
    Unknown,
}

/// Un message Valmet DNA (UDP 2517).
///
/// ```mermaid
/// ---
/// title: ValmetDnaPacket
/// ---
/// packet-beta
/// 0-15: "Magic 0xAB01"
/// 16-31: "Source node (0x80NN)"
/// 32-47: "Destination (0x00FF)"
/// 48-63: "Length (datagram - 2)"
/// 64-95: "Message kind"
/// 96-127: "Body (variable)"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ValmetDnaPacket<'a> {
    /// Identifiant du noeud emetteur : `0x80NN` sur toutes les trames
    /// observees, `NN` le numero du noeud.
    pub source_node: u16,
    /// `0x00FF` sur toutes les trames observees, toutes en multicast.
    pub destination: u16,
    /// Longueur declaree : le datagramme moins deux.
    pub length: u16,
    /// La famille de message, telle quelle.
    pub kind_code: u32,
    /// La famille nommee, quand [`MessageKind`] la connait.
    pub kind: Option<MessageKind>,
    /// Tout ce qui suit l'en-tete de douze octets, tel quel.
    pub body: &'a [u8],
    pub message: ValmetDnaMessage<'a>,
}

impl ValmetDnaPacket<'_> {
    /// L'octet bas de l'identifiant du noeud source.
    pub fn node_number(&self) -> u8 {
        self.source_node.to_be_bytes()[1]
    }

    /// Sonde sur UDP 2517, 4516, 4517 et les ports declares : un message a
    /// l'en-tete coherent, de famille inconnue, ou de famille connue a sa
    /// taille exacte, ou une balise.
    pub(crate) fn is_port_udp_match(payload: &[u8]) -> bool {
        ValmetDnaPacket::try_from(payload).is_ok() || TimeBeacon::try_from(payload).is_ok()
    }

    /// Sonde aveugle, sur tout autre port UDP : magie, longueur egale au
    /// datagramme moins deux, et une famille connue a sa taille exacte —
    /// plus de 64 bits de contrainte.
    pub(crate) fn is_blind_udp_match(payload: &[u8]) -> bool {
        ValmetDnaPacket::try_from(payload).is_ok_and(|packet| packet.kind.is_some())
    }
}

impl<'a> TryFrom<&'a [u8]> for ValmetDnaPacket<'a> {
    type Error = ValmetDnaParseError;

    fn try_from(payload: &'a [u8]) -> Result<Self, Self::Error> {
        ensure_len(payload, VALMET_DNA_HEADER_LENGTH)?;
        validate_magic(u16_at(payload, 0))?;
        let source_node = u16_at(payload, 2);
        let destination = u16_at(payload, 4);
        let length = u16_at(payload, 6);
        validate_length(length, payload.len())?;
        let kind_code = u32_at(payload, 8);
        let kind = MessageKind::from_code(kind_code);
        let message = match kind {
            Some(MessageKind::Status) => ValmetDnaMessage::Status(StatusTelegram::parse(payload)?),
            Some(MessageKind::Tag) => ValmetDnaMessage::Tag(TagMessage::parse(payload)?),
            None => ValmetDnaMessage::Unknown,
        };
        Ok(Self {
            source_node,
            destination,
            length,
            kind_code,
            kind,
            body: &payload[VALMET_DNA_HEADER_LENGTH..],
            message,
        })
    }
}

/// La balise de 42 octets qu'un noeud emet toutes les 30 s sur UDP 4516 ->
/// 4517, vers le groupe multicast. Un seul exemplaire observe par capture :
/// le code et le compteur sont rendus tels quels.
///
/// ```mermaid
/// ---
/// title: TimeBeacon
/// ---
/// packet-beta
/// 0-31: "Zero"
/// 32-47: "Magic 0xABCC"
/// 48-63: "Code"
/// 64-95: "Counter"
/// 96-223: "Non identifie (16 octets)"
/// 224-303: "DnaClock (10 octets)"
/// 304-335: "Node IPv4 address"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct TimeBeacon {
    pub code: u16,
    pub counter: u32,
    /// La meme horloge que celle des telegrammes d'etat.
    pub clock: Option<DnaClock>,
    /// L'adresse IPv4 du noeud : la source IP du datagramme.
    pub node_ip: Ipv4Addr,
}

impl TryFrom<&[u8]> for TimeBeacon {
    type Error = ValmetDnaParseError;

    fn try_from(payload: &[u8]) -> Result<Self, Self::Error> {
        validate_beacon_frame(payload)?;
        Ok(Self {
            code: u16_at(payload, BEACON_CODE_OFFSET),
            counter: u32_at(payload, BEACON_COUNTER_OFFSET),
            clock: DnaClock::from_bytes(&payload[BEACON_CLOCK_OFFSET..]),
            node_ip: ipv4_at(payload, BEACON_NODE_IP_OFFSET),
        })
    }
}

/// Lectures big-endian a un offset que l'appelant a deja borne.
fn u16_at(payload: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([payload[offset], payload[offset + 1]])
}

fn u32_at(payload: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        payload[offset],
        payload[offset + 1],
        payload[offset + 2],
        payload[offset + 3],
    ])
}

fn ipv4_at(payload: &[u8], offset: usize) -> Ipv4Addr {
    Ipv4Addr::new(
        payload[offset],
        payload[offset + 1],
        payload[offset + 2],
        payload[offset + 3],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// pcaps_exemple/protocols/valmet_dna/valmet-dna-multicast-anon.pcap,
    /// trame 1 (UDP 2517 -> 2517, 10.0.2.1 -> 239.0.171.1) : le telegramme
    /// d'etat du noeud 0x801D.
    const STATUS: &str = concat!(
        "ab01801d00ff007c00000fff001003b00000048ace4818e03d0018803f000000",
        "000000000a0002010005000000000003010120200000000000001d00018a0052",
        "c59c00000001ef00ab0100000000000000000000000000000000000000000000",
        "00000000000000000000540f5bf154059702000000000000000009d609d6",
    );

    /// Meme capture, trame 9 (10.0.2.6) : un message a etiquette du noeud
    /// 0x8028, etiquette de 43 octets de classe `di`.
    const TAG: &str = concat!(
        "ab01802800ff0071001e00d0000105060a3b00005103000000000000002b0000",
        "00000000000081a47c1800030000000000000000000000000002000000000000",
        "05f4fcd80000002b3a653a64693a414b30353a6e72697330353a6f696777786a",
        "3032363a6f69787767652832293a6177637273",
    );

    /// Meme capture, trame 2 (10.0.2.2) : un message a etiquette de dix
    /// octets qui ne sont pas du texte (`:e:A2` puis 0xC1, `1`, NUL, 0xFEFF).
    const SHORT_TAG: &str = concat!(
        "ab01800a00ff0050001e00d0000101260b2500000003000000000000000a0000",
        "000000000000c5c07c180003000000000000000000000000000a000000000000",
        "03a0fd600000000a3a653a4132c13100feff",
    );

    /// Meme capture, trame 591 (UDP 4516 -> 4517, 10.0.2.9) : la balise.
    const BEACON: &str = concat!(
        "00000000abcc0006238000003e0f252702d8ffe0000000000000000086950900",
        "0003010120200a000209",
    );

    #[test]
    fn test_decodes_a_status_telegram() {
        let bytes = hex::decode(STATUS).unwrap();
        assert_eq!(bytes.len(), 126);
        let packet = ValmetDnaPacket::try_from(bytes.as_slice()).expect("telegramme d'etat");
        assert_eq!(
            (packet.source_node, packet.destination, packet.length),
            (0x801D, 0x00FF, 124)
        );
        assert_eq!(packet.kind_code, 0x0000_0FFF);
        assert_eq!(packet.kind, Some(MessageKind::Status));
        assert_eq!(packet.node_number(), 0x1D);
        assert_eq!(packet.body.len(), 114);
        assert!(bytes.as_ptr_range().contains(&packet.body.as_ptr()));
        let ValmetDnaMessage::Status(status) = packet.message else {
            panic!("{:?}", packet.message);
        };
        assert_eq!(status.node_ip, Ipv4Addr::new(10, 0, 2, 1));
        assert_eq!(status.node_number, 29);
        assert_eq!(status.multicast_group, Ipv4Addr::new(239, 0, 171, 1));
        assert_eq!(
            (status.tick, status.previous_tick),
            (0x540F_5BF1, 0x5405_9702)
        );
        assert_eq!(status.tick - status.previous_tick, 640_239);
        let clock = status.clock.expect("horloge valide");
        assert_eq!(
            clock,
            DnaClock {
                fraction: 0,
                second: 0,
                minute: 0,
                hour: 0,
                weekday: 3,
                day: 1,
                month: 1,
                year: 2020,
            }
        );
        assert_eq!(clock.microseconds_of_day(), 0);
    }

    #[test]
    fn test_decodes_a_tag_message() {
        let bytes = hex::decode(TAG).unwrap();
        assert_eq!(bytes.len(), 115);
        let packet = ValmetDnaPacket::try_from(bytes.as_slice()).expect("message a etiquette");
        assert_eq!((packet.source_node, packet.length), (0x8028, 113));
        assert_eq!(packet.kind, Some(MessageKind::Tag));
        let ValmetDnaMessage::Tag(tag) = packet.message else {
            panic!("{:?}", packet.message);
        };
        assert_eq!(tag.tag_length, 43);
        assert_eq!(tag.tag.len(), 43);
        assert!(bytes.as_ptr_range().contains(&tag.tag.as_ptr()));
        assert_eq!(
            tag.tag_text(),
            Some(":e:di:AK05:nris05:oigwxj026:oixwge(2):awcrs")
        );
        assert_eq!(tag.class(), Some("di"));
        assert_eq!(tag.path(), Some("AK05:nris05:oigwxj026:oixwge(2):awcrs"));
    }

    #[test]
    fn test_a_short_tag_is_kept_as_bytes() {
        let bytes = hex::decode(SHORT_TAG).unwrap();
        assert_eq!(bytes.len(), 82);
        let packet = ValmetDnaPacket::try_from(bytes.as_slice()).expect("message a etiquette");
        let ValmetDnaMessage::Tag(tag) = packet.message else {
            panic!("{:?}", packet.message);
        };
        assert_eq!(tag.tag_length, 10);
        assert!(tag.tag.starts_with(b":e:"));
        assert_eq!(tag.tag_text(), None);
        assert_eq!(tag.class(), None);
        assert_eq!(tag.path(), None);
    }

    #[test]
    fn test_tag_accessors_need_the_full_shape() {
        let tag = |bytes: &'static [u8]| TagMessage {
            tag_length: bytes.len() as u16,
            tag: bytes,
        };
        assert_eq!(tag(b":e:pr:").class(), Some("pr"));
        assert_eq!(tag(b":e:pr:").path(), Some(""));
        assert_eq!(tag(b":e::chemin").class(), None);
        assert_eq!(tag(b":e:pr").class(), None);
        assert_eq!(tag(b"pr:chemin").class(), None);
        assert_eq!(tag(b"").tag_text(), Some(""));
    }

    #[test]
    fn test_an_unknown_kind_passes_on_port_only() {
        let mut bytes = hex::decode(STATUS).unwrap();
        bytes[8..12].copy_from_slice(&[0x00, 0x00, 0x10, 0x00]);
        let packet = ValmetDnaPacket::try_from(bytes.as_slice()).expect("famille inconnue");
        assert_eq!(packet.kind_code, 0x1000);
        assert_eq!(packet.kind, None);
        assert_eq!(packet.message, ValmetDnaMessage::Unknown);
        assert!(ValmetDnaPacket::is_port_udp_match(&bytes));
        assert!(!ValmetDnaPacket::is_blind_udp_match(&bytes));

        let status = hex::decode(STATUS).unwrap();
        assert!(ValmetDnaPacket::is_port_udp_match(&status));
        assert!(ValmetDnaPacket::is_blind_udp_match(&status));
        let tag = hex::decode(TAG).unwrap();
        assert!(ValmetDnaPacket::is_blind_udp_match(&tag));
        let beacon = hex::decode(BEACON).unwrap();
        assert!(ValmetDnaPacket::is_port_udp_match(&beacon));
        assert!(!ValmetDnaPacket::is_blind_udp_match(&beacon));
    }

    #[test]
    fn test_rejects_a_bad_header() {
        let status = hex::decode(STATUS).unwrap();
        assert_eq!(
            ValmetDnaPacket::try_from(&status[..8]),
            Err(ValmetDnaParseError::Truncated {
                expected: 12,
                actual: 8
            })
        );
        let mut magic = status.clone();
        magic[1] = 0x02;
        assert_eq!(
            ValmetDnaPacket::try_from(magic.as_slice()),
            Err(ValmetDnaParseError::InvalidMagic(0xAB02))
        );
        // Un octet de moins : la longueur declaree ne couvre plus le
        // datagramme moins deux.
        assert_eq!(
            ValmetDnaPacket::try_from(&status[..125]),
            Err(ValmetDnaParseError::LengthMismatch {
                declared: 124,
                actual: 125
            })
        );
        // Longueur coherente mais telegramme d'etat trop court.
        let mut short = status[..125].to_vec();
        short[7] = 123;
        assert_eq!(
            ValmetDnaPacket::try_from(short.as_slice()),
            Err(ValmetDnaParseError::InvalidMessageLength {
                kind: 0x0000_0FFF,
                expected: 126,
                actual: 125
            })
        );
    }

    #[test]
    fn test_rejects_a_bad_tag_length() {
        let tag = hex::decode(TAG).unwrap();
        let mut echo = tag.clone();
        echo[71] = 42;
        assert_eq!(
            ValmetDnaPacket::try_from(echo.as_slice()),
            Err(ValmetDnaParseError::TagLengthMismatch {
                declared: 43,
                echo: 42
            })
        );
        let mut overflow = tag.clone();
        overflow[29] = 44;
        overflow[71] = 44;
        assert_eq!(
            ValmetDnaPacket::try_from(overflow.as_slice()),
            Err(ValmetDnaParseError::InvalidMessageLength {
                kind: 0x001E_00D0,
                expected: 116,
                actual: 115
            })
        );
        // En-tete fixe incomplet, longueur declaree coherente.
        let mut header = tag[..40].to_vec();
        header[7] = 38;
        assert_eq!(
            ValmetDnaPacket::try_from(header.as_slice()),
            Err(ValmetDnaParseError::Truncated {
                expected: 72,
                actual: 40
            })
        );
        // Etiquette vide : 72 octets, les deux longueurs nulles.
        let mut empty = tag[..72].to_vec();
        empty[7] = 70;
        empty[29] = 0;
        empty[71] = 0;
        let packet = ValmetDnaPacket::try_from(empty.as_slice()).expect("etiquette vide");
        assert_eq!(
            packet.message,
            ValmetDnaMessage::Tag(TagMessage {
                tag_length: 0,
                tag: &[]
            })
        );
    }

    #[test]
    fn test_decodes_a_beacon() {
        let bytes = hex::decode(BEACON).unwrap();
        assert_eq!(bytes.len(), 42);
        let beacon = TimeBeacon::try_from(bytes.as_slice()).expect("balise");
        assert_eq!((beacon.code, beacon.counter), (6, 0x2380_0000));
        assert_eq!(beacon.node_ip, Ipv4Addr::new(10, 0, 2, 9));
        let clock = beacon.clock.expect("horloge valide");
        assert_eq!(
            (clock.fraction, clock.second, clock.minute, clock.hour),
            (9586, 9, 0, 0)
        );
        assert_eq!(
            (clock.weekday, clock.day, clock.month, clock.year),
            (3, 1, 1, 2020)
        );
        assert_eq!(clock.microseconds_of_day(), 9_958_600);

        assert_eq!(
            TimeBeacon::try_from(&bytes[..41]),
            Err(ValmetDnaParseError::InvalidBeaconLength { actual: 41 })
        );
        let mut prefix = bytes.clone();
        prefix[0] = 1;
        assert_eq!(
            TimeBeacon::try_from(prefix.as_slice()),
            Err(ValmetDnaParseError::InvalidBeaconPrefix(0x0100_0000))
        );
        let mut magic = bytes.clone();
        magic[4] = 0xAB;
        magic[5] = 0x01;
        assert_eq!(
            TimeBeacon::try_from(magic.as_slice()),
            Err(ValmetDnaParseError::InvalidBeaconMagic(0xAB01))
        );
        // Un message `AB 01` n'est pas une balise, et reciproquement.
        assert!(TimeBeacon::try_from(hex::decode(STATUS).unwrap().as_slice()).is_err());
        assert_eq!(
            ValmetDnaPacket::try_from(bytes.as_slice()),
            Err(ValmetDnaParseError::InvalidMagic(0))
        );
    }

    #[test]
    fn test_clock_rejects_non_bcd_bytes_and_impossible_dates() {
        let valid = [0x70, 0x08, 0x37, 0x52, 0x10, 0x02, 0x03, 0x11, 0x26, 0x20];
        let clock = DnaClock::from_bytes(&valid).expect("horloge valide");
        assert_eq!(
            clock,
            DnaClock {
                fraction: 870,
                second: 37,
                minute: 52,
                hour: 10,
                weekday: 2,
                day: 3,
                month: 11,
                year: 2026,
            }
        );
        assert_eq!(clock.microseconds_of_day(), 39_157_087_000);
        assert_eq!(DnaClock::from_bytes(&valid[..9]), None);
        for (index, byte) in [
            (0, 0x7A), // quartet non decimal
            (2, 0x60), // secondes
            (3, 0x60), // minutes
            (4, 0x24), // heure
            (5, 0x08), // jour de la semaine
            (6, 0x00), // jour
            (6, 0x32),
            (7, 0x00), // mois
            (7, 0x13),
        ] {
            let mut bytes = valid;
            bytes[index] = byte;
            assert_eq!(
                DnaClock::from_bytes(&bytes),
                None,
                "octet {index} = {byte:#04x}"
            );
        }
        // Une horloge a zero (noeud non regle) n'est pas une date.
        assert_eq!(DnaClock::from_bytes(&[0; 10]), None);
    }
}
