// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! GOOSE, Generic Object Oriented Substation Event (IEC 61850-8-1 §8) : les
//! evenements d'un poste electrique, publies en multicast directement sur
//! Ethernet (EtherType `0x88B8`, etiquette VLAN frequente), sans IP ni
//! transport — la trame se decode dans la couche internet, comme PTP et
//! Profinet. Un en-tete de huit octets (APPID, longueur qui couvre tout ce
//! qui suit l'EtherType, deux reserves dont le bit de simulation) precede
//! le goosePdu en BER : reference du bloc de controle, duree de vie, jeu de
//! donnees, identifiant, horodatage, numeros d'etat et de sequence,
//! simulation, revision de configuration, mise en service, nombre
//! d'entrees, puis `allData` — chaque valeur gardee avec son etiquette BER
//! et ses octets.

use std::convert::TryFrom;

use crate::{
    checks::internet::goose::{
        GOOSE_HEADER_LENGTH, GOOSE_RESERVED1_SIMULATION, GOOSE_TAG_ALL_DATA, GOOSE_TAG_CONF_REV,
        GOOSE_TAG_DATA_SET, GOOSE_TAG_GO_ID, GOOSE_TAG_GOCB_REF, GOOSE_TAG_NDS_COM,
        GOOSE_TAG_NUM_DAT_SET_ENTRIES, GOOSE_TAG_SECURITY, GOOSE_TAG_SIMULATION, GOOSE_TAG_SQ_NUM,
        GOOSE_TAG_ST_NUM, GOOSE_TAG_TIME_ALLOWED_TO_LIVE, GOOSE_TAG_TIMESTAMP, ensure_len,
        extract_ber_length, extract_bool, extract_u32, validate_element_fits, validate_length,
        validate_pdu_tag, validate_timestamp_length,
    },
    errors::internet::goose::GooseParseError,
    parse::application::protocols::bounded_capacity,
};

/// UtcTime (IEC 61850-8-1 §8.1.3.7) : secondes depuis 1970, fraction de
/// seconde sur 24 bits, qualite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct UtcTime {
    pub seconds: u32,
    /// Fraction de seconde en 1/2^24.
    pub fraction: u32,
    /// Bit 7 seconde intercalaire connue, 6 horloge en defaut, 5 horloge
    /// non synchronisee, bits 0 a 4 precision en bits de fraction.
    pub quality: u8,
}

impl UtcTime {
    pub fn leap_second_known(&self) -> bool {
        self.quality & 0x80 != 0
    }

    pub fn clock_failure(&self) -> bool {
        self.quality & 0x40 != 0
    }

    pub fn clock_not_synchronized(&self) -> bool {
        self.quality & 0x20 != 0
    }

    /// Nanosecondes de la fraction, arrondies vers le bas.
    pub fn nanoseconds(&self) -> u32 {
        ((u64::from(self.fraction) * 1_000_000_000) >> 24) as u32
    }
}

/// Type d'une valeur de `allData` (IEC 61850-8-1 annexe A, Data), nomme par
/// son numero de choix — l'etiquette BER contextuelle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DataKind {
    Array,
    Structure,
    Boolean,
    BitString,
    Integer,
    Unsigned,
    FloatingPoint,
    OctetString,
    VisibleString,
    GeneralizedTime,
    BinaryTime,
    Bcd,
    BooleanArray,
    ObjId,
    MmsString,
    UtcTime,
}

impl DataKind {
    pub fn from_tag(tag: u8) -> Option<Self> {
        Some(match tag & 0x1f {
            1 => Self::Array,
            2 => Self::Structure,
            3 => Self::Boolean,
            4 => Self::BitString,
            5 => Self::Integer,
            6 => Self::Unsigned,
            7 => Self::FloatingPoint,
            9 => Self::OctetString,
            10 => Self::VisibleString,
            11 => Self::GeneralizedTime,
            12 => Self::BinaryTime,
            13 => Self::Bcd,
            14 => Self::BooleanArray,
            15 => Self::ObjId,
            16 => Self::MmsString,
            17 => Self::UtcTime,
            _ => return None,
        })
    }
}

/// Une valeur de `allData` : son etiquette BER, son type et ses octets ;
/// un tableau ou une structure garde ses elements codes dans `value`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct GooseData<'a> {
    pub tag: u8,
    pub kind: Option<DataKind>,
    pub value: &'a [u8],
}

impl GooseData<'_> {
    pub fn as_bool(&self) -> Option<bool> {
        match (self.kind, self.value) {
            (Some(DataKind::Boolean), [byte]) => Some(*byte != 0),
            _ => None,
        }
    }
}

/// Le goosePdu (IEC 61850-8-1 annexe A).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct GoosePdu<'a> {
    /// Reference du bloc de controle, `LD/LLN0$GO$gcb`.
    pub gocb_ref: &'a str,
    /// Millisecondes avant que l'abonne tienne l'emetteur pour perdu.
    pub time_allowed_to_live: u32,
    pub data_set: &'a str,
    pub go_id: Option<&'a str>,
    pub timestamp: UtcTime,
    /// Numero d'etat : incremente a chaque changement de donnees.
    pub st_num: u32,
    /// Numero de sequence : incremente a chaque retransmission, remis a
    /// zero avec l'etat.
    pub sq_num: u32,
    pub simulation: bool,
    pub conf_rev: u32,
    /// Needs commissioning.
    pub nds_com: bool,
    pub num_dat_set_entries: u32,
    pub all_data: Vec<GooseData<'a>>,
    /// Le champ `security` (edition 2), tel quel.
    pub security: Option<&'a [u8]>,
}

/// Une trame GOOSE.
///
/// ```mermaid
/// ---
/// title: GoosePacket
/// ---
/// packet-beta
/// 0-15: "APPID u16"
/// 16-31: "Length u16 (from APPID to the end)"
/// 32-47: "Reserved 1 (bit 15: simulation)"
/// 48-63: "Reserved 2"
/// 64-127: "goosePdu (BER, tag 0x61)"
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct GoosePacket<'a> {
    pub app_id: u16,
    pub length: u16,
    pub reserved1: u16,
    pub reserved2: u16,
    pub pdu: GoosePdu<'a>,
}

impl GoosePacket<'_> {
    /// Bit S de la reserve 1 : la trame vient d'un simulateur.
    pub fn simulation_bit(&self) -> bool {
        self.reserved1 & GOOSE_RESERVED1_SIMULATION != 0
    }
}

impl<'a> TryFrom<&'a [u8]> for GoosePacket<'a> {
    type Error = GooseParseError;

    fn try_from(payload: &'a [u8]) -> Result<Self, Self::Error> {
        ensure_len(payload, GOOSE_HEADER_LENGTH + 2)?;
        let length = u16::from_be_bytes([payload[2], payload[3]]);
        validate_length(length, payload.len())?;
        validate_pdu_tag(payload[GOOSE_HEADER_LENGTH])?;
        let (pdu_len, len_octets) = extract_ber_length(payload, GOOSE_HEADER_LENGTH + 1)?;
        let pdu_start = GOOSE_HEADER_LENGTH + 1 + len_octets;
        validate_element_fits(
            payload[GOOSE_HEADER_LENGTH],
            pdu_len,
            payload.len() - pdu_start,
        )?;
        let pdu_bytes = &payload[pdu_start..pdu_start + pdu_len];
        let trailing = payload.len() - pdu_start - pdu_len;
        if trailing != 0 {
            return Err(GooseParseError::UnexpectedTrailingBytes(trailing));
        }
        Ok(GoosePacket {
            app_id: u16::from_be_bytes([payload[0], payload[1]]),
            length,
            reserved1: u16::from_be_bytes([payload[4], payload[5]]),
            reserved2: u16::from_be_bytes([payload[6], payload[7]]),
            pdu: parse_pdu(pdu_bytes)?,
        })
    }
}

/// Les elements BER successifs d'un contenu : `(tag, valeur)`.
struct Elements<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for Elements<'a> {
    type Item = Result<(u8, &'a [u8]), GooseParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.bytes.len() {
            return None;
        }
        let tag = self.bytes[self.offset];
        let (length, len_octets) = match extract_ber_length(self.bytes, self.offset + 1) {
            Ok(value) => value,
            Err(error) => {
                self.offset = self.bytes.len();
                return Some(Err(error));
            }
        };
        let start = self.offset + 1 + len_octets;
        if let Err(error) = validate_element_fits(tag, length, self.bytes.len() - start) {
            self.offset = self.bytes.len();
            return Some(Err(error));
        }
        self.offset = start + length;
        Some(Ok((tag, &self.bytes[start..start + length])))
    }
}

fn parse_pdu(bytes: &[u8]) -> Result<GoosePdu<'_>, GooseParseError> {
    let mut gocb_ref = None;
    let mut time_allowed_to_live = None;
    let mut data_set = None;
    let mut go_id = None;
    let mut timestamp = None;
    let mut st_num = None;
    let mut sq_num = None;
    let mut simulation = false;
    let mut conf_rev = None;
    let mut nds_com = false;
    let mut num_dat_set_entries = None;
    let mut all_data = None;
    let mut security = None;
    for element in (Elements { bytes, offset: 0 }) {
        let (tag, value) = element?;
        match tag {
            GOOSE_TAG_GOCB_REF => gocb_ref = Some(visible_string(value)),
            GOOSE_TAG_TIME_ALLOWED_TO_LIVE => time_allowed_to_live = Some(extract_u32(tag, value)?),
            GOOSE_TAG_DATA_SET => data_set = Some(visible_string(value)),
            GOOSE_TAG_GO_ID => go_id = Some(visible_string(value)),
            GOOSE_TAG_TIMESTAMP => {
                validate_timestamp_length(value.len())?;
                timestamp = Some(UtcTime {
                    seconds: u32::from_be_bytes([value[0], value[1], value[2], value[3]]),
                    fraction: u32::from_be_bytes([0, value[4], value[5], value[6]]),
                    quality: value[7],
                });
            }
            GOOSE_TAG_ST_NUM => st_num = Some(extract_u32(tag, value)?),
            GOOSE_TAG_SQ_NUM => sq_num = Some(extract_u32(tag, value)?),
            GOOSE_TAG_SIMULATION => simulation = extract_bool(tag, value)?,
            GOOSE_TAG_CONF_REV => conf_rev = Some(extract_u32(tag, value)?),
            GOOSE_TAG_NDS_COM => nds_com = extract_bool(tag, value)?,
            GOOSE_TAG_NUM_DAT_SET_ENTRIES => num_dat_set_entries = Some(extract_u32(tag, value)?),
            GOOSE_TAG_ALL_DATA => all_data = Some(parse_all_data(value)?),
            GOOSE_TAG_SECURITY => security = Some(value),
            // Un champ que l'edition en vigueur ne definit pas : ignore,
            // comme un abonne doit le faire.
            _ => {}
        }
    }
    Ok(GoosePdu {
        gocb_ref: gocb_ref.ok_or(GooseParseError::MissingField(GOOSE_TAG_GOCB_REF))?,
        time_allowed_to_live: time_allowed_to_live.ok_or(GooseParseError::MissingField(
            GOOSE_TAG_TIME_ALLOWED_TO_LIVE,
        ))?,
        data_set: data_set.ok_or(GooseParseError::MissingField(GOOSE_TAG_DATA_SET))?,
        go_id,
        timestamp: timestamp.ok_or(GooseParseError::MissingField(GOOSE_TAG_TIMESTAMP))?,
        st_num: st_num.ok_or(GooseParseError::MissingField(GOOSE_TAG_ST_NUM))?,
        sq_num: sq_num.ok_or(GooseParseError::MissingField(GOOSE_TAG_SQ_NUM))?,
        simulation,
        conf_rev: conf_rev.ok_or(GooseParseError::MissingField(GOOSE_TAG_CONF_REV))?,
        nds_com,
        num_dat_set_entries: num_dat_set_entries
            .ok_or(GooseParseError::MissingField(GOOSE_TAG_NUM_DAT_SET_ENTRIES))?,
        all_data: all_data.ok_or(GooseParseError::MissingField(GOOSE_TAG_ALL_DATA))?,
        security,
    })
}

/// Les chaines du PDU sont des VisibleString ASCII ; un octet hors ASCII
/// est rendu tel quel par le decodage UTF-8 permissif.
fn visible_string(value: &[u8]) -> &str {
    match std::str::from_utf8(value) {
        Ok(text) => text,
        Err(error) => std::str::from_utf8(&value[..error.valid_up_to()]).unwrap_or(""),
    }
}

fn parse_all_data(bytes: &[u8]) -> Result<Vec<GooseData<'_>>, GooseParseError> {
    let mut data = Vec::with_capacity(bounded_capacity(32, bytes.len(), 2));
    for element in (Elements { bytes, offset: 0 }) {
        let (tag, value) = element?;
        data.push(GooseData {
            tag,
            kind: DataKind::from_tag(tag),
            value,
        });
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// pcaps_exemple/protocols/goose/iti_GOOSE.pcap, trame 1 : le message
    /// `gcb01` d'un relais GE F650, huit valeurs (tshark 4.6.6). Octets apres
    /// l'EtherType.
    const F650: &str = concat!(
        "0001009100000000618186801a4745446576696365463635302f4c4c4e3024474f2467",
        "636230318103009c4082184745446576696365463635302f4c4c4e3024474f4f534531",
        "830b463635305f474f4f5345318408386ebbf34217280a85010186010a870100880101",
        "8901008a0108ab20830100840303000083010084030300008301008403030000830100",
        "8403030000"
    );

    /// iti_GOOSE_DEMO.pcap, trame 1 : VLAN 10, APPID 0x2000, dix booleens.
    const DEMO: &str = concat!(
        "2000006c0000000061628003313131810500000027108203323232830333333384084d",
        "dda51adbe76d008505000000000186050000000001870100880500000000018901008a",
        "05000000000aab1e830100830100830100830100830100830100830100830100830100",
        "830100"
    );

    #[test]
    fn test_decodes_a_f650_message_against_tshark() {
        let bytes = hex::decode(F650).unwrap();
        assert_eq!(bytes.len(), 145);
        let packet = GoosePacket::try_from(bytes.as_slice()).expect("GOOSE");
        assert_eq!((packet.app_id, packet.length), (1, 145));
        assert_eq!((packet.reserved1, packet.reserved2), (0, 0));
        assert!(!packet.simulation_bit());
        let pdu = &packet.pdu;
        assert_eq!(pdu.gocb_ref, "GEDeviceF650/LLN0$GO$gcb01");
        assert_eq!(pdu.time_allowed_to_live, 40000);
        assert_eq!(pdu.data_set, "GEDeviceF650/LLN0$GOOSE1");
        assert_eq!(pdu.go_id, Some("F650_GOOSE1"));
        // tshark : Jan  2, 2000 02:46:11.258165836 UTC.
        assert_eq!(pdu.timestamp.seconds, 0x386e_bbf3);
        assert_eq!(pdu.timestamp.fraction, 0x421728);
        assert_eq!(pdu.timestamp.nanoseconds(), 258_165_836);
        assert_eq!(pdu.timestamp.quality, 0x0a);
        assert!(!pdu.timestamp.leap_second_known() && !pdu.timestamp.clock_failure());
        assert_eq!((pdu.st_num, pdu.sq_num), (1, 10));
        assert!(!pdu.simulation);
        assert_eq!(pdu.conf_rev, 1);
        assert!(!pdu.nds_com);
        assert_eq!(pdu.num_dat_set_entries, 8);
        assert_eq!(pdu.all_data.len(), 8);
        let kinds: Vec<Option<DataKind>> = pdu.all_data.iter().map(|d| d.kind).collect();
        assert_eq!(
            kinds,
            [
                Some(DataKind::Boolean),
                Some(DataKind::BitString),
                Some(DataKind::Boolean),
                Some(DataKind::BitString),
                Some(DataKind::Boolean),
                Some(DataKind::BitString),
                Some(DataKind::Boolean),
                Some(DataKind::BitString),
            ]
        );
        assert_eq!(pdu.all_data[0].as_bool(), Some(false));
        assert_eq!(pdu.all_data[1].value, &[0x03, 0x00, 0x00]);
        assert_eq!(pdu.all_data[1].as_bool(), None);
        assert_eq!(pdu.security, None);
        assert!(bytes.as_ptr_range().contains(&pdu.gocb_ref.as_ptr()));
    }

    #[test]
    fn test_decodes_the_demo_frame_with_five_byte_integers() {
        let bytes = hex::decode(DEMO).unwrap();
        assert_eq!(bytes.len(), 108);
        let packet = GoosePacket::try_from(bytes.as_slice()).expect("GOOSE");
        assert_eq!(packet.app_id, 0x2000);
        let pdu = &packet.pdu;
        assert_eq!(
            (pdu.gocb_ref, pdu.data_set, pdu.go_id),
            ("111", "222", Some("333"))
        );
        assert_eq!(pdu.time_allowed_to_live, 10000);
        assert_eq!((pdu.st_num, pdu.sq_num, pdu.conf_rev), (1, 1, 1));
        assert_eq!(pdu.num_dat_set_entries, 10);
        assert_eq!(pdu.all_data.len(), 10);
        assert!(pdu.all_data.iter().all(|d| d.as_bool() == Some(false)));
        assert_eq!(pdu.timestamp.seconds, 0x4ddd_a51a);
    }

    #[test]
    fn test_rejections() {
        let bytes = hex::decode(F650).unwrap();
        assert_eq!(
            GoosePacket::try_from(&bytes[..9]),
            Err(GooseParseError::Truncated {
                expected: 10,
                actual: 9
            })
        );
        assert_eq!(
            GoosePacket::try_from(&bytes[..144]),
            Err(GooseParseError::LengthMismatch {
                declared: 145,
                actual: 144
            })
        );
        let mut tag = bytes.clone();
        tag[8] = 0x60;
        assert_eq!(
            GoosePacket::try_from(tag.as_slice()),
            Err(GooseParseError::InvalidPduTag(0x60))
        );
        let mut pdu_len = bytes.clone();
        pdu_len[10] = 0x90;
        assert_eq!(
            GoosePacket::try_from(pdu_len.as_slice()),
            Err(GooseParseError::ElementOverflow {
                tag: 0x61,
                declared: 144,
                available: 134
            })
        );
        let mut shorter_pdu = bytes.clone();
        shorter_pdu[10] = 0x85;
        assert_eq!(
            GoosePacket::try_from(shorter_pdu.as_slice()),
            Err(GooseParseError::UnexpectedTrailingBytes(1))
        );
        // Le gocbRef retire : champ obligatoire manquant.
        let mut no_gocb = bytes.clone();
        no_gocb[11] = 0x8f;
        assert_eq!(
            GoosePacket::try_from(no_gocb.as_slice()),
            Err(GooseParseError::MissingField(GOOSE_TAG_GOCB_REF))
        );
        // Un stNum sur six octets ne tient pas dans la trame reelle sans en
        // decaler le reste : PDU synthetique.
        let mut synthetic = vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x61, 0x00];
        let fields: &[u8] = &[
            0x80, 0x01, b'a', 0x81, 0x01, 0x01, 0x82, 0x01, b'b', 0x84, 0x08, 0, 0, 0, 0, 0, 0, 0,
            0, 0x85, 0x06, 0, 0, 0, 0, 0, 1, 0x86, 0x01, 0x00, 0x88, 0x01, 0x01, 0x8a, 0x01, 0x00,
            0xab, 0x00,
        ];
        synthetic.extend_from_slice(fields);
        synthetic[9] = fields.len() as u8;
        let len = synthetic.len() as u16;
        synthetic[2..4].copy_from_slice(&len.to_be_bytes());
        assert_eq!(
            GoosePacket::try_from(synthetic.as_slice()),
            Err(GooseParseError::IntegerTooLong {
                tag: 0x85,
                length: 6
            })
        );
        // Les huit octets du stNum (offsets 29 a 36) deviennent un stNum de
        // deux octets et un booleen de simulation de deux octets.
        let mut two_byte_bool = synthetic.clone();
        assert_eq!(&two_byte_bool[29..31], &[0x85, 0x06]);
        two_byte_bool[29..37].copy_from_slice(&[0x85, 0x02, 0x00, 0x01, 0x87, 0x02, 0x00, 0x00]);
        assert_eq!(
            GoosePacket::try_from(two_byte_bool.as_slice()),
            Err(GooseParseError::InvalidBoolean {
                tag: 0x87,
                length: 2
            })
        );
        // Les dix octets de l'horodatage (offsets 19 a 28) deviennent un
        // horodatage de six octets suivi d'un element inconnu vide.
        let mut short_timestamp = synthetic.clone();
        assert_eq!(&short_timestamp[19..21], &[0x84, 0x08]);
        short_timestamp[19..29].copy_from_slice(&[0x84, 0x06, 0, 0, 0, 0, 0, 0, 0x8b, 0x00]);
        assert_eq!(
            GoosePacket::try_from(short_timestamp.as_slice()),
            Err(GooseParseError::InvalidTimestamp(6))
        );
    }
}
