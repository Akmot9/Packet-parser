// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! IEC 60870-5-104 : la telecommande du secteur electrique europeen, le
//! compagnon de DNP3, sur TCP 2404. Un segment porte un ou plusieurs APDU :
//! chacun commence par `0x68`, une longueur, puis un champ de controle de
//! quatre octets qui dit son format — **I** (numerote, porte un ASDU), **S**
//! (acquittement seul) ou **U** (STARTDT, STOPDT, TESTFR). L'ASDU
//! (IEC 60870-5-101 avec les parametres de la -104) donne le type nomme
//! par [`AsduType`], la cause de transmission, l'adresse commune et ses
//! objets d'information — adresse sur trois octets et element dont la
//! taille vient de la norme, en sequence ou non.
//!
//! Sans etat : un APDU coupe par la segmentation TCP est decode sur ce qui
//! en reste et marque [`Iec104Packet::truncated`] ; un type inconnu laisse
//! ses octets dans [`Asdu::undecoded`]. Garde par le port 2404 : `0x68` et
//! une longueur sont deux octets, trop peu pour sonder tout segment TCP.

use std::convert::TryFrom;

use crate::{
    checks::application::iec104::{
        IEC104_APCI_LENGTH, IEC104_ASDU_HEADER_LENGTH, IEC104_IOA_LENGTH, IEC104_STARTDT_ACT,
        IEC104_STARTDT_CON, IEC104_STOPDT_ACT, IEC104_STOPDT_CON, IEC104_TESTFR_ACT,
        IEC104_TESTFR_CON, element_size, ensure_len, extract_length, validate_asdu_length,
        validate_control_only, validate_object_count, validate_start_byte,
        validate_unnumbered_function,
    },
    errors::application::iec104::Iec104ParseError,
    parse::application::protocols::bounded_capacity,
};

/// Fonction d'un APDU de format U (§5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum UnnumberedFunction {
    StartDtAct,
    StartDtCon,
    StopDtAct,
    StopDtCon,
    TestFrAct,
    TestFrCon,
}

impl UnnumberedFunction {
    fn from_bits(function: u8) -> Option<Self> {
        Some(match function {
            IEC104_STARTDT_ACT => Self::StartDtAct,
            IEC104_STARTDT_CON => Self::StartDtCon,
            IEC104_STOPDT_ACT => Self::StopDtAct,
            IEC104_STOPDT_CON => Self::StopDtCon,
            IEC104_TESTFR_ACT => Self::TestFrAct,
            IEC104_TESTFR_CON => Self::TestFrCon,
            _ => return None,
        })
    }

    /// Les bits de fonction du premier octet de controle.
    pub fn bits(self) -> u8 {
        match self {
            Self::StartDtAct => IEC104_STARTDT_ACT,
            Self::StartDtCon => IEC104_STARTDT_CON,
            Self::StopDtAct => IEC104_STOPDT_ACT,
            Self::StopDtCon => IEC104_STOPDT_CON,
            Self::TestFrAct => IEC104_TESTFR_ACT,
            Self::TestFrCon => IEC104_TESTFR_CON,
        }
    }
}

/// Format du champ de controle (§5).
///
/// ```mermaid
/// ---
/// title: APCI
/// ---
/// packet-beta
/// 0-7: "Start 0x68"
/// 8-15: "Length u8"
/// 16-31: "Control 1-2: N(S) << 1 (I) / format bits (S, U)"
/// 32-47: "Control 3-4: N(R) << 1"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ApciFormat {
    /// Numerote : porte un ASDU.
    Information {
        send_sequence: u16,
        receive_sequence: u16,
    },
    /// Supervision : acquitte seulement.
    Supervisory { receive_sequence: u16 },
    /// Non numerote : controle de la liaison.
    Unnumbered(UnnumberedFunction),
}

/// Types d'ASDU (IEC 60870-5-101 §7.2.1.1), par leur mnemonique : M
/// (information en surveillance), C (commande), P (parametre), F
/// (fichier) ; NA/NB/NC sans horodatage, TA/TB avec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AsduType {
    /// M_SP_NA_1, information simple.
    MSpNa1,
    MSpTa1,
    /// M_DP_NA_1, information double.
    MDpNa1,
    MDpTa1,
    /// M_ST_NA_1, position de prise.
    MStNa1,
    MStTa1,
    /// M_BO_NA_1, chaine de 32 bits.
    MBoNa1,
    MBoTa1,
    /// M_ME_NA_1, mesure normalisee.
    MMeNa1,
    MMeTa1,
    /// M_ME_NB_1, mesure echelonnee.
    MMeNb1,
    MMeTb1,
    /// M_ME_NC_1, mesure flottante.
    MMeNc1,
    MMeTc1,
    /// M_IT_NA_1, totaux integres.
    MItNa1,
    MItTa1,
    MEpTa1,
    MEpTb1,
    MEpTc1,
    MPsNa1,
    MMeNd1,
    /// M_SP_TB_1, information simple avec CP56Time2a.
    MSpTb1,
    MDpTb1,
    MStTb1,
    MBoTb1,
    MMeTd1,
    MMeTe1,
    MMeTf1,
    MItTb1,
    MEpTd1,
    MEpTe1,
    MEpTf1,
    /// C_SC_NA_1, commande simple.
    CScNa1,
    /// C_DC_NA_1, commande double.
    CDcNa1,
    CRcNa1,
    CSeNa1,
    CSeNb1,
    CSeNc1,
    CBoNa1,
    CScTa1,
    CDcTa1,
    CRcTa1,
    CSeTa1,
    CSeTb1,
    CSeTc1,
    CBoTa1,
    /// M_EI_NA_1, fin d'initialisation.
    MEiNa1,
    /// C_IC_NA_1, interrogation.
    CIcNa1,
    CCiNa1,
    CRdNa1,
    /// C_CS_NA_1, synchronisation d'horloge.
    CCsNa1,
    CTsNa1,
    CRpNa1,
    CCdNa1,
    CTsTa1,
    PMeNa1,
    PMeNb1,
    PMeNc1,
    PAcNa1,
    FFrNa1,
    FSrNa1,
    FScNa1,
    FLsNa1,
    FAfNa1,
    FSgNa1,
    FDrTa1,
    FScNb1,
}

impl AsduType {
    pub fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::MSpNa1,
            2 => Self::MSpTa1,
            3 => Self::MDpNa1,
            4 => Self::MDpTa1,
            5 => Self::MStNa1,
            6 => Self::MStTa1,
            7 => Self::MBoNa1,
            8 => Self::MBoTa1,
            9 => Self::MMeNa1,
            10 => Self::MMeTa1,
            11 => Self::MMeNb1,
            12 => Self::MMeTb1,
            13 => Self::MMeNc1,
            14 => Self::MMeTc1,
            15 => Self::MItNa1,
            16 => Self::MItTa1,
            17 => Self::MEpTa1,
            18 => Self::MEpTb1,
            19 => Self::MEpTc1,
            20 => Self::MPsNa1,
            21 => Self::MMeNd1,
            30 => Self::MSpTb1,
            31 => Self::MDpTb1,
            32 => Self::MStTb1,
            33 => Self::MBoTb1,
            34 => Self::MMeTd1,
            35 => Self::MMeTe1,
            36 => Self::MMeTf1,
            37 => Self::MItTb1,
            38 => Self::MEpTd1,
            39 => Self::MEpTe1,
            40 => Self::MEpTf1,
            45 => Self::CScNa1,
            46 => Self::CDcNa1,
            47 => Self::CRcNa1,
            48 => Self::CSeNa1,
            49 => Self::CSeNb1,
            50 => Self::CSeNc1,
            51 => Self::CBoNa1,
            58 => Self::CScTa1,
            59 => Self::CDcTa1,
            60 => Self::CRcTa1,
            61 => Self::CSeTa1,
            62 => Self::CSeTb1,
            63 => Self::CSeTc1,
            64 => Self::CBoTa1,
            70 => Self::MEiNa1,
            100 => Self::CIcNa1,
            101 => Self::CCiNa1,
            102 => Self::CRdNa1,
            103 => Self::CCsNa1,
            104 => Self::CTsNa1,
            105 => Self::CRpNa1,
            106 => Self::CCdNa1,
            107 => Self::CTsTa1,
            110 => Self::PMeNa1,
            111 => Self::PMeNb1,
            112 => Self::PMeNc1,
            113 => Self::PAcNa1,
            120 => Self::FFrNa1,
            121 => Self::FSrNa1,
            122 => Self::FScNa1,
            123 => Self::FLsNa1,
            124 => Self::FAfNa1,
            125 => Self::FSgNa1,
            126 => Self::FDrTa1,
            127 => Self::FScNb1,
            _ => return None,
        })
    }
}

/// Un objet d'information : son adresse et son element, tel quel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct InformationObject<'a> {
    /// Adresse d'objet d'information sur trois octets ; en sequence, celle
    /// du premier objet plus le rang.
    pub address: u32,
    pub element: &'a [u8],
}

/// Un ASDU (IEC 60870-5-101 §7.2, parametres de la -104).
///
/// ```mermaid
/// ---
/// title: Asdu
/// ---
/// packet-beta
/// 0-7: "Type identification u8"
/// 8-15: "SQ (1 bit) + number of objects (7 bits)"
/// 16-23: "Cause of transmission (6 bits) + P/N + T"
/// 24-31: "Originator address u8"
/// 32-47: "Common address u16 LE"
/// 48-71: "Information object address (3 bytes LE)"
/// 72-95: "Information element(s)"
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Asdu<'a> {
    pub type_id: u8,
    pub kind: Option<AsduType>,
    /// SQ : une seule adresse puis des elements contigus.
    pub sequence: bool,
    /// Nombre d'objets ou d'elements annonce.
    pub count: u8,
    /// Cause de transmission, six bits (§7.2.3).
    pub cause: u8,
    /// P/N : confirmation negative.
    pub negative: bool,
    /// T : test.
    pub test: bool,
    pub originator: u8,
    pub common_address: u16,
    pub objects: Vec<InformationObject<'a>>,
    /// Ce qui reste apres les objets lus : vide quand tout est decode ;
    /// sinon un type inconnu, un segment de fichier, ou un APDU coupe.
    pub undecoded: &'a [u8],
}

/// Un APDU : APCI et, en format I, son ASDU.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Apdu<'a> {
    /// Longueur declaree : controle et ASDU, hors les deux premiers octets.
    pub length: u8,
    pub control: [u8; 4],
    pub format: ApciFormat,
    /// `None` pour les formats S et U, et pour un format I que le segment
    /// coupe avant la fin de l'en-tete d'ASDU.
    pub asdu: Option<Asdu<'a>>,
}

/// Un segment TCP : ses APDU, le dernier eventuellement coupe.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Iec104Packet<'a> {
    pub apdus: Vec<Apdu<'a>>,
    /// Le dernier APDU annonce plus que le segment n'en porte.
    pub truncated: bool,
}

impl<'a> TryFrom<&'a [u8]> for Iec104Packet<'a> {
    type Error = Iec104ParseError;

    fn try_from(payload: &'a [u8]) -> Result<Self, Self::Error> {
        let mut apdus = Vec::with_capacity(bounded_capacity(8, payload.len(), IEC104_APCI_LENGTH));
        let mut truncated = false;
        let mut offset = 0;
        while offset < payload.len() {
            let rest = &payload[offset..];
            ensure_len(rest, IEC104_APCI_LENGTH)?;
            validate_start_byte(rest[0])?;
            let length = extract_length(rest[1])?;
            let declared_end = 2 + usize::from(length);
            let end = declared_end.min(rest.len());
            truncated = declared_end > rest.len();
            apdus.push(parse_apdu(length, &rest[2..end], truncated)?);
            offset += end;
        }
        if apdus.is_empty() {
            return Err(Iec104ParseError::Truncated {
                expected: IEC104_APCI_LENGTH,
                actual: 0,
            });
        }
        Ok(Iec104Packet { apdus, truncated })
    }
}

/// `body` : le champ de controle et l'ASDU present ; `truncated` quand le
/// segment coupe l'APDU, auquel cas un ASDU dont l'en-tete manque reste
/// `None` au lieu d'etre une erreur.
fn parse_apdu(length: u8, body: &[u8], truncated: bool) -> Result<Apdu<'_>, Iec104ParseError> {
    let control = [body[0], body[1], body[2], body[3]];
    let receive_sequence = u16::from_le_bytes([control[2], control[3]]) >> 1;
    let (format, asdu) = match control[0] & 0x03 {
        0x01 => {
            validate_control_only("S", length)?;
            (ApciFormat::Supervisory { receive_sequence }, None)
        }
        0x03 => {
            validate_control_only("U", length)?;
            let function = validate_unnumbered_function(control[0])?;
            let function = UnnumberedFunction::from_bits(function)
                .ok_or(Iec104ParseError::InvalidUnnumberedFunction(control[0]))?;
            (ApciFormat::Unnumbered(function), None)
        }
        _ => {
            let send_sequence = u16::from_le_bytes([control[0], control[1]]) >> 1;
            let asdu = if truncated && body.len() - 4 < IEC104_ASDU_HEADER_LENGTH {
                None
            } else {
                Some(parse_asdu(&body[4..])?)
            };
            (
                ApciFormat::Information {
                    send_sequence,
                    receive_sequence,
                },
                asdu,
            )
        }
    };
    Ok(Apdu {
        length,
        control,
        format,
        asdu,
    })
}

fn parse_asdu(bytes: &[u8]) -> Result<Asdu<'_>, Iec104ParseError> {
    validate_asdu_length(bytes.len())?;
    let type_id = bytes[0];
    let sequence = bytes[1] & 0x80 != 0;
    let count = bytes[1] & 0x7f;
    validate_object_count(type_id, count)?;
    let mut asdu = Asdu {
        type_id,
        kind: AsduType::from_code(type_id),
        sequence,
        count,
        cause: bytes[2] & 0x3f,
        negative: bytes[2] & 0x40 != 0,
        test: bytes[2] & 0x80 != 0,
        originator: bytes[3],
        common_address: u16::from_le_bytes([bytes[4], bytes[5]]),
        objects: Vec::new(),
        undecoded: &bytes[IEC104_ASDU_HEADER_LENGTH..],
    };
    let Some(size) = element_size(type_id) else {
        return Ok(asdu);
    };
    let objects_bytes = &bytes[IEC104_ASDU_HEADER_LENGTH..];
    let mut objects = Vec::with_capacity(bounded_capacity(
        usize::from(count),
        objects_bytes.len(),
        (size + IEC104_IOA_LENGTH).max(1),
    ));
    let mut offset = 0;
    if sequence {
        // Une adresse, puis `count` elements contigus.
        if objects_bytes.len() >= IEC104_IOA_LENGTH {
            let base = ioa(objects_bytes);
            offset = IEC104_IOA_LENGTH;
            for rank in 0..u32::from(count) {
                let Some(element) = objects_bytes.get(offset..offset + size) else {
                    break;
                };
                objects.push(InformationObject {
                    address: base + rank,
                    element,
                });
                offset += size;
            }
        }
    } else {
        for _ in 0..count {
            let Some(object) = objects_bytes.get(offset..offset + IEC104_IOA_LENGTH + size) else {
                break;
            };
            objects.push(InformationObject {
                address: ioa(object),
                element: &object[IEC104_IOA_LENGTH..],
            });
            offset += IEC104_IOA_LENGTH + size;
        }
    }
    asdu.objects = objects;
    asdu.undecoded = &objects_bytes[offset..];
    Ok(asdu)
}

fn ioa(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// pcaps_exemple/protocols/iec104/wireshark_iec104.pcap, trames 4, 5, 7
    /// et 8 : TESTFR et STARTDT, activation et confirmation (tshark 4.6.6).
    const TESTFR_ACT: &str = "680443000000";
    const TESTFR_CON: &str = "680483000000";
    const STARTDT_ACT: &str = "680407000000";
    const STARTDT_CON: &str = "68040b000000";
    /// Trame 9 : interrogation generale (C_IC_NA_1, QOI 20) de la station 10.
    const INTERROGATION: &str = "680e00000000640106000a0000000014";
    /// Trame 10 : fin d'initialisation (M_EI_NA_1), cause 4.
    const END_OF_INIT: &str = "680e00000000460104000a0000000000";
    /// Trame 20 : commande simple (C_SC_NA_1) sur l'objet 2, N(S) 2, N(R) 33.
    const SINGLE_COMMAND: &str = "680e040042002d0106000a0002000001";
    /// wireshark_IEC104_SQ.pcapng, trame 1 : tete du segment, un ASDU
    /// M_SP_NA_1 en sequence de seize informations simples, puis un second
    /// APDU coupe pour la graine.
    const SEQUENCE: &str =
        "681d02000200019014001e0400000000000000000000000000000000000101681d040002000190";

    #[test]
    fn test_unnumbered_apdus_against_tshark() {
        for (hex, function) in [
            (TESTFR_ACT, UnnumberedFunction::TestFrAct),
            (TESTFR_CON, UnnumberedFunction::TestFrCon),
            (STARTDT_ACT, UnnumberedFunction::StartDtAct),
            (STARTDT_CON, UnnumberedFunction::StartDtCon),
        ] {
            let bytes = hex::decode(hex).unwrap();
            let packet = Iec104Packet::try_from(bytes.as_slice()).expect(hex);
            assert_eq!(packet.apdus.len(), 1);
            assert!(!packet.truncated);
            let apdu = &packet.apdus[0];
            assert_eq!(apdu.length, 4);
            assert_eq!(apdu.format, ApciFormat::Unnumbered(function));
            assert_eq!(apdu.asdu, None);
            assert_eq!(function.bits(), apdu.control[0] & 0xfc);
        }
    }

    #[test]
    fn test_information_apdus_against_tshark() {
        let bytes = hex::decode(INTERROGATION).unwrap();
        let packet = Iec104Packet::try_from(bytes.as_slice()).expect("interrogation");
        let apdu = &packet.apdus[0];
        assert_eq!(apdu.length, 14);
        assert_eq!(
            apdu.format,
            ApciFormat::Information {
                send_sequence: 0,
                receive_sequence: 0
            }
        );
        let asdu = apdu.asdu.as_ref().expect("ASDU");
        assert_eq!((asdu.type_id, asdu.kind), (100, Some(AsduType::CIcNa1)));
        assert!(!asdu.sequence);
        assert_eq!((asdu.count, asdu.cause, asdu.originator), (1, 6, 0));
        assert!(!asdu.negative && !asdu.test);
        assert_eq!(asdu.common_address, 10);
        assert_eq!(
            asdu.objects,
            [InformationObject {
                address: 0,
                element: &[20]
            }]
        );
        assert!(asdu.undecoded.is_empty());

        let bytes = hex::decode(END_OF_INIT).unwrap();
        let packet = Iec104Packet::try_from(bytes.as_slice()).expect("fin d'init");
        let asdu = packet.apdus[0].asdu.as_ref().unwrap();
        assert_eq!((asdu.kind, asdu.cause), (Some(AsduType::MEiNa1), 4));
        assert_eq!(asdu.objects[0].element, &[0]);

        let bytes = hex::decode(SINGLE_COMMAND).unwrap();
        let packet = Iec104Packet::try_from(bytes.as_slice()).expect("commande");
        let apdu = &packet.apdus[0];
        assert_eq!(
            apdu.format,
            ApciFormat::Information {
                send_sequence: 2,
                receive_sequence: 33
            }
        );
        let asdu = apdu.asdu.as_ref().unwrap();
        assert_eq!(asdu.kind, Some(AsduType::CScNa1));
        assert_eq!(asdu.objects[0].address, 2);
        assert_eq!(asdu.objects[0].element, &[0x01]);
    }

    #[test]
    fn test_sequence_and_truncated_second_apdu() {
        let bytes = hex::decode(SEQUENCE).unwrap();
        let packet = Iec104Packet::try_from(bytes.as_slice()).expect("sequence");
        assert_eq!(packet.apdus.len(), 2);
        assert!(packet.truncated);
        let first = &packet.apdus[0];
        assert_eq!(first.length, 29);
        assert_eq!(
            first.format,
            ApciFormat::Information {
                send_sequence: 1,
                receive_sequence: 1
            }
        );
        let asdu = first.asdu.as_ref().unwrap();
        assert_eq!(asdu.kind, Some(AsduType::MSpNa1));
        assert!(asdu.sequence);
        assert_eq!(
            (asdu.count, asdu.cause, asdu.common_address),
            (16, 20, 1054)
        );
        assert_eq!(asdu.objects.len(), 16);
        assert_eq!(
            asdu.objects.iter().map(|o| o.address).collect::<Vec<_>>(),
            (0..16).collect::<Vec<u32>>()
        );
        assert_eq!(asdu.objects[15].element, &[0x01]);
        assert_eq!(asdu.objects[0].element, &[0x00]);
        assert!(asdu.undecoded.is_empty());
        // Le second APDU : controle lu, ASDU coupe avant son en-tete.
        let second = &packet.apdus[1];
        assert_eq!(second.length, 29);
        assert!(matches!(
            second.format,
            ApciFormat::Information {
                send_sequence: 2,
                ..
            }
        ));
        assert_eq!(second.asdu, None);
    }

    #[test]
    fn test_supervisory_unknown_type_and_rejections() {
        let supervisory = [0x68, 0x04, 0x01, 0x00, 0x42, 0x00];
        let packet = Iec104Packet::try_from(&supervisory[..]).expect("S");
        assert_eq!(
            packet.apdus[0].format,
            ApciFormat::Supervisory {
                receive_sequence: 33
            }
        );

        // Un type inconnu : en-tete lu, objets non decodes.
        let unknown = [
            0x68, 0x0a, 0x00, 0x00, 0x00, 0x00, 200, 0x01, 0x03, 0x00, 0x0a, 0x00,
        ];
        let packet = Iec104Packet::try_from(&unknown[..]).expect("type inconnu");
        let asdu = packet.apdus[0].asdu.as_ref().unwrap();
        assert_eq!((asdu.type_id, asdu.kind), (200, None));
        assert!(asdu.objects.is_empty());

        let bytes = hex::decode(INTERROGATION).unwrap();
        let mut start = bytes.clone();
        start[0] = 0x69;
        assert_eq!(
            Iec104Packet::try_from(start.as_slice()),
            Err(Iec104ParseError::InvalidStartByte(0x69))
        );
        let mut length = bytes.clone();
        length[1] = 3;
        assert_eq!(
            Iec104Packet::try_from(length.as_slice()),
            Err(Iec104ParseError::InvalidLength(3))
        );
        let mut function = hex::decode(STARTDT_ACT).unwrap();
        function[2] = 0x0f;
        assert_eq!(
            Iec104Packet::try_from(function.as_slice()),
            Err(Iec104ParseError::InvalidUnnumberedFunction(0x0f))
        );
        let mut long_u = hex::decode(STARTDT_ACT).unwrap();
        long_u[1] = 5;
        long_u.push(0);
        assert_eq!(
            Iec104Packet::try_from(long_u.as_slice()),
            Err(Iec104ParseError::ControlOnlyFormat {
                format: "U",
                length: 5
            })
        );
        let mut empty = bytes.clone();
        empty[7] = 0x00;
        assert_eq!(
            Iec104Packet::try_from(empty.as_slice()),
            Err(Iec104ParseError::EmptyAsdu(100))
        );
        assert_eq!(
            Iec104Packet::try_from(&bytes[..5]),
            Err(Iec104ParseError::Truncated {
                expected: 6,
                actual: 5
            })
        );
        // Deux APDU complets dans un segment.
        let mut both = hex::decode(STARTDT_ACT).unwrap();
        both.extend_from_slice(&bytes);
        let packet = Iec104Packet::try_from(both.as_slice()).expect("deux APDU");
        assert_eq!(packet.apdus.len(), 2);
        assert!(!packet.truncated);
        assert!(
            both.as_ptr_range().contains(
                &packet.apdus[1].asdu.as_ref().unwrap().objects[0]
                    .element
                    .as_ptr()
            )
        );
    }
}
