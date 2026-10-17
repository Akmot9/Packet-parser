// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! DNP3, Distributed Network Protocol (IEEE 1815) : le protocole SCADA du
//! secteur electrique nord-americain, sur TCP ou UDP 20000 — ou tout autre
//! port, sa signature se suffit : chaque trame de liaison commence par
//! `05 64`, et son en-tete comme chaque bloc de seize octets de donnees
//! utilisateur porte un CRC-16/DNP que le decodeur verifie. C'est ce CRC qui
//! rend le sondage aveugle sur, comme pour S7comm.
//!
//! Trois couches, lues sans etat : la **liaison** (longueur, controle —
//! direction, primaire, bits de comptage, fonction —, adresses de destination
//! et de source) ; le **transport**, un octet en tete des donnees
//! utilisateur (premier, dernier, sequence) ; l'**application**, quand le
//! fragment commence dans cette trame : controle, code de fonction,
//! indications internes des reponses, puis les en-tetes d'objets — groupe,
//! variation, qualificatif, plage ou compte — avec la position de leurs
//! donnees, dont la taille vient de l'annexe A de la norme. Les donnees
//! utilisateur sont recopiees sans leurs CRC dans [`LinkFrame::user_data`] :
//! les CRC coupent les blocs tous les seize octets, un emprunt direct au
//! payload serait discontinu.

use std::{convert::TryFrom, ops::Range};

use crate::{
    checks::application::dnp3::{
        DNP3_APPLICATION_HEADER_LENGTH, DNP3_APPLICATION_RESPONSE_HEADER_LENGTH, DNP3_BLOCK_LENGTH,
        DNP3_CRC_LENGTH, DNP3_FUNCTION_AUTHENTICATION_RESPONSE, DNP3_FUNCTION_RESPONSE,
        DNP3_FUNCTION_UNSOLICITED_RESPONSE, DNP3_LINK_HEADER_LENGTH, ObjectSize, ensure_len,
        extract_length, function_carries_object_data, link_frame_wire_length, object_size,
        validate_block_crc, validate_header_crc, validate_start_bytes,
    },
    errors::application::dnp3::Dnp3ParseError,
    parse::application::protocols::bounded_capacity,
};

/// En-tete de liaison (IEEE 1815-2012 §9.2.4).
///
/// ```mermaid
/// ---
/// title: LinkHeader
/// ---
/// packet-beta
/// 0-15: "Start 0x0564"
/// 16-23: "Length u8"
/// 24-31: "Control u8"
/// 32-47: "Destination u16 LE"
/// 48-63: "Source u16 LE"
/// 64-79: "CRC u16 LE"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct LinkHeader {
    /// Octets apres LENGTH, CRC exclus : 5 plus les donnees utilisateur.
    pub length: u8,
    /// Brut : DIR 0x80, PRM 0x40, FCB 0x20 (ou reserve), FCV 0x10 (ou DFC),
    /// code de fonction sur les quatre bits bas.
    pub control: u8,
    pub destination: u16,
    pub source: u16,
    /// CRC transmis, verifie au decodage.
    pub crc: u16,
}

impl LinkHeader {
    /// DIR : du maitre vers la station (1) ou l'inverse (0).
    pub fn direction_from_master(&self) -> bool {
        self.control & 0x80 != 0
    }

    /// PRM : message d'une station primaire (1) ou secondaire (0).
    pub fn primary(&self) -> bool {
        self.control & 0x40 != 0
    }

    /// FCB, significatif quand `primary` et `frame_count_valid`.
    pub fn frame_count_bit(&self) -> bool {
        self.control & 0x20 != 0
    }

    /// FCV (primaire) ; en secondaire, le meme bit est DFC, controle de flux.
    pub fn frame_count_valid(&self) -> bool {
        self.control & 0x10 != 0
    }

    pub fn function_code(&self) -> u8 {
        self.control & 0x0f
    }

    pub fn function(&self) -> Option<LinkFunction> {
        LinkFunction::from_code(self.primary(), self.function_code())
    }
}

/// Fonctions de liaison (§9.2.4.1.3), selon le sens primaire ou secondaire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LinkFunction {
    // Primaire
    ResetLinkStates,
    TestLinkStates,
    ConfirmedUserData,
    UnconfirmedUserData,
    RequestLinkStatus,
    // Secondaire
    Ack,
    Nack,
    LinkStatus,
    NotSupported,
}

impl LinkFunction {
    pub fn from_code(primary: bool, code: u8) -> Option<Self> {
        Some(match (primary, code) {
            (true, 0) => Self::ResetLinkStates,
            (true, 2) => Self::TestLinkStates,
            (true, 3) => Self::ConfirmedUserData,
            (true, 4) => Self::UnconfirmedUserData,
            (true, 9) => Self::RequestLinkStatus,
            (false, 0) => Self::Ack,
            (false, 1) => Self::Nack,
            (false, 11) => Self::LinkStatus,
            (false, 15) => Self::NotSupported,
            _ => return None,
        })
    }
}

/// En-tete de transport (§8) : un octet en tete des donnees utilisateur.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct TransportHeader {
    pub raw: u8,
}

impl TransportHeader {
    /// FIN : dernier segment du fragment applicatif.
    pub fn is_final(&self) -> bool {
        self.raw & 0x80 != 0
    }

    /// FIR : premier segment du fragment — l'en-tete applicatif suit.
    pub fn is_first(&self) -> bool {
        self.raw & 0x40 != 0
    }

    pub fn sequence(&self) -> u8 {
        self.raw & 0x3f
    }
}

/// En-tete applicatif (§4.2.2) : controle, fonction, et pour les reponses
/// les indications internes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ApplicationHeader {
    /// Brut : FIR 0x80, FIN 0x40, CON 0x20, UNS 0x10, sequence sur quatre
    /// bits.
    pub control: u8,
    pub function_code: u8,
    /// IIN1 puis IIN2 (§4.2.2.8), reponses seulement.
    pub internal_indications: Option<[u8; 2]>,
}

impl ApplicationHeader {
    pub fn is_first(&self) -> bool {
        self.control & 0x80 != 0
    }

    pub fn is_final(&self) -> bool {
        self.control & 0x40 != 0
    }

    /// CON : une confirmation applicative est demandee.
    pub fn confirm_requested(&self) -> bool {
        self.control & 0x20 != 0
    }

    /// UNS : message non sollicite.
    pub fn unsolicited(&self) -> bool {
        self.control & 0x10 != 0
    }

    pub fn sequence(&self) -> u8 {
        self.control & 0x0f
    }

    pub fn function(&self) -> Option<ApplicationFunction> {
        ApplicationFunction::from_code(self.function_code)
    }

    pub fn is_response(&self) -> bool {
        matches!(
            self.function_code,
            DNP3_FUNCTION_RESPONSE
                | DNP3_FUNCTION_UNSOLICITED_RESPONSE
                | DNP3_FUNCTION_AUTHENTICATION_RESPONSE
        )
    }
}

/// Codes de fonction applicatifs (§4.2.2.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ApplicationFunction {
    Confirm,
    Read,
    Write,
    Select,
    Operate,
    DirectOperate,
    DirectOperateNoResponse,
    ImmediateFreeze,
    ImmediateFreezeNoResponse,
    FreezeClear,
    FreezeClearNoResponse,
    FreezeAtTime,
    FreezeAtTimeNoResponse,
    ColdRestart,
    WarmRestart,
    InitializeData,
    InitializeApplication,
    StartApplication,
    StopApplication,
    SaveConfiguration,
    EnableUnsolicited,
    DisableUnsolicited,
    AssignClass,
    DelayMeasure,
    RecordCurrentTime,
    OpenFile,
    CloseFile,
    DeleteFile,
    GetFileInfo,
    AuthenticateFile,
    AbortFile,
    ActivateConfig,
    AuthenticationRequest,
    AuthenticationRequestNoAck,
    Response,
    UnsolicitedResponse,
    AuthenticationResponse,
}

impl ApplicationFunction {
    pub fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0 => Self::Confirm,
            1 => Self::Read,
            2 => Self::Write,
            3 => Self::Select,
            4 => Self::Operate,
            5 => Self::DirectOperate,
            6 => Self::DirectOperateNoResponse,
            7 => Self::ImmediateFreeze,
            8 => Self::ImmediateFreezeNoResponse,
            9 => Self::FreezeClear,
            10 => Self::FreezeClearNoResponse,
            11 => Self::FreezeAtTime,
            12 => Self::FreezeAtTimeNoResponse,
            13 => Self::ColdRestart,
            14 => Self::WarmRestart,
            15 => Self::InitializeData,
            16 => Self::InitializeApplication,
            17 => Self::StartApplication,
            18 => Self::StopApplication,
            19 => Self::SaveConfiguration,
            20 => Self::EnableUnsolicited,
            21 => Self::DisableUnsolicited,
            22 => Self::AssignClass,
            23 => Self::DelayMeasure,
            24 => Self::RecordCurrentTime,
            25 => Self::OpenFile,
            26 => Self::CloseFile,
            27 => Self::DeleteFile,
            28 => Self::GetFileInfo,
            29 => Self::AuthenticateFile,
            30 => Self::AbortFile,
            31 => Self::ActivateConfig,
            32 => Self::AuthenticationRequest,
            33 => Self::AuthenticationRequestNoAck,
            0x81 => Self::Response,
            0x82 => Self::UnsolicitedResponse,
            0x83 => Self::AuthenticationResponse,
            _ => return None,
        })
    }
}

/// Code de prefixe du qualificatif (§4.2.2.7.1, quartet haut).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PrefixCode {
    None,
    /// Chaque objet est precede de son index, sur 1, 2 ou 4 octets.
    Index {
        octets: u8,
    },
    /// Chaque objet est precede de sa taille, sur 1, 2 ou 4 octets.
    Size {
        octets: u8,
    },
    Reserved(u8),
}

impl PrefixCode {
    fn from_code(code: u8) -> Self {
        match code {
            0 => Self::None,
            1 => Self::Index { octets: 1 },
            2 => Self::Index { octets: 2 },
            3 => Self::Index { octets: 4 },
            4 => Self::Size { octets: 1 },
            5 => Self::Size { octets: 2 },
            6 => Self::Size { octets: 4 },
            other => Self::Reserved(other),
        }
    }

    fn octets(self) -> usize {
        match self {
            Self::Index { octets } | Self::Size { octets } => usize::from(octets),
            Self::None | Self::Reserved(_) => 0,
        }
    }
}

/// Plage ou compte d'un en-tete d'objets (§4.2.2.7.1, quartet bas).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RangeSpecifier {
    /// Codes 0 a 2 : index de depart et de fin, inclus.
    StartStop { start: u32, stop: u32, octets: u8 },
    /// Codes 3 a 5 : adresses absolues de depart et de fin.
    Absolute { start: u32, stop: u32, octets: u8 },
    /// Code 6 : tous les objets, aucune donnee.
    All,
    /// Codes 7 a 9 : nombre d'objets, sur 1, 2 ou 4 octets.
    Count { count: u32, octets: u8 },
    /// Code 11 : nombre d'objets sur un octet, objets a taille variable.
    VariableCount { count: u8 },
    /// Codes 10, 12 a 15 : la norme ne les definit pas, le decodeur
    /// s'arrete sur cet en-tete.
    Reserved(u8),
}

impl RangeSpecifier {
    /// Le nombre d'objets que la plage annonce, quand elle en annonce un,
    /// `fin - depart + 1` pour une plage : `None` pour `All` et `Reserved`,
    /// pour une plage inversee, dont la fin precede le depart de plus d'un
    /// index (#181), et pour la plage complete de 0 a `0xFFFFFFFF`, dont les
    /// 2^32 objets ne tiennent pas dans un `u32` (#180). Une fin qui precede
    /// le depart d'un seul index, de 5 a 4, annonce zero objet, comme chez
    /// tshark pour les codes de plage 0 a 2 (il lit les codes 3 a 5 comme une
    /// adresse unique, soit un objet).
    pub fn object_count(&self) -> Option<u32> {
        u32::try_from(self.wide_object_count()?).ok()
    }

    /// Le meme compte sur 64 bits, ou tient celui de la plage complete.
    fn wide_object_count(&self) -> Option<u64> {
        match self {
            Self::StartStop { start, stop, .. } | Self::Absolute { start, stop, .. } => {
                (u64::from(*stop) + 1).checked_sub(u64::from(*start))
            }
            Self::Count { count, .. } => Some(u64::from(*count)),
            Self::VariableCount { count } => Some(u64::from(*count)),
            Self::All | Self::Reserved(_) => None,
        }
    }
}

/// Un en-tete d'objets (§4.2.2.7) et la position de ses donnees dans
/// [`LinkFrame::user_data`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ObjectHeader {
    pub group: u8,
    pub variation: u8,
    /// Le qualificatif brut.
    pub qualifier: u8,
    pub prefix: PrefixCode,
    pub range: RangeSpecifier,
    /// Les octets des objets (prefixes compris), dans `user_data`. Dans une
    /// requete sans donnees d'objets (lecture, gel...), seulement les objets
    /// prefixes de leur taille (lecture d'un bloc de fichier, g70v5
    /// qualificatif `0x5b`) ou, quand le qualificatif prefixe des index, la
    /// liste des index des points demandes (#182) ; rien sinon. Vide aussi
    /// quand la plage n'annonce aucun objet, ou quand les donnees ne se
    /// delimitent pas : elles restent alors dans
    /// [`ApplicationFragment::undecoded`].
    pub data: Range<usize>,
}

/// Le debut d'un fragment applicatif, present quand le segment de transport
/// est le premier (FIR) de son fragment.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ApplicationFragment {
    pub header: ApplicationHeader,
    /// Les en-tetes d'objets decodes, dans l'ordre.
    pub objects: Vec<ObjectHeader>,
    /// Ce qui n'a pas ete decode dans `user_data` : vide quand tout a ete
    /// lu ; sinon ce qui suit un en-tete dont les donnees ne se delimitent
    /// pas — prefixe ou plage reserves, plage inversee (#181), groupe
    /// inconnu qui annonce des objets, donnees ou index manquants, dont ceux
    /// de la plage complete (#180) —, ou la suite d'un fragment coupe par le
    /// transport.
    pub undecoded: Range<usize>,
}

/// Une trame de liaison, ses CRC verifies.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LinkFrame<'a> {
    pub header: LinkHeader,
    /// La trame telle qu'elle est sur le fil, CRC compris.
    pub raw: &'a [u8],
    /// Les donnees utilisateur, CRC retires : au plus 250 octets.
    pub user_data: Vec<u8>,
    /// Absent quand la trame n'a pas de donnees utilisateur (fonctions de
    /// liaison seules).
    pub transport: Option<TransportHeader>,
    /// Present quand le segment de transport est le premier du fragment.
    pub application: Option<ApplicationFragment>,
}

impl LinkFrame<'_> {
    /// Les octets d'un en-tete d'objets.
    pub fn object_data(&self, object: &ObjectHeader) -> &[u8] {
        &self.user_data[object.data.clone()]
    }
}

/// Un payload DNP3 : une ou plusieurs trames de liaison qui le pavent.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Dnp3Packet<'a> {
    pub frames: Vec<LinkFrame<'a>>,
}

impl<'a> TryFrom<&'a [u8]> for Dnp3Packet<'a> {
    type Error = Dnp3ParseError;

    fn try_from(payload: &'a [u8]) -> Result<Self, Self::Error> {
        let first = parse_link_frame(payload)?;
        let mut frames = Vec::with_capacity(bounded_capacity(
            payload.len() / DNP3_LINK_HEADER_LENGTH,
            payload.len(),
            DNP3_LINK_HEADER_LENGTH,
        ));
        let mut offset = first.raw.len();
        frames.push(first);
        while offset < payload.len() {
            let frame = parse_link_frame(&payload[offset..])?;
            offset += frame.raw.len();
            frames.push(frame);
        }
        if offset != payload.len() {
            return Err(Dnp3ParseError::UnexpectedTrailingBytes {
                trailing: payload.len() - offset,
            });
        }
        Ok(Dnp3Packet { frames })
    }
}

fn parse_link_frame(buf: &[u8]) -> Result<LinkFrame<'_>, Dnp3ParseError> {
    ensure_len(buf, DNP3_LINK_HEADER_LENGTH)?;
    validate_start_bytes([buf[0], buf[1]])?;
    let (length, user_len) = extract_length(buf[2])?;
    let crc = u16::from_le_bytes([buf[8], buf[9]]);
    validate_header_crc(buf, crc)?;
    let header = LinkHeader {
        length,
        control: buf[3],
        destination: u16::from_le_bytes([buf[4], buf[5]]),
        source: u16::from_le_bytes([buf[6], buf[7]]),
        crc,
    };
    let wire_len = link_frame_wire_length(user_len);
    ensure_len(buf, wire_len)?;
    let raw = &buf[..wire_len];

    let mut user_data = Vec::with_capacity(user_len);
    let mut offset = DNP3_LINK_HEADER_LENGTH;
    for block in 0.. {
        if user_data.len() == user_len {
            break;
        }
        let block_len = (user_len - user_data.len()).min(DNP3_BLOCK_LENGTH);
        let data = &raw[offset..offset + block_len];
        let crc = u16::from_le_bytes([raw[offset + block_len], raw[offset + block_len + 1]]);
        validate_block_crc(block, data, crc)?;
        user_data.extend_from_slice(data);
        offset += block_len + DNP3_CRC_LENGTH;
    }

    let transport = user_data.first().map(|&raw| TransportHeader { raw });
    let application = match transport {
        Some(transport) if transport.is_first() => Some(parse_application(&user_data[1..], 1)?),
        _ => None,
    };
    Ok(LinkFrame {
        header,
        raw,
        user_data,
        transport,
        application,
    })
}

/// `fragment` commence a l'offset `base` de `user_data`.
fn parse_application(fragment: &[u8], base: usize) -> Result<ApplicationFragment, Dnp3ParseError> {
    if fragment.len() < DNP3_APPLICATION_HEADER_LENGTH {
        return Err(Dnp3ParseError::ApplicationHeaderTooShort {
            actual: fragment.len(),
        });
    }
    let mut header = ApplicationHeader {
        control: fragment[0],
        function_code: fragment[1],
        internal_indications: None,
    };
    let mut offset = DNP3_APPLICATION_HEADER_LENGTH;
    if header.is_response() {
        if fragment.len() < DNP3_APPLICATION_RESPONSE_HEADER_LENGTH {
            return Err(Dnp3ParseError::ApplicationHeaderTooShort {
                actual: fragment.len(),
            });
        }
        header.internal_indications = Some([fragment[2], fragment[3]]);
        offset = DNP3_APPLICATION_RESPONSE_HEADER_LENGTH;
    }

    let with_data = function_carries_object_data(header.function_code);
    let mut objects = Vec::with_capacity(bounded_capacity(8, fragment.len() - offset, 3));
    while offset < fragment.len() {
        let Some((object, complete)) = parse_object_header(fragment, offset, base, with_data)
        else {
            break;
        };
        offset = object.data.end - base;
        objects.push(object);
        if !complete {
            break;
        }
    }
    Ok(ApplicationFragment {
        header,
        objects,
        undecoded: base + offset..base + fragment.len(),
    })
}

/// Un en-tete d'objets a `offset` dans `fragment`, et si la chaine peut
/// continuer apres lui. `None` quand l'en-tete ou sa plage sont coupes ;
/// `(header, false)` quand l'en-tete se lit mais que ses donnees ne se
/// delimitent pas : prefixe ou plage reserves (le qualificatif `0xed` d'un
/// vieux maitre du corpus), plage inversee (#181), groupe inconnu qui
/// annonce des objets, donnees ou index manquants — dont ceux des 2^32
/// objets de la plage complete, de 0 a `0xFFFFFFFF`, qu'aucune trame ne
/// tient (#180). Le decodeur s'arrete alors sur cet en-tete. tshark 4.6.6
/// aussi sur des donnees manquantes, un groupe inconnu qui annonce des
/// objets ou un compte negatif (« Negative number of items »). Il lit en
/// revanche l'en-tete suivant apres une plage reservee (zero objet), un
/// prefixe reserve (objets lus sans prefixe), et une plage de quatre octets
/// dont le compte, calcule sur 32 bits, revient a zero (la plage complete)
/// ou redevient positif (un depart qui depasse la fin de plus de 2^31 + 1,
/// de `0xFFFFFFFF` a 5). A l'inverse, ce compte est negatif pour une plage
/// de 2^31 objets ou plus (de 0 a `0xFFFFFFFE`) : tshark s'arrete, la ou le
/// decodeur continue quand rien ne suit l'en-tete. Il lit enfin les codes
/// de plage 3 a 5 comme une adresse unique.
fn parse_object_header(
    fragment: &[u8],
    offset: usize,
    base: usize,
    with_data: bool,
) -> Option<(ObjectHeader, bool)> {
    let bytes = fragment.get(offset..)?;
    let (&group, &variation, &qualifier) = (bytes.first()?, bytes.get(1)?, bytes.get(2)?);
    // Le prefixe tient sur trois bits, le bit 7 est reserve (§4.2.2.7.1).
    let prefix = PrefixCode::from_code((qualifier >> 4) & 0x07);
    let range_code = qualifier & 0x0f;
    let mut cursor = 3;
    let mut read = |octets: u8| -> Option<u32> {
        let field = bytes.get(cursor..cursor + usize::from(octets))?;
        cursor += usize::from(octets);
        Some(match octets {
            1 => u32::from(field[0]),
            2 => u32::from(u16::from_le_bytes([field[0], field[1]])),
            _ => u32::from_le_bytes([field[0], field[1], field[2], field[3]]),
        })
    };
    let range = match range_code {
        code @ 0..=2 => {
            let octets = 1 << code;
            RangeSpecifier::StartStop {
                start: read(octets)?,
                stop: read(octets)?,
                octets,
            }
        }
        code @ 3..=5 => {
            let octets = 1 << (code - 3);
            RangeSpecifier::Absolute {
                start: read(octets)?,
                stop: read(octets)?,
                octets,
            }
        }
        6 => RangeSpecifier::All,
        code @ 7..=9 => {
            let octets = 1 << (code - 7);
            RangeSpecifier::Count {
                count: read(octets)?,
                octets,
            }
        }
        11 => RangeSpecifier::VariableCount {
            count: read(1)? as u8,
        },
        other => RangeSpecifier::Reserved(other),
    };
    let data_start = base + offset + cursor;
    let mut header = ObjectHeader {
        group,
        variation,
        qualifier,
        prefix,
        range,
        data: data_start..data_start,
    };
    if matches!(range, RangeSpecifier::Reserved(_)) || matches!(prefix, PrefixCode::Reserved(_)) {
        return Some((header, false));
    }
    // Ni champ de plage ni objets.
    if range == RangeSpecifier::All {
        return Some((header, true));
    }
    // Sans compte, la plage est inversee (#181). Celui de la plage complete,
    // 2^32, est compte sur 64 bits : seule la taille de ses donnees decide
    // (#180).
    let Some(count) = range.wide_object_count() else {
        return Some((header, false));
    };
    // Zero objet, de 5 a 4 ou par un compte nul : rien ne suit l'en-tete,
    // quel que soit le groupe, et la chaine continue, comme chez tshark.
    if count == 0 {
        return Some((header, true));
    }
    // Une lecture ne porte pas de donnees d'objets, sauf quand le prefixe
    // de taille en annonce : la lecture d'un bloc de fichier (g70v5,
    // qualificatif 0x5b) transporte l'identifiant et le numero de bloc. Un
    // prefixe d'index y donne la liste des points demandes, sans objets
    // (qualificatifs 0x17, 0x28, 0x39) : le decodeur l'enjambe (#182).
    // tshark aussi dans une lecture ou un gel, sauf pour les variations par
    // defaut et les classes (g1v0, g20v0, g30v0, g60v1...), dont il
    // n'enjambe que le premier index.
    let data_len = if with_data || matches!(prefix, PrefixCode::Size { .. }) {
        object_data_length(bytes, cursor, prefix, group, variation, count)
    } else if let PrefixCode::Index { octets } = prefix {
        index_list_length(bytes, cursor, octets, count)
    } else {
        return Some((header, true));
    };
    let Some(data_len) = data_len else {
        return Some((header, false));
    };
    header.data = data_start..data_start + data_len;
    Some((header, true))
}

/// La longueur de la liste des `count` index de `octets` octets qui suit un
/// en-tete sans objets, a partir de `cursor` dans `bytes`.
fn index_list_length(bytes: &[u8], cursor: usize, octets: u8, count: u64) -> Option<usize> {
    let len = usize::try_from(count.checked_mul(u64::from(octets))?).ok()?;
    (cursor.checked_add(len)? <= bytes.len()).then_some(len)
}

/// La longueur des `count` objets qui suivent un en-tete, prefixes compris,
/// a partir de `cursor` dans `bytes`.
fn object_data_length(
    bytes: &[u8],
    cursor: usize,
    prefix: PrefixCode,
    group: u8,
    variation: u8,
    count: u64,
) -> Option<usize> {
    let data_len = match prefix {
        PrefixCode::Size { octets } => {
            // Chaque objet annonce sa taille : on les enjambe un par un.
            let mut len = 0usize;
            let mut local = cursor;
            for _ in 0..count {
                let size = usize::try_from(read_at(bytes, local, octets)?).ok()?;
                local = local.checked_add(usize::from(octets))?.checked_add(size)?;
                len = local - cursor;
            }
            if bytes.len() < local {
                return None;
            }
            len
        }
        _ => {
            let per_object = match object_size(group, variation)? {
                ObjectSize::Bytes(size) => Some(size),
                ObjectSize::Bits(_) => None,
                ObjectSize::None => Some(0),
                // Sans prefixe de taille, un objet a taille variable n'est
                // pas delimitable.
                ObjectSize::Prefixed => return None,
            };
            // La longueur se calcule sur 64 bits, comme le compte : sur une
            // cible 32 bits aussi, les 2^32 objets de taille nulle de la
            // plage complete tiennent en zero octet (#180).
            let data = match per_object {
                Some(size) => {
                    count.checked_mul(u64::try_from(prefix.octets().checked_add(size)?).ok()?)?
                }
                None => {
                    let ObjectSize::Bits(bits) = object_size(group, variation)? else {
                        return None;
                    };
                    if prefix.octets() != 0 {
                        // Les objets tasses ne sont jamais prefixes.
                        return None;
                    }
                    count.checked_mul(u64::from(bits))?.div_ceil(8)
                }
            };
            let data = usize::try_from(data).ok()?;
            if bytes.len() < cursor.checked_add(data)? {
                return None;
            }
            data
        }
    };
    Some(data_len)
}

fn read_at(bytes: &[u8], offset: usize, octets: u8) -> Option<u32> {
    let field = bytes.get(offset..offset.checked_add(usize::from(octets))?)?;
    Some(match octets {
        1 => u32::from(field[0]),
        2 => u32::from(u16::from_le_bytes([field[0], field[1]])),
        _ => u32::from_le_bytes([field[0], field[1], field[2], field[3]]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// pcaps_exemple/protocols/dnp3/dnp3_read.pcap, trame 4 : lecture des
    /// classes 1, 2, 3 et 0 par le maitre 3 vers la station 2 (tshark 4.6.6).
    const READ_REQUEST: &str = "056414c4020003004503c7c8013c02063c03063c04063c010642ac";

    /// dnp3_link_only.pcap, trames 1 et 2 : demande d'etat de liaison et
    /// sa reponse, sans donnees utilisateur.
    const REQUEST_LINK_STATUS: &str = "05640549640001007e5f";
    const LINK_STATUS: &str = "0564058b01006400a097";

    /// #180 : trames synthetiques dont un en-tete d'objets annonce la plage
    /// complete, de 0 a `0xFFFFFFFF` sur quatre octets (qualificatif `0x02`),
    /// seul ou suivi de la lecture de la classe 0 (g60v1). tshark 4.6.6
    /// compte zero objet et lit chaque fois l'en-tete suivant.
    const FULL_RANGE_RESPONSE: &str = "0564154401000200d976c0c08100001e010200000000ffffffff4424";
    const FULL_RANGE_RESPONSE_THEN_CLASS_0: &str =
        "05641844010002008c14c0c48100001e010200000000ffffffff5dd13c0106277c";
    const FULL_RANGE_READ_THEN_CLASS_0: &str =
        "056416c402000100173ec0c1011e010200000000ffffffff3c018ef4063b4a";
    /// Reponse : plage complete d'objets de taille nulle (g60v1).
    const FULL_RANGE_OF_CLASS_0_THEN_CLASS_0: &str =
        "05641844010002008c14c0c28100003c010200000000ffffffff5a9e3c0106277c";
    /// Lecture prefixee d'index sur un octet (qualificatif `0x12`).
    const FULL_RANGE_INDEX_READ_THEN_CLASS_0: &str =
        "056416c402000100173ec0c8011e011200000000ffffffff3c014418063b4a";

    /// #181 : lectures et reponse synthetiques de plages inversees (g30v1),
    /// puis de la classe 0. tshark 4.6.6 signale 5 a 2 et 10 a 5 sur quatre
    /// octets (« Negative number of items ») et s'arrete ; il compte zero
    /// objet pour 5 a 4 et continue ; de 0xFFFFFFFF a 5, son compte, calcule
    /// sur 32 bits, redevient positif (7 objets) et il continue.
    const INVERTED_RANGE_READ_THEN_CLASS_0: &str = "056410c402000100ce55c0c5011e010005023c01061031";
    const EMPTY_RANGE_READ_THEN_CLASS_0: &str = "056410c402000100ce55c0c0011e010005043c0106f33c";
    const EMPTY_RANGE_RESPONSE_THEN_CLASS_0: &str =
        "0564124401000200e7a8c0c18100001e010005043c01064195";
    const INVERTED_32_BIT_RANGE_READ_THEN_CLASS_0: &str =
        "056416c402000100173ec0c6011e01020a000000050000003c0144b7063b4a";
    const WRAPPED_RANGE_READ_THEN_CLASS_0: &str =
        "056416c402000100173ec0c5011e0102ffffffff050000003c01fade063b4a";
    /// Reponses : plage vide (5 a 4) puis compte nul (qualificatif `0x07`)
    /// d'un groupe inconnu (g200v1), puis la classe 0 ; tshark 4.6.6 compte
    /// zero objet et continue.
    const EMPTY_RANGE_OF_UNKNOWN_GROUP_THEN_CLASS_0: &str =
        "0564124401000200e7a8c0c1810000c8010005043c0106a153";
    const ZERO_COUNT_OF_UNKNOWN_GROUP_THEN_CLASS_0: &str =
        "0564114401000200b73bc0c2810000c80107003c0106cb1d";
    /// Plages d'adresses (codes 3 a 5), que tshark lit comme une adresse
    /// unique : lectures de 5 a 2 et de 5 a 4 (qualificatif `0x03`), reponse
    /// sur la plage complete (`0x05`), chacune suivie de la classe 0.
    const INVERTED_ADDRESS_RANGE_READ_THEN_CLASS_0: &str =
        "056410c402000100ce55c0c3011e010305023c0106feb3";
    const EMPTY_ADDRESS_RANGE_READ_THEN_CLASS_0: &str =
        "056410c402000100ce55c0c4011e010305043c0106a075";
    const FULL_ADDRESS_RANGE_RESPONSE_THEN_CLASS_0: &str =
        "05641844010002008c14c0c58100001e010500000000fffffffff03d3c0106277c";

    /// #182 : requetes synthetiques de points choisis. tshark 4.6.6 enjambe
    /// les index (« Point Number 3 », « Point Number 7 »...) et lit l'en-tete
    /// suivant.
    const READ_BY_INDEX_THEN_CLASS_0: [(&str, u8, u32, &[u8]); 3] = [
        // g30v1, qualificatif 0x17 : index 3 et 7 sur un octet.
        (
            "056411c40200010029e0c0c3011e01170203073c0106d12a",
            0x17,
            2,
            &[3, 7],
        ),
        // Qualificatif 0x28 : index 258 sur deux octets.
        (
            "056412c4020001007973c0c4011e0128010002013c0106d102",
            0x28,
            1,
            &[0x02, 0x01],
        ),
        // Qualificatif 0x39 : index 5 sur quatre octets.
        (
            "056416c402000100173ec0c7011e013901000000050000003c01b5c9063b4a",
            0x39,
            1,
            &[5, 0, 0, 0],
        ),
    ];
    /// Gel immediat de deux compteurs (g20v1, qualificatif `0x17`).
    const FREEZE_BY_INDEX: &str = "05640ec4020001000adcc0c607140117020104824a";
    /// Lecture de deux points choisis en variation par defaut (g30v0,
    /// qualificatif `0x17`, index 3 et 7), puis de la classe 0. tshark 4.6.6
    /// n'enjambe que l'index 3 (« Number of items is invalid for normally
    /// empty object ») et lit la suite comme un en-tete ; le decodeur
    /// enjambe les deux.
    const READ_BY_INDEX_DEFAULT_VARIATION_THEN_CLASS_0: &str =
        "056411c40200010029e0c0c7011e00170203073c0106fb66";
    /// Lecture qui annonce trois index et n'en porte que deux.
    const TRUNCATED_INDEX_LIST: &str = "05640ec4020001000adcc0c9011e01170303078df2";

    /// Un en-tete d'objets decode : groupe, variation, plage et octets de
    /// donnees.
    type DecodedObject = (u8, u8, RangeSpecifier, Vec<u8>);

    /// Les en-tetes d'objets d'une trame synthetique, et ce qui reste non
    /// decode.
    fn decode_objects(hex_frame: &str) -> (Vec<DecodedObject>, Vec<u8>) {
        let bytes = hex::decode(hex_frame).unwrap();
        let packet = Dnp3Packet::try_from(bytes.as_slice()).expect("trame valide");
        let frame = &packet.frames[0];
        let application = frame.application.as_ref().expect("application");
        let objects = application
            .objects
            .iter()
            .map(|o| (o.group, o.variation, o.range, frame.object_data(o).to_vec()))
            .collect();
        (
            objects,
            frame.user_data[application.undecoded.clone()].to_vec(),
        )
    }

    fn start_stop(start: u32, stop: u32, octets: u8) -> RangeSpecifier {
        RangeSpecifier::StartStop {
            start,
            stop,
            octets,
        }
    }

    const CLASS_0: DecodedObject = (60, 1, RangeSpecifier::All, Vec::new());

    #[test]
    fn test_full_range_does_not_overflow_the_object_count() {
        let full = start_stop(0, u32::MAX, 4);
        assert_eq!(hex::decode(FULL_RANGE_RESPONSE).unwrap().len(), 28);
        // Le compte debordait : panique avec les controles de debordement,
        // `Some(0)` en release.
        assert_eq!(full.object_count(), None);
        assert_eq!(
            decode_objects(FULL_RANGE_RESPONSE),
            (vec![(30, 1, full, vec![])], vec![])
        );
        // Les donnees de 2^32 objets de cinq octets ne tiennent pas : la
        // chaine s'arrete, la ou tshark lit la classe 0.
        assert_eq!(
            decode_objects(FULL_RANGE_RESPONSE_THEN_CLASS_0),
            (vec![(30, 1, full, vec![])], vec![60, 1, 0x06])
        );
        // Une lecture sans prefixe ne porte rien apres l'en-tete, et 2^32
        // objets de taille nulle tiennent en zero octet : la chaine
        // continue, comme chez tshark.
        for hex_frame in [
            FULL_RANGE_READ_THEN_CLASS_0,
            FULL_RANGE_OF_CLASS_0_THEN_CLASS_0,
        ] {
            let (objects, undecoded) = decode_objects(hex_frame);
            assert_eq!(objects[0].2, full, "{hex_frame}");
            assert_eq!(objects[1..], [CLASS_0], "{hex_frame}");
            assert!(undecoded.is_empty(), "{hex_frame}");
        }
        // 2^32 index ne tiennent pas non plus.
        let (objects, undecoded) = decode_objects(FULL_RANGE_INDEX_READ_THEN_CLASS_0);
        assert_eq!(objects, vec![(30, 1, full, vec![])]);
        assert_eq!(undecoded, [60, 1, 0x06]);
        // Les plages ordinaires gardent leur compte.
        assert_eq!(start_stop(0, 0, 4).object_count(), Some(1));
        assert_eq!(
            start_stop(0, u32::MAX - 1, 4).object_count(),
            Some(u32::MAX)
        );
    }

    #[test]
    fn test_an_inverted_range_stops_the_chain() {
        let inverted = start_stop(5, 2, 1);
        assert_eq!(inverted.object_count(), None);
        assert_eq!(
            decode_objects(INVERTED_RANGE_READ_THEN_CLASS_0),
            (vec![(30, 1, inverted, vec![])], vec![60, 1, 0x06])
        );
        // De 5 a 4, la plage est vide : zero objet, et la chaine continue
        // dans une lecture comme dans une reponse, comme chez tshark.
        let empty = start_stop(5, 4, 1);
        assert_eq!(empty.object_count(), Some(0));
        for hex_frame in [
            EMPTY_RANGE_READ_THEN_CLASS_0,
            EMPTY_RANGE_RESPONSE_THEN_CLASS_0,
        ] {
            assert_eq!(
                decode_objects(hex_frame),
                (vec![(30, 1, empty, vec![]), CLASS_0], vec![]),
                "{hex_frame}"
            );
        }
        // Sur quatre octets aussi, une plage inversee arrete la chaine. De
        // 10 a 5, tshark compte -4 et s'arrete ; de 0xFFFFFFFF a 5, son
        // compte, calcule sur 32 bits, redevient positif et il continue.
        let inverted_32 = start_stop(10, 5, 4);
        assert_eq!(
            decode_objects(INVERTED_32_BIT_RANGE_READ_THEN_CLASS_0),
            (vec![(30, 1, inverted_32, vec![])], vec![60, 1, 0x06])
        );
        let wrapped = start_stop(u32::MAX, 5, 4);
        assert_eq!(wrapped.object_count(), None);
        assert_eq!(
            decode_objects(WRAPPED_RANGE_READ_THEN_CLASS_0),
            (vec![(30, 1, wrapped, vec![])], vec![60, 1, 0x06])
        );
    }

    #[test]
    fn test_a_header_without_objects_never_stops_the_chain() {
        // Une plage vide ou un compte nul : rien ne suit l'en-tete, meme
        // d'un groupe inconnu, et la chaine continue, comme chez tshark. La
        // 11.6.0 s'arretait sur le compte nul.
        assert_eq!(
            decode_objects(EMPTY_RANGE_OF_UNKNOWN_GROUP_THEN_CLASS_0),
            (vec![(200, 1, start_stop(5, 4, 1), vec![]), CLASS_0], vec![])
        );
        let zero = RangeSpecifier::Count {
            count: 0,
            octets: 1,
        };
        assert_eq!(
            decode_objects(ZERO_COUNT_OF_UNKNOWN_GROUP_THEN_CLASS_0),
            (vec![(200, 1, zero, vec![]), CLASS_0], vec![])
        );
    }

    #[test]
    fn test_address_ranges_are_counted_like_index_ranges() {
        let address = |start, stop, octets| RangeSpecifier::Absolute {
            start,
            stop,
            octets,
        };
        // tshark lit les codes 3 a 5 comme une adresse unique, puis la suite
        // comme un nouvel en-tete ; la crate y lit un depart et une fin.
        assert_eq!(
            decode_objects(INVERTED_ADDRESS_RANGE_READ_THEN_CLASS_0),
            (vec![(30, 1, address(5, 2, 1), vec![])], vec![60, 1, 0x06])
        );
        assert_eq!(address(5, 4, 1).object_count(), Some(0));
        assert_eq!(
            decode_objects(EMPTY_ADDRESS_RANGE_READ_THEN_CLASS_0),
            (vec![(30, 1, address(5, 4, 1), vec![]), CLASS_0], vec![])
        );
        let full = address(0, u32::MAX, 4);
        assert_eq!(full.object_count(), None);
        assert_eq!(
            decode_objects(FULL_ADDRESS_RANGE_RESPONSE_THEN_CLASS_0),
            (vec![(30, 1, full, vec![])], vec![60, 1, 0x06])
        );
    }

    #[test]
    fn test_a_request_by_index_skips_the_index_list() {
        for (hex_frame, qualifier, count, indexes) in READ_BY_INDEX_THEN_CLASS_0 {
            let bytes = hex::decode(hex_frame).unwrap();
            let packet = Dnp3Packet::try_from(bytes.as_slice()).expect("lecture");
            let frame = &packet.frames[0];
            let application = frame.application.as_ref().expect("application");
            assert_eq!(application.objects.len(), 2, "{hex_frame}");
            let points = &application.objects[0];
            assert_eq!(
                (points.group, points.variation, points.qualifier),
                (30, 1, qualifier)
            );
            assert_eq!(points.range.object_count(), Some(count));
            assert_eq!(frame.object_data(points), indexes, "{hex_frame}");
            let class_0 = &application.objects[1];
            assert_eq!((class_0.group, class_0.variation), (60, 1));
            assert!(application.undecoded.is_empty(), "{hex_frame}");
        }
        let count = |count| RangeSpecifier::Count { count, octets: 1 };
        assert_eq!(
            decode_objects(FREEZE_BY_INDEX),
            (vec![(20, 1, count(2), vec![1, 4])], vec![])
        );
        assert_eq!(
            decode_objects(READ_BY_INDEX_DEFAULT_VARIATION_THEN_CLASS_0),
            (vec![(30, 0, count(2), vec![3, 7]), CLASS_0], vec![])
        );
        // Une liste coupee arrete la chaine, et ses index restent non
        // decodes.
        assert_eq!(
            decode_objects(TRUNCATED_INDEX_LIST),
            (vec![(30, 1, count(3), vec![])], vec![3, 7])
        );
    }

    #[test]
    fn test_decodes_a_read_request_against_tshark() {
        let bytes = hex::decode(READ_REQUEST).unwrap();
        assert_eq!(bytes.len(), 27);
        let packet = Dnp3Packet::try_from(bytes.as_slice()).expect("lecture");
        assert_eq!(packet.frames.len(), 1);
        let frame = &packet.frames[0];
        assert_eq!(frame.raw.len(), 27);
        let header = frame.header;
        assert_eq!(header.length, 20);
        assert_eq!(header.control, 0xc4);
        assert!(header.direction_from_master());
        assert!(header.primary());
        assert!(!header.frame_count_bit());
        assert!(!header.frame_count_valid());
        assert_eq!(header.function(), Some(LinkFunction::UnconfirmedUserData));
        assert_eq!((header.destination, header.source), (2, 3));
        assert_eq!(header.crc, 0x0345);
        assert_eq!(frame.user_data.len(), 15);
        let transport = frame.transport.expect("transport");
        assert_eq!(transport.raw, 0xc7);
        assert!(transport.is_first() && transport.is_final());
        assert_eq!(transport.sequence(), 7);
        let application = frame.application.as_ref().expect("application");
        assert_eq!(application.header.control, 0xc8);
        assert!(application.header.is_first() && application.header.is_final());
        assert!(!application.header.confirm_requested());
        assert_eq!(application.header.sequence(), 8);
        assert_eq!(
            application.header.function(),
            Some(ApplicationFunction::Read)
        );
        assert_eq!(application.header.internal_indications, None);
        let objects: Vec<(u8, u8, u8)> = application
            .objects
            .iter()
            .map(|o| (o.group, o.variation, o.qualifier))
            .collect();
        assert_eq!(objects, [(60, 2, 6), (60, 3, 6), (60, 4, 6), (60, 1, 6)]);
        assert!(
            application
                .objects
                .iter()
                .all(|o| o.range == RangeSpecifier::All)
        );
        assert!(application.objects.iter().all(|o| o.data.is_empty()));
        assert!(application.undecoded.is_empty());
    }

    #[test]
    fn test_link_only_frames_and_several_frames_per_payload() {
        let request = hex::decode(REQUEST_LINK_STATUS).unwrap();
        let packet = Dnp3Packet::try_from(request.as_slice()).expect("link status request");
        let frame = &packet.frames[0];
        assert_eq!(frame.header.length, 5);
        assert_eq!(
            frame.header.function(),
            Some(LinkFunction::RequestLinkStatus)
        );
        assert_eq!((frame.header.destination, frame.header.source), (100, 1));
        assert!(frame.user_data.is_empty());
        assert_eq!(frame.transport, None);
        assert_eq!(frame.application, None);

        let status = hex::decode(LINK_STATUS).unwrap();
        let packet = Dnp3Packet::try_from(status.as_slice()).expect("link status");
        let frame = &packet.frames[0];
        // Dans cette capture, la station (port 20000) demande l'etat de la
        // liaison et le maitre (port 1128) repond : DIR porte le sens.
        assert!(!frame.header.primary());
        assert!(frame.header.direction_from_master());
        assert_eq!(frame.header.function(), Some(LinkFunction::LinkStatus));

        let mut both = request.clone();
        both.extend_from_slice(&status);
        let packet = Dnp3Packet::try_from(both.as_slice()).expect("deux trames");
        assert_eq!(packet.frames.len(), 2);
        assert!(both.as_ptr_range().contains(&packet.frames[1].raw.as_ptr()));

        both.push(0x05);
        assert_eq!(
            Dnp3Packet::try_from(both.as_slice()),
            Err(Dnp3ParseError::Truncated {
                expected: 10,
                actual: 1
            })
        );
    }

    /// Reponse synthetique : IIN, un objet g30v3 (32 bits sans drapeau)
    /// en plage 0-1, des entrees binaires tassees g1v1 en plage 0-9, puis
    /// un groupe inconnu : son en-tete est lu, et la chaine s'arrete.
    #[test]
    fn test_response_objects_and_unknown_group() {
        let mut user = vec![0xc0, 0xc1, 0x81, 0x00, 0x00];
        user.extend_from_slice(&[30, 3, 0x00, 0, 1]);
        user.extend_from_slice(&[1, 0, 0, 0, 2, 0, 0, 0]);
        user.extend_from_slice(&[1, 1, 0x00, 0, 9]);
        user.extend_from_slice(&[0b1010_1010, 0b0000_0011]);
        user.extend_from_slice(&[200, 1, 0x00, 0, 0, 0xff]);
        let frame = build_frame(0x44, 1, 100, &user);
        let packet = Dnp3Packet::try_from(frame.as_slice()).expect("reponse");
        let frame = &packet.frames[0];
        let application = frame.application.as_ref().expect("application");
        assert_eq!(
            application.header.function(),
            Some(ApplicationFunction::Response)
        );
        assert_eq!(application.header.internal_indications, Some([0, 0]));
        // Le groupe inconnu : son en-tete est lu, puis la chaine s'arrete.
        assert_eq!(application.objects.len(), 3);
        let analog = &application.objects[0];
        assert_eq!((analog.group, analog.variation), (30, 3));
        assert_eq!(
            analog.range,
            RangeSpecifier::StartStop {
                start: 0,
                stop: 1,
                octets: 1
            }
        );
        assert_eq!(frame.object_data(analog), &[1, 0, 0, 0, 2, 0, 0, 0]);
        let binary = &application.objects[1];
        assert_eq!(binary.range.object_count(), Some(10));
        assert_eq!(frame.object_data(binary), &[0b1010_1010, 0b0000_0011]);
        let unknown = &application.objects[2];
        assert_eq!((unknown.group, unknown.variation), (200, 1));
        assert!(unknown.data.is_empty());
        assert_eq!(&frame.user_data[application.undecoded.clone()], &[0xff]);
    }

    /// Un objet prefixe par sa taille (fichier g70v5, qualificatif 0x5B) et
    /// un objet prefixe par son index (CROB g12v1, 0x28).
    #[test]
    fn test_size_and_index_prefixed_objects() {
        let mut user = vec![0xc0, 0xc5, 0x02];
        user.extend_from_slice(&[70, 5, 0x5b, 1, 4, 0, 0xde, 0xad, 0xbe, 0xef]);
        user.extend_from_slice(&[12, 1, 0x28, 1, 0, 7, 0]);
        user.extend_from_slice(&[0x41, 1, 100, 0, 0, 0, 100, 0, 0, 0, 0]);
        let frame = build_frame(0xc4, 2, 3, &user);
        let packet = Dnp3Packet::try_from(frame.as_slice()).expect("ecriture");
        let application = packet.frames[0].application.as_ref().expect("application");
        assert_eq!(application.objects.len(), 2);
        assert_eq!(
            application.objects[0].range,
            RangeSpecifier::VariableCount { count: 1 }
        );
        assert_eq!(
            packet.frames[0].object_data(&application.objects[0]),
            &[4, 0, 0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(
            application.objects[1].prefix,
            PrefixCode::Index { octets: 2 }
        );
        assert_eq!(
            packet.frames[0].object_data(&application.objects[1]).len(),
            13
        );
        assert!(application.undecoded.is_empty());

        // La meme requete en lecture : des en-tetes sans donnees.
        let mut read = vec![0xc0, 0xc5, 0x01];
        read.extend_from_slice(&[30, 0, 0x01, 0, 0, 9, 0]);
        let frame = build_frame(0xc4, 2, 3, &read);
        let packet = Dnp3Packet::try_from(frame.as_slice()).expect("lecture");
        let application = packet.frames[0].application.as_ref().expect("application");
        assert_eq!(application.objects.len(), 1);
        assert_eq!(application.objects[0].range.object_count(), Some(10));
        assert!(application.objects[0].data.is_empty());
    }

    #[test]
    fn test_rejects_bad_crcs_starts_and_lengths() {
        let bytes = hex::decode(READ_REQUEST).unwrap();
        let mut start = bytes.clone();
        start[1] = 0x65;
        assert_eq!(
            Dnp3Packet::try_from(start.as_slice()),
            Err(Dnp3ParseError::InvalidStartBytes([0x05, 0x65]))
        );
        let mut header_crc = bytes.clone();
        header_crc[4] ^= 0x01;
        assert!(matches!(
            Dnp3Packet::try_from(header_crc.as_slice()),
            Err(Dnp3ParseError::HeaderCrcMismatch { actual: 0x0345, .. })
        ));
        let mut block_crc = bytes.clone();
        block_crc[12] ^= 0x01;
        assert!(matches!(
            Dnp3Packet::try_from(block_crc.as_slice()),
            Err(Dnp3ParseError::BlockCrcMismatch {
                block: 0,
                actual: 0xac42,
                ..
            })
        ));
        let mut short_length = bytes.clone();
        short_length[2] = 4;
        assert_eq!(
            Dnp3Packet::try_from(short_length.as_slice()),
            Err(Dnp3ParseError::InvalidLength(4))
        );
        assert_eq!(
            Dnp3Packet::try_from(&bytes[..26]),
            Err(Dnp3ParseError::Truncated {
                expected: 27,
                actual: 26
            })
        );
        // Un premier segment de transport sans en-tete applicatif.
        let frame = build_frame(0xc4, 2, 3, &[0xc0, 0x01]);
        assert_eq!(
            Dnp3Packet::try_from(frame.as_slice()),
            Err(Dnp3ParseError::ApplicationHeaderTooShort { actual: 1 })
        );
    }

    /// Un segment de transport qui n'est pas le premier : liaison et
    /// transport decodes, pas d'application.
    #[test]
    fn test_continuation_segment_has_no_application() {
        let frame = build_frame(0x44, 1, 100, &[0x81, 1, 2, 3, 4, 5]);
        let packet = Dnp3Packet::try_from(frame.as_slice()).expect("suite");
        let frame = &packet.frames[0];
        let transport = frame.transport.expect("transport");
        assert!(transport.is_final() && !transport.is_first());
        assert_eq!(transport.sequence(), 1);
        assert_eq!(frame.application, None);
        assert_eq!(frame.user_data, [0x81, 1, 2, 3, 4, 5]);
    }

    /// Construit une trame : en-tete, CRC, blocs de seize octets et leurs CRC.
    fn build_frame(control: u8, destination: u16, source: u16, user: &[u8]) -> Vec<u8> {
        use crate::checks::application::dnp3::crc16;
        let mut frame = vec![0x05, 0x64, (user.len() + 5) as u8, control];
        frame.extend_from_slice(&destination.to_le_bytes());
        frame.extend_from_slice(&source.to_le_bytes());
        let crc = crc16(&frame);
        frame.extend_from_slice(&crc.to_le_bytes());
        for block in user.chunks(16) {
            frame.extend_from_slice(block);
            frame.extend_from_slice(&crc16(block).to_le_bytes());
        }
        frame
    }
}
