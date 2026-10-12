// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! DIS, Distributed Interactive Simulation (IEEE 1278.1) : le protocole qui
//! relie les simulateurs militaires — position des entites, tirs, radios
//! simulees, environnement. Les formats de PDU sont decrits librement par
//! le projet Open-DIS et les enumerations par SISO-REF-010.
//!
//! Un datagramme UDP porte un ou plusieurs PDU, chacun introduit par un
//! en-tete de douze octets : version (1 a 7), identifiant d'exercice, type
//! (1 a 72), famille, horodatage, longueur, puis bourrage ou, en version 7,
//! le PDU Status. Le decodeur identifie chaque PDU et decode en valeurs
//! typees les Entity State, Transmitter et Signal ; les autres corps
//! restent en octets.
//!
//! Deux lectures : [`DisPacket::try_from`] exige que les PDU pavent
//! exactement le datagramme — c'est la signature de la sonde aveugle, DIS
//! n'ayant pas de port IANA (3000 par usage, 6993 et 22999 dans le corpus) ;
//! [`DisPacket::try_from_lenient`], derriere le port 3000 ou un port declare
//! par Decode As, accepte une longueur declaree plus courte que le
//! datagramme et garde le reste dans [`DisPacket::trailing`] — trois PDU
//! reels du corpus annoncent 48 octets pour 160, et tshark les disseque
//! sans s'arreter a la longueur.

use std::convert::TryFrom;

use crate::{
    checks::application::dis::{
        DIS_ENTITY_STATE_FIXED_LENGTH, DIS_HEADER_LENGTH, DIS_PDU_ENTITY_STATE, DIS_PDU_SIGNAL,
        DIS_PDU_TRANSMITTER, DIS_SIGNAL_FIXED_LENGTH, DIS_TRANSMITTER_FIXED_LENGTH,
        DIS_VARIABLE_PARAMETER_LENGTH, DIS_VERSION_2012, ensure_len, extract_length,
        extract_pdu_type, extract_protocol_family, extract_version, validate_body_length,
    },
    errors::application::dis::DisParseError,
    parse::application::protocols::bounded_capacity,
};

/// En-tete d'un PDU (IEEE 1278.1-2012, §6.2.66).
///
/// ```mermaid
/// ---
/// title: DisHeader
/// ---
/// packet-beta
/// 0-7: "protocolVersion u8"
/// 8-15: "exerciseId u8"
/// 16-23: "pduType u8"
/// 24-31: "protocolFamily u8"
/// 32-63: "timestamp u32"
/// 64-79: "length u16"
/// 80-87: "pduStatus u8 (v7) / padding"
/// 88-95: "padding u8"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct DisHeader {
    pub protocol_version: u8,
    pub exercise_id: u8,
    pub pdu_type: u8,
    pub protocol_family: u8,
    /// Horodatage brut : 31 bits de temps en 1/2^31 heure, et le bit de
    /// poids faible a un pour un temps absolu.
    pub timestamp: u32,
    /// Longueur declaree du PDU, en-tete compris.
    pub length: u16,
    /// PDU Status (version 7) ; bourrage avant.
    pub pdu_status: u8,
    pub padding: u8,
}

impl DisHeader {
    /// Horodatage absolu (bit 0) ou relatif.
    pub fn absolute_timestamp(&self) -> bool {
        self.timestamp & 0x01 != 0
    }

    /// Les 31 bits de temps, en unites de 1/2^31 heure.
    pub fn timestamp_units(&self) -> u32 {
        self.timestamp >> 1
    }

    /// Le PDU Status n'existe qu'en version 7.
    pub fn status(&self) -> Option<u8> {
        (self.protocol_version >= DIS_VERSION_2012).then_some(self.pdu_status)
    }
}

/// Type de PDU (IEEE 1278.1-2012, SISO-REF-010 « PDU Type »).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PduType {
    EntityState,
    Fire,
    Detonation,
    Collision,
    ServiceRequest,
    ResupplyOffer,
    ResupplyReceived,
    ResupplyCancel,
    RepairComplete,
    RepairResponse,
    CreateEntity,
    RemoveEntity,
    StartResume,
    StopFreeze,
    Acknowledge,
    ActionRequest,
    ActionResponse,
    DataQuery,
    SetData,
    Data,
    EventReport,
    Comment,
    ElectromagneticEmission,
    Designator,
    Transmitter,
    Signal,
    Receiver,
    Iff,
    UnderwaterAcoustic,
    SupplementalEmissionEntityState,
    IntercomSignal,
    IntercomControl,
    AggregateState,
    IsGroupOf,
    TransferOwnership,
    IsPartOf,
    MinefieldState,
    MinefieldQuery,
    MinefieldData,
    MinefieldResponseNack,
    EnvironmentalProcess,
    GriddedData,
    PointObjectState,
    LinearObjectState,
    ArealObjectState,
    Tspi,
    Appearance,
    ArticulatedParts,
    LeFire,
    LeDetonation,
    CreateEntityReliable,
    RemoveEntityReliable,
    StartResumeReliable,
    StopFreezeReliable,
    AcknowledgeReliable,
    ActionRequestReliable,
    ActionResponseReliable,
    DataQueryReliable,
    SetDataReliable,
    DataReliable,
    EventReportReliable,
    CommentReliable,
    RecordReliable,
    SetRecordReliable,
    RecordQueryReliable,
    CollisionElastic,
    EntityStateUpdate,
    DirectedEnergyFire,
    EntityDamageStatus,
    InformationOperationsAction,
    InformationOperationsReport,
    Attribute,
}

impl PduType {
    fn from_code(code: u8) -> Option<Self> {
        const TYPES: [PduType; 72] = [
            PduType::EntityState,
            PduType::Fire,
            PduType::Detonation,
            PduType::Collision,
            PduType::ServiceRequest,
            PduType::ResupplyOffer,
            PduType::ResupplyReceived,
            PduType::ResupplyCancel,
            PduType::RepairComplete,
            PduType::RepairResponse,
            PduType::CreateEntity,
            PduType::RemoveEntity,
            PduType::StartResume,
            PduType::StopFreeze,
            PduType::Acknowledge,
            PduType::ActionRequest,
            PduType::ActionResponse,
            PduType::DataQuery,
            PduType::SetData,
            PduType::Data,
            PduType::EventReport,
            PduType::Comment,
            PduType::ElectromagneticEmission,
            PduType::Designator,
            PduType::Transmitter,
            PduType::Signal,
            PduType::Receiver,
            PduType::Iff,
            PduType::UnderwaterAcoustic,
            PduType::SupplementalEmissionEntityState,
            PduType::IntercomSignal,
            PduType::IntercomControl,
            PduType::AggregateState,
            PduType::IsGroupOf,
            PduType::TransferOwnership,
            PduType::IsPartOf,
            PduType::MinefieldState,
            PduType::MinefieldQuery,
            PduType::MinefieldData,
            PduType::MinefieldResponseNack,
            PduType::EnvironmentalProcess,
            PduType::GriddedData,
            PduType::PointObjectState,
            PduType::LinearObjectState,
            PduType::ArealObjectState,
            PduType::Tspi,
            PduType::Appearance,
            PduType::ArticulatedParts,
            PduType::LeFire,
            PduType::LeDetonation,
            PduType::CreateEntityReliable,
            PduType::RemoveEntityReliable,
            PduType::StartResumeReliable,
            PduType::StopFreezeReliable,
            PduType::AcknowledgeReliable,
            PduType::ActionRequestReliable,
            PduType::ActionResponseReliable,
            PduType::DataQueryReliable,
            PduType::SetDataReliable,
            PduType::DataReliable,
            PduType::EventReportReliable,
            PduType::CommentReliable,
            PduType::RecordReliable,
            PduType::SetRecordReliable,
            PduType::RecordQueryReliable,
            PduType::CollisionElastic,
            PduType::EntityStateUpdate,
            PduType::DirectedEnergyFire,
            PduType::EntityDamageStatus,
            PduType::InformationOperationsAction,
            PduType::InformationOperationsReport,
            PduType::Attribute,
        ];
        TYPES.get(usize::from(code).checked_sub(1)?).copied()
    }
}

/// Identifiant d'entite (§6.2.28) : site, application, entite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct EntityId {
    pub site: u16,
    pub application: u16,
    pub entity: u16,
}

impl EntityId {
    fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            site: u16::from_be_bytes([bytes[0], bytes[1]]),
            application: u16::from_be_bytes([bytes[2], bytes[3]]),
            entity: u16::from_be_bytes([bytes[4], bytes[5]]),
        }
    }
}

/// Type d'entite (§6.2.30) : les sept champs de l'enumeration SISO.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct EntityType {
    pub kind: u8,
    pub domain: u8,
    pub country: u16,
    pub category: u8,
    pub subcategory: u8,
    pub specific: u8,
    pub extra: u8,
}

impl EntityType {
    fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            kind: bytes[0],
            domain: bytes[1],
            country: u16::from_be_bytes([bytes[2], bytes[3]]),
            category: bytes[4],
            subcategory: bytes[5],
            specific: bytes[6],
            extra: bytes[7],
        }
    }
}

/// Type de modulation d'un emetteur (§6.2.59) : etalement de spectre,
/// modulation majeure, detail, systeme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ModulationType {
    /// Bits : 0 saut de frequence, 1 pseudo-bruit, 2 saut temporel.
    pub spread_spectrum: u16,
    pub major: u16,
    pub detail: u16,
    pub system: u16,
}

/// Vecteur de trois flottants simple precision.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct Vector3 {
    pub x: f32,
    pub y: f32,
    pub z: f32,
}

/// Coordonnees geocentriques en double precision (§6.2.98), en metres.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct WorldCoordinates {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

fn f32_at(bytes: &[u8], offset: usize) -> f32 {
    f32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn f64_at(bytes: &[u8], offset: usize) -> f64 {
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&bytes[offset..offset + 8]);
    f64::from_be_bytes(raw)
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

/// Corps d'un PDU, selon son type.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum DisBody<'a> {
    /// Entity State (§7.2.2) : position et apparence d'une entite.
    EntityState {
        entity_id: EntityId,
        force_id: u8,
        /// Nombre de parametres d'articulation ou d'attache qui suivent.
        variable_parameter_count: u8,
        entity_type: EntityType,
        alternative_entity_type: EntityType,
        /// Metres par seconde.
        linear_velocity: Vector3,
        location: WorldCoordinates,
        /// Angles d'Euler psi, theta, phi, en radians.
        orientation: Vector3,
        appearance: u32,
        /// Algorithme de dead reckoning (premier octet des parametres).
        dead_reckoning_algorithm: u8,
        /// Jeu de caracteres puis onze octets de marquage.
        marking: [u8; 12],
        capabilities: u32,
        /// Les parametres variables, seize octets chacun.
        variable_parameters: &'a [u8],
    },
    /// Transmitter (§7.7.2) : etat d'un emetteur radio simule.
    Transmitter {
        entity_id: EntityId,
        radio_id: u16,
        radio_entity_type: EntityType,
        /// 0 off, 1 allume sans emettre, 2 en emission.
        transmit_state: u8,
        input_source: u8,
        /// Version 7 : nombre de parametres variables de l'emetteur ;
        /// bourrage avant.
        variable_parameter_count: u16,
        antenna_location: WorldCoordinates,
        relative_antenna_location: Vector3,
        antenna_pattern_type: u16,
        antenna_pattern_length: u16,
        frequency_hz: u64,
        bandwidth_hz: f32,
        /// Decibels-milliwatts.
        power_dbm: f32,
        modulation_type: ModulationType,
        crypto_system: u16,
        crypto_key_id: u16,
        modulation_parameter_length: u8,
    },
    /// Signal (§7.7.3) : des echantillons audio ou des donnees radio.
    Signal {
        entity_id: EntityId,
        radio_id: u16,
        encoding_scheme: u16,
        tdl_type: u16,
        sample_rate: u32,
        /// En bits.
        data_length: u16,
        samples: u16,
        /// Les donnees, bourrage de fin compris.
        data: &'a [u8],
    },
    /// Tout autre type : corps brut, en-tete exclu.
    Opaque(&'a [u8]),
}

/// Un PDU : son en-tete, son type nomme et son corps.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct DisPdu<'a> {
    pub header: DisHeader,
    pub pdu_type: PduType,
    pub body: DisBody<'a>,
    /// Le PDU entier, en-tete compris, tel que sa longueur le delimite.
    pub raw: &'a [u8],
}

/// Un datagramme DIS : ses PDU, dans l'ordre du wire.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct DisPacket<'a> {
    pub pdus: Vec<DisPdu<'a>>,
    /// Octets apres le dernier PDU qui ne forment pas un PDU : vide par
    /// [`DisPacket::try_from`], possible par [`DisPacket::try_from_lenient`]
    /// quand la longueur declaree est fausse.
    pub trailing: &'a [u8],
}

impl<'a> TryFrom<&'a [u8]> for DisPacket<'a> {
    type Error = DisParseError;

    /// Lecture stricte : les PDU pavent exactement le datagramme.
    fn try_from(payload: &'a [u8]) -> Result<Self, Self::Error> {
        let packet = Self::parse(payload)?;
        if !packet.trailing.is_empty() {
            return Err(DisParseError::UnexpectedTrailingBytes {
                trailing: packet.trailing.len(),
            });
        }
        Ok(packet)
    }
}

impl<'a> DisPacket<'a> {
    /// Lecture tolerante : au moins un PDU, et le reste du datagramme garde
    /// dans `trailing` s'il ne forme pas un PDU. Pour un port qui dit deja
    /// que c'est du DIS.
    pub fn try_from_lenient(payload: &'a [u8]) -> Result<Self, DisParseError> {
        Self::parse(payload)
    }

    fn parse(payload: &'a [u8]) -> Result<Self, DisParseError> {
        let first = parse_pdu(payload)?;
        let mut pdus = Vec::with_capacity(bounded_capacity(
            payload.len() / DIS_HEADER_LENGTH,
            payload.len(),
            DIS_HEADER_LENGTH,
        ));
        let mut offset = first.raw.len();
        pdus.push(first);
        while offset < payload.len() {
            let Ok(pdu) = parse_pdu(&payload[offset..]) else {
                break;
            };
            offset += pdu.raw.len();
            pdus.push(pdu);
        }
        Ok(DisPacket {
            pdus,
            trailing: &payload[offset..],
        })
    }
}

fn parse_pdu(buf: &[u8]) -> Result<DisPdu<'_>, DisParseError> {
    ensure_len(buf, DIS_HEADER_LENGTH)?;
    let protocol_version = extract_version(buf[0])?;
    let pdu_type_code = extract_pdu_type(buf[2])?;
    let pdu_type =
        PduType::from_code(pdu_type_code).ok_or(DisParseError::ReservedPduType(pdu_type_code))?;
    let protocol_family = extract_protocol_family(buf[3])?;
    let length = extract_length([buf[8], buf[9]], buf.len())?;
    let header = DisHeader {
        protocol_version,
        exercise_id: buf[1],
        pdu_type: pdu_type_code,
        protocol_family,
        timestamp: u32_at(buf, 4),
        length,
        pdu_status: buf[10],
        padding: buf[11],
    };
    let raw = &buf[..usize::from(length)];
    let body = &raw[DIS_HEADER_LENGTH..];
    let body = match pdu_type_code {
        DIS_PDU_ENTITY_STATE => entity_state(body)?,
        DIS_PDU_TRANSMITTER => transmitter(body)?,
        DIS_PDU_SIGNAL => signal(body)?,
        _ => DisBody::Opaque(body),
    };
    Ok(DisPdu {
        header,
        pdu_type,
        body,
        raw,
    })
}

fn entity_state(body: &[u8]) -> Result<DisBody<'_>, DisParseError> {
    validate_body_length(
        DIS_PDU_ENTITY_STATE,
        DIS_ENTITY_STATE_FIXED_LENGTH,
        body.len(),
    )?;
    let variable_parameter_count = body[7];
    let parameters_len = usize::from(variable_parameter_count) * DIS_VARIABLE_PARAMETER_LENGTH;
    validate_body_length(
        DIS_PDU_ENTITY_STATE,
        DIS_ENTITY_STATE_FIXED_LENGTH + parameters_len,
        body.len(),
    )?;
    let mut marking = [0u8; 12];
    marking.copy_from_slice(&body[116..128]);
    Ok(DisBody::EntityState {
        entity_id: EntityId::from_bytes(&body[0..6]),
        force_id: body[6],
        variable_parameter_count,
        entity_type: EntityType::from_bytes(&body[8..16]),
        alternative_entity_type: EntityType::from_bytes(&body[16..24]),
        linear_velocity: Vector3 {
            x: f32_at(body, 24),
            y: f32_at(body, 28),
            z: f32_at(body, 32),
        },
        location: WorldCoordinates {
            x: f64_at(body, 36),
            y: f64_at(body, 44),
            z: f64_at(body, 52),
        },
        orientation: Vector3 {
            x: f32_at(body, 60),
            y: f32_at(body, 64),
            z: f32_at(body, 68),
        },
        appearance: u32_at(body, 72),
        dead_reckoning_algorithm: body[76],
        marking,
        capabilities: u32_at(body, 128),
        variable_parameters: &body
            [DIS_ENTITY_STATE_FIXED_LENGTH..DIS_ENTITY_STATE_FIXED_LENGTH + parameters_len],
    })
}

fn transmitter(body: &[u8]) -> Result<DisBody<'_>, DisParseError> {
    validate_body_length(
        DIS_PDU_TRANSMITTER,
        DIS_TRANSMITTER_FIXED_LENGTH,
        body.len(),
    )?;
    Ok(DisBody::Transmitter {
        entity_id: EntityId::from_bytes(&body[0..6]),
        radio_id: u16_at(body, 6),
        radio_entity_type: EntityType::from_bytes(&body[8..16]),
        transmit_state: body[16],
        input_source: body[17],
        variable_parameter_count: u16_at(body, 18),
        antenna_location: WorldCoordinates {
            x: f64_at(body, 20),
            y: f64_at(body, 28),
            z: f64_at(body, 36),
        },
        relative_antenna_location: Vector3 {
            x: f32_at(body, 44),
            y: f32_at(body, 48),
            z: f32_at(body, 52),
        },
        antenna_pattern_type: u16_at(body, 56),
        antenna_pattern_length: u16_at(body, 58),
        frequency_hz: u64::from_be_bytes([
            body[60], body[61], body[62], body[63], body[64], body[65], body[66], body[67],
        ]),
        bandwidth_hz: f32_at(body, 68),
        power_dbm: f32_at(body, 72),
        modulation_type: ModulationType {
            spread_spectrum: u16_at(body, 76),
            major: u16_at(body, 78),
            detail: u16_at(body, 80),
            system: u16_at(body, 82),
        },
        crypto_system: u16_at(body, 84),
        crypto_key_id: u16_at(body, 86),
        modulation_parameter_length: body[88],
    })
}

fn signal(body: &[u8]) -> Result<DisBody<'_>, DisParseError> {
    validate_body_length(DIS_PDU_SIGNAL, DIS_SIGNAL_FIXED_LENGTH, body.len())?;
    Ok(DisBody::Signal {
        entity_id: EntityId::from_bytes(&body[0..6]),
        radio_id: u16_at(body, 6),
        encoding_scheme: u16_at(body, 8),
        tdl_type: u16_at(body, 10),
        sample_rate: u32_at(body, 12),
        data_length: u16_at(body, 16),
        samples: u16_at(body, 18),
        data: &body[DIS_SIGNAL_FIXED_LENGTH..],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// pcaps_exemple/protocols/dis/wireshark_12043_dis_v7_transmitter.pcap,
    /// trame 1 (UDP 3000) : Transmitter DIS v7, recoupe avec tshark 4.6.6.
    const V7_TRANSMITTER: &str = concat!(
        "070119047b3278cf00680000fa80f01bfffefffe0700000001000000010000000000000000000000",
        "00000000000000000000000000000000000000000000000000000000000000000000000005f5e100",
        "46c35000c387000000000003000100010000000000000000",
    );

    /// pcaps_exemple/protocols/dis/dis_voice_sample.pcap, trame 29 (UDP
    /// 6993) : Signal DIS v6, 1 024 echantillons mu-law — tete du PDU, les
    /// 1 024 octets de donnees sont remplaces par des zeros (synthetique
    /// pour la partie donnees, longueurs reelles).
    const V6_SIGNAL_HEAD: &str = "06011a040002bb0e042000007dfd00fd000100020001000000001f4020000400";

    /// pcaps_exemple/protocols/dis/wireshark_3492_dis_test2.pcap, trame 1
    /// (UDP 6993) : Set Data DIS v4 qui annonce 48 octets pour 160.
    const V4_SET_DATA: &str = concat!(
        "040b13054f2545f60030000000c8001f000100c8000b000100000beb000000000000000400000003",
        "00094eda00000001000000be0000000200094ed700000003000001220000000400094f5700000140",
        "40265dddddddd689401c000000000000000001a5000001314224cccd4193333300a43c0201010101",
        "00094f5800000040303132333435363700094f590000008041424344454647484950515253545556"
    );

    #[test]
    fn test_decodes_a_v7_transmitter_against_tshark() {
        let bytes = hex::decode(V7_TRANSMITTER).unwrap();
        let packet = DisPacket::try_from(bytes.as_slice()).expect("Transmitter v7");
        assert_eq!(packet.pdus.len(), 1);
        assert!(packet.trailing.is_empty());
        let pdu = &packet.pdus[0];
        assert_eq!(pdu.header.protocol_version, 7);
        assert_eq!(pdu.header.exercise_id, 1);
        assert_eq!(pdu.pdu_type, PduType::Transmitter);
        assert_eq!(pdu.header.protocol_family, 4);
        assert!(pdu.header.absolute_timestamp());
        assert_eq!(pdu.header.length, 104);
        assert_eq!(pdu.header.status(), Some(0));
        assert_eq!(pdu.raw.len(), 104);
        let DisBody::Transmitter {
            entity_id,
            radio_id,
            radio_entity_type,
            transmit_state,
            input_source,
            antenna_pattern_type,
            antenna_pattern_length,
            frequency_hz,
            bandwidth_hz,
            power_dbm,
            modulation_type,
            crypto_system,
            crypto_key_id,
            modulation_parameter_length,
            variable_parameter_count,
            ..
        } = pdu.body
        else {
            panic!("Transmitter attendu");
        };
        assert_eq!(
            entity_id,
            EntityId {
                site: 64128,
                application: 61467,
                entity: 65534
            }
        );
        assert_eq!(radio_id, 65534);
        assert_eq!((radio_entity_type.kind, radio_entity_type.category), (7, 1));
        assert_eq!((transmit_state, input_source), (1, 0));
        assert_eq!((antenna_pattern_type, antenna_pattern_length), (0, 0));
        assert_eq!(frequency_hz, 100_000_000);
        assert_eq!(bandwidth_hz, 25_000.0);
        assert_eq!(power_dbm, -270.0);
        assert_eq!(
            modulation_type,
            ModulationType {
                spread_spectrum: 0,
                major: 3,
                detail: 1,
                system: 1
            }
        );
        assert_eq!((crypto_system, crypto_key_id), (0, 0));
        assert_eq!(modulation_parameter_length, 0);
        assert_eq!(variable_parameter_count, 0);
    }

    #[test]
    fn test_decodes_a_signal_pdu_against_tshark() {
        let mut bytes = hex::decode(V6_SIGNAL_HEAD).unwrap();
        bytes.extend(std::iter::repeat_n(0u8, 1024));
        assert_eq!(bytes.len(), 1056);
        let packet = DisPacket::try_from(bytes.as_slice()).expect("Signal v6");
        let pdu = &packet.pdus[0];
        assert_eq!(pdu.pdu_type, PduType::Signal);
        assert_eq!(pdu.header.protocol_version, 6);
        assert!(!pdu.header.absolute_timestamp());
        assert_eq!(pdu.header.status(), None);
        let DisBody::Signal {
            entity_id,
            radio_id,
            encoding_scheme,
            tdl_type,
            sample_rate,
            data_length,
            samples,
            data,
        } = pdu.body
        else {
            panic!("Signal attendu");
        };
        assert_eq!(
            (entity_id.site, entity_id.application, entity_id.entity),
            (32253, 253, 1)
        );
        assert_eq!(radio_id, 2);
        assert_eq!((encoding_scheme, tdl_type), (0x0001, 0));
        assert_eq!((sample_rate, data_length, samples), (8000, 8192, 1024));
        assert_eq!(data.len(), 1024);
        assert!(bytes.as_ptr_range().contains(&data.as_ptr()));
    }

    #[test]
    fn test_lenient_reading_keeps_the_rest_of_a_mis_sized_pdu() {
        let bytes = hex::decode(V4_SET_DATA).unwrap();
        assert_eq!(bytes.len(), 160);
        assert_eq!(
            DisPacket::try_from(bytes.as_slice()),
            Err(DisParseError::UnexpectedTrailingBytes { trailing: 112 })
        );
        let packet = DisPacket::try_from_lenient(bytes.as_slice()).expect("lecture tolerante");
        assert_eq!(packet.pdus.len(), 1);
        let pdu = &packet.pdus[0];
        assert_eq!(pdu.pdu_type, PduType::SetData);
        assert_eq!(pdu.header.protocol_version, 4);
        assert_eq!(pdu.header.exercise_id, 11);
        assert_eq!(pdu.header.protocol_family, 5);
        assert_eq!(pdu.header.length, 48);
        assert_eq!(pdu.raw.len(), 48);
        assert!(matches!(pdu.body, DisBody::Opaque(body) if body.len() == 36));
        assert_eq!(packet.trailing.len(), 112);
    }

    /// Octets synthetiques : deux PDU dans un datagramme (un Transmitter
    /// reel puis un Comment minimal), et un Entity State minimal avec un
    /// parametre d'articulation.
    #[test]
    fn test_several_pdus_and_entity_state() {
        let mut bytes = hex::decode(V7_TRANSMITTER).unwrap();
        bytes.extend_from_slice(&[0x07, 0x01, 0x16, 0x05, 0, 0, 0, 0, 0x00, 0x0c, 0, 0]);
        let packet = DisPacket::try_from(bytes.as_slice()).expect("deux PDU");
        assert_eq!(
            packet
                .pdus
                .iter()
                .map(|pdu| pdu.pdu_type)
                .collect::<Vec<_>>(),
            [PduType::Transmitter, PduType::Comment]
        );
        assert!(packet.trailing.is_empty());

        let mut state = vec![0x06, 0x01, 0x01, 0x01, 0, 0, 0, 0, 0x00, 0x00, 0, 0];
        let mut body = vec![0u8; DIS_ENTITY_STATE_FIXED_LENGTH];
        body[..6].copy_from_slice(&[0x00, 0x01, 0x00, 0x02, 0x00, 0x03]);
        body[6] = 1; // force
        body[7] = 1; // un parametre
        body[8..16].copy_from_slice(&[1, 2, 0x00, 0x11, 3, 4, 5, 6]);
        body[36..44].copy_from_slice(&4_000_000.0f64.to_be_bytes());
        body[72..76].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        body[76] = 2; // DRM(F, P, W)
        body[116] = 1; // ASCII
        body[117..128].copy_from_slice(b"PACKET     ");
        body[128..132].copy_from_slice(&0x0000_0001u32.to_be_bytes());
        state.extend_from_slice(&body);
        state.extend_from_slice(&[0xaa; DIS_VARIABLE_PARAMETER_LENGTH]);
        let len = state.len() as u16;
        state[8..10].copy_from_slice(&len.to_be_bytes());
        let packet = DisPacket::try_from(state.as_slice()).expect("Entity State");
        let DisBody::EntityState {
            entity_id,
            force_id,
            variable_parameter_count,
            entity_type,
            location,
            appearance,
            dead_reckoning_algorithm,
            marking,
            capabilities,
            variable_parameters,
            ..
        } = packet.pdus[0].body
        else {
            panic!("Entity State attendu");
        };
        assert_eq!(
            (entity_id.site, entity_id.application, entity_id.entity),
            (1, 2, 3)
        );
        assert_eq!((force_id, variable_parameter_count), (1, 1));
        assert_eq!((entity_type.kind, entity_type.country), (1, 0x11));
        assert_eq!(location.x, 4_000_000.0);
        assert_eq!(appearance, 0x1234_5678);
        assert_eq!(dead_reckoning_algorithm, 2);
        assert_eq!(&marking[1..], b"PACKET     ");
        assert_eq!(capabilities, 1);
        assert_eq!(variable_parameters, &[0xaa; 16]);

        // Un parametre annonce mais absent.
        state[12 + 7] = 2;
        assert_eq!(
            DisPacket::try_from(state.as_slice()),
            Err(DisParseError::BodyTooShort {
                pdu_type: 1,
                expected: DIS_ENTITY_STATE_FIXED_LENGTH + 32,
                actual: DIS_ENTITY_STATE_FIXED_LENGTH + 16,
            })
        );
    }

    #[test]
    fn test_rejects_bad_headers() {
        let bytes = hex::decode(V7_TRANSMITTER).unwrap();
        assert!(matches!(
            DisPacket::try_from(&bytes[..8]),
            Err(DisParseError::Truncated {
                expected: 12,
                actual: 8
            })
        ));
        let mut version = bytes.clone();
        version[0] = 8;
        assert_eq!(
            DisPacket::try_from(version.as_slice()),
            Err(DisParseError::UnsupportedVersion(8))
        );
        let mut pdu_type = bytes.clone();
        pdu_type[2] = 73;
        assert_eq!(
            DisPacket::try_from(pdu_type.as_slice()),
            Err(DisParseError::ReservedPduType(73))
        );
        let mut family = bytes.clone();
        family[3] = 14;
        assert_eq!(
            DisPacket::try_from(family.as_slice()),
            Err(DisParseError::ReservedProtocolFamily(14))
        );
        let mut length = bytes.clone();
        length[9] = 0x70;
        assert_eq!(
            DisPacket::try_from(length.as_slice()),
            Err(DisParseError::LengthOverflow {
                declared: 112,
                available: 104
            })
        );
        length[8..10].copy_from_slice(&[0, 11]);
        assert_eq!(
            DisPacket::try_from(length.as_slice()),
            Err(DisParseError::InvalidLength(11))
        );
        // Transmitter trop court pour ses champs fixes.
        let mut short = bytes[..60].to_vec();
        short[8..10].copy_from_slice(&[0, 60]);
        assert_eq!(
            DisPacket::try_from(short.as_slice()),
            Err(DisParseError::BodyTooShort {
                pdu_type: 25,
                expected: 92,
                actual: 48
            })
        );
    }
}
