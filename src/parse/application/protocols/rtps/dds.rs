// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! La couche DDS que portent les sous-messages DATA et DATA_FRAG de RTPS
//! (#317) : QoS en ligne, en-tete d'encapsulation des donnees serialisees,
//! et donnees de decouverte SPDP et SEDP (DDSI-RTPS 2.5 §8.5, §9.3.1.4,
//! §9.6 ; DDS-XTypes 1.3 §7.6.3.1.2).
//!
//! Tout se decode a la demande, depuis un [`RtpsSubmessage`] deja decoupe :
//! [`RtpsSubmessage::inline_qos`], [`RtpsSubmessage::serialized_payload`] et
//! [`RtpsSubmessage::discovery`]. La detection et
//! [`RtpsPacket::try_from`](super::RtpsPacket) n'en dependent pas : un DATA
//! dont la ParameterList est malformee reste un message RTPS valide.
//!
//! La decouverte est ce qu'un participant DDS annonce de lui-meme (SPDP :
//! GUID, domaine, locators, duree de bail, endpoints integres) et de ses
//! endpoints (SEDP : nom du topic et de son type, GUID, QoS). Les donnees
//! d'un type utilisateur restent des octets : sans son IDL, rien ne dit
//! comment les lire.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{
    checks::application::rtps::{
        DATA_FLAG_INLINE_QOS, ENCAPSULATION_CDR_BE, ENCAPSULATION_CDR_LE, ENCAPSULATION_CDR2_BE,
        ENCAPSULATION_CDR2_LE, ENCAPSULATION_D_CDR2_BE, ENCAPSULATION_D_CDR2_LE,
        ENCAPSULATION_PL_CDR_BE, ENCAPSULATION_PL_CDR_LE, ENCAPSULATION_PL_CDR2_BE,
        ENCAPSULATION_PL_CDR2_LE, ENCAPSULATION_XML, ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER,
        ENTITYID_SEDP_PUBLICATIONS_WRITER, ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER,
        ENTITYID_SEDP_SUBSCRIPTIONS_WRITER, ENTITYID_SEDP_TOPICS_WRITER,
        ENTITYID_SPDP_PARTICIPANT_SECURE_WRITER, ENTITYID_SPDP_PARTICIPANT_WRITER,
        LOCATOR_KIND_UDPV4, LOCATOR_KIND_UDPV6, PID_BUILTIN_ENDPOINT_SET,
        PID_DEFAULT_MULTICAST_LOCATOR, PID_DEFAULT_UNICAST_LOCATOR, PID_DOMAIN_ID, PID_DURABILITY,
        PID_ENDPOINT_GUID, PID_ENTITY_NAME, PID_KEY_HASH, PID_METATRAFFIC_MULTICAST_LOCATOR,
        PID_METATRAFFIC_UNICAST_LOCATOR, PID_MULTICAST_LOCATOR, PID_MUST_UNDERSTAND_FLAG,
        PID_PARTICIPANT_GUID, PID_PARTICIPANT_LEASE_DURATION, PID_PROTOCOL_VERSION,
        PID_RELIABILITY, PID_STATUS_INFO, PID_TOPIC_NAME, PID_TYPE_NAME, PID_UNICAST_LOCATOR,
        PID_VENDOR_ID, PID_VENDOR_SPECIFIC_FLAG, RTPS_ENCAPSULATION_HEADER_LENGTH,
        RTPS_PARAMETER_HEADER_LENGTH, cdr_string, inline_qos_offset, parameter_list_length,
        read_u16, read_u32,
    },
    errors::application::rtps::RtpsParseError,
    parse::application::protocols::rtps::{RtpsSubmessage, SubmessageDetails},
};

/// Identifiant de representation des donnees serialisees (DDS-XTypes 1.3
/// Table 60) : CDR classique, ParameterList (PL_CDR), XCDR2 et ses formes
/// delimitee et mutable, XML, chacun en grand ou petit-boutiste.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RtpsEncapsulation {
    CdrBe,
    CdrLe,
    /// ParameterList, la representation de la decouverte.
    PlCdrBe,
    PlCdrLe,
    Xml,
    Cdr2Be,
    Cdr2Le,
    /// XCDR2 d'un type mutable : des EMHEADER, pas une ParameterList.
    PlCdr2Be,
    PlCdr2Le,
    /// XCDR2 d'un type appendable : un DHEADER de longueur en tete.
    DCdr2Be,
    DCdr2Le,
    /// Identifiant hors de la table, d'une implementation par exemple.
    Other(u16),
}

impl RtpsEncapsulation {
    pub fn from_code(code: u16) -> Self {
        match code {
            ENCAPSULATION_CDR_BE => Self::CdrBe,
            ENCAPSULATION_CDR_LE => Self::CdrLe,
            ENCAPSULATION_PL_CDR_BE => Self::PlCdrBe,
            ENCAPSULATION_PL_CDR_LE => Self::PlCdrLe,
            ENCAPSULATION_XML => Self::Xml,
            ENCAPSULATION_CDR2_BE => Self::Cdr2Be,
            ENCAPSULATION_CDR2_LE => Self::Cdr2Le,
            ENCAPSULATION_PL_CDR2_BE => Self::PlCdr2Be,
            ENCAPSULATION_PL_CDR2_LE => Self::PlCdr2Le,
            ENCAPSULATION_D_CDR2_BE => Self::DCdr2Be,
            ENCAPSULATION_D_CDR2_LE => Self::DCdr2Le,
            other => Self::Other(other),
        }
    }

    /// L'identifiant tel que porte par le fil.
    pub fn code(self) -> u16 {
        match self {
            Self::CdrBe => ENCAPSULATION_CDR_BE,
            Self::CdrLe => ENCAPSULATION_CDR_LE,
            Self::PlCdrBe => ENCAPSULATION_PL_CDR_BE,
            Self::PlCdrLe => ENCAPSULATION_PL_CDR_LE,
            Self::Xml => ENCAPSULATION_XML,
            Self::Cdr2Be => ENCAPSULATION_CDR2_BE,
            Self::Cdr2Le => ENCAPSULATION_CDR2_LE,
            Self::PlCdr2Be => ENCAPSULATION_PL_CDR2_BE,
            Self::PlCdr2Le => ENCAPSULATION_PL_CDR2_LE,
            Self::DCdr2Be => ENCAPSULATION_D_CDR2_BE,
            Self::DCdr2Le => ENCAPSULATION_D_CDR2_LE,
            Self::Other(code) => code,
        }
    }

    /// Le nom de la table, `CDR_LE` par exemple ; `None` hors de la table.
    pub fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::CdrBe => "CDR_BE",
            Self::CdrLe => "CDR_LE",
            Self::PlCdrBe => "PL_CDR_BE",
            Self::PlCdrLe => "PL_CDR_LE",
            Self::Xml => "XML",
            Self::Cdr2Be => "CDR2_BE",
            Self::Cdr2Le => "CDR2_LE",
            Self::PlCdr2Be => "PL_CDR2_BE",
            Self::PlCdr2Le => "PL_CDR2_LE",
            Self::DCdr2Be => "D_CDR2_BE",
            Self::DCdr2Le => "D_CDR2_LE",
            Self::Other(_) => return None,
        })
    }

    /// L'ordre d'octets des donnees ; `None` pour XML et hors de la table.
    pub fn little_endian(self) -> Option<bool> {
        match self {
            Self::CdrBe | Self::PlCdrBe | Self::Cdr2Be | Self::PlCdr2Be | Self::DCdr2Be => {
                Some(false)
            }
            Self::CdrLe | Self::PlCdrLe | Self::Cdr2Le | Self::PlCdr2Le | Self::DCdr2Le => {
                Some(true)
            }
            Self::Xml | Self::Other(_) => None,
        }
    }

    /// PL_CDR, grand ou petit-boutiste : les donnees sont une ParameterList.
    pub fn is_parameter_list(self) -> bool {
        matches!(self, Self::PlCdrBe | Self::PlCdrLe)
    }
}

/// Les donnees serialisees d'un DATA, ou le debut de celles d'un DATA_FRAG
/// (son premier fragment) : l'en-tete d'encapsulation (§10.2), toujours en
/// grand-boutiste, puis les donnees.
///
/// ```mermaid
/// ---
/// title: RtpsSerializedPayload
/// ---
/// packet-beta
/// 0-15: "representation identifier u16"
/// 16-31: "representation options u16"
/// 32-63: "data (reste du sous-message)"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RtpsSerializedPayload<'a> {
    pub encapsulation: RtpsEncapsulation,
    /// Options de representation. XTypes y range, dans les deux bits de
    /// poids faible, le nombre d'octets de bourrage en fin de donnees.
    pub options: u16,
    /// Les donnees apres l'en-tete, jusqu'a la fin du sous-message, bourrage
    /// compris ; pour un DATA_FRAG, la fin du premier fragment seulement.
    pub data: &'a [u8],
}

impl<'a> RtpsSerializedPayload<'a> {
    /// Decode l'en-tete d'encapsulation en tete de `bytes`.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, RtpsParseError> {
        if bytes.len() < RTPS_ENCAPSULATION_HEADER_LENGTH {
            return Err(RtpsParseError::SerializedPayloadTooShort {
                actual: bytes.len(),
            });
        }
        Ok(Self {
            encapsulation: RtpsEncapsulation::from_code(u16::from_be_bytes([bytes[0], bytes[1]])),
            options: u16::from_be_bytes([bytes[2], bytes[3]]),
            data: &bytes[RTPS_ENCAPSULATION_HEADER_LENGTH..],
        })
    }

    /// La ParameterList d'une encapsulation PL_CDR ; `None` pour une autre.
    pub fn parameters(&self) -> Option<Result<RtpsParameterList<'a>, RtpsParseError>> {
        let little_endian = match self.encapsulation {
            RtpsEncapsulation::PlCdrBe => false,
            RtpsEncapsulation::PlCdrLe => true,
            _ => return None,
        };
        Some(RtpsParameterList::parse(self.data, little_endian).map(|(list, _)| list))
    }
}

/// Une ParameterList (§9.4.2.11), validee : chaque parametre tient dans la
/// liste, et un PID_SENTINEL la termine. Chaque parametre a cette forme,
/// sa valeur alignee sur quatre octets :
///
/// ```mermaid
/// ---
/// title: RtpsParameter
/// ---
/// packet-beta
/// 0-15: "parameterId u16"
/// 16-31: "length u16"
/// 32-63: "value (length octets)"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RtpsParameterList<'a> {
    /// Les parametres, sans le PID_SENTINEL final.
    pub bytes: &'a [u8],
    /// Ordre d'octets des en-tetes et des valeurs : celui du sous-message
    /// pour des QoS en ligne, celui de l'encapsulation pour des donnees.
    pub little_endian: bool,
}

impl<'a> RtpsParameterList<'a> {
    /// Decode la liste en tete de `bytes` ; rend la liste et le nombre
    /// d'octets consommes, PID_SENTINEL compris. Ce qui suit le sentinel est
    /// ignore.
    pub fn parse(bytes: &'a [u8], little_endian: bool) -> Result<(Self, usize), RtpsParseError> {
        let (length, consumed) = parameter_list_length(bytes, little_endian)?;
        Ok((
            Self {
                bytes: &bytes[..length],
                little_endian,
            },
            consumed,
        ))
    }

    /// Les parametres, dans l'ordre du fil, sans le PID_SENTINEL.
    pub fn iter(&self) -> impl Iterator<Item = RtpsParameter<'a>> + 'a {
        let (bytes, little_endian) = (self.bytes, self.little_endian);
        let mut offset = 0;
        std::iter::from_fn(move || {
            let header = bytes.get(offset..offset + RTPS_PARAMETER_HEADER_LENGTH)?;
            let id = read_u16([header[0], header[1]], little_endian);
            let length = usize::from(read_u16([header[2], header[3]], little_endian));
            let start = offset + RTPS_PARAMETER_HEADER_LENGTH;
            let value = bytes.get(start..start + length)?;
            offset = start + length;
            Some(RtpsParameter {
                id,
                value,
                little_endian,
            })
        })
    }

    /// Le premier parametre d'identifiant `id`.
    pub fn get(&self, id: u16) -> Option<RtpsParameter<'a>> {
        self.iter().find(|parameter| parameter.id == id)
    }

    /// PID_TOPIC_NAME : le nom du topic, sans son NUL final.
    pub fn topic_name(&self) -> Option<&'a [u8]> {
        self.get(PID_TOPIC_NAME)?.string()
    }

    /// PID_TYPE_NAME : le nom du type des donnees du topic.
    pub fn type_name(&self) -> Option<&'a [u8]> {
        self.get(PID_TYPE_NAME)?.string()
    }

    /// PID_ENTITY_NAME : le nom que l'application donne au participant ou a
    /// l'endpoint.
    pub fn entity_name(&self) -> Option<&'a [u8]> {
        self.get(PID_ENTITY_NAME)?.string()
    }

    /// PID_PARTICIPANT_GUID : guidPrefix puis entityId du participant.
    pub fn participant_guid(&self) -> Option<[u8; 16]> {
        self.get(PID_PARTICIPANT_GUID)?.guid()
    }

    /// PID_ENDPOINT_GUID : GUID du writer ou du reader annonce par SEDP.
    pub fn endpoint_guid(&self) -> Option<[u8; 16]> {
        self.get(PID_ENDPOINT_GUID)?.guid()
    }

    /// PID_KEY_HASH, une QoS en ligne : l'empreinte de la cle de
    /// l'instance, le GUID lui-meme pour un topic integre.
    pub fn key_hash(&self) -> Option<[u8; 16]> {
        self.get(PID_KEY_HASH)?.guid()
    }

    /// PID_STATUS_INFO, une QoS en ligne : instance supprimee ou
    /// desenregistree.
    pub fn status_info(&self) -> Option<RtpsStatusInfo> {
        let value = self.get(PID_STATUS_INFO)?.value;
        // StatusInfo_t est un octet[4] : les flags sont dans le dernier.
        Some(RtpsStatusInfo {
            flags: u32::from_be_bytes(value.get(..4)?.try_into().ok()?),
        })
    }

    /// PID_DOMAIN_ID.
    pub fn domain_id(&self) -> Option<u32> {
        self.get(PID_DOMAIN_ID)?.u32_value()
    }

    /// PID_PROTOCOL_VERSION : `(major, minor)`.
    pub fn protocol_version(&self) -> Option<(u8, u8)> {
        let value = self.get(PID_PROTOCOL_VERSION)?.value;
        Some((*value.first()?, *value.get(1)?))
    }

    /// PID_VENDORID, deux octets : `0x0110` pour Cyclone DDS...
    pub fn vendor_id(&self) -> Option<u16> {
        let value = self.get(PID_VENDOR_ID)?.value;
        Some(u16::from_be_bytes([*value.first()?, *value.get(1)?]))
    }

    /// PID_BUILTIN_ENDPOINT_SET : un bit par endpoint integre du
    /// participant (§9.3.2, `BuiltinEndpointSet_t`).
    pub fn builtin_endpoint_set(&self) -> Option<u32> {
        self.get(PID_BUILTIN_ENDPOINT_SET)?.u32_value()
    }

    /// PID_PARTICIPANT_LEASE_DURATION : delai sans nouvelle apres lequel les
    /// autres oublient le participant.
    pub fn participant_lease_duration(&self) -> Option<RtpsDuration> {
        self.get(PID_PARTICIPANT_LEASE_DURATION)?.duration()
    }

    /// PID_RELIABILITY.
    pub fn reliability(&self) -> Option<RtpsReliability> {
        let parameter = self.get(PID_RELIABILITY)?;
        Some(RtpsReliability {
            kind: RtpsReliabilityKind::from_code(parameter.u32_value()?),
            max_blocking_time: parameter.duration_at(4),
        })
    }

    /// PID_DURABILITY.
    pub fn durability(&self) -> Option<RtpsDurabilityKind> {
        Some(RtpsDurabilityKind::from_code(
            self.get(PID_DURABILITY)?.u32_value()?,
        ))
    }

    /// Les locators, dans l'ordre du fil, avec le role que leur PID leur
    /// donne.
    pub fn locators(&self) -> impl Iterator<Item = (RtpsLocatorRole, RtpsLocator)> + 'a {
        self.iter().filter_map(|parameter| {
            Some((
                RtpsLocatorRole::from_pid(parameter.id)?,
                parameter.locator()?,
            ))
        })
    }
}

/// Un parametre d'une [`RtpsParameterList`] : son identifiant et sa valeur,
/// empruntee, avec l'ordre d'octets de la liste.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RtpsParameter<'a> {
    pub id: u16,
    pub value: &'a [u8],
    pub little_endian: bool,
}

impl<'a> RtpsParameter<'a> {
    /// Bit 15 : un PID propre a l'implementation qu'annonce le vendorId.
    pub fn is_vendor_specific(&self) -> bool {
        self.id & PID_VENDOR_SPECIFIC_FLAG != 0
    }

    /// Bit 14 : un recepteur qui ne le comprend pas doit ignorer le
    /// sous-message entier.
    pub fn must_understand(&self) -> bool {
        self.id & PID_MUST_UNDERSTAND_FLAG != 0
    }

    /// Le nom de la specification, `PID_TOPIC_NAME` par exemple ; `None`
    /// pour un PID vendeur, dont le sens depend du vendorId, ou inconnu.
    pub fn name(&self) -> Option<&'static str> {
        Some(match self.id {
            0x0000 => "PID_PAD",
            0x0001 => "PID_SENTINEL",
            0x0002 => "PID_PARTICIPANT_LEASE_DURATION",
            0x0004 => "PID_TIME_BASED_FILTER",
            0x0005 => "PID_TOPIC_NAME",
            0x0006 => "PID_OWNERSHIP_STRENGTH",
            0x0007 => "PID_TYPE_NAME",
            0x000f => "PID_DOMAIN_ID",
            0x0015 => "PID_PROTOCOL_VERSION",
            0x0016 => "PID_VENDORID",
            0x001a => "PID_RELIABILITY",
            0x001b => "PID_LIVELINESS",
            0x001d => "PID_DURABILITY",
            0x001e => "PID_DURABILITY_SERVICE",
            0x001f => "PID_OWNERSHIP",
            0x0021 => "PID_PRESENTATION",
            0x0023 => "PID_DEADLINE",
            0x0025 => "PID_DESTINATION_ORDER",
            0x0027 => "PID_LATENCY_BUDGET",
            0x0029 => "PID_PARTITION",
            0x002b => "PID_LIFESPAN",
            0x002c => "PID_USER_DATA",
            0x002d => "PID_GROUP_DATA",
            0x002e => "PID_TOPIC_DATA",
            0x002f => "PID_UNICAST_LOCATOR",
            0x0030 => "PID_MULTICAST_LOCATOR",
            0x0031 => "PID_DEFAULT_UNICAST_LOCATOR",
            0x0032 => "PID_METATRAFFIC_UNICAST_LOCATOR",
            0x0033 => "PID_METATRAFFIC_MULTICAST_LOCATOR",
            0x0034 => "PID_PARTICIPANT_MANUAL_LIVELINESS_COUNT",
            0x0035 => "PID_CONTENT_FILTER_PROPERTY",
            0x0040 => "PID_HISTORY",
            0x0041 => "PID_RESOURCE_LIMITS",
            0x0043 => "PID_EXPECTS_INLINE_QOS",
            0x0048 => "PID_DEFAULT_MULTICAST_LOCATOR",
            0x0049 => "PID_TRANSPORT_PRIORITY",
            0x0050 => "PID_PARTICIPANT_GUID",
            0x0052 => "PID_GROUP_GUID",
            0x0055 => "PID_CONTENT_FILTER_INFO",
            0x0056 => "PID_COHERENT_SET",
            0x0057 => "PID_DIRECTED_WRITE",
            0x0058 => "PID_BUILTIN_ENDPOINT_SET",
            0x0059 => "PID_PROPERTY_LIST",
            0x005a => "PID_ENDPOINT_GUID",
            0x0060 => "PID_TYPE_MAX_SIZE_SERIALIZED",
            0x0061 => "PID_ORIGINAL_WRITER_INFO",
            0x0062 => "PID_ENTITY_NAME",
            0x0063 => "PID_GROUP_COHERENT_SET",
            0x0064 => "PID_GROUP_SEQ_NUM",
            0x0065 => "PID_WRITER_GROUP_INFO",
            0x0066 => "PID_SECURE_WRITER_GROUP_INFO",
            0x0070 => "PID_KEY_HASH",
            0x0071 => "PID_STATUS_INFO",
            0x0073 => "PID_DATA_REPRESENTATION",
            0x0074 => "PID_TYPE_CONSISTENCY_ENFORCEMENT",
            0x0075 => "PID_TYPE_INFORMATION",
            0x0077 => "PID_BUILTIN_ENDPOINT_QOS",
            0x1001 => "PID_IDENTITY_TOKEN",
            0x1002 => "PID_PERMISSIONS_TOKEN",
            0x1003 => "PID_DATA_TAGS",
            0x1004 => "PID_ENDPOINT_SECURITY_INFO",
            0x1005 => "PID_PARTICIPANT_SECURITY_INFO",
            0x1006 => "PID_IDENTITY_STATUS_TOKEN",
            0x4014 => "PID_DOMAIN_TAG",
            _ => return None,
        })
    }

    /// La valeur lue comme une chaine CDR (longueur u32, octets, NUL) ; rend
    /// les octets sans le NUL, `None` si la longueur deborde.
    pub fn string(&self) -> Option<&'a [u8]> {
        cdr_string(self.value, self.little_endian)
    }

    /// Les quatre premiers octets de la valeur, dans l'ordre de la liste.
    pub fn u32_value(&self) -> Option<u32> {
        self.u32_at(0)
    }

    /// Les seize premiers octets de la valeur : un `GUID_t` ou un `KeyHash_t`.
    pub fn guid(&self) -> Option<[u8; 16]> {
        self.value.get(..16)?.try_into().ok()
    }

    /// La valeur lue comme un `Duration_t`.
    pub fn duration(&self) -> Option<RtpsDuration> {
        self.duration_at(0)
    }

    /// La valeur lue comme un `Locator_t`.
    pub fn locator(&self) -> Option<RtpsLocator> {
        Some(RtpsLocator {
            kind: self.u32_at(0)? as i32,
            port: self.u32_at(4)?,
            address: self.value.get(8..24)?.try_into().ok()?,
        })
    }

    fn u32_at(&self, offset: usize) -> Option<u32> {
        let bytes = self.value.get(offset..offset + 4)?;
        Some(read_u32(bytes.try_into().ok()?, self.little_endian))
    }

    fn duration_at(&self, offset: usize) -> Option<RtpsDuration> {
        Some(RtpsDuration {
            seconds: self.u32_at(offset)? as i32,
            fraction: self.u32_at(offset + 4)?,
        })
    }
}

/// Un `Duration_t` (§9.3.2) : secondes signees et fraction en 2^-32 s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct RtpsDuration {
    pub seconds: i32,
    pub fraction: u32,
}

impl RtpsDuration {
    /// `DURATION_INFINITE` : `0x7fffffff` secondes, `0xffffffff` de fraction.
    pub fn is_infinite(&self) -> bool {
        self.seconds == i32::MAX && self.fraction == u32::MAX
    }
}

/// Un `Locator_t` (§9.3.2) : ou joindre un participant ou un endpoint.
///
/// ```mermaid
/// ---
/// title: RtpsLocator
/// ---
/// packet-beta
/// 0-31: "kind i32"
/// 32-63: "port u32"
/// 64-191: "address 16 octets"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct RtpsLocator {
    /// 1 pour UDPv4, 2 pour UDPv6 ; d'autres valeurs pour les transports
    /// propres a une implementation (memoire partagee...).
    pub kind: i32,
    pub port: u32,
    /// Une adresse IPv4 occupe les quatre derniers octets.
    pub address: [u8; 16],
}

impl RtpsLocator {
    /// L'adresse d'un locator UDPv4.
    pub fn ipv4(&self) -> Option<Ipv4Addr> {
        (self.kind == LOCATOR_KIND_UDPV4).then(|| {
            Ipv4Addr::new(
                self.address[12],
                self.address[13],
                self.address[14],
                self.address[15],
            )
        })
    }

    /// L'adresse d'un locator UDPv6.
    pub fn ipv6(&self) -> Option<Ipv6Addr> {
        (self.kind == LOCATOR_KIND_UDPV6).then(|| Ipv6Addr::from(self.address))
    }
}

/// Le role d'un locator, d'apres le PID qui le porte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RtpsLocatorRole {
    /// Donnees d'un endpoint.
    Unicast,
    Multicast,
    /// Donnees des endpoints du participant, par defaut.
    DefaultUnicast,
    DefaultMulticast,
    /// Metatrafic du participant : decouverte, heartbeats, acquittements.
    MetatrafficUnicast,
    MetatrafficMulticast,
}

impl RtpsLocatorRole {
    pub fn from_pid(id: u16) -> Option<Self> {
        Some(match id {
            PID_UNICAST_LOCATOR => Self::Unicast,
            PID_MULTICAST_LOCATOR => Self::Multicast,
            PID_DEFAULT_UNICAST_LOCATOR => Self::DefaultUnicast,
            PID_DEFAULT_MULTICAST_LOCATOR => Self::DefaultMulticast,
            PID_METATRAFFIC_UNICAST_LOCATOR => Self::MetatrafficUnicast,
            PID_METATRAFFIC_MULTICAST_LOCATOR => Self::MetatrafficMulticast,
            _ => return None,
        })
    }
}

/// PID_STATUS_INFO (§9.6.4.9) : les flags de l'instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct RtpsStatusInfo {
    pub flags: u32,
}

impl RtpsStatusInfo {
    /// Flag D : l'instance est supprimee (dispose).
    pub fn disposed(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// Flag U : l'instance est desenregistree (unregister).
    pub fn unregistered(&self) -> bool {
        self.flags & 0x02 != 0
    }

    /// Flag F : l'echantillon est filtre pour ce reader.
    pub fn filtered(&self) -> bool {
        self.flags & 0x04 != 0
    }
}

/// QoS RELIABILITY : le type et le temps de blocage maximal d'un writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct RtpsReliability {
    pub kind: RtpsReliabilityKind,
    /// Absent d'une valeur de quatre octets.
    pub max_blocking_time: Option<RtpsDuration>,
}

/// Valeurs du fil (§9.6.3.4) : 1 et 2, pas celles de l'API DDS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RtpsReliabilityKind {
    BestEffort,
    Reliable,
    Other(u32),
}

impl RtpsReliabilityKind {
    pub fn from_code(code: u32) -> Self {
        match code {
            1 => Self::BestEffort,
            2 => Self::Reliable,
            other => Self::Other(other),
        }
    }
}

/// QoS DURABILITY : ce qu'un reader arrive en retard recoit encore.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RtpsDurabilityKind {
    Volatile,
    TransientLocal,
    Transient,
    Persistent,
    Other(u32),
}

impl RtpsDurabilityKind {
    pub fn from_code(code: u32) -> Self {
        match code {
            0 => Self::Volatile,
            1 => Self::TransientLocal,
            2 => Self::Transient,
            3 => Self::Persistent,
            other => Self::Other(other),
        }
    }
}

/// Le topic integre que publie un writer de la decouverte (§8.5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RtpsBuiltinTopic {
    /// SPDP : un participant.
    Participant,
    /// SEDP : un topic.
    Topic,
    /// SEDP : un writer.
    Publication,
    /// SEDP : un reader.
    Subscription,
}

impl RtpsBuiltinTopic {
    /// Le topic integre d'un writer de la decouverte, securise (DDS
    /// Security) ou non ; `None` pour un autre writer.
    pub fn from_writer(writer_id: u32) -> Option<Self> {
        Some(match writer_id {
            ENTITYID_SPDP_PARTICIPANT_WRITER | ENTITYID_SPDP_PARTICIPANT_SECURE_WRITER => {
                Self::Participant
            }
            ENTITYID_SEDP_TOPICS_WRITER => Self::Topic,
            ENTITYID_SEDP_PUBLICATIONS_WRITER | ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER => {
                Self::Publication
            }
            ENTITYID_SEDP_SUBSCRIPTIONS_WRITER | ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER => {
                Self::Subscription
            }
            _ => return None,
        })
    }

    /// Le nom DDS du topic, `DCPSParticipant` par exemple.
    pub fn name(self) -> &'static str {
        match self {
            Self::Participant => "DCPSParticipant",
            Self::Topic => "DCPSTopic",
            Self::Publication => "DCPSPublication",
            Self::Subscription => "DCPSSubscription",
        }
    }
}

/// Les donnees de decouverte d'un DATA : ce qu'un writer SPDP ou SEDP
/// annonce, en ParameterList.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RtpsDiscovery<'a> {
    pub topic: RtpsBuiltinTopic,
    /// Writer securise de DDS Security (entityId `0xff....c2`).
    pub secure: bool,
    /// Flag K sans flag D : une cle seule, celle d'un participant ou d'un
    /// endpoint qui se retire.
    pub key_only: bool,
    /// PL_CDR, grand ou petit-boutiste.
    pub encapsulation: RtpsEncapsulation,
    pub parameters: RtpsParameterList<'a>,
}

impl<'a> RtpsSubmessage<'a> {
    /// Longueur des champs fixes d'un DATA ou d'un DATA_FRAG, que le
    /// decoupage a deja verifiee ; `None` pour un autre sous-message.
    fn data_fixed_length(&self) -> Option<usize> {
        match self.details {
            SubmessageDetails::Data { .. } => Some(20),
            SubmessageDetails::DataFrag { .. } => Some(32),
            _ => None,
        }
    }

    /// Les QoS en ligne d'un DATA ou d'un DATA_FRAG dont le flag Q est leve,
    /// dans l'ordre d'octets du sous-message ; `None` pour un autre
    /// sous-message, ou sans le flag.
    pub fn inline_qos(&self) -> Option<Result<RtpsParameterList<'a>, RtpsParseError>> {
        let fixed = self.data_fixed_length()?;
        if self.flags & DATA_FLAG_INLINE_QOS == 0 {
            return None;
        }
        let body = self.body;
        Some(
            inline_qos_offset(body, self.little_endian, fixed).and_then(|offset| {
                RtpsParameterList::parse(&body[offset..], self.little_endian).map(|(list, _)| list)
            }),
        )
    }

    /// Les donnees serialisees d'un DATA qui en porte (flag D, ou flag K
    /// pour une cle), ou le debut de celles d'un DATA_FRAG qui commence au
    /// premier fragment ; `None` sinon.
    pub fn serialized_payload(&self) -> Option<Result<RtpsSerializedPayload<'a>, RtpsParseError>> {
        let fixed = self.data_fixed_length()?;
        let carries = match self.details {
            SubmessageDetails::Data {
                serialized_payload,
                serialized_key,
                ..
            } => serialized_payload || serialized_key,
            SubmessageDetails::DataFrag {
                fragment_starting_number,
                ..
            } => fragment_starting_number == 1,
            _ => false,
        };
        if !carries {
            return None;
        }
        let body = self.body;
        Some(
            inline_qos_offset(body, self.little_endian, fixed)
                .and_then(|offset| {
                    if self.flags & DATA_FLAG_INLINE_QOS == 0 {
                        return Ok(offset);
                    }
                    let (_, consumed) =
                        RtpsParameterList::parse(&body[offset..], self.little_endian)?;
                    Ok(offset + consumed)
                })
                .and_then(|offset| RtpsSerializedPayload::parse(&body[offset..])),
        )
    }

    /// Les donnees de decouverte d'un DATA publie par un writer SPDP ou
    /// SEDP ; `None` pour un autre writer, un DATA_FRAG, ou un DATA sans
    /// donnees ni cle (un retrait annonce par les seules QoS en ligne).
    pub fn discovery(&self) -> Option<Result<RtpsDiscovery<'a>, RtpsParseError>> {
        let SubmessageDetails::Data {
            writer_id,
            serialized_payload,
            serialized_key,
            ..
        } = self.details
        else {
            return None;
        };
        let topic = RtpsBuiltinTopic::from_writer(writer_id)?;
        let payload = self.serialized_payload()?;
        Some(payload.and_then(|payload| {
            let little_endian = match payload.encapsulation {
                RtpsEncapsulation::PlCdrBe => false,
                RtpsEncapsulation::PlCdrLe => true,
                other => {
                    return Err(RtpsParseError::NotAParameterList {
                        encapsulation: other.code(),
                    });
                }
            };
            let (parameters, _) = RtpsParameterList::parse(payload.data, little_endian)?;
            Ok(RtpsDiscovery {
                topic,
                secure: writer_id >> 24 == 0xff,
                key_only: serialized_key && !serialized_payload,
                encapsulation: payload.encapsulation,
                parameters,
            })
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::application::protocols::rtps::RtpsPacket;

    /// Trame 1 de pcaps_exemple/protocols/rtps/wireshark_15868_micro_2_4_11.pcapng
    /// (RTI Connext Micro 2.4.11) : INFO_TS puis le DATA SPDP du participant,
    /// key hash en QoS en ligne, donnees PL_CDR_LE.
    const MICRO_SPDP: &str = concat!(
        "525450530201010a010a0000dec0adde00000000090108000500000051b81e0515079c01",
        "00001000000100c7000100c2000000000100000070001000010a0000dec0adde00000000",
        "000001c1010001000003000050001000010a0000dec0adde00000000000001c162001400",
        "0f0000005f7061727469636970616e745f300000580004003f0000001500040002010000",
        "16000400010a0000310018000100000097550000000000000000000000000000c0a8010a",
        "320018000100000096550000000000000000000000000000c0a8010a33001800010000008c",
        "550000000000000000000000000000efff00010200080064000000000000000080040002",
        "04000b5900b80004000000160000006464732e7379735f696e666f2e686f73746e616d65",
        "0000000d0000004175746f7361722d686f737400000000180000006464732e7379735f69",
        "6e666f2e70726f636573735f6964000200000039000000140000006464732e7379735f69",
        "6e666f2e746172676574001b0000007463323978744f73656b436f72655461736b696e67",
        "362e3272320000140000007274692e736572766963652e76657273696f6e000900000032",
        "2e342e31312e300000000001000000"
    );

    /// Trame 29 de pcaps_exemple/protocols/rtps/rtps.pcap (RTI Connext) : le
    /// participant se retire. DATA du writer SPDP sans donnees, QoS en ligne
    /// seules : key hash, status info unregister et dispose, puis un
    /// PID_SENTINEL de longueur 1, que la specification dit d'ignorer.
    const RTI_SPDP_RETREAT: &str = concat!(
        "5254505302010101c0a87a0100003a4c0000000109010800790d4a5931b4c8ae15033400",
        "0000100000000000000100c2000000000200000070001000c0a87a0100003a4c00000001",
        "000001c1710004000000000301000100"
    );

    /// Trame 12 de pcaps_exemple/protocols/rtps/wireshark_6449_opendds_messenger.pcap
    /// (OpenDDS) : DATA d'un writer utilisateur, flags Q et K, status info
    /// dispose, puis une cle serialisee CDR_LE.
    const OPENDDS_KEY_ONLY: &str = concat!(
        "525450530201010301030000000000000000000109010800ee58934e6b9db814150b0000",
        "000010000000000000000102ffffffff00000000710004000000000101000000000100006300",
        "0000"
    );

    fn message(hex: &str) -> RtpsPacket<'static> {
        let bytes: &'static [u8] = Box::leak(hex::decode(hex).unwrap().into_boxed_slice());
        RtpsPacket::try_from(bytes).expect("message RTPS")
    }

    fn data<'a>(packet: &'a RtpsPacket<'static>) -> &'a RtpsSubmessage<'static> {
        packet
            .message()
            .expect("un message")
            .submessages
            .iter()
            .find(|submessage| matches!(submessage.details, SubmessageDetails::Data { .. }))
            .expect("un DATA")
    }

    #[test]
    fn test_spdp_participant_of_connext_micro_is_decoded() {
        let packet = message(MICRO_SPDP);
        let submessage = data(&packet);
        let guid: [u8; 16] = hex::decode("010a0000dec0adde00000000000001c1")
            .unwrap()
            .try_into()
            .unwrap();

        let qos = submessage
            .inline_qos()
            .expect("flag Q")
            .expect("QoS valides");
        assert_eq!(qos.key_hash(), Some(guid));
        assert_eq!(qos.iter().count(), 1);

        let payload = submessage
            .serialized_payload()
            .expect("flag D")
            .expect("donnees valides");
        assert_eq!(payload.encapsulation, RtpsEncapsulation::PlCdrLe);
        assert_eq!(payload.options, 0);

        let discovery = submessage
            .discovery()
            .expect("writer SPDP")
            .expect("decouverte valide");
        assert_eq!(discovery.topic, RtpsBuiltinTopic::Participant);
        assert_eq!(discovery.topic.name(), "DCPSParticipant");
        assert!(!discovery.secure && !discovery.key_only);
        let list = discovery.parameters;
        assert!(list.little_endian);
        assert_eq!(list.participant_guid(), Some(guid));
        assert_eq!(list.entity_name(), Some(&b"_participant_0"[..]));
        assert_eq!(list.builtin_endpoint_set(), Some(0x3f));
        assert_eq!(list.protocol_version(), Some((2, 1)));
        assert_eq!(list.vendor_id(), Some(0x010a));
        let lease = list.participant_lease_duration().expect("bail");
        assert_eq!((lease.seconds, lease.fraction), (100, 0));
        assert!(!lease.is_infinite());
        assert_eq!(list.topic_name(), None);
        assert_eq!(list.domain_id(), None);
        let locators: Vec<(RtpsLocatorRole, Ipv4Addr, u32)> = list
            .locators()
            .map(|(role, locator)| (role, locator.ipv4().expect("UDPv4"), locator.port))
            .collect();
        assert_eq!(
            locators,
            [
                (
                    RtpsLocatorRole::DefaultUnicast,
                    Ipv4Addr::new(192, 168, 1, 10),
                    21_911
                ),
                (
                    RtpsLocatorRole::MetatrafficUnicast,
                    Ipv4Addr::new(192, 168, 1, 10),
                    21_910
                ),
                (
                    RtpsLocatorRole::MetatrafficMulticast,
                    Ipv4Addr::new(239, 255, 0, 1),
                    21_900
                ),
            ]
        );
        let ids: Vec<u16> = list.iter().map(|parameter| parameter.id).collect();
        assert_eq!(
            ids,
            [
                0x0050, 0x0062, 0x0058, 0x0015, 0x0016, 0x0031, 0x0032, 0x0033, 0x0002, 0x8000,
                0x0059
            ]
        );
        let vendor = list.get(0x8000).expect("PID vendeur RTI");
        assert!(vendor.is_vendor_specific() && !vendor.must_understand());
        assert_eq!(vendor.name(), None);
        assert_eq!(
            list.get(0x0059).and_then(|parameter| parameter.name()),
            Some("PID_PROPERTY_LIST")
        );
    }

    #[test]
    fn test_spdp_retreat_carries_key_hash_and_status_info() {
        let packet = message(RTI_SPDP_RETREAT);
        let submessage = data(&packet);
        let qos = submessage
            .inline_qos()
            .expect("flag Q")
            .expect("QoS valides");
        assert_eq!(
            qos.key_hash().map(hex::encode),
            Some("c0a87a0100003a4c00000001000001c1".to_string())
        );
        let status = qos.status_info().expect("status info");
        assert_eq!(status.flags, 3);
        assert!(status.disposed() && status.unregistered() && !status.filtered());
        // Ni donnees ni cle : rien a decouvrir.
        assert_eq!(submessage.serialized_payload(), None);
        assert_eq!(submessage.discovery(), None);
    }

    #[test]
    fn test_key_only_data_of_a_user_writer() {
        let packet = message(OPENDDS_KEY_ONLY);
        let submessage = data(&packet);
        let status = submessage
            .inline_qos()
            .expect("flag Q")
            .expect("QoS valides")
            .status_info()
            .expect("status info");
        assert!(status.disposed() && !status.unregistered());
        let payload = submessage
            .serialized_payload()
            .expect("flag K")
            .expect("cle valide");
        assert_eq!(payload.encapsulation, RtpsEncapsulation::CdrLe);
        assert_eq!(payload.data, [0x63, 0, 0, 0]);
        assert_eq!(payload.parameters(), None);
        // Writer utilisateur 0x00000102 : pas de decouverte.
        assert_eq!(submessage.discovery(), None);
    }

    /// Octets synthetiques : le DATA de la trame OpenDDS, son writer remplace
    /// par celui de SPDP. Une cle CDR_LE n'est pas une ParameterList.
    #[test]
    fn test_discovery_refuses_a_payload_that_is_not_pl_cdr() {
        let packet = message(&OPENDDS_KEY_ONLY.replace("00000102ffffffff", "000100c2ffffffff"));
        assert_eq!(
            data(&packet).discovery(),
            Some(Err(RtpsParseError::NotAParameterList { encapsulation: 1 }))
        );
    }

    /// Octets synthetiques : `octetsToInlineQos` de la trame du retrait (16)
    /// remplace par 64, au-dela du corps de 52 octets, puis par 8, dans les
    /// champs fixes.
    #[test]
    fn test_octets_to_inline_qos_must_point_inside_the_body() {
        // id 0x15, flags 0x03, longueur 52, extraFlags, puis octetsToInlineQos.
        let header = "1503340000001000";
        for (octets, expected) in [("4000", 64), ("0800", 8)] {
            let packet =
                message(&RTI_SPDP_RETREAT.replace(header, &format!("150334000000{octets}")));
            assert_eq!(
                data(&packet).inline_qos(),
                Some(Err(RtpsParseError::InvalidOctetsToInlineQos {
                    octets_to_inline_qos: expected,
                    body: 52,
                }))
            );
        }
    }

    /// Octets synthetiques : listes et en-tetes malformes.
    #[test]
    fn test_malformed_parameter_lists_are_refused() {
        // Un status info sans sentinel.
        assert_eq!(
            RtpsParameterList::parse(&[0x71, 0, 4, 0, 0, 0, 0, 3], true),
            Err(RtpsParseError::ParameterListUnterminated { length: 8 })
        );
        // Un en-tete de parametre coupe.
        assert_eq!(
            RtpsParameterList::parse(&[0x71, 0], true),
            Err(RtpsParseError::ParameterTruncated {
                offset: 0,
                expected: 4,
                actual: 2,
            })
        );
        // Une valeur annoncee de huit octets, quatre presents.
        assert_eq!(
            RtpsParameterList::parse(&[0, 0x71, 0, 8, 0, 0, 0, 3], false),
            Err(RtpsParseError::ParameterTruncated {
                offset: 0,
                expected: 8,
                actual: 4,
            })
        );
        // Une liste vide : le sentinel seul, ce qui suit est ignore.
        let (list, consumed) = RtpsParameterList::parse(&[1, 0, 0, 0, 0xaa], true).unwrap();
        assert_eq!((list.bytes.len(), consumed), (0, 4));
        assert_eq!(
            RtpsSerializedPayload::parse(&[0, 3, 0]),
            Err(RtpsParseError::SerializedPayloadTooShort { actual: 3 })
        );
    }

    #[test]
    fn test_encapsulation_identifiers_round_trip() {
        for code in 0..=0x0016 {
            let encapsulation = RtpsEncapsulation::from_code(code);
            assert_eq!(encapsulation.code(), code);
            assert_eq!(
                encapsulation.is_parameter_list(),
                matches!(code, 0x0002 | 0x0003)
            );
            if encapsulation.name().is_some() && code != 0x0004 {
                assert_eq!(encapsulation.little_endian(), Some(code & 1 == 1));
            }
        }
        assert_eq!(RtpsEncapsulation::from_code(0x0011).name(), Some("CDR2_LE"));
        assert_eq!(RtpsEncapsulation::from_code(0x0004).little_endian(), None);
        assert_eq!(RtpsEncapsulation::from_code(0xc000).name(), None);
    }

    #[test]
    fn test_builtin_writers_are_recognised() {
        for (writer, topic) in [
            (0x0001_00c2, RtpsBuiltinTopic::Participant),
            (0xff01_01c2, RtpsBuiltinTopic::Participant),
            (0x0000_02c2, RtpsBuiltinTopic::Topic),
            (0x0000_03c2, RtpsBuiltinTopic::Publication),
            (0xff00_03c2, RtpsBuiltinTopic::Publication),
            (0x0000_04c2, RtpsBuiltinTopic::Subscription),
            (0xff00_04c2, RtpsBuiltinTopic::Subscription),
        ] {
            assert_eq!(RtpsBuiltinTopic::from_writer(writer), Some(topic));
        }
        // Le writer des messages de participant (WLP) et un writer
        // utilisateur ne publient pas de decouverte.
        assert_eq!(RtpsBuiltinTopic::from_writer(0x0002_00c2), None);
        assert_eq!(RtpsBuiltinTopic::from_writer(0x0000_0403), None);
    }

    /// Octets synthetiques : un locator UDPv6 et une duree infinie.
    #[test]
    fn test_locator_and_duration_values() {
        let mut value = vec![2, 0, 0, 0, 0xe9, 0x1c, 0, 0];
        value.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let parameter = RtpsParameter {
            id: 0x0031,
            value: &value,
            little_endian: true,
        };
        let locator = parameter.locator().unwrap();
        assert_eq!((locator.kind, locator.port), (2, 7401));
        assert_eq!(locator.ipv4(), None);
        assert_eq!(locator.ipv6(), Some("fe80::1".parse().unwrap()));
        let infinite = RtpsParameter {
            id: 0x0002,
            value: &[0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff, 0xff],
            little_endian: true,
        };
        assert!(infinite.duration().unwrap().is_infinite());
        assert_eq!(infinite.locator(), None);
    }
}
