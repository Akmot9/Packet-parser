// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! BACnet/IP (ASHRAE 135, annexe J) : la gestion technique du batiment sur
//! UDP 47808. Un datagramme porte un **BVLC** (`0x81`, fonction, longueur
//! qui couvre exactement le datagramme), puis pour les fonctions qui
//! transportent un NPDU — unicast, broadcast, Forwarded-NPDU,
//! Distribute-Broadcast — la couche reseau (version 1, controle, adresses
//! de destination et de source, compte de sauts, message reseau) et l'APDU
//! (type, identifiant d'invocation, service, segmentation). Le contenu des
//! services, en codage par etiquettes, reste des octets.
//!
//! La longueur BVLC egale au datagramme, la version 1 et les bits reserves
//! du controle a zero font une signature qui se passe du port : sonde
//! aveugle sur UDP, et regle de port sur 47808 a 47823.

use std::{convert::TryFrom, net::Ipv4Addr};

use crate::{
    checks::application::bacnet::{
        BVLC_HEADER_LENGTH, NPDU_CONTROL_DESTINATION, NPDU_CONTROL_EXPECTING_REPLY,
        NPDU_CONTROL_NETWORK_MESSAGE, NPDU_CONTROL_PRIORITY, NPDU_CONTROL_SOURCE,
        NPDU_HEADER_LENGTH, ensure_len, extract_apdu_type, validate_bvlc_function,
        validate_bvlc_length, validate_bvlc_type, validate_npdu_version,
    },
    errors::application::bacnet::BacnetParseError,
};

/// Fonctions BVLC (annexe J.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BvlcFunction {
    Result,
    WriteBroadcastDistributionTable,
    ReadBroadcastDistributionTable,
    ReadBroadcastDistributionTableAck,
    ForwardedNpdu,
    RegisterForeignDevice,
    ReadForeignDeviceTable,
    ReadForeignDeviceTableAck,
    DeleteForeignDeviceTableEntry,
    DistributeBroadcastToNetwork,
    OriginalUnicastNpdu,
    OriginalBroadcastNpdu,
    SecureBvll,
}

impl BvlcFunction {
    pub fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0x00 => Self::Result,
            0x01 => Self::WriteBroadcastDistributionTable,
            0x02 => Self::ReadBroadcastDistributionTable,
            0x03 => Self::ReadBroadcastDistributionTableAck,
            0x04 => Self::ForwardedNpdu,
            0x05 => Self::RegisterForeignDevice,
            0x06 => Self::ReadForeignDeviceTable,
            0x07 => Self::ReadForeignDeviceTableAck,
            0x08 => Self::DeleteForeignDeviceTableEntry,
            0x09 => Self::DistributeBroadcastToNetwork,
            0x0a => Self::OriginalUnicastNpdu,
            0x0b => Self::OriginalBroadcastNpdu,
            0x0c => Self::SecureBvll,
            _ => return None,
        })
    }

    /// Les fonctions qui portent un NPDU.
    fn carries_npdu(self) -> bool {
        matches!(
            self,
            Self::ForwardedNpdu
                | Self::DistributeBroadcastToNetwork
                | Self::OriginalUnicastNpdu
                | Self::OriginalBroadcastNpdu
        )
    }
}

/// En-tete BVLC (annexe J.2).
///
/// ```mermaid
/// ---
/// title: BvlcHeader
/// ---
/// packet-beta
/// 0-7: "Type 0x81"
/// 8-15: "Function u8"
/// 16-31: "Length u16 (whole datagram)"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct BvlcHeader {
    pub function: u8,
    pub kind: BvlcFunction,
    pub length: u16,
}

/// Adresse reseau BACnet (clause 6.2.2) : numero de reseau et adresse MAC
/// de longueur variable (vide pour un broadcast).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct NetworkAddress<'a> {
    pub network: u16,
    pub address: &'a [u8],
}

/// Types d'APDU (clause 20.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ApduType {
    ConfirmedRequest,
    UnconfirmedRequest,
    SimpleAck,
    ComplexAck,
    SegmentAck,
    Error,
    Reject,
    Abort,
}

impl ApduType {
    fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0 => Self::ConfirmedRequest,
            1 => Self::UnconfirmedRequest,
            2 => Self::SimpleAck,
            3 => Self::ComplexAck,
            4 => Self::SegmentAck,
            5 => Self::Error,
            6 => Self::Reject,
            7 => Self::Abort,
            _ => return None,
        })
    }
}

/// Services confirmes (clause 21, BACnetConfirmedServiceChoice).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ConfirmedService {
    AcknowledgeAlarm,
    ConfirmedCovNotification,
    ConfirmedEventNotification,
    GetAlarmSummary,
    GetEnrollmentSummary,
    SubscribeCov,
    AtomicReadFile,
    AtomicWriteFile,
    AddListElement,
    RemoveListElement,
    CreateObject,
    DeleteObject,
    ReadProperty,
    ReadPropertyConditional,
    ReadPropertyMultiple,
    WriteProperty,
    WritePropertyMultiple,
    DeviceCommunicationControl,
    ConfirmedPrivateTransfer,
    ConfirmedTextMessage,
    ReinitializeDevice,
    VtOpen,
    VtClose,
    VtData,
    Authenticate,
    RequestKey,
    ReadRange,
    LifeSafetyOperation,
    SubscribeCovProperty,
    GetEventInformation,
    SubscribeCovPropertyMultiple,
    ConfirmedCovNotificationMultiple,
    ConfirmedAuditNotification,
    AuditLogQuery,
}

impl ConfirmedService {
    pub fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0 => Self::AcknowledgeAlarm,
            1 => Self::ConfirmedCovNotification,
            2 => Self::ConfirmedEventNotification,
            3 => Self::GetAlarmSummary,
            4 => Self::GetEnrollmentSummary,
            5 => Self::SubscribeCov,
            6 => Self::AtomicReadFile,
            7 => Self::AtomicWriteFile,
            8 => Self::AddListElement,
            9 => Self::RemoveListElement,
            10 => Self::CreateObject,
            11 => Self::DeleteObject,
            12 => Self::ReadProperty,
            13 => Self::ReadPropertyConditional,
            14 => Self::ReadPropertyMultiple,
            15 => Self::WriteProperty,
            16 => Self::WritePropertyMultiple,
            17 => Self::DeviceCommunicationControl,
            18 => Self::ConfirmedPrivateTransfer,
            19 => Self::ConfirmedTextMessage,
            20 => Self::ReinitializeDevice,
            21 => Self::VtOpen,
            22 => Self::VtClose,
            23 => Self::VtData,
            24 => Self::Authenticate,
            25 => Self::RequestKey,
            26 => Self::ReadRange,
            27 => Self::LifeSafetyOperation,
            28 => Self::SubscribeCovProperty,
            29 => Self::GetEventInformation,
            30 => Self::SubscribeCovPropertyMultiple,
            31 => Self::ConfirmedCovNotificationMultiple,
            32 => Self::ConfirmedAuditNotification,
            33 => Self::AuditLogQuery,
            _ => return None,
        })
    }
}

/// Services non confirmes (clause 21, BACnetUnconfirmedServiceChoice).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum UnconfirmedService {
    IAm,
    IHave,
    UnconfirmedCovNotification,
    UnconfirmedEventNotification,
    UnconfirmedPrivateTransfer,
    UnconfirmedTextMessage,
    TimeSynchronization,
    WhoHas,
    WhoIs,
    UtcTimeSynchronization,
    WriteGroup,
    UnconfirmedCovNotificationMultiple,
    UnconfirmedAuditNotification,
    WhoAmI,
    YouAre,
}

impl UnconfirmedService {
    pub fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0 => Self::IAm,
            1 => Self::IHave,
            2 => Self::UnconfirmedCovNotification,
            3 => Self::UnconfirmedEventNotification,
            4 => Self::UnconfirmedPrivateTransfer,
            5 => Self::UnconfirmedTextMessage,
            6 => Self::TimeSynchronization,
            7 => Self::WhoHas,
            8 => Self::WhoIs,
            9 => Self::UtcTimeSynchronization,
            10 => Self::WriteGroup,
            11 => Self::UnconfirmedCovNotificationMultiple,
            12 => Self::UnconfirmedAuditNotification,
            13 => Self::WhoAmI,
            14 => Self::YouAre,
            _ => return None,
        })
    }
}

/// Un APDU (clause 20.1) : type, drapeaux, identifiant d'invocation,
/// service ou motif, segmentation, puis les donnees du service telles
/// quelles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Apdu<'a> {
    pub apdu_type: u8,
    pub kind: ApduType,
    /// Le quartet bas du premier octet : SEG 0x08, MOR 0x04, SA 0x02 pour
    /// les requetes confirmees et les reponses complexes ; NAK 0x02, SRV
    /// 0x01 pour les acquittements de segment ; SRV 0x01 pour les abandons.
    pub flags: u8,
    /// Absent des requetes non confirmees.
    pub invoke_id: Option<u8>,
    /// Requete confirmee : segments et taille d'APDU acceptes (octet brut).
    pub max_segments_and_apdu: Option<u8>,
    /// Numero de sequence et fenetre, pour les PDU segmentes et les
    /// acquittements de segment.
    pub segment: Option<(u8, u8)>,
    /// Choix de service des requetes, acquittements et erreurs.
    pub service: Option<u8>,
    /// Motif d'un rejet ou d'un abandon.
    pub reason: Option<u8>,
    /// Les donnees du service, codees par etiquettes.
    pub data: &'a [u8],
}

impl Apdu<'_> {
    pub fn confirmed_service(&self) -> Option<ConfirmedService> {
        match self.kind {
            ApduType::ConfirmedRequest
            | ApduType::SimpleAck
            | ApduType::ComplexAck
            | ApduType::Error => ConfirmedService::from_code(self.service?),
            _ => None,
        }
    }

    pub fn unconfirmed_service(&self) -> Option<UnconfirmedService> {
        match self.kind {
            ApduType::UnconfirmedRequest => UnconfirmedService::from_code(self.service?),
            _ => None,
        }
    }
}

/// Ce que porte le NPDU : un message de la couche reseau ou un APDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NpduMessage<'a> {
    /// Message reseau (clause 6.4) : type, identifiant de vendeur pour les
    /// types proprietaires (0x80 et plus), donnees.
    Network {
        message_type: u8,
        vendor_id: Option<u16>,
        data: &'a [u8],
    },
    Apdu(Apdu<'a>),
}

/// NPDU (clause 6.2).
///
/// ```mermaid
/// ---
/// title: Npdu
/// ---
/// packet-beta
/// 0-7: "Version 1"
/// 8-15: "Control u8"
/// 16-31: "DNET u16 (if control bit 5)"
/// 32-39: "DLEN u8"
/// 40-55: "DADR (DLEN bytes)"
/// 56-71: "SNET u16 (if control bit 3)"
/// 72-79: "SLEN u8"
/// 80-95: "SADR (SLEN bytes)"
/// 96-103: "Hop count (if DNET)"
/// 104-127: "Network message or APDU"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Npdu<'a> {
    pub version: u8,
    pub control: u8,
    pub destination: Option<NetworkAddress<'a>>,
    pub source: Option<NetworkAddress<'a>>,
    pub hop_count: Option<u8>,
    pub message: NpduMessage<'a>,
}

impl Npdu<'_> {
    pub fn expecting_reply(&self) -> bool {
        self.control & NPDU_CONTROL_EXPECTING_REPLY != 0
    }

    /// 0 normal, 1 urgent, 2 critical equipment, 3 life safety.
    pub fn priority(&self) -> u8 {
        self.control & NPDU_CONTROL_PRIORITY
    }
}

/// Un datagramme BACnet/IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct BacnetPacket<'a> {
    pub bvlc: BvlcHeader,
    /// Forwarded-NPDU : l'adresse IP et le port de l'emetteur d'origine.
    pub forwarded_from: Option<(Ipv4Addr, u16)>,
    /// Present pour les fonctions qui transportent un NPDU.
    pub npdu: Option<Npdu<'a>>,
    /// Le corps BVLC apres l'en-tete (et l'origine d'un Forwarded-NPDU) :
    /// le NPDU, ou les donnees des autres fonctions (code de resultat,
    /// duree de vie, tables de distribution).
    pub body: &'a [u8],
}

impl<'a> TryFrom<&'a [u8]> for BacnetPacket<'a> {
    type Error = BacnetParseError;

    fn try_from(payload: &'a [u8]) -> Result<Self, Self::Error> {
        ensure_len(payload, BVLC_HEADER_LENGTH)?;
        validate_bvlc_type(payload[0])?;
        validate_bvlc_function(payload[1])?;
        let kind = BvlcFunction::from_code(payload[1])
            .ok_or(BacnetParseError::UnknownBvlcFunction(payload[1]))?;
        let length = u16::from_be_bytes([payload[2], payload[3]]);
        validate_bvlc_length(length, payload.len())?;
        let bvlc = BvlcHeader {
            function: payload[1],
            kind,
            length,
        };
        let mut body = &payload[BVLC_HEADER_LENGTH..];
        let mut forwarded_from = None;
        if kind == BvlcFunction::ForwardedNpdu {
            ensure_len(body, 6)?;
            forwarded_from = Some((
                Ipv4Addr::new(body[0], body[1], body[2], body[3]),
                u16::from_be_bytes([body[4], body[5]]),
            ));
            body = &body[6..];
        }
        let npdu = if kind.carries_npdu() {
            Some(parse_npdu(body)?)
        } else {
            None
        };
        Ok(BacnetPacket {
            bvlc,
            forwarded_from,
            npdu,
            body,
        })
    }
}

fn parse_npdu(bytes: &[u8]) -> Result<Npdu<'_>, BacnetParseError> {
    ensure_len(bytes, NPDU_HEADER_LENGTH)?;
    validate_npdu_version(bytes[0])?;
    let control = bytes[1];
    let mut offset = NPDU_HEADER_LENGTH;
    let mut destination = None;
    if control & NPDU_CONTROL_DESTINATION != 0 {
        let (address, consumed) = network_address(&bytes[offset..])?;
        destination = Some(address);
        offset += consumed;
    }
    let mut source = None;
    if control & NPDU_CONTROL_SOURCE != 0 {
        let (address, consumed) = network_address(&bytes[offset..])?;
        source = Some(address);
        offset += consumed;
    }
    let mut hop_count = None;
    if destination.is_some() {
        ensure_len(bytes, offset + 1)?;
        hop_count = Some(bytes[offset]);
        offset += 1;
    }
    let rest = &bytes[offset..];
    let message = if control & NPDU_CONTROL_NETWORK_MESSAGE != 0 {
        ensure_len(rest, 1)?;
        let message_type = rest[0];
        let (vendor_id, data) = if message_type >= 0x80 {
            ensure_len(rest, 3)?;
            (Some(u16::from_be_bytes([rest[1], rest[2]])), &rest[3..])
        } else {
            (None, &rest[1..])
        };
        NpduMessage::Network {
            message_type,
            vendor_id,
            data,
        }
    } else {
        NpduMessage::Apdu(parse_apdu(rest)?)
    };
    Ok(Npdu {
        version: bytes[0],
        control,
        destination,
        source,
        hop_count,
        message,
    })
}

/// Numero de reseau, longueur d'adresse, adresse (clause 6.2.2).
fn network_address(bytes: &[u8]) -> Result<(NetworkAddress<'_>, usize), BacnetParseError> {
    ensure_len(bytes, 3)?;
    let len = usize::from(bytes[2]);
    ensure_len(bytes, 3 + len)?;
    Ok((
        NetworkAddress {
            network: u16::from_be_bytes([bytes[0], bytes[1]]),
            address: &bytes[3..3 + len],
        },
        3 + len,
    ))
}

fn parse_apdu(bytes: &[u8]) -> Result<Apdu<'_>, BacnetParseError> {
    ensure_len(bytes, 1)?;
    let apdu_type = extract_apdu_type(bytes[0])?;
    let kind =
        ApduType::from_code(apdu_type).ok_or(BacnetParseError::UnknownApduType(apdu_type))?;
    let flags = bytes[0] & 0x0f;
    let segmented = flags & 0x08 != 0;
    let mut apdu = Apdu {
        apdu_type,
        kind,
        flags,
        invoke_id: None,
        max_segments_and_apdu: None,
        segment: None,
        service: None,
        reason: None,
        data: &[],
    };
    let mut offset = 1;
    let mut take = |n: usize| -> Result<&[u8], BacnetParseError> {
        ensure_len(bytes, offset + n)?;
        let field = &bytes[offset..offset + n];
        offset += n;
        Ok(field)
    };
    match kind {
        ApduType::ConfirmedRequest => {
            let fixed = take(2)?;
            apdu.max_segments_and_apdu = Some(fixed[0]);
            apdu.invoke_id = Some(fixed[1]);
            if segmented {
                let segment = take(2)?;
                apdu.segment = Some((segment[0], segment[1]));
            }
            apdu.service = Some(take(1)?[0]);
        }
        ApduType::UnconfirmedRequest => {
            apdu.service = Some(take(1)?[0]);
        }
        ApduType::SimpleAck | ApduType::Error => {
            let fixed = take(2)?;
            apdu.invoke_id = Some(fixed[0]);
            apdu.service = Some(fixed[1]);
        }
        ApduType::ComplexAck => {
            apdu.invoke_id = Some(take(1)?[0]);
            if segmented {
                let segment = take(2)?;
                apdu.segment = Some((segment[0], segment[1]));
            }
            apdu.service = Some(take(1)?[0]);
        }
        ApduType::SegmentAck => {
            let fixed = take(3)?;
            apdu.invoke_id = Some(fixed[0]);
            apdu.segment = Some((fixed[1], fixed[2]));
        }
        ApduType::Reject | ApduType::Abort => {
            let fixed = take(2)?;
            apdu.invoke_id = Some(fixed[0]);
            apdu.reason = Some(fixed[1]);
        }
    }
    apdu.data = &bytes[offset..];
    Ok(apdu)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// pcaps_exemple/protocols/bacnet/iti_bacnet_test.pcap, trame 3 : un
    /// readProperty (service 12) unicast, invocation 1 (tshark 4.6.6).
    const READ_PROPERTY: &str = "810a001101040005010c0c023fffff194b";
    /// Trame 4 : la reponse complexe, meme invocation et service.
    const COMPLEX_ACK: &str = "810a0017010030010c0c023fffff194b3ec4020001f43f";
    /// Trames 21, 22, 25 : lecture de table de distribution, resultat,
    /// enregistrement de dispositif etranger.
    const READ_BDT: &str = "81020004";
    const RESULT: &str = "810000060020";
    const REGISTER_FOREIGN_DEVICE: &str = "810500060010";
    /// pcaps_exemple/protocols/bacnet/ndpi_bacnet.pcap, trame 10 : Who-Is
    /// en broadcast vers le reseau 65535, compte de sauts 255.
    const WHO_IS: &str = "810b000c0120ffff00ff1008";
    /// Trame 22 : message reseau I-Am-Router-To-Network (0x01).
    const NETWORK_MESSAGE: &str = "810b000d01a0ffff00ff010000";

    #[test]
    fn test_read_property_and_complex_ack_against_tshark() {
        let bytes = hex::decode(READ_PROPERTY).unwrap();
        let packet = BacnetPacket::try_from(bytes.as_slice()).expect("readProperty");
        assert_eq!(packet.bvlc.kind, BvlcFunction::OriginalUnicastNpdu);
        assert_eq!((packet.bvlc.function, packet.bvlc.length), (0x0a, 17));
        assert_eq!(packet.forwarded_from, None);
        let npdu = packet.npdu.expect("NPDU");
        assert_eq!((npdu.version, npdu.control), (1, 0x04));
        assert!(npdu.expecting_reply());
        assert_eq!(npdu.priority(), 0);
        assert_eq!(
            (npdu.destination, npdu.source, npdu.hop_count),
            (None, None, None)
        );
        let NpduMessage::Apdu(apdu) = npdu.message else {
            panic!("APDU attendu");
        };
        assert_eq!(apdu.kind, ApduType::ConfirmedRequest);
        assert_eq!(apdu.flags, 0);
        assert_eq!(apdu.max_segments_and_apdu, Some(0x05));
        assert_eq!(apdu.invoke_id, Some(1));
        assert_eq!(apdu.service, Some(12));
        assert_eq!(
            apdu.confirmed_service(),
            Some(ConfirmedService::ReadProperty)
        );
        assert_eq!(apdu.unconfirmed_service(), None);
        assert_eq!(apdu.data, &[0x0c, 0x02, 0x3f, 0xff, 0xff, 0x19, 0x4b]);
        assert!(bytes.as_ptr_range().contains(&apdu.data.as_ptr()));

        let bytes = hex::decode(COMPLEX_ACK).unwrap();
        let packet = BacnetPacket::try_from(bytes.as_slice()).expect("ComplexACK");
        let NpduMessage::Apdu(apdu) = packet.npdu.unwrap().message else {
            panic!("APDU attendu");
        };
        assert_eq!(apdu.kind, ApduType::ComplexAck);
        assert_eq!((apdu.invoke_id, apdu.service), (Some(1), Some(12)));
        assert_eq!(apdu.segment, None);
        assert_eq!(apdu.data.len(), 14);
    }

    #[test]
    fn test_bvlc_functions_without_npdu() {
        for (hex, kind, body) in [
            (
                READ_BDT,
                BvlcFunction::ReadBroadcastDistributionTable,
                &[][..],
            ),
            (RESULT, BvlcFunction::Result, &[0x00, 0x20][..]),
            (
                REGISTER_FOREIGN_DEVICE,
                BvlcFunction::RegisterForeignDevice,
                &[0x00, 0x10][..],
            ),
        ] {
            let bytes = hex::decode(hex).unwrap();
            let packet = BacnetPacket::try_from(bytes.as_slice()).expect(hex);
            assert_eq!(packet.bvlc.kind, kind);
            assert_eq!(packet.npdu, None);
            assert_eq!(packet.body, body);
        }
    }

    #[test]
    fn test_broadcast_who_is_and_network_message() {
        let bytes = hex::decode(WHO_IS).unwrap();
        let packet = BacnetPacket::try_from(bytes.as_slice()).expect("Who-Is");
        assert_eq!(packet.bvlc.kind, BvlcFunction::OriginalBroadcastNpdu);
        let npdu = packet.npdu.unwrap();
        assert_eq!(npdu.control, 0x20);
        assert_eq!(
            npdu.destination,
            Some(NetworkAddress {
                network: 65535,
                address: &[]
            })
        );
        assert_eq!(npdu.source, None);
        assert_eq!(npdu.hop_count, Some(255));
        let NpduMessage::Apdu(apdu) = npdu.message else {
            panic!("APDU attendu");
        };
        assert_eq!(apdu.kind, ApduType::UnconfirmedRequest);
        assert_eq!(apdu.invoke_id, None);
        assert_eq!(apdu.unconfirmed_service(), Some(UnconfirmedService::WhoIs));
        assert!(apdu.data.is_empty());

        let bytes = hex::decode(NETWORK_MESSAGE).unwrap();
        let packet = BacnetPacket::try_from(bytes.as_slice()).expect("message reseau");
        let npdu = packet.npdu.unwrap();
        assert_eq!(npdu.control, 0xa0);
        assert_eq!(
            npdu.message,
            NpduMessage::Network {
                message_type: 0x01,
                vendor_id: None,
                data: &[0x00, 0x00]
            }
        );
    }

    /// Un Forwarded-NPDU synthetique autour du readProperty reel, et un
    /// message reseau proprietaire avec son identifiant de vendeur.
    #[test]
    fn test_forwarded_npdu_and_vendor_message() {
        let inner = hex::decode(READ_PROPERTY).unwrap();
        let mut forwarded = vec![0x81, 0x04, 0, 0, 192, 168, 1, 10, 0xba, 0xc0];
        forwarded.extend_from_slice(&inner[4..]);
        let len = forwarded.len() as u16;
        forwarded[2..4].copy_from_slice(&len.to_be_bytes());
        let packet = BacnetPacket::try_from(forwarded.as_slice()).expect("Forwarded-NPDU");
        assert_eq!(packet.bvlc.kind, BvlcFunction::ForwardedNpdu);
        assert_eq!(
            packet.forwarded_from,
            Some((Ipv4Addr::new(192, 168, 1, 10), 47808))
        );
        let NpduMessage::Apdu(apdu) = packet.npdu.unwrap().message else {
            panic!("APDU attendu");
        };
        assert_eq!(
            apdu.confirmed_service(),
            Some(ConfirmedService::ReadProperty)
        );

        let vendor = [0x81, 0x0a, 0x00, 0x0a, 0x01, 0x80, 0x90, 0x01, 0x05, 0xaa];
        let packet = BacnetPacket::try_from(&vendor[..]).expect("message vendeur");
        assert_eq!(
            packet.npdu.unwrap().message,
            NpduMessage::Network {
                message_type: 0x90,
                vendor_id: Some(0x0105),
                data: &[0xaa]
            }
        );
    }

    #[test]
    fn test_rejections() {
        let bytes = hex::decode(READ_PROPERTY).unwrap();
        let mut bvlc_type = bytes.clone();
        bvlc_type[0] = 0x82;
        assert_eq!(
            BacnetPacket::try_from(bvlc_type.as_slice()),
            Err(BacnetParseError::InvalidBvlcType(0x82))
        );
        let mut function = bytes.clone();
        function[1] = 0x0d;
        assert_eq!(
            BacnetPacket::try_from(function.as_slice()),
            Err(BacnetParseError::UnknownBvlcFunction(0x0d))
        );
        assert_eq!(
            BacnetPacket::try_from(&bytes[..16]),
            Err(BacnetParseError::LengthMismatch {
                declared: 17,
                actual: 16
            })
        );
        let mut version = bytes.clone();
        version[4] = 2;
        assert_eq!(
            BacnetPacket::try_from(version.as_slice()),
            Err(BacnetParseError::UnsupportedNpduVersion(2))
        );
        let mut apdu_type = bytes.clone();
        apdu_type[6] = 0x80;
        assert_eq!(
            BacnetPacket::try_from(apdu_type.as_slice()),
            Err(BacnetParseError::UnknownApduType(8))
        );
        // Un readProperty coupe avant son service.
        let mut short = bytes[..8].to_vec();
        short[2..4].copy_from_slice(&8u16.to_be_bytes());
        assert_eq!(
            BacnetPacket::try_from(short.as_slice()),
            Err(BacnetParseError::Truncated {
                expected: 3,
                actual: 2
            })
        );
        assert_eq!(
            BacnetPacket::try_from(&b"\x81\x0a\x00"[..]),
            Err(BacnetParseError::Truncated {
                expected: 4,
                actual: 3
            })
        );
    }
}
