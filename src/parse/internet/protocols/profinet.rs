// Copyright (c) 2024 Cyprien Avico <avicocyprien@yahoo.com>
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! PROFINET (IEC 61158-6-10) sur Ethernet, EtherType `0x8892`.
//!
//! Toute trame PROFINET RT commence par un **Frame ID** de deux octets, dont
//! la plage dit ce qu'elle porte : donnees cycliques RT_CLASS_1 ou
//! RT_CLASS_3, alarmes, synchronisation PTCP, fragments, ou un message
//! **DCP** (Discovery and basic Configuration Protocol, Frame ID `0xFEFC` a
//! `0xFEFF`). Les plages sont celles du dissecteur `pn_rt` de Wireshark
//! (`plugins/epan/profinet/packet-pn-rt.c`), hors mode time-aware.
//!
//! Deux niveaux :
//!
//! - [`validate_frame`] est ce que la couche internet applique a toute trame
//!   `0x8892` : le Frame ID doit etre attribue, et un Frame ID DCP doit
//!   porter un message DCP lisible. Une trame cyclique, une alarme, une
//!   trame PTCP ou un fragment sont valides par leur seul Frame ID (issue
//!   #133) ;
//! - [`ProfinetPacket`] decode un message DCP : l'en-tete fixe, puis tous
//!   ses blocs, avec le BlockInfo des reponses et le BlockQualifier d'une
//!   requete Set mis a part, et le NameOfStation pris dans le bloc qui le
//!   porte, option 2 / suboption 2 (issue #141).

use serde::Serialize;
use std::convert::TryFrom;

use crate::{
    checks::internet::profinet::{
        DCP_BLOCK_HEADER_LEN, extract_dcp_block_header, extract_dcp_blocks_data,
        extract_name_of_station, validate_dcp_block_fits, validate_dcp_block_prefix,
        validate_frame_id, validate_packet_length,
    },
    errors::internet::profinet::ProfinetPacketError,
};

/// Classe d'un Frame ID PROFINET RT (IEC 61158-6-10). Le discriminant est le
/// debut de la plage ; [`FrameId::from_u16`] classe une valeur, et rend
/// `None` pour une valeur reservee.
#[repr(u16)]
#[derive(Debug, Serialize, Clone, Eq, PartialEq, Hash, Default)]
#[non_exhaustive]
pub enum FrameId {
    /// `0xC000`–`0xF7FF` : donnees cycliques RT_CLASS_1 / RT_CLASS_UDP, unicast.
    #[default]
    Unicast = 0xC000,
    /// `0xF800`–`0xFBFF` : donnees cycliques RT_CLASS_1 / RT_CLASS_UDP, multicast.
    Multicast = 0xF800,
    /// `0xFEFD` : DCP Get ou Set, requete ou reponse.
    GetReqSetReqGetRespSetResp = 0xFEFD,
    /// `0xFEFE` : DCP Identify request (multicast).
    IdentifyReq = 0xFEFE,
    /// `0xFEFF` : DCP Identify response.
    IdentifyResp = 0xFEFF,
    /// `0x0020`–`0x0021` et `0x0080`–`0x0081` : PTCP RTSync, avec et sans Follow Up.
    Sync = 0x0020,
    /// `0x0100`–`0x0FFF` : donnees cycliques RT_CLASS_3 (IRT).
    RtClass3 = 0x0100,
    /// `0x8000`–`0xBBFF` : donnees cycliques RT_CLASS_1, unicast.
    RtClass1Unicast = 0x8000,
    /// `0xBC00`–`0xBFFF` : donnees cycliques RT_CLASS_1, multicast.
    RtClass1Multicast = 0xBC00,
    /// `0xFC01` (`0xFC41` avec securite) : alarme PN-IO haute priorite.
    AlarmHigh = 0xFC01,
    /// `0xFE01` (`0xFE41` avec securite) : alarme PN-IO basse priorite.
    AlarmLow = 0xFE01,
    /// `0xFE02` (`0xFE42` avec securite) : RSI (Remote Service Interface).
    Rsi = 0xFE02,
    /// `0xFE03` : SXP via RTAv3.
    Sxp = 0xFE03,
    /// `0xFEFC` : DCP Hello.
    Hello = 0xFEFC,
    /// `0xFF00`–`0xFF01` : PTCP Announce.
    PtcpAnnounce = 0xFF00,
    /// `0xFF20`–`0xFF21` : PTCP Follow Up.
    PtcpFollowUp = 0xFF20,
    /// `0xFF40`–`0xFF43` : PTCP Delay (requete et reponses).
    PtcpDelay = 0xFF40,
    /// `0xFF80`–`0xFF8F` : fragment d'une trame RT.
    Fragment = 0xFF80,
}

impl FrameId {
    /// Classe un Frame ID ; `None` pour une valeur reservee.
    pub fn from_u16(value: u16) -> Option<FrameId> {
        match value {
            0x0020..=0x0021 | 0x0080..=0x0081 => Some(FrameId::Sync),
            0x0100..=0x0FFF => Some(FrameId::RtClass3),
            0x8000..=0xBBFF => Some(FrameId::RtClass1Unicast),
            0xBC00..=0xBFFF => Some(FrameId::RtClass1Multicast),
            0xC000..=0xF7FF => Some(FrameId::Unicast),
            0xF800..=0xFBFF => Some(FrameId::Multicast),
            0xFC01 | 0xFC41 => Some(FrameId::AlarmHigh),
            0xFE01 | 0xFE41 => Some(FrameId::AlarmLow),
            0xFE02 | 0xFE42 => Some(FrameId::Rsi),
            0xFE03 => Some(FrameId::Sxp),
            0xFEFC => Some(FrameId::Hello),
            0xFEFD => Some(FrameId::GetReqSetReqGetRespSetResp),
            0xFEFE => Some(FrameId::IdentifyReq),
            0xFEFF => Some(FrameId::IdentifyResp),
            0xFF00..=0xFF01 => Some(FrameId::PtcpAnnounce),
            0xFF20..=0xFF21 => Some(FrameId::PtcpFollowUp),
            0xFF40..=0xFF43 => Some(FrameId::PtcpDelay),
            0xFF80..=0xFF8F => Some(FrameId::Fragment),
            _ => None,
        }
    }

    /// Les quatre Frame ID DCP : la trame porte un message que
    /// [`ProfinetPacket`] decode.
    pub const fn is_dcp(&self) -> bool {
        matches!(
            self,
            FrameId::Hello
                | FrameId::GetReqSetReqGetRespSetResp
                | FrameId::IdentifyReq
                | FrameId::IdentifyResp
        )
    }
}

/// ServiceID DCP.
pub const DCP_SERVICE_GET: u8 = 3;
pub const DCP_SERVICE_SET: u8 = 4;
pub const DCP_SERVICE_IDENTIFY: u8 = 5;
pub const DCP_SERVICE_HELLO: u8 = 6;
/// ServiceType d'une requete ; une reponse vaut 1 (succes) ou 5 (non supporte).
pub const DCP_SERVICE_TYPE_REQUEST: u8 = 0;

/// Un bloc DCP : option, suboption, et ses donnees.
///
/// Le BlockInfo (deux octets en tete des blocs d'une reponse Identify ou Get
/// et d'une requete Hello) et le BlockQualifier (deux octets en tete des
/// blocs d'une requete Set) sont mis a part dans `qualifier` : `data` est ce
/// qui suit. Un bloc de longueur impaire est suivi d'un octet de bourrage,
/// qui n'apparait ni dans `data` ni dans `block_length`.
#[derive(Debug, Serialize, Clone, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub struct DcpBlock<'a> {
    pub option: u8,
    pub suboption: u8,
    /// DCPBlockLength tel qu'annonce, BlockInfo ou BlockQualifier compris.
    pub block_length: u16,
    /// BlockInfo ou BlockQualifier selon le service ; `None` quand le
    /// service n'en met pas (filtres d'une Identify request, reponse Set...).
    pub qualifier: Option<u16>,
    /// Les donnees du bloc, apres le BlockInfo ou le BlockQualifier.
    pub data: &'a [u8],
}

impl DcpBlock<'_> {
    /// Option 2 / suboption 2 : le bloc NameOfStation.
    pub const fn is_name_of_station(&self) -> bool {
        self.option == 2 && self.suboption == 2
    }
}

/// Un message DCP (Frame ID `0xFEFC` a `0xFEFF`) : l'en-tete fixe et ses
/// blocs.
#[derive(Debug, Default, Serialize, Clone, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub struct ProfinetPacket<'a> {
    pub frame_id: FrameId,
    pub service_id: u8,
    pub service_type: u8,
    pub xid: u32,
    pub response_delay: u16,
    pub dcp_data_length: u16,
    /// Option du premier bloc, 0 sans bloc. Conserve pour compatibilite :
    /// `blocks` porte tous les blocs.
    pub option: u8,
    /// Suboption du premier bloc, 0 sans bloc.
    pub suboption: u8,
    /// DCPBlockLength du premier bloc, 0 sans bloc.
    pub dcp_block_length: u16,
    /// Le NameOfStation du message (bloc option 2 / suboption 2), vide quand
    /// le message n'en porte pas.
    pub name_of_station: &'a str,
    /// Tous les blocs, dans l'ordre du message.
    pub blocks: Vec<DcpBlock<'a>>,
}

/// Valide une trame PROFINET RT telle qu'elle suit l'EtherType `0x8892` :
/// son Frame ID doit etre attribue, et un Frame ID DCP doit porter un
/// message DCP lisible. Rend la classe du Frame ID.
pub fn validate_frame(data: &[u8]) -> Result<FrameId, ProfinetPacketError> {
    let frame_id = validate_frame_id(data)?;
    if frame_id.is_dcp() {
        ProfinetPacket::try_from(data)?;
    }
    Ok(frame_id)
}

impl<'a> TryFrom<&'a [u8]> for ProfinetPacket<'a> {
    type Error = ProfinetPacketError;

    fn try_from(data: &'a [u8]) -> Result<Self, Self::Error> {
        validate_packet_length(data)?;
        let frame_id = validate_frame_id(data)?;
        if !frame_id.is_dcp() {
            return Err(ProfinetPacketError::NotDcp(u16::from_be_bytes([
                data[0], data[1],
            ])));
        }
        let service_id = data[2];
        let service_type = data[3];
        let xid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let response_delay = u16::from_be_bytes([data[8], data[9]]);
        let dcp_data_length = u16::from_be_bytes([data[10], data[11]]);
        let blocks_data = extract_dcp_blocks_data(data, dcp_data_length)?;
        let blocks = parse_dcp_blocks(blocks_data, service_id, service_type)?;
        let name_of_station = match blocks.iter().find(|block| block.is_name_of_station()) {
            Some(block) => extract_name_of_station(block.data)?,
            None => "",
        };
        let (option, suboption, dcp_block_length) = blocks.first().map_or((0, 0, 0), |block| {
            (block.option, block.suboption, block.block_length)
        });
        Ok(ProfinetPacket {
            frame_id,
            service_id,
            service_type,
            xid,
            response_delay,
            dcp_data_length,
            option,
            suboption,
            dcp_block_length,
            name_of_station,
            blocks,
        })
    }
}

/// Decoupe les blocs d'un message DCP. Le BlockInfo et le BlockQualifier
/// sont presents ou non selon le service, comme le dissecteur `pn_dcp` de
/// Wireshark les lit : BlockInfo dans les reponses Identify et Get et dans
/// une requete Hello, BlockQualifier dans une requete Set, rien ailleurs.
fn parse_dcp_blocks<'a>(
    mut rest: &'a [u8],
    service_id: u8,
    service_type: u8,
) -> Result<Vec<DcpBlock<'a>>, ProfinetPacketError> {
    let is_response = service_type != DCP_SERVICE_TYPE_REQUEST;
    let has_block_info = matches!(
        (service_id, is_response),
        (DCP_SERVICE_IDENTIFY, true) | (DCP_SERVICE_HELLO, false) | (DCP_SERVICE_GET, true)
    );
    let has_block_qualifier = service_id == DCP_SERVICE_SET && !is_response;
    let prefix: u16 = if has_block_info || has_block_qualifier {
        2
    } else {
        0
    };

    let mut blocks = Vec::new();
    while !rest.is_empty() {
        let (option, suboption, block_length) = extract_dcp_block_header(rest)?;
        let body = &rest[DCP_BLOCK_HEADER_LEN..];
        validate_dcp_block_fits(option, suboption, block_length, body.len())?;
        validate_dcp_block_prefix(option, suboption, block_length, prefix)?;
        let block = &body[..usize::from(block_length)];
        let (qualifier, data) = if prefix == 2 {
            (Some(u16::from_be_bytes([block[0], block[1]])), &block[2..])
        } else {
            (None, block)
        };
        blocks.push(DcpBlock {
            option,
            suboption,
            block_length,
            qualifier,
            data,
        });
        // Un bloc de longueur impaire est suivi d'un octet de bourrage,
        // compte dans DCPDataLength ; un emetteur qui l'omet en fin de
        // message n'est pas refuse.
        let mut consumed = DCP_BLOCK_HEADER_LEN + usize::from(block_length);
        if block_length % 2 == 1 && consumed < rest.len() {
            consumed += 1;
        }
        rest = &rest[consumed..];
    }
    Ok(blocks)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// En-tete DCP puis blocs, sans bourrage Ethernet.
    fn dcp(frame_id: u16, service_id: u8, service_type: u8, blocks: &[u8]) -> Vec<u8> {
        let mut data = frame_id.to_be_bytes().to_vec();
        data.extend_from_slice(&[service_id, service_type, 0x01, 0x00, 0x00, 0x01, 0x00, 0x80]);
        data.extend_from_slice(&(blocks.len() as u16).to_be_bytes());
        data.extend_from_slice(blocks);
        data
    }

    #[test]
    fn frame_ids_are_classed_by_range() {
        let cases = [
            (0x0020, Some(FrameId::Sync)),
            (0x0081, Some(FrameId::Sync)),
            (0x0100, Some(FrameId::RtClass3)),
            (0x0FFF, Some(FrameId::RtClass3)),
            (0x8000, Some(FrameId::RtClass1Unicast)),
            (0xBBFF, Some(FrameId::RtClass1Unicast)),
            (0xBC00, Some(FrameId::RtClass1Multicast)),
            (0xC000, Some(FrameId::Unicast)),
            (0xF7FF, Some(FrameId::Unicast)),
            (0xF800, Some(FrameId::Multicast)),
            (0xFBFF, Some(FrameId::Multicast)),
            (0xFC01, Some(FrameId::AlarmHigh)),
            (0xFC41, Some(FrameId::AlarmHigh)),
            (0xFE01, Some(FrameId::AlarmLow)),
            (0xFE02, Some(FrameId::Rsi)),
            (0xFE03, Some(FrameId::Sxp)),
            (0xFEFC, Some(FrameId::Hello)),
            (0xFEFD, Some(FrameId::GetReqSetReqGetRespSetResp)),
            (0xFEFE, Some(FrameId::IdentifyReq)),
            (0xFEFF, Some(FrameId::IdentifyResp)),
            (0xFF00, Some(FrameId::PtcpAnnounce)),
            (0xFF21, Some(FrameId::PtcpFollowUp)),
            (0xFF40, Some(FrameId::PtcpDelay)),
            (0xFF43, Some(FrameId::PtcpDelay)),
            (0xFF80, Some(FrameId::Fragment)),
            (0xFF8F, Some(FrameId::Fragment)),
            // reservees
            (0x0000, None),
            (0x0022, None),
            (0x1000, None),
            (0x7FFF, None),
            (0xFC00, None),
            (0xFE00, None),
            (0xFEFB, None),
            (0xFF02, None),
            (0xFF44, None),
            (0xFF90, None),
            (0xFFFF, None),
        ];
        for (value, expected) in cases {
            assert_eq!(FrameId::from_u16(value), expected, "{value:#06x}");
        }
        assert!(FrameId::Hello.is_dcp() && FrameId::IdentifyResp.is_dcp());
        assert!(!FrameId::Unicast.is_dcp() && !FrameId::PtcpDelay.is_dcp());
    }

    #[test]
    fn a_cyclic_frame_is_valid_by_its_frame_id_alone() {
        // RT_CLASS_1, 40 octets de donnees d'E/S a 0xFF : ni DCP, ni erreur.
        let mut data = vec![0x80, 0x00];
        data.extend_from_slice(&[0xff; 40]);
        assert_eq!(validate_frame(&data), Ok(FrameId::RtClass1Unicast));
        assert_eq!(
            ProfinetPacket::try_from(data.as_slice()),
            Err(ProfinetPacketError::NotDcp(0x8000))
        );
        // Deux octets suffisent ; un seul, non.
        assert_eq!(validate_frame(&[0xff, 0x40]), Ok(FrameId::PtcpDelay));
        assert_eq!(
            validate_frame(&[0xff]),
            Err(ProfinetPacketError::FrameTooShort(1))
        );
        assert_eq!(
            validate_frame(&[0x00, 0x00, 0x00]),
            Err(ProfinetPacketError::UnknownFrameId(0))
        );
    }

    #[test]
    fn identify_request_filter_has_no_block_info() {
        let data = dcp(
            0xFEFE,
            DCP_SERVICE_IDENTIFY,
            0,
            &[2, 2, 0, 4, b'p', b'l', b'c', b'1'],
        );
        let packet = ProfinetPacket::try_from(data.as_slice()).unwrap();
        assert_eq!(packet.frame_id, FrameId::IdentifyReq);
        assert_eq!(packet.service_id, DCP_SERVICE_IDENTIFY);
        assert_eq!(packet.dcp_data_length, 8);
        assert_eq!(packet.name_of_station, "plc1");
        assert_eq!(packet.blocks.len(), 1);
        assert_eq!(packet.blocks[0].qualifier, None);
        assert_eq!(packet.blocks[0].data, b"plc1");
        assert_eq!(
            (packet.option, packet.suboption, packet.dcp_block_length),
            (2, 2, 4)
        );
        assert_eq!(validate_frame(&data), Ok(FrameId::IdentifyReq));
    }

    #[test]
    fn identify_response_blocks_carry_block_info() {
        // DeviceOptions (2/5), puis NameOfStation (2/2) de longueur impaire
        // suivi de son octet de bourrage, puis DeviceInitiative (6/1).
        let blocks = [
            2, 5, 0, 4, 0, 0, 2, 2, // DeviceOptions : BlockInfo 0, une option 2/2
            2, 2, 0, 5, 0, 0, b'p', b'l', b'c', 0, // NameOfStation "plc", bourrage
            6, 1, 0, 4, 0, 0, 0, 1, // DeviceInitiative : BlockInfo 0, valeur 1
        ];
        let data = dcp(0xFEFF, DCP_SERVICE_IDENTIFY, 1, &blocks);
        let packet = ProfinetPacket::try_from(data.as_slice()).unwrap();
        assert_eq!(packet.name_of_station, "plc");
        assert_eq!(packet.blocks.len(), 3);
        assert_eq!(packet.blocks[0].qualifier, Some(0));
        assert_eq!(packet.blocks[0].data, &[2, 2]);
        assert_eq!(packet.blocks[1].block_length, 5);
        assert_eq!(packet.blocks[1].data, b"plc");
        assert_eq!(packet.blocks[2].data, &[0, 1]);
        // Le premier bloc n'est pas le NameOfStation : les champs de
        // compatibilite le disent, le nom vient du bon bloc.
        assert_eq!((packet.option, packet.suboption), (2, 5));
    }

    #[test]
    fn set_request_blocks_carry_a_qualifier_and_hello_a_block_info() {
        // Set request : bloc IP (1/2) avec BlockQualifier 1, puis NameOfStation.
        let blocks = [
            1, 2, 0, 14, 0, 1, 192, 168, 0, 10, 255, 255, 255, 0, 192, 168, 0, 1, 2, 2, 0, 6, 0, 1,
            b'p', b'l', b'c', b'1',
        ];
        let data = dcp(0xFEFD, DCP_SERVICE_SET, 0, &blocks);
        let packet = ProfinetPacket::try_from(data.as_slice()).unwrap();
        assert_eq!(packet.blocks[0].qualifier, Some(1));
        assert_eq!(
            packet.blocks[0].data,
            &[192, 168, 0, 10, 255, 255, 255, 0, 192, 168, 0, 1]
        );
        assert_eq!(packet.name_of_station, "plc1");
        // Hello request : BlockInfo, comme une reponse.
        let hello = dcp(
            0xFEFC,
            DCP_SERVICE_HELLO,
            0,
            &[2, 2, 0, 6, 0, 0, b'p', b'l', b'c', b'1'],
        );
        let packet = ProfinetPacket::try_from(hello.as_slice()).unwrap();
        assert_eq!(packet.frame_id, FrameId::Hello);
        assert_eq!(packet.name_of_station, "plc1");
        // Set response : bloc Control/Response sans prefixe.
        let response = dcp(0xFEFD, DCP_SERVICE_SET, 1, &[5, 4, 0, 3, 1, 2, 0, 0]);
        let packet = ProfinetPacket::try_from(response.as_slice()).unwrap();
        assert_eq!(packet.blocks[0].qualifier, None);
        assert_eq!(packet.blocks[0].data, &[1, 2, 0]);
        assert_eq!(packet.name_of_station, "");
    }

    #[test]
    fn dcp_hello_of_issue_133_is_valid() {
        let frame = [
            0xfe, 0xfc, 0x04, 0x00, 0x00, 0x00, 0x10, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x02, 0x02,
            0x00, 0x06, 0x00, 0x00, 0x70, 0x6c, 0x63, 0x31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(validate_frame(&frame), Ok(FrameId::Hello));
    }

    #[test]
    fn lengths_are_bounded() {
        // DCPDataLength au-dela de la trame.
        let mut data = dcp(0xFEFE, DCP_SERVICE_IDENTIFY, 0, &[0xff, 0xff, 0, 0]);
        data[11] = 6;
        assert_eq!(
            ProfinetPacket::try_from(data.as_slice()),
            Err(ProfinetPacketError::DcpDataOverflow {
                declared: 6,
                available: 4
            })
        );
        // DCPBlockLength au-dela des blocs.
        let data = dcp(
            0xFEFE,
            DCP_SERVICE_IDENTIFY,
            0,
            &[2, 2, 0, 9, b'p', b'l', b'c', b'1'],
        );
        assert_eq!(
            ProfinetPacket::try_from(data.as_slice()),
            Err(ProfinetPacketError::DcpBlockOverflow {
                option: 2,
                suboption: 2,
                declared: 9,
                available: 4
            })
        );
        // Un bloc de reponse trop court pour son BlockInfo.
        let data = dcp(0xFEFF, DCP_SERVICE_IDENTIFY, 1, &[2, 2, 0, 1, b'p', 0]);
        assert_eq!(
            ProfinetPacket::try_from(data.as_slice()),
            Err(ProfinetPacketError::DcpBlockTooShort {
                option: 2,
                suboption: 2,
                declared: 1,
                needed: 2
            })
        );
        // En-tete de bloc tronque, et en-tete DCP tronque.
        let data = dcp(0xFEFE, DCP_SERVICE_IDENTIFY, 0, &[2, 2, 0]);
        assert_eq!(
            ProfinetPacket::try_from(data.as_slice()),
            Err(ProfinetPacketError::InvalidDcpBlockLength(3))
        );
        assert_eq!(
            ProfinetPacket::try_from(&[0xfe, 0xfe, 5, 0][..]),
            Err(ProfinetPacketError::PacketTooShort(4))
        );
    }

    #[test]
    fn name_of_station_must_be_utf8_but_other_blocks_may_be_binary() {
        let data = dcp(
            0xFEFF,
            DCP_SERVICE_IDENTIFY,
            1,
            &[2, 2, 0, 4, 0, 0, 0xc0, 0xa8],
        );
        assert_eq!(
            ProfinetPacket::try_from(data.as_slice()),
            Err(ProfinetPacketError::InvalidNameOfStation)
        );
        let data = dcp(
            0xFEFF,
            DCP_SERVICE_IDENTIFY,
            1,
            &[1, 2, 0, 4, 0, 0, 0xc0, 0xa8],
        );
        assert_eq!(
            ProfinetPacket::try_from(data.as_slice())
                .unwrap()
                .name_of_station,
            ""
        );
    }

    #[test]
    fn a_message_without_block_decodes_to_no_block() {
        let data = dcp(0xFEFD, DCP_SERVICE_GET, 0, &[]);
        let packet = ProfinetPacket::try_from(data.as_slice()).unwrap();
        assert!(packet.blocks.is_empty());
        assert_eq!(
            (packet.option, packet.suboption, packet.dcp_block_length),
            (0, 0, 0)
        );
        assert_eq!(packet.name_of_station, "");
    }

    #[test]
    fn ethernet_padding_after_the_blocks_is_ignored() {
        // Comme sur le fil : trame de 60 octets, blocs puis zeros.
        let mut payload = dcp(0xFEFE, DCP_SERVICE_IDENTIFY, 0, &[0xff, 0xff, 0, 0]);
        payload.resize(46, 0);
        let packet = ProfinetPacket::try_from(payload.as_slice()).unwrap();
        assert_eq!(packet.blocks.len(), 1);
        assert_eq!((packet.option, packet.suboption), (0xff, 0xff));
        assert_eq!(packet.name_of_station, "");
    }
}
