// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! STANAG 5066 SIS, Subnetwork Interface Sublayer (annexe A de l'Ed. 4,
//! brouillon v1.6 publie par Isode) : la couche qui relie les applications
//! au noeud radio HF au-dela de l'horizon, sur TCP 5066. Elle transporte
//! notamment ACP 142 (P_MUL) et la messagerie STANAG 4406 annexe E.
//!
//! Chaque S_PDU commence par le preambule `90 EB`, un octet de version
//! (0), deux octets de taille de la primitive (type compris) et le type de
//! primitive (1 a 27). Le decodeur est **stateless** : il decode le premier
//! S_PDU du segment TCP. Un S_PDU qui deborde du segment est accepte et
//! marque [`SisPdu::truncated`] — ses champs fixes, presents dans le
//! premier segment, restent decodes et l'U_PDU est rendu tel qu'il est ;
//! un segment de continuation, sans preambule, n'est pas du SIS. Quand un
//! segment porte plusieurs S_PDU, [`SisPdu::consumed`] donne le debut du
//! suivant.

use core::fmt;
use std::convert::TryFrom;

use crate::{
    checks::application::stanag5066::{
        SIS_BIND_ACCEPTED, SIS_BIND_REJECTED, SIS_BIND_REQUEST, SIS_DATAFLOW_OFF, SIS_DATAFLOW_ON,
        SIS_EXPEDITED_UNIDATA_INDICATION, SIS_EXPEDITED_UNIDATA_REQUEST,
        SIS_EXPEDITED_UNIDATA_REQUEST_CONFIRM, SIS_EXPEDITED_UNIDATA_REQUEST_REJECTED,
        SIS_HARD_LINK_ACCEPT, SIS_HARD_LINK_ESTABLISH, SIS_HARD_LINK_ESTABLISHED,
        SIS_HARD_LINK_INDICATION, SIS_HARD_LINK_REJECT, SIS_HARD_LINK_REJECTED,
        SIS_HARD_LINK_TERMINATE, SIS_HARD_LINK_TERMINATED, SIS_HEADER_LENGTH, SIS_KEEP_ALIVE,
        SIS_MANAGEMENT_MESSAGE_INDICATION, SIS_MANAGEMENT_MESSAGE_REQUEST, SIS_SUBNET_AVAILABILITY,
        SIS_UNBIND_INDICATION, SIS_UNBIND_REQUEST, SIS_UNIDATA_INDICATION, SIS_UNIDATA_REQUEST,
        SIS_UNIDATA_REQUEST_CONFIRM, SIS_UNIDATA_REQUEST_REJECTED, ensure_len, extract_pdu_type,
        extract_primitive_size, extract_version, validate_preamble, validate_primitive_length,
        validate_trailer,
    },
    errors::application::stanag5066::Stanag5066ParseError,
};

/// En-tete d'un S_PDU (annexe A, §A.1).
///
/// ```mermaid
/// ---
/// title: SisHeader
/// ---
/// packet-beta
/// 0-15: "sync 0x90EB"
/// 16-23: "version u8 (0)"
/// 24-39: "S_Primitive size u16"
/// 40-47: "type u8"
/// 48-95: "primitive (size - 1 octets)"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SisHeader {
    pub version: u8,
    /// Taille de la primitive, type compris.
    pub primitive_size: u16,
    pub pdu_type: u8,
}

/// Type de S_PDU (annexe A, §A.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PduType {
    BindRequest,
    UnbindRequest,
    BindAccepted,
    BindRejected,
    UnbindIndication,
    HardLinkEstablish,
    HardLinkTerminate,
    HardLinkEstablished,
    HardLinkRejected,
    HardLinkTerminated,
    HardLinkIndication,
    HardLinkAccept,
    HardLinkReject,
    SubnetAvailability,
    DataflowOn,
    DataflowOff,
    KeepAlive,
    ManagementMessageRequest,
    ManagementMessageIndication,
    UnidataRequest,
    UnidataIndication,
    UnidataRequestConfirm,
    UnidataRequestRejected,
    ExpeditedUnidataRequest,
    ExpeditedUnidataIndication,
    ExpeditedUnidataRequestConfirm,
    ExpeditedUnidataRequestRejected,
}

impl PduType {
    fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            SIS_BIND_REQUEST => Self::BindRequest,
            SIS_UNBIND_REQUEST => Self::UnbindRequest,
            SIS_BIND_ACCEPTED => Self::BindAccepted,
            SIS_BIND_REJECTED => Self::BindRejected,
            SIS_UNBIND_INDICATION => Self::UnbindIndication,
            SIS_HARD_LINK_ESTABLISH => Self::HardLinkEstablish,
            SIS_HARD_LINK_TERMINATE => Self::HardLinkTerminate,
            SIS_HARD_LINK_ESTABLISHED => Self::HardLinkEstablished,
            SIS_HARD_LINK_REJECTED => Self::HardLinkRejected,
            SIS_HARD_LINK_TERMINATED => Self::HardLinkTerminated,
            SIS_HARD_LINK_INDICATION => Self::HardLinkIndication,
            SIS_HARD_LINK_ACCEPT => Self::HardLinkAccept,
            SIS_HARD_LINK_REJECT => Self::HardLinkReject,
            SIS_SUBNET_AVAILABILITY => Self::SubnetAvailability,
            SIS_DATAFLOW_ON => Self::DataflowOn,
            SIS_DATAFLOW_OFF => Self::DataflowOff,
            SIS_KEEP_ALIVE => Self::KeepAlive,
            SIS_MANAGEMENT_MESSAGE_REQUEST => Self::ManagementMessageRequest,
            SIS_MANAGEMENT_MESSAGE_INDICATION => Self::ManagementMessageIndication,
            SIS_UNIDATA_REQUEST => Self::UnidataRequest,
            SIS_UNIDATA_INDICATION => Self::UnidataIndication,
            SIS_UNIDATA_REQUEST_CONFIRM => Self::UnidataRequestConfirm,
            SIS_UNIDATA_REQUEST_REJECTED => Self::UnidataRequestRejected,
            SIS_EXPEDITED_UNIDATA_REQUEST => Self::ExpeditedUnidataRequest,
            SIS_EXPEDITED_UNIDATA_INDICATION => Self::ExpeditedUnidataIndication,
            SIS_EXPEDITED_UNIDATA_REQUEST_CONFIRM => Self::ExpeditedUnidataRequestConfirm,
            SIS_EXPEDITED_UNIDATA_REQUEST_REJECTED => Self::ExpeditedUnidataRequestRejected,
            _ => return None,
        })
    }
}

/// Adresse d'un noeud (annexe A, §A.2.1) : taille en demi-octets (trois
/// bits), indicateur de groupe, puis l'adresse — lue sur quatre octets,
/// comme tshark, soit 28 bits d'adresse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct NodeAddress {
    /// Taille annoncee, en demi-octets.
    pub size: u8,
    pub group: bool,
    /// Les 28 bits d'adresse, `0x0a324202` pour `10.50.66.2`.
    pub address: u32,
    /// Les quatre octets, tels quels.
    pub raw: [u8; 4],
}

impl NodeAddress {
    fn from_bytes(raw: [u8; 4]) -> Self {
        Self {
            size: raw[0] >> 5,
            group: raw[0] & 0x10 != 0,
            address: u32::from_be_bytes(raw) & 0x0fff_ffff,
            raw,
        }
    }
}

impl fmt::Display for NodeAddress {
    /// Notation pointee de tshark : les 29 bits de poids faible des quatre
    /// octets (indicateur de groupe compris), comme une adresse IPv4.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.raw[0] & 0x1f,
            self.raw[1],
            self.raw[2],
            self.raw[3]
        )
    }
}

/// Type de service demande (annexe A, §A.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ServiceType {
    /// Quatre bits : 1 ARQ, 2 non-ARQ (diffusion), 3 non-ARQ avec erreurs.
    pub transmission_mode: u8,
    /// Deux bits : 0 aucune, 1 confirmation par le noeud, 2 par le client.
    pub delivery_confirmation: u8,
    /// Bit « delivery order » a zero : livraison dans l'ordre.
    pub in_order_delivery: bool,
    /// Un champ etendu suit.
    pub extended: bool,
    pub raw: u8,
}

impl ServiceType {
    fn from_byte(raw: u8) -> Self {
        Self {
            transmission_mode: raw >> 4,
            delivery_confirmation: (raw >> 2) & 0x03,
            in_order_delivery: raw & 0x02 == 0,
            extended: raw & 0x01 != 0,
            raw,
        }
    }
}

/// Les champs typees d'une primitive, selon son type. Les primitives
/// voisines partagent une variante : les liaisons dures (6 a 13), les
/// messages de gestion (18, 19), les donnees et leurs confirmations (20 a
/// 27).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SisPrimitive<'a> {
    /// S_BIND_REQUEST.
    Bind {
        sap_id: u8,
        rank: u8,
        service_type: ServiceType,
    },
    /// S_BIND_ACCEPTED.
    BindAccepted { sap_id: u8, mtu: u16 },
    /// S_BIND_REJECTED et S_UNBIND_INDICATION.
    Rejected { reason: u8 },
    /// S_HARD_LINK_* : `reason` pour REJECTED, TERMINATED et REJECT,
    /// `remote_status` pour ESTABLISHED et INDICATION ; TERMINATE ne porte
    /// que l'adresse.
    HardLink {
        reason: Option<u8>,
        remote_status: Option<u8>,
        /// Deux bits.
        link_type: Option<u8>,
        /// Deux bits.
        priority: Option<u8>,
        remote_sap_id: Option<u8>,
        remote_node: NodeAddress,
    },
    /// S_SUBNET_AVAILABILITY.
    SubnetAvailability { status: u8, reason: u8 },
    /// S_MANAGEMENT_MESSAGE_REQUEST et INDICATION.
    Management { message_type: u8, body: &'a [u8] },
    /// S_UNIDATA_* et S_EXPEDITED_UNIDATA_* : `priority` pour les
    /// requetes et indications non expediees, `reason` pour les rejets,
    /// `service_type`, `minimum_retransmissions` et `time_to_live` pour les
    /// requetes, `transmission_mode`, `source_sap_id` et `source` pour les
    /// indications.
    Unidata {
        priority: Option<u8>,
        reason: Option<u8>,
        destination_sap_id: u8,
        destination: NodeAddress,
        service_type: Option<ServiceType>,
        minimum_retransmissions: Option<u8>,
        /// Vingt bits, LSB 2 s.
        time_to_live: Option<u32>,
        transmission_mode: Option<u8>,
        source_sap_id: Option<u8>,
        source: Option<NodeAddress>,
        /// Taille annoncee de l'U_PDU.
        u_pdu_size: u16,
        /// L'U_PDU present dans le segment : plus court que `u_pdu_size`
        /// quand le S_PDU est tronque.
        u_pdu: &'a [u8],
    },
    /// S_UNBIND_REQUEST, S_DATAFLOW_ON, S_DATAFLOW_OFF, S_KEEP_ALIVE.
    Empty,
}

/// Le premier S_PDU d'un segment TCP.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SisPdu<'a> {
    pub header: SisHeader,
    pub pdu_type: PduType,
    pub primitive: SisPrimitive<'a>,
    /// Le segment ne contient pas toute la primitive annoncee : le S_PDU
    /// deborde sur le segment suivant.
    pub truncated: bool,
    consumed: usize,
}

impl SisPdu<'_> {
    /// Octets de ce S_PDU presents dans le buffer, en-tete compris : le
    /// S_PDU suivant commence la.
    pub fn consumed(&self) -> usize {
        self.consumed
    }
}

impl<'a> TryFrom<&'a [u8]> for SisPdu<'a> {
    type Error = Stanag5066ParseError;

    fn try_from(payload: &'a [u8]) -> Result<Self, Self::Error> {
        ensure_len(payload, SIS_HEADER_LENGTH + 1)?;
        validate_preamble([payload[0], payload[1]])?;
        let version = extract_version(payload[2])?;
        let primitive_size = extract_primitive_size([payload[3], payload[4]])?;
        let pdu_type_code = extract_pdu_type(payload[5])?;
        let pdu_type = PduType::from_code(pdu_type_code)
            .ok_or(Stanag5066ParseError::ReservedPduType(pdu_type_code))?;
        let header = SisHeader {
            version,
            primitive_size,
            pdu_type: pdu_type_code,
        };

        let declared_end = SIS_HEADER_LENGTH + usize::from(primitive_size);
        let truncated = payload.len() < declared_end;
        let end = declared_end.min(payload.len());
        // La primitive, type exclu.
        let body = &payload[SIS_HEADER_LENGTH + 1..end];
        validate_primitive_length(pdu_type_code, body.len())?;
        let primitive = primitive(pdu_type_code, body, truncated)?;
        if !truncated {
            validate_trailer(&payload[end..])?;
        }
        Ok(SisPdu {
            header,
            pdu_type,
            primitive,
            truncated,
            consumed: end,
        })
    }
}

fn node_address(body: &[u8], offset: usize) -> NodeAddress {
    NodeAddress::from_bytes([
        body[offset],
        body[offset + 1],
        body[offset + 2],
        body[offset + 3],
    ])
}

/// Decoupe la primitive (`body`, type exclu) selon son type ; les champs
/// fixes ont ete verifies presents.
fn primitive(
    pdu_type: u8,
    body: &[u8],
    truncated: bool,
) -> Result<SisPrimitive<'_>, Stanag5066ParseError> {
    Ok(match pdu_type {
        SIS_BIND_REQUEST => SisPrimitive::Bind {
            sap_id: body[0] >> 4,
            rank: body[0] & 0x0f,
            service_type: ServiceType::from_byte(body[1]),
        },
        SIS_BIND_ACCEPTED => SisPrimitive::BindAccepted {
            sap_id: body[0] >> 4,
            mtu: u16::from_be_bytes([body[1], body[2]]),
        },
        SIS_BIND_REJECTED | SIS_UNBIND_INDICATION => SisPrimitive::Rejected { reason: body[0] },
        SIS_HARD_LINK_ESTABLISH | SIS_HARD_LINK_ACCEPT => SisPrimitive::HardLink {
            reason: None,
            remote_status: None,
            link_type: Some(body[0] >> 6),
            priority: Some((body[0] >> 4) & 0x03),
            remote_sap_id: Some(body[0] & 0x0f),
            remote_node: node_address(body, 1),
        },
        SIS_HARD_LINK_TERMINATE => SisPrimitive::HardLink {
            reason: None,
            remote_status: None,
            link_type: None,
            priority: None,
            remote_sap_id: None,
            remote_node: node_address(body, 0),
        },
        SIS_HARD_LINK_ESTABLISHED | SIS_HARD_LINK_INDICATION => SisPrimitive::HardLink {
            reason: None,
            remote_status: Some(body[0]),
            link_type: Some(body[1] >> 6),
            priority: Some((body[1] >> 4) & 0x03),
            remote_sap_id: Some(body[1] & 0x0f),
            remote_node: node_address(body, 2),
        },
        SIS_HARD_LINK_REJECTED | SIS_HARD_LINK_TERMINATED | SIS_HARD_LINK_REJECT => {
            SisPrimitive::HardLink {
                reason: Some(body[0]),
                remote_status: None,
                link_type: Some(body[1] >> 6),
                priority: Some((body[1] >> 4) & 0x03),
                remote_sap_id: Some(body[1] & 0x0f),
                remote_node: node_address(body, 2),
            }
        }
        SIS_SUBNET_AVAILABILITY => SisPrimitive::SubnetAvailability {
            status: body[0],
            reason: body[1],
        },
        SIS_MANAGEMENT_MESSAGE_REQUEST | SIS_MANAGEMENT_MESSAGE_INDICATION => {
            SisPrimitive::Management {
                message_type: body[0],
                body: &body[1..],
            }
        }
        SIS_UNIDATA_REQUEST | SIS_EXPEDITED_UNIDATA_REQUEST => {
            // priorite/SAP, adresse, type de service, retransmissions + TTL
            // (vingt bits), taille, U_PDU.
            let u_pdu_size = u16::from_be_bytes([body[9], body[10]]);
            SisPrimitive::Unidata {
                priority: (pdu_type == SIS_UNIDATA_REQUEST).then_some(body[0] >> 4),
                reason: None,
                destination_sap_id: body[0] & 0x0f,
                destination: node_address(body, 1),
                service_type: Some(ServiceType::from_byte(body[5])),
                minimum_retransmissions: Some(body[6] >> 4),
                time_to_live: Some(u32::from_be_bytes([0, body[6] & 0x0f, body[7], body[8]])),
                transmission_mode: None,
                source_sap_id: None,
                source: None,
                u_pdu_size,
                u_pdu: u_pdu(pdu_type, &body[11..], u_pdu_size, truncated)?,
            }
        }
        SIS_UNIDATA_INDICATION | SIS_EXPEDITED_UNIDATA_INDICATION => {
            // priorite/SAP, adresse destination, mode/SAP source, adresse
            // source, taille, [blocs en erreur], U_PDU.
            let transmission_mode = body[5] >> 4;
            let u_pdu_size = u16::from_be_bytes([body[10], body[11]]);
            let mut rest = &body[12..];
            // Non-ARQ avec erreurs (mode 3) : la liste des blocs errones puis
            // celle des blocs non recus, chacune comptee sur deux octets puis
            // quatre octets par bloc.
            if transmission_mode == 3 {
                for _ in 0..2 {
                    let Some(count) = rest
                        .get(..2)
                        .map(|c| usize::from(u16::from_be_bytes([c[0], c[1]])))
                    else {
                        break;
                    };
                    rest = rest.get(2 + 4 * count..).unwrap_or_default();
                }
            }
            SisPrimitive::Unidata {
                priority: (pdu_type == SIS_UNIDATA_INDICATION).then_some(body[0] >> 4),
                reason: None,
                destination_sap_id: body[0] & 0x0f,
                destination: node_address(body, 1),
                service_type: None,
                minimum_retransmissions: None,
                time_to_live: None,
                transmission_mode: Some(transmission_mode),
                source_sap_id: Some(body[5] & 0x0f),
                source: Some(node_address(body, 6)),
                u_pdu_size,
                u_pdu: u_pdu(pdu_type, rest, u_pdu_size, truncated)?,
            }
        }
        SIS_UNIDATA_REQUEST_CONFIRM
        | SIS_UNIDATA_REQUEST_REJECTED
        | SIS_EXPEDITED_UNIDATA_REQUEST_CONFIRM
        | SIS_EXPEDITED_UNIDATA_REQUEST_REJECTED => {
            // inutilise ou motif/SAP, adresse, taille, (partie de l') U_PDU.
            let rejected = matches!(
                pdu_type,
                SIS_UNIDATA_REQUEST_REJECTED | SIS_EXPEDITED_UNIDATA_REQUEST_REJECTED
            );
            let u_pdu_size = u16::from_be_bytes([body[5], body[6]]);
            SisPrimitive::Unidata {
                priority: None,
                reason: rejected.then_some(body[0] >> 4),
                destination_sap_id: body[0] & 0x0f,
                destination: node_address(body, 1),
                service_type: None,
                minimum_retransmissions: None,
                time_to_live: None,
                transmission_mode: None,
                source_sap_id: None,
                source: None,
                u_pdu_size,
                u_pdu: u_pdu(pdu_type, &body[7..], u_pdu_size, truncated)?,
            }
        }
        _ => SisPrimitive::Empty,
    })
}

/// L'U_PDU d'une primitive de donnees : tout ce qui reste quand le S_PDU
/// est tronque ; sinon exactement `declared` octets — ou `declared + 4`,
/// quatre octets de compteurs qu'un noeud Rockwell Collins (v2.1 et
/// anterieures) insere avant l'U_PDU d'une indication, comme tshark.
fn u_pdu(
    pdu_type: u8,
    rest: &[u8],
    declared: u16,
    truncated: bool,
) -> Result<&[u8], Stanag5066ParseError> {
    if truncated {
        return Ok(rest);
    }
    let declared = usize::from(declared);
    let indication = matches!(
        pdu_type,
        SIS_UNIDATA_INDICATION | SIS_EXPEDITED_UNIDATA_INDICATION
    );
    if indication && rest.len() == declared + 4 {
        return Ok(&rest[4..]);
    }
    if rest.len() != declared {
        return Err(Stanag5066ParseError::PrimitiveTooShort {
            pdu_type,
            expected: declared,
            actual: rest.len(),
        });
    }
    Ok(rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Trames reelles de pcaps_exemple/protocols/stanag5066/ (voir SOURCE.md),
    // recoupees avec tshark 4.6.6.

    /// S5066-HFChat-1.pcap, trame 25 : S_BIND_REQUEST du client HF Chat
    /// (SAP 5, rang 1, ARQ, confirmation par le noeud).
    const HFCHAT_BIND_REQUEST: &str = "90eb00000401511400";
    /// Trame 26 : S_BIND_ACCEPTED, SAP 5, MTU 250.
    const HFCHAT_BIND_ACCEPTED: &str = "90eb000004035000fa";
    /// Trame 40 : S_UNBIND_REQUEST.
    const HFCHAT_UNBIND: &str = "90eb00000102";
    /// Trame 28 : premier segment d'un S_UNIDATA_INDICATION de 30 octets —
    /// les 13 octets de champs fixes, l'U_PDU de 17 octets est dans le
    /// segment suivant.
    const HFCHAT_INDICATION_FIRST_SEGMENT: &str = "90eb00001e1505e564640215e56464010011";
    /// Trame 32 : premier segment d'un S_UNIDATA_REQUEST (priorite 1,
    /// SAP 5, TTL 160, U_PDU de 16 octets a suivre).
    const HFCHAT_REQUEST_FIRST_SEGMENT: &str = "90eb00001c1415e5646401140000a00010";
    /// S5066-HFChat-Rejected.pcap, trame 11 : S_UNIDATA_REQUEST_REJECTED,
    /// motif 3, premier segment.
    const HFCHAT_REJECTED_FIRST_SEGMENT: &str = "90eb00001b1735e56464010013";
    /// S5066-Expedited.pcap, trame 3 : S_HARD_LINK_INDICATION, type de
    /// liaison 2, SAP distant 13, noeud 0.0.0.2.
    const EXPEDITED_HARD_LINK_INDICATION: &str = "90eb0000070b018de0000002";
    /// Trame 5 : S_EXPEDITED_UNIDATA_INDICATION, « test ».
    const EXPEDITED_INDICATION: &str = "90eb000011190de00000011de0000002000474657374";
    /// Trame 7 : S_EXPEDITED_UNIDATA_REQUEST, « ack ».
    const EXPEDITED_REQUEST: &str = "90eb00000f180de000000218000000000361636b";
    /// Trame 8 : S_EXPEDITED_UNIDATA_REQUEST_CONFIRM, « ack ».
    const EXPEDITED_CONFIRM: &str = "90eb00000b1a0de0000002000361636b";
    /// wireshark_10827_sis_acp142.pcap, trame 3 : S_UNIDATA_REQUEST vers
    /// 10.50.66.2, SAP 2 (T-MMHS), non-ARQ, U_PDU ACP 142 de 38 octets.
    const ACP142_REQUEST: &str = concat!(
        "90eb0000321402ea3242022c0000000026000000002000002001020006abc10a324201013eeca554a5ef",
        "ac000100000a32420200000000"
    );

    fn pdu(hex: &str) -> (&'static [u8], SisPdu<'static>) {
        let bytes: &'static [u8] = Box::leak(hex::decode(hex).unwrap().into_boxed_slice());
        (bytes, SisPdu::try_from(bytes).expect("S_PDU"))
    }

    #[test]
    fn test_decodes_bind_primitives_against_tshark() {
        let (bytes, bind) = pdu(HFCHAT_BIND_REQUEST);
        assert_eq!(bind.header.primitive_size, 4);
        assert_eq!(bind.pdu_type, PduType::BindRequest);
        assert!(!bind.truncated);
        assert_eq!(bind.consumed(), bytes.len());
        let SisPrimitive::Bind {
            sap_id,
            rank,
            service_type,
        } = bind.primitive
        else {
            panic!("bind attendu");
        };
        assert_eq!((sap_id, rank), (5, 1));
        assert_eq!(service_type.transmission_mode, 1);
        assert_eq!(service_type.delivery_confirmation, 1);
        assert!(service_type.in_order_delivery && !service_type.extended);

        let (_, accepted) = pdu(HFCHAT_BIND_ACCEPTED);
        assert_eq!(accepted.pdu_type, PduType::BindAccepted);
        assert_eq!(
            accepted.primitive,
            SisPrimitive::BindAccepted {
                sap_id: 5,
                mtu: 250
            }
        );

        let (_, unbind) = pdu(HFCHAT_UNBIND);
        assert_eq!(unbind.pdu_type, PduType::UnbindRequest);
        assert_eq!(unbind.primitive, SisPrimitive::Empty);
        assert_eq!(unbind.consumed(), 6);
    }

    #[test]
    fn test_decodes_unidata_request_with_acp142_against_tshark() {
        let (bytes, request) = pdu(ACP142_REQUEST);
        assert_eq!(request.pdu_type, PduType::UnidataRequest);
        assert!(!request.truncated);
        assert_eq!(request.consumed(), bytes.len());
        let SisPrimitive::Unidata {
            priority,
            reason,
            destination_sap_id,
            destination,
            service_type,
            minimum_retransmissions,
            time_to_live,
            transmission_mode,
            source_sap_id,
            source,
            u_pdu_size,
            u_pdu,
        } = request.primitive
        else {
            panic!("unidata attendu");
        };
        assert_eq!((priority, reason), (Some(0), None));
        assert_eq!(destination_sap_id, 2);
        assert_eq!(destination.to_string(), "10.50.66.2");
        assert_eq!((destination.size, destination.group), (7, false));
        assert_eq!(destination.address, 0x0a32_4202);
        let service = service_type.unwrap();
        assert_eq!(service.transmission_mode, 2);
        assert_eq!(service.delivery_confirmation, 3);
        assert_eq!((minimum_retransmissions, time_to_live), (Some(0), Some(0)));
        assert_eq!(
            (transmission_mode, source_sap_id, source),
            (None, None, None)
        );
        assert_eq!(u_pdu_size, 38);
        assert_eq!(u_pdu.len(), 38);
        // En-tete transport client (T-MMHS) : identifiant d'application
        // 0x2000, ACP 142.
        assert_eq!(&u_pdu[..6], &[0x00, 0x00, 0x00, 0x00, 0x20, 0x00]);
        assert!(bytes.as_ptr_range().contains(&u_pdu.as_ptr()));
    }

    #[test]
    fn test_decodes_expedited_primitives_against_tshark() {
        let (_, indication) = pdu(EXPEDITED_INDICATION);
        assert_eq!(indication.pdu_type, PduType::ExpeditedUnidataIndication);
        let SisPrimitive::Unidata {
            priority,
            destination_sap_id,
            destination,
            transmission_mode,
            source_sap_id,
            source,
            u_pdu_size,
            u_pdu,
            ..
        } = indication.primitive
        else {
            panic!("unidata attendu");
        };
        assert_eq!(priority, None);
        assert_eq!(destination_sap_id, 13);
        assert_eq!(destination.to_string(), "0.0.0.1");
        assert_eq!((transmission_mode, source_sap_id), (Some(1), Some(13)));
        assert_eq!(source.unwrap().to_string(), "0.0.0.2");
        assert_eq!((u_pdu_size, u_pdu), (4, &b"test"[..]));

        let (_, request) = pdu(EXPEDITED_REQUEST);
        assert_eq!(request.pdu_type, PduType::ExpeditedUnidataRequest);
        let SisPrimitive::Unidata {
            priority,
            service_type,
            time_to_live,
            u_pdu,
            ..
        } = request.primitive
        else {
            panic!("unidata attendu");
        };
        assert_eq!(priority, None);
        assert_eq!(service_type.unwrap().delivery_confirmation, 2);
        assert_eq!(time_to_live, Some(0));
        assert_eq!(u_pdu, b"ack");

        let (_, confirm) = pdu(EXPEDITED_CONFIRM);
        assert_eq!(confirm.pdu_type, PduType::ExpeditedUnidataRequestConfirm);
        let SisPrimitive::Unidata {
            reason,
            destination_sap_id,
            u_pdu,
            ..
        } = confirm.primitive
        else {
            panic!("unidata attendu");
        };
        assert_eq!((reason, destination_sap_id), (None, 13));
        assert_eq!(u_pdu, b"ack");

        let (_, hard_link) = pdu(EXPEDITED_HARD_LINK_INDICATION);
        assert_eq!(hard_link.pdu_type, PduType::HardLinkIndication);
        let SisPrimitive::HardLink {
            reason,
            remote_status,
            link_type,
            priority,
            remote_sap_id,
            remote_node,
        } = hard_link.primitive
        else {
            panic!("liaison dure attendue");
        };
        assert_eq!((reason, remote_status), (None, Some(1)));
        assert_eq!(
            (link_type, priority, remote_sap_id),
            (Some(2), Some(0), Some(13))
        );
        assert_eq!(remote_node.to_string(), "0.0.0.2");
    }

    /// Un S_PDU coupe entre deux segments : le premier porte l'en-tete et
    /// les champs fixes, l'U_PDU manque en tout ou partie.
    #[test]
    fn test_first_segment_of_a_split_pdu_is_accepted_and_flagged() {
        let (bytes, indication) = pdu(HFCHAT_INDICATION_FIRST_SEGMENT);
        assert_eq!(indication.header.primitive_size, 30);
        assert!(indication.truncated);
        assert_eq!(indication.consumed(), bytes.len());
        let SisPrimitive::Unidata {
            priority,
            destination_sap_id,
            destination,
            source,
            u_pdu_size,
            u_pdu,
            ..
        } = indication.primitive
        else {
            panic!("unidata attendu");
        };
        assert_eq!((priority, destination_sap_id), (Some(0), 5));
        assert_eq!(destination.to_string(), "5.100.100.2");
        assert_eq!(source.unwrap().to_string(), "5.100.100.1");
        assert_eq!((u_pdu_size, u_pdu.len()), (17, 0));

        let (_, request) = pdu(HFCHAT_REQUEST_FIRST_SEGMENT);
        assert!(request.truncated);
        let SisPrimitive::Unidata {
            priority,
            time_to_live,
            service_type,
            u_pdu_size,
            u_pdu,
            ..
        } = request.primitive
        else {
            panic!("unidata attendu");
        };
        assert_eq!((priority, time_to_live), (Some(1), Some(160)));
        assert_eq!(service_type.unwrap().delivery_confirmation, 1);
        assert_eq!((u_pdu_size, u_pdu.len()), (16, 0));

        let (_, rejected) = pdu(HFCHAT_REJECTED_FIRST_SEGMENT);
        assert_eq!(rejected.pdu_type, PduType::UnidataRequestRejected);
        assert!(rejected.truncated);
        let SisPrimitive::Unidata {
            reason, u_pdu_size, ..
        } = rejected.primitive
        else {
            panic!("unidata attendu");
        };
        assert_eq!((reason, u_pdu_size), (Some(3), 19));

        // Le segment de continuation (trame 30), sans preambule.
        assert_eq!(
            SisPdu::try_from(&b"<0> Hello there.\n"[..]),
            Err(Stanag5066ParseError::InvalidPreamble(*b"<0"))
        );
    }

    /// Plusieurs S_PDU dans un segment : `consumed` donne le suivant, et
    /// ce qui suit un S_PDU complet doit commencer un S_PDU.
    #[test]
    fn test_several_pdus_in_a_segment_and_trailer_rules() {
        let mut bytes = hex::decode(EXPEDITED_REQUEST).unwrap();
        let first_len = bytes.len();
        bytes.extend_from_slice(&hex::decode(EXPEDITED_CONFIRM).unwrap());
        let first = SisPdu::try_from(bytes.as_slice()).expect("premier S_PDU");
        assert_eq!(first.consumed(), first_len);
        assert!(!first.truncated);
        let second = SisPdu::try_from(&bytes[first.consumed()..]).expect("second S_PDU");
        assert_eq!(second.pdu_type, PduType::ExpeditedUnidataRequestConfirm);
        assert_eq!(first.consumed() + second.consumed(), bytes.len());

        // Un S_PDU complet suivi d'octets quelconques : pas du SIS.
        let mut trailing = hex::decode(EXPEDITED_REQUEST).unwrap();
        trailing.extend_from_slice(b"ack");
        assert_eq!(
            SisPdu::try_from(trailing.as_slice()),
            Err(Stanag5066ParseError::UnexpectedTrailingBytes { trailing: 3 })
        );
        // Un debut de preambule suffit.
        let mut partial = hex::decode(EXPEDITED_REQUEST).unwrap();
        partial.extend_from_slice(&[0x90, 0xeb]);
        assert!(SisPdu::try_from(partial.as_slice()).is_ok());
    }

    #[test]
    fn test_rejects_malformed_headers_and_primitives() {
        assert!(matches!(
            SisPdu::try_from(&[0x90, 0xeb, 0x00][..]),
            Err(Stanag5066ParseError::Truncated {
                expected: 6,
                actual: 3
            })
        ));
        assert_eq!(
            SisPdu::try_from(&[0x90, 0xeb, 0x01, 0x00, 0x01, 0x02][..]),
            Err(Stanag5066ParseError::UnsupportedVersion(1))
        );
        assert_eq!(
            SisPdu::try_from(&[0x90, 0xeb, 0x00, 0x00, 0x00, 0x02][..]),
            Err(Stanag5066ParseError::EmptyPrimitive)
        );
        assert_eq!(
            SisPdu::try_from(&[0x90, 0xeb, 0x00, 0x00, 0x01, 0x1c][..]),
            Err(Stanag5066ParseError::ReservedPduType(28))
        );
        // S_BIND_REQUEST annonce 4 octets mais n'en porte que 2 : les
        // champs fixes manquent, meme tronque ce n'est pas decodable.
        assert_eq!(
            SisPdu::try_from(&[0x90, 0xeb, 0x00, 0x00, 0x04, 0x01, 0x51][..]),
            Err(Stanag5066ParseError::PrimitiveTooShort {
                pdu_type: 1,
                expected: 3,
                actual: 1
            })
        );
        // U_PDU annonce de 3 octets dans un S_PDU complet qui n'en porte
        // qu'un : la primitive fait 9 octets, type compris.
        assert_eq!(
            SisPdu::try_from(&hex::decode("90eb0000091a0de0000002000361").unwrap()[..]),
            Err(Stanag5066ParseError::PrimitiveTooShort {
                pdu_type: 26,
                expected: 3,
                actual: 1
            })
        );
    }

    /// Octets synthetiques : indication non-ARQ avec erreurs (mode 3), deux
    /// blocs errones et un non recu avant l'U_PDU ; et le decalage de
    /// quatre octets d'un noeud Rockwell Collins.
    #[test]
    fn test_non_arq_with_errors_and_rockwell_collins_offset() {
        let mut bytes = hex::decode("90eb0000001505e564640235e5646401").unwrap();
        bytes.extend_from_slice(&[0x00, 0x02]); // U_PDU size 2
        bytes.extend_from_slice(&[0x00, 0x02, 0, 1, 0, 2, 0, 3, 0, 4]); // 2 blocs errones
        bytes.extend_from_slice(&[0x00, 0x01, 0, 5, 0, 6]); // 1 bloc non recu
        bytes.extend_from_slice(b"ok");
        bytes[4] = (bytes.len() - 5) as u8;
        let pdu = SisPdu::try_from(bytes.as_slice()).expect("mode 3");
        let SisPrimitive::Unidata {
            transmission_mode,
            u_pdu,
            ..
        } = pdu.primitive
        else {
            panic!("unidata attendu");
        };
        assert_eq!(transmission_mode, Some(3));
        assert_eq!(u_pdu, b"ok");

        let mut rc = hex::decode("90eb0000001505e564640215e5646401").unwrap();
        rc.extend_from_slice(&[0x00, 0x02, 0, 0, 0, 0]);
        rc.extend_from_slice(b"ok");
        rc[4] = (rc.len() - 5) as u8;
        let pdu = SisPdu::try_from(rc.as_slice()).expect("Rockwell Collins");
        let SisPrimitive::Unidata { u_pdu, .. } = pdu.primitive else {
            panic!("unidata attendu");
        };
        assert_eq!(u_pdu, b"ok");
    }
}
