// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! RDP, Remote Desktop Protocol (MS-RDPBCGR), sur TCP 3389 : la pile
//! TPKT (RFC 1006), COTP X.224 (RFC 905) et MCS (T.125) que la 10.0.0 a
//! outillee pour S7comm. Le decodeur lit, segment par segment :
//!
//! - la **connexion X.224** : le Connection Request du client avec son
//!   jeton de routage ou son cookie `Cookie: mstshash=<user>` et sa demande
//!   de negociation (protocoles de securite proposes), le Connection
//!   Confirm du serveur avec la reponse (protocole retenu) ou l'echec ;
//! - les **PDU MCS** qui suivent quand la securite RDP standard est retenue :
//!   Connect-Initial et Connect-Response (BER), puis les DomainMCSPDU (PER)
//!   — Erect Domain, Attach User, Channel Join, Send Data avec l'utilisateur
//!   et le canal, Disconnect Provider Ultimatum.
//!
//! Quand la negociation retient TLS ou CredSSP, ce qui suit sur la
//! connexion est du TLS, et un parseur sans etat l'etiquette TLS : c'est
//! le choix teste sur `rdp-to-ssl.pcap`. Un TPKT qui deborde du segment est
//! decode sur ce qu'il en reste et marque [`RdpPacket::truncated`] ; ses
//! suites, sans en-tete, restent inconnues.

use std::convert::TryFrom;

use crate::{
    checks::application::rdp::{
        CORRELATION_INFO_PRESENT, MCS_CONNECT_INITIAL_TAG, MCS_CONNECT_RESPONSE_TAG,
        MCS_USER_ID_BASE, PROTOCOL_HYBRID, PROTOCOL_HYBRID_EX, PROTOCOL_RDP, PROTOCOL_RDSTLS,
        PROTOCOL_SSL, RDP_COOKIE_PREFIX, RDP_NEG_CORRELATION_INFO_LENGTH, RDP_NEG_FAILURE,
        RDP_NEG_LENGTH, RDP_NEG_REQUEST, RDP_NEG_RESPONSE, RDP_TOKEN_TERMINATOR,
        TPKT_HEADER_LENGTH, ensure_len, extract_tpkt_length, validate_correlation_info,
        validate_negotiation_length, validate_tpkt_header,
    },
    errors::application::rdp::RdpParseError,
    parse::application::protocols::{bounded_capacity, copt::CotpPduType},
};

/// Demande de negociation (MS-RDPBCGR §2.2.1.1.1), dans le Connection
/// Request, et la correlation info (§2.2.1.1.2) qui la suit quand elle
/// leve CORRELATION_INFO_PRESENT.
///
/// ```mermaid
/// ---
/// title: NegotiationRequest
/// ---
/// packet-beta
/// 0-7: "type 0x01"
/// 8-15: "flags u8"
/// 16-31: "length 8 (LE)"
/// 32-63: "requestedProtocols u32 LE"
/// 64-71: "type 0x06"
/// 72-79: "flags 0"
/// 80-95: "length 36 (LE)"
/// 96-223: "correlationId (16 octets)"
/// 224-351: "reserved (16 octets)"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct NegotiationRequest {
    /// Drapeaux bruts (§2.2.1.1.1) : `0x01` RESTRICTED_ADMIN_MODE_REQUIRED
    /// (ouverture de session sans identifiants sur CredSSP, « restricted
    /// admin mode »), `0x02` REDIRECTED_AUTHENTICATION_MODE_REQUIRED
    /// (ouverture sans identifiants, l'authentification etant redirigee sur
    /// CredSSP, « Remote Credential Guard »), `0x08` CORRELATION_INFO_PRESENT
    /// (le Connection Request porte apres la demande une structure
    /// RDP_NEG_CORRELATION_INFO, §2.2.1.1.2).
    pub flags: u8,
    /// Bits : 1 TLS, 2 CredSSP, 4 RDSTLS, 8 CredSSP avec Early User
    /// Authorization Result, `0x10` RDS-AAD-Auth (PROTOCOL_RDSAAD,
    /// authentification Entra ID, §5.4.5.4) ; zero pour la securite RDP
    /// standard seule.
    pub requested_protocols: u32,
    /// `correlationId` de la correlation info (§2.2.1.1.2), les seize
    /// octets qui suivent son en-tete, quand `flags` leve
    /// CORRELATION_INFO_PRESENT et que la structure est la. La norme veut
    /// un premier octet autre que `0x00` et `0xF4` et aucun octet `0x0D`,
    /// ce que le decodeur ne verifie pas, pas plus que tshark. `None` quand
    /// le drapeau est bas, ou quand il est leve sans que rien ne suive la
    /// demande (ce que tshark marque malforme et que la 11.6.0 acceptait).
    pub correlation_id: Option<[u8; 16]>,
}

impl NegotiationRequest {
    /// Drapeau CORRELATION_INFO_PRESENT (`0x08`).
    pub fn correlation_info_present(&self) -> bool {
        self.flags & CORRELATION_INFO_PRESENT != 0
    }

    pub fn tls(&self) -> bool {
        self.requested_protocols & PROTOCOL_SSL != 0
    }

    pub fn credssp(&self) -> bool {
        self.requested_protocols & (PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX) != 0
    }

    pub fn rdstls(&self) -> bool {
        self.requested_protocols & PROTOCOL_RDSTLS != 0
    }

    /// Aucun protocole externe : la securite RDP standard seule.
    pub fn standard_security_only(&self) -> bool {
        self.requested_protocols == PROTOCOL_RDP
    }
}

/// Reponse du serveur (§2.2.1.2.1) ou echec (§2.2.1.2.2), dans le
/// Connection Confirm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NegotiationResponse {
    Accepted {
        /// Drapeaux bruts (§2.2.1.2.1) : `0x01`
        /// EXTENDED_CLIENT_DATA_SUPPORTED (blocs de donnees client etendus
        /// dans le GCC Conference Create Request), `0x02`
        /// DYNVC_GFX_PROTOCOL_SUPPORTED (Graphics Pipeline Extension,
        /// MS-RDPEGFX), `0x04` NEGRSP_FLAG_RESERVED (reserve, que le client
        /// ignore), `0x08` RESTRICTED_ADMIN_MODE_SUPPORTED (ouverture de
        /// session sans identifiants sur CredSSP), `0x10`
        /// REDIRECTED_AUTHENTICATION_MODE_SUPPORTED (« Remote Credential
        /// Guard »). Le Connection Confirm de la trame 9 de
        /// `rdp-no-cookie-mstshash.pcap` les leve tous (`0x1f`).
        flags: u8,
        /// Le protocole retenu : 0 RDP standard, 1 TLS, 2 CredSSP, 4
        /// RDSTLS, 8 CredSSP avec Early User Authorization Result, `0x10`
        /// RDS-AAD-Auth (PROTOCOL_RDSAAD, authentification Entra ID,
        /// §5.4.5.4).
        selected_protocol: u32,
    },
    Failure {
        /// §2.2.1.2.2 : 1 TLS ou CredSSP requis (SSL_REQUIRED_BY_SERVER),
        /// 2 securite RDP standard seule, aucun protocole externe
        /// (SSL_NOT_ALLOWED_BY_SERVER), 3 pas de certificat valide sur le
        /// serveur (SSL_CERT_NOT_ON_SERVER), 4 protocoles demandes
        /// incoherents avec celui deja en vigueur, approche directe
        /// seulement (INCONSISTENT_FLAGS), 5 CredSSP requis
        /// (HYBRID_REQUIRED_BY_SERVER), 6 TLS avec authentification du
        /// client par certificat requis (SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER),
        /// 7 authentification Entra ID requise, par RDS-AAD-Auth
        /// (ENTRA_AUTH_REQUIRED_BY_SERVER, que tshark 4.6.6 ne nomme pas).
        failure_code: u32,
    },
}

/// Un DomainMCSPDU ou un ConnectMCSPDU (T.125 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum McsPduType {
    ConnectInitial,
    ConnectResponse,
    ErectDomainRequest,
    DisconnectProviderUltimatum,
    AttachUserRequest,
    AttachUserConfirm,
    ChannelJoinRequest,
    ChannelJoinConfirm,
    SendDataRequest,
    SendDataIndication,
}

impl McsPduType {
    /// Le choix PER d'un DomainMCSPDU : les six bits hauts du premier octet.
    fn from_domain_choice(choice: u8) -> Option<Self> {
        Some(match choice {
            1 => Self::ErectDomainRequest,
            8 => Self::DisconnectProviderUltimatum,
            10 => Self::AttachUserRequest,
            11 => Self::AttachUserConfirm,
            14 => Self::ChannelJoinRequest,
            15 => Self::ChannelJoinConfirm,
            25 => Self::SendDataRequest,
            26 => Self::SendDataIndication,
            _ => return None,
        })
    }
}

/// Send Data Request ou Indication (T.125 §7, PER) : l'utilisateur, le
/// canal et les donnees — la charge RDP, chiffree ou non.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct McsSendData<'a> {
    /// Identifiant d'utilisateur, a partir de 1001.
    pub initiator: u16,
    pub channel_id: u16,
    /// Priorite (deux bits hauts) et segmentation (deux bits suivants).
    pub priority_and_segmentation: u8,
    /// Longueur annoncee des donnees.
    pub declared_length: Option<u16>,
    /// Les donnees presentes dans ce segment.
    pub data: &'a [u8],
}

/// Un PDU MCS : son type et ses octets apres le choix ou l'etiquette.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct McsPdu<'a> {
    pub kind: McsPduType,
    /// Tout le PDU, choix ou etiquette compris.
    pub raw: &'a [u8],
    /// Decode pour les Send Data.
    pub send_data: Option<McsSendData<'a>>,
}

/// Ce qu'un TPDU COTP porte.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RdpPayload<'a> {
    /// X.224 Connection Request du client (§2.2.1.1).
    ConnectionRequest {
        /// Le jeton tel quel, `Cookie: mstshash=<user>` ou un routingToken,
        /// sans son CR LF.
        token: Option<&'a [u8]>,
        negotiation: Option<NegotiationRequest>,
    },
    /// X.224 Connection Confirm du serveur (§2.2.1.2).
    ConnectionConfirm {
        negotiation: Option<NegotiationResponse>,
    },
    /// Un PDU MCS dans un Data TPDU.
    Mcs(McsPdu<'a>),
}

impl RdpPayload<'_> {
    /// Le nom d'utilisateur d'un cookie `Cookie: mstshash=<user>`.
    pub fn cookie_user(&self) -> Option<&str> {
        let Self::ConnectionRequest {
            token: Some(token), ..
        } = self
        else {
            return None;
        };
        let user = token.strip_prefix(RDP_COOKIE_PREFIX)?;
        std::str::from_utf8(user).ok()
    }
}

/// Le TPDU COTP X.224 (RFC 905) d'un TPKT RDP : CR, CC ou DT en classe 0.
///
/// MS-RDPBCGR compte le jeton et la negociation d'un CR/CC dans le LI, la
/// ou [`crate::parse::application::protocols::copt::CotpHeader`] y lit des
/// parametres : le decodeur lit donc lui-meme la partie fixe.
///
/// ```mermaid
/// ---
/// title: X224Tpdu (CR/CC)
/// ---
/// packet-beta
/// 0-7: "LI u8"
/// 8-15: "Type (0xe0 CR, 0xd0 CC)"
/// 16-31: "Destination reference u16"
/// 32-47: "Source reference u16"
/// 48-55: "Class u8"
/// 56-127: "X.224 user data (token, negotiation)"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct X224Tpdu {
    pub length_indicator: u8,
    pub pdu_type: CotpPduType,
    /// CR et CC seulement.
    pub dst_ref: Option<u16>,
    pub src_ref: Option<u16>,
    pub class: Option<u8>,
    /// DT seulement : dernier TPDU de la TSDU.
    pub end_of_tsdu: Option<bool>,
}

/// Un TPKT et son TPDU COTP.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RdpPdu<'a> {
    /// Longueur declaree du TPKT, en-tete compris.
    pub tpkt_length: u16,
    pub cotp: X224Tpdu,
    pub payload: RdpPayload<'a>,
}

/// Un segment TCP : ses TPKT, le dernier eventuellement coupe.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RdpPacket<'a> {
    pub pdus: Vec<RdpPdu<'a>>,
    /// Le dernier TPKT annonce plus que le segment n'en porte : decode sur
    /// ce qui est la, la suite viendra sans en-tete.
    pub truncated: bool,
}

impl<'a> TryFrom<&'a [u8]> for RdpPacket<'a> {
    type Error = RdpParseError;

    fn try_from(payload: &'a [u8]) -> Result<Self, Self::Error> {
        let mut pdus = Vec::with_capacity(bounded_capacity(4, payload.len(), 7));
        let mut truncated = false;
        let mut offset = 0;
        while offset < payload.len() {
            let rest = &payload[offset..];
            ensure_len(
                rest,
                usize::from(crate::checks::application::rdp::TPKT_MIN_LENGTH),
            )?;
            validate_tpkt_header(rest[0], rest[1])?;
            let tpkt_length = extract_tpkt_length([rest[2], rest[3]])?;
            let end = usize::from(tpkt_length).min(rest.len());
            truncated = usize::from(tpkt_length) > rest.len();
            let tpdu = &rest[TPKT_HEADER_LENGTH..end];
            pdus.push(parse_tpdu(tpkt_length, tpdu)?);
            offset += end;
        }
        if pdus.is_empty() {
            return Err(RdpParseError::Truncated {
                expected: usize::from(crate::checks::application::rdp::TPKT_MIN_LENGTH),
                actual: 0,
            });
        }
        Ok(RdpPacket { pdus, truncated })
    }
}

fn parse_tpdu(tpkt_length: u16, tpdu: &[u8]) -> Result<RdpPdu<'_>, RdpParseError> {
    ensure_len(tpdu, 3)?;
    let length_indicator = tpdu[0];
    let pdu_type = CotpPduType::from(tpdu[1]);
    let (cotp, payload) = match pdu_type {
        CotpPduType::ConnectionRequest | CotpPduType::ConnectionConfirm => {
            ensure_len(tpdu, 7)?;
            // Le LI couvre la partie fixe et les donnees X.224 ; un TPKT coupe
            // s'arrete avant.
            let end = (usize::from(length_indicator) + 1).min(tpdu.len());
            let user_data = &tpdu[7..end.max(7)];
            let cotp = X224Tpdu {
                length_indicator,
                pdu_type,
                dst_ref: Some(u16::from_be_bytes([tpdu[2], tpdu[3]])),
                src_ref: Some(u16::from_be_bytes([tpdu[4], tpdu[5]])),
                class: Some(tpdu[6]),
                end_of_tsdu: None,
            };
            let payload = if pdu_type == CotpPduType::ConnectionRequest {
                connection_request(user_data)?
            } else {
                connection_confirm(user_data)?
            };
            (cotp, payload)
        }
        CotpPduType::Data => {
            let cotp = X224Tpdu {
                length_indicator,
                pdu_type,
                dst_ref: None,
                src_ref: None,
                class: None,
                end_of_tsdu: Some(tpdu[2] & 0x80 != 0),
            };
            let user_data = &tpdu[(usize::from(length_indicator) + 1).min(tpdu.len())..];
            (cotp, RdpPayload::Mcs(mcs_pdu(user_data)?))
        }
        _ => return Err(RdpParseError::UnexpectedTpdu(tpdu[1])),
    };
    Ok(RdpPdu {
        tpkt_length,
        cotp,
        payload,
    })
}

fn connection_request(user_data: &[u8]) -> Result<RdpPayload<'_>, RdpParseError> {
    let (token, rest) = match user_data
        .windows(RDP_TOKEN_TERMINATOR.len())
        .position(|window| window == RDP_TOKEN_TERMINATOR)
    {
        Some(end) => (
            Some(&user_data[..end]),
            &user_data[end + RDP_TOKEN_TERMINATOR.len()..],
        ),
        None => (None, user_data),
    };
    let negotiation = match rest {
        [] => None,
        [RDP_NEG_REQUEST, ..] => {
            let (structure, tail) = negotiation_structure(rest)?;
            let flags = structure[1];
            let correlation_id = if flags & CORRELATION_INFO_PRESENT != 0 {
                correlation_info(tail)?
            } else if tail.is_empty() {
                None
            } else {
                return Err(RdpParseError::UnexpectedX224Data(tail.len()));
            };
            Some(NegotiationRequest {
                flags,
                requested_protocols: u32::from_le_bytes([
                    structure[4],
                    structure[5],
                    structure[6],
                    structure[7],
                ]),
                correlation_id,
            })
        }
        other => return Err(RdpParseError::UnexpectedX224Data(other.len())),
    };
    Ok(RdpPayload::ConnectionRequest { token, negotiation })
}

fn connection_confirm(user_data: &[u8]) -> Result<RdpPayload<'_>, RdpParseError> {
    let negotiation = match user_data {
        [] => None,
        [RDP_NEG_RESPONSE | RDP_NEG_FAILURE, ..] => {
            let (structure, tail) = negotiation_structure(user_data)?;
            if !tail.is_empty() {
                return Err(RdpParseError::UnexpectedX224Data(tail.len()));
            }
            let value =
                u32::from_le_bytes([structure[4], structure[5], structure[6], structure[7]]);
            Some(if structure[0] == RDP_NEG_RESPONSE {
                NegotiationResponse::Accepted {
                    flags: structure[1],
                    selected_protocol: value,
                }
            } else {
                NegotiationResponse::Failure {
                    failure_code: value,
                }
            })
        }
        other => return Err(RdpParseError::UnexpectedX224Data(other.len())),
    };
    Ok(RdpPayload::ConnectionConfirm { negotiation })
}

/// Les huit octets d'une structure de negociation (type, drapeaux,
/// longueur, valeur) et ce qui les suit. Une longueur declaree autre que 8
/// est une [`RdpParseError::InvalidNegotiation`] ; une structure coupee
/// avant ses huit octets, mais dont la longueur declaree est juste ou
/// illisible, une [`RdpParseError::Truncated`].
fn negotiation_structure(data: &[u8]) -> Result<(&[u8], &[u8]), RdpParseError> {
    if let [_, _, l0, l1, ..] = data {
        validate_negotiation_length(data[0], u16::from_le_bytes([*l0, *l1]))?;
    }
    ensure_len(data, usize::from(RDP_NEG_LENGTH))?;
    Ok(data.split_at(usize::from(RDP_NEG_LENGTH)))
}

/// La correlation info annoncee par CORRELATION_INFO_PRESENT : type `0x06`,
/// longueur 36, puis le `correlationId`. Rien a sa place reste accepte,
/// comme en 11.6.0 ; une structure d'un autre type ou d'une autre longueur
/// est refusee, une structure coupee aussi, et des octets apres elle de
/// meme.
fn correlation_info(data: &[u8]) -> Result<Option<[u8; 16]>, RdpParseError> {
    if data.is_empty() {
        return Ok(None);
    }
    if let [structure_type, _, l0, l1, ..] = data {
        validate_correlation_info(*structure_type, u16::from_le_bytes([*l0, *l1]))?;
    }
    let length = usize::from(RDP_NEG_CORRELATION_INFO_LENGTH);
    ensure_len(data, length)?;
    if data.len() > length {
        return Err(RdpParseError::UnexpectedX224Data(data.len() - length));
    }
    let mut correlation_id = [0; 16];
    correlation_id.copy_from_slice(&data[4..20]);
    Ok(Some(correlation_id))
}

fn mcs_pdu(user_data: &[u8]) -> Result<McsPdu<'_>, RdpParseError> {
    ensure_len(user_data, 1)?;
    if user_data.starts_with(&MCS_CONNECT_INITIAL_TAG)
        || user_data.starts_with(&MCS_CONNECT_RESPONSE_TAG)
    {
        ber_length(&user_data[2..]).ok_or(RdpParseError::InvalidBerLength)?;
        let kind = if user_data[1] == MCS_CONNECT_INITIAL_TAG[1] {
            McsPduType::ConnectInitial
        } else {
            McsPduType::ConnectResponse
        };
        return Ok(McsPdu {
            kind,
            raw: user_data,
            send_data: None,
        });
    }
    let choice = user_data[0] >> 2;
    let kind =
        McsPduType::from_domain_choice(choice).ok_or(RdpParseError::UnknownMcsPdu(choice))?;
    let send_data = match kind {
        McsPduType::SendDataRequest | McsPduType::SendDataIndication => Some(send_data(user_data)?),
        _ => None,
    };
    Ok(McsPdu {
        kind,
        raw: user_data,
        send_data,
    })
}

/// Longueur BER (X.690 §8.1.3) : courte, ou longue sur un a quatre octets.
fn ber_length(bytes: &[u8]) -> Option<(usize, usize)> {
    let first = *bytes.first()?;
    if first & 0x80 == 0 {
        return Some((usize::from(first), 1));
    }
    let octets = usize::from(first & 0x7f);
    if octets == 0 || octets > 4 {
        return None;
    }
    let digits = bytes.get(1..1 + octets)?;
    let length = digits
        .iter()
        .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
    Some((length, 1 + octets))
}

/// Send Data (T.125 §7, PER aligne) : choix, initiator, channelId, priorite
/// et segmentation, longueur, donnees.
fn send_data(bytes: &[u8]) -> Result<McsSendData<'_>, RdpParseError> {
    ensure_len(bytes, 6)?;
    let initiator = u16::from_be_bytes([bytes[1], bytes[2]]).wrapping_add(MCS_USER_ID_BASE);
    let channel_id = u16::from_be_bytes([bytes[3], bytes[4]]);
    let priority_and_segmentation = bytes[5];
    let rest = &bytes[6..];
    let (declared_length, data) = match rest {
        [] => (None, rest),
        [short, data @ ..] if short & 0x80 == 0 => (Some(u16::from(*short)), data),
        [high, low, data @ ..] if high & 0xc0 == 0x80 => {
            (Some(u16::from_be_bytes([high & 0x3f, *low])), data)
        }
        // Longueur fragmentee (0xc0) : les donnees suivent sans compte lisible.
        _ => (None, rest),
    };
    Ok(McsSendData {
        initiator,
        channel_id,
        priority_and_segmentation,
        declared_length,
        data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// pcaps_exemple/protocols/rdp/rdp-x509.pcap, trame 6 : Connection
    /// Request avec cookie et demande de negociation (tshark 4.6.6).
    const CR_WITH_COOKIE: &str = "0300002f2ae00000000000436f6f6b69653a206d737473686173683d4a4f484e2d504320200d0a0100080000000000";
    /// rdp-no-cookie-mstshash.pcap, trame 7 : sans cookie, TLS, CredSSP et
    /// CredSSP-EX demandes.
    const CR_WITHOUT_COOKIE: &str = "030000130ee00000000000010008000b000000";
    /// rdp-x509.pcap, trame 7 : Connection Confirm, securite RDP standard.
    const CC_STANDARD: &str = "030000130ed000001234000200080000000000";
    /// rdp-no-cookie-mstshash.pcap, trame 9 : CredSSP-EX retenu, drapeaux 0x1f.
    const CC_HYBRID_EX: &str = "030000130ed00000123400021f080008000000";
    /// rdp-proprietary-encryption.pcap, trames 16, 17, 19, 20, 21 : les
    /// DomainMCSPDU de l'etablissement de session.
    const ERECT_DOMAIN: &str = "0300000c02f0800401000100";
    const ATTACH_USER_REQUEST: &str = "0300000802f08028";
    const ATTACH_USER_CONFIRM: &str = "0300000b02f0802e000007";
    const CHANNEL_JOIN_REQUEST: &str = "0300000c02f08038000703f0";
    const CHANNEL_JOIN_CONFIRM: &str = "0300000f02f0803e00000703f003f0";
    /// Meme capture, trame 32 : tete d'un Send Data Request vers le canal
    /// 1003, 80 octets annonces (tronque ici a 40 pour la graine).
    const SEND_DATA_HEAD: &str =
        "0300005e02f08064000703eb705001020000480000008b689c55b7c81a58755f6260006995ae78bab7";
    /// Meme capture, trame 14 : tete du Connect-Initial (BER, 416 octets).
    const CONNECT_INITIAL_HEAD: &str = "030001ac02f0807f658201a00401010401010101ff3019020122";

    fn parse(hex: &str) -> RdpPacket<'static> {
        let bytes: &'static [u8] = Box::leak(hex::decode(hex).unwrap().into_boxed_slice());
        RdpPacket::try_from(bytes).expect("RDP")
    }

    #[test]
    fn test_connection_request_with_and_without_cookie() {
        let packet = parse(CR_WITH_COOKIE);
        assert_eq!(packet.pdus.len(), 1);
        assert!(!packet.truncated);
        let pdu = &packet.pdus[0];
        assert_eq!(pdu.tpkt_length, 47);
        assert_eq!(pdu.cotp.pdu_type, CotpPduType::ConnectionRequest);
        assert_eq!((pdu.cotp.dst_ref, pdu.cotp.src_ref), (Some(0), Some(0)));
        assert_eq!(pdu.cotp.class, Some(0));
        let RdpPayload::ConnectionRequest { token, negotiation } = &pdu.payload else {
            panic!("CR attendu");
        };
        assert_eq!(*token, Some(&b"Cookie: mstshash=JOHN-PC  "[..]));
        assert_eq!(pdu.payload.cookie_user(), Some("JOHN-PC  "));
        let negotiation = negotiation.expect("negociation");
        assert_eq!(negotiation.flags, 0);
        assert_eq!(negotiation.requested_protocols, 0);
        assert!(!negotiation.tls() && !negotiation.credssp() && !negotiation.rdstls());
        assert!(negotiation.standard_security_only());

        let packet = parse(CR_WITHOUT_COOKIE);
        let RdpPayload::ConnectionRequest { token, negotiation } = &packet.pdus[0].payload else {
            panic!("CR attendu");
        };
        assert_eq!(*token, None);
        assert_eq!(packet.pdus[0].payload.cookie_user(), None);
        let negotiation = negotiation.expect("negociation");
        assert_eq!(negotiation.requested_protocols, 0x0b);
        assert!(negotiation.tls() && negotiation.credssp() && !negotiation.rdstls());
    }

    /// #187 : Connection Request avec RDP_NEG_CORRELATION_INFO (drapeau
    /// `0x08`), synthetiques, conformes a §2.2.1.1.2. tshark 4.6.6 lit les
    /// deux structures (`rdp.neg_type` 0x01 puis 0x06, `rdp.neg_length` 8
    /// puis 36) et `rdp.correlationInfo.correlationId`.
    const CR_CORRELATION_WITH_COOKIE: &str = concat!(
        "0300004b46e00000000000436f6f6b69653a206d737473686173683d780d0a010808000b",
        "00000006002400a1b2c3d4e5f60718293a4b5c6d7e8f9000000000000000000000000000000000"
    );
    const CR_CORRELATION_WITHOUT_COOKIE: &str = concat!(
        "0300003732e00000000000010808000b00000006002400a1b2c3d4e5f60718293a4b5c6d",
        "7e8f9000000000000000000000000000000000"
    );
    const CORRELATION_ID: [u8; 16] = [
        0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f,
        0x90,
    ];

    #[test]
    fn test_connection_request_with_correlation_info() {
        for (hex, expected_token) in [
            (CR_CORRELATION_WITH_COOKIE, Some(&b"Cookie: mstshash=x"[..])),
            (CR_CORRELATION_WITHOUT_COOKIE, None),
        ] {
            let packet = parse(hex);
            assert_eq!(packet.pdus.len(), 1);
            assert!(!packet.truncated);
            let RdpPayload::ConnectionRequest { token, negotiation } = &packet.pdus[0].payload
            else {
                panic!("CR attendu");
            };
            assert_eq!(*token, expected_token);
            let negotiation = negotiation.expect("negociation");
            assert_eq!(negotiation.flags, 0x08);
            assert!(negotiation.correlation_info_present());
            assert_eq!(negotiation.requested_protocols, 0x0b);
            assert!(negotiation.tls() && negotiation.credssp());
            assert_eq!(negotiation.correlation_id, Some(CORRELATION_ID));
        }

        // Le drapeau sans la structure : accepte, comme en 11.6.0 (tshark :
        // malforme).
        let packet = parse("030000130ee00000000000010808000b000000");
        let RdpPayload::ConnectionRequest { negotiation, .. } = &packet.pdus[0].payload else {
            panic!("CR attendu");
        };
        let negotiation = negotiation.expect("negociation");
        assert!(negotiation.correlation_info_present());
        assert_eq!(negotiation.correlation_id, None);

        // Sans le drapeau, la demande de negociation est faite de ses huit
        // octets : la 11.6.0 repondait « declares 8 bytes, not 8 ».
        let bytes = hex::decode(CR_CORRELATION_WITHOUT_COOKIE).unwrap();
        let mut without_flag = bytes.clone();
        without_flag[12] = 0x00;
        assert_eq!(
            RdpPacket::try_from(without_flag.as_slice()),
            Err(RdpParseError::UnexpectedX224Data(36))
        );
        // Longueur 32 (tshark : « RDP Correlation Info length is 32, not
        // 36 ») ou type autre que 0x06.
        let mut length_32 = bytes.clone();
        length_32[21] = 0x20;
        assert_eq!(
            RdpPacket::try_from(length_32.as_slice()),
            Err(RdpParseError::InvalidCorrelationInfo {
                structure_type: 0x06,
                length: 32
            })
        );
        let mut other_type = bytes.clone();
        other_type[19] = 0x07;
        assert_eq!(
            RdpPacket::try_from(other_type.as_slice()),
            Err(RdpParseError::InvalidCorrelationInfo {
                structure_type: 0x07,
                length: 36
            })
        );
        // Structure coupee par la segmentation : le TPKT et le LI couvrent
        // 51 octets, la correlation info n'en a que 32.
        let mut cut = bytes[..51].to_vec();
        cut[3] = 51;
        cut[4] = 46;
        assert_eq!(
            RdpPacket::try_from(cut.as_slice()),
            Err(RdpParseError::Truncated {
                expected: 36,
                actual: 32
            })
        );
        // Un octet apres la correlation info.
        let mut extra = bytes.clone();
        extra.push(0);
        extra[3] = 56;
        extra[4] = 51;
        assert_eq!(
            RdpPacket::try_from(extra.as_slice()),
            Err(RdpParseError::UnexpectedX224Data(1))
        );

        // Une demande de negociation coupee au milieu de ses huit octets
        // (longueur declaree juste) : Truncated, plus « declares 8 bytes,
        // not 8 ».
        let bytes = hex::decode(CR_WITH_COOKIE).unwrap();
        let packet = RdpPacket::try_from(&bytes[..43]);
        assert_eq!(
            packet,
            Err(RdpParseError::Truncated {
                expected: 8,
                actual: 4
            })
        );
        // Un Connection Confirm dont le LI couvre quatre octets apres la
        // reponse.
        let bytes = hex::decode("0300001712d00000123400020008000000000000000000").unwrap();
        assert_eq!(
            RdpPacket::try_from(bytes.as_slice()),
            Err(RdpParseError::UnexpectedX224Data(4))
        );
    }

    #[test]
    fn test_connection_confirm() {
        let packet = parse(CC_STANDARD);
        let pdu = &packet.pdus[0];
        assert_eq!(pdu.cotp.pdu_type, CotpPduType::ConnectionConfirm);
        assert_eq!(pdu.cotp.src_ref, Some(0x1234));
        assert_eq!(
            pdu.payload,
            RdpPayload::ConnectionConfirm {
                negotiation: Some(NegotiationResponse::Accepted {
                    flags: 0,
                    selected_protocol: 0
                })
            }
        );
        let packet = parse(CC_HYBRID_EX);
        assert_eq!(
            packet.pdus[0].payload,
            RdpPayload::ConnectionConfirm {
                negotiation: Some(NegotiationResponse::Accepted {
                    flags: 0x1f,
                    selected_protocol: 8
                })
            }
        );
        // Un echec de negociation synthetique : TLS requis.
        let mut failure = hex::decode(CC_STANDARD).unwrap();
        failure[11] = 0x03;
        failure[15] = 0x01;
        let packet = RdpPacket::try_from(failure.as_slice()).expect("echec");
        assert_eq!(
            packet.pdus[0].payload,
            RdpPayload::ConnectionConfirm {
                negotiation: Some(NegotiationResponse::Failure { failure_code: 1 })
            }
        );
    }

    #[test]
    fn test_mcs_domain_pdus_and_send_data() {
        for (hex, kind) in [
            (ERECT_DOMAIN, McsPduType::ErectDomainRequest),
            (ATTACH_USER_REQUEST, McsPduType::AttachUserRequest),
            (ATTACH_USER_CONFIRM, McsPduType::AttachUserConfirm),
            (CHANNEL_JOIN_REQUEST, McsPduType::ChannelJoinRequest),
            (CHANNEL_JOIN_CONFIRM, McsPduType::ChannelJoinConfirm),
        ] {
            let packet = parse(hex);
            let RdpPayload::Mcs(mcs) = &packet.pdus[0].payload else {
                panic!("MCS attendu pour {hex}");
            };
            assert_eq!(mcs.kind, kind, "{hex}");
            assert_eq!(mcs.send_data, None);
            assert_eq!(packet.pdus[0].cotp.pdu_type, CotpPduType::Data);
        }

        let packet = parse(SEND_DATA_HEAD);
        assert!(packet.truncated);
        let RdpPayload::Mcs(mcs) = &packet.pdus[0].payload else {
            panic!("MCS attendu");
        };
        assert_eq!(mcs.kind, McsPduType::SendDataRequest);
        let send = mcs.send_data.expect("send data");
        assert_eq!(send.initiator, 1008);
        assert_eq!(send.channel_id, 1003);
        assert_eq!(send.priority_and_segmentation, 0x70);
        assert_eq!(send.declared_length, Some(80));
        assert_eq!(send.data.len(), 27);
        assert_eq!(&send.data[..4], &[0x01, 0x02, 0x00, 0x00]);

        let packet = parse(CONNECT_INITIAL_HEAD);
        assert!(packet.truncated);
        assert_eq!(packet.pdus[0].tpkt_length, 428);
        let RdpPayload::Mcs(mcs) = &packet.pdus[0].payload else {
            panic!("MCS attendu");
        };
        assert_eq!(mcs.kind, McsPduType::ConnectInitial);
    }

    #[test]
    fn test_several_tpkts_and_rejections() {
        let mut both = hex::decode(ATTACH_USER_REQUEST).unwrap();
        both.extend_from_slice(&hex::decode(ERECT_DOMAIN).unwrap());
        let packet = RdpPacket::try_from(both.as_slice()).expect("deux TPKT");
        assert_eq!(packet.pdus.len(), 2);
        assert!(!packet.truncated);

        let bytes = hex::decode(CR_WITH_COOKIE).unwrap();
        let mut version = bytes.clone();
        version[0] = 2;
        assert_eq!(
            RdpPacket::try_from(version.as_slice()),
            Err(RdpParseError::InvalidTpkt {
                version: 2,
                reserved: 0
            })
        );
        let mut short = bytes.clone();
        short[3] = 6;
        assert_eq!(
            RdpPacket::try_from(short.as_slice()),
            Err(RdpParseError::TpktTooShort(6))
        );
        let mut tpdu = bytes.clone();
        tpdu[5] = 0x80;
        assert!(matches!(
            RdpPacket::try_from(tpdu.as_slice()),
            Err(RdpParseError::UnexpectedTpdu(0x80))
        ));
        let mut negotiation = bytes.clone();
        negotiation[41] = 9;
        assert_eq!(
            RdpPacket::try_from(negotiation.as_slice()),
            Err(RdpParseError::InvalidNegotiation {
                structure_type: 1,
                length: 9
            })
        );
        let mut garbage = bytes.clone();
        garbage[39] = 0x55;
        assert_eq!(
            RdpPacket::try_from(garbage.as_slice()),
            Err(RdpParseError::UnexpectedX224Data(8))
        );
        let mut choice = hex::decode(ERECT_DOMAIN).unwrap();
        choice[7] = 0xfc;
        assert_eq!(
            RdpPacket::try_from(choice.as_slice()),
            Err(RdpParseError::UnknownMcsPdu(63))
        );
        assert!(matches!(
            RdpPacket::try_from(&b"\x03\x00\x00\x05\x02\xf0\x80"[..]),
            Err(RdpParseError::TpktTooShort(5))
        ));
        assert!(RdpPacket::try_from(&[][..]).is_err());
    }
}
