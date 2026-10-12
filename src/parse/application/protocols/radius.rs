// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! RADIUS, Remote Authentication Dial In User Service (RFC 2865,
//! comptabilite RFC 2866, changement d'autorisation RFC 5176) : qui se
//! connecte, par quel equipement, avec quel resultat. UDP 1812 et 1813, les
//! anciens 1645 et 1646, 3799 pour la RFC 5176 — et tout autre port : un
//! code connu, une longueur qui couvre exactement le datagramme et des
//! attributs qui le pavent suffisent a le reconnaitre a l'aveugle.
//!
//! Le decodeur lit l'en-tete (code nomme par [`RadiusCode`], identifiant,
//! longueur, authentificateur) et la liste des attributs — type nomme par
//! [`AttributeType`], valeur empruntee au datagramme, accesseurs pour les
//! entiers, adresses et textes de la RFC, identifiant de vendeur des
//! Vendor-Specific. Les mots de passe restent chiffres : rien ici ne
//! connait le secret partage.

use std::{convert::TryFrom, net::Ipv4Addr};

use crate::{
    checks::application::radius::{
        RADIUS_ATTRIBUTE_HEADER_LENGTH, RADIUS_HEADER_LENGTH, RADIUS_VENDOR_ID_LENGTH, ensure_len,
        validate_attribute_length, validate_code, validate_length,
    },
    errors::application::radius::RadiusParseError,
    parse::application::protocols::bounded_capacity,
};

/// Codes de paquet (RFC 2865 §3, RFC 2866 §4, RFC 5176 §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RadiusCode {
    AccessRequest,
    AccessAccept,
    AccessReject,
    AccountingRequest,
    AccountingResponse,
    AccessChallenge,
    StatusServer,
    StatusClient,
    DisconnectRequest,
    DisconnectAck,
    DisconnectNak,
    CoaRequest,
    CoaAck,
    CoaNak,
}

impl RadiusCode {
    pub fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::AccessRequest,
            2 => Self::AccessAccept,
            3 => Self::AccessReject,
            4 => Self::AccountingRequest,
            5 => Self::AccountingResponse,
            11 => Self::AccessChallenge,
            12 => Self::StatusServer,
            13 => Self::StatusClient,
            40 => Self::DisconnectRequest,
            41 => Self::DisconnectAck,
            42 => Self::DisconnectNak,
            43 => Self::CoaRequest,
            44 => Self::CoaAck,
            45 => Self::CoaNak,
            _ => return None,
        })
    }
}

/// Types d'attributs des RFC 2865, 2866, 2868, 2869, 3162 et 5176 (registre
/// IANA « RADIUS Attribute Types »).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AttributeType {
    UserName,
    UserPassword,
    ChapPassword,
    NasIpAddress,
    NasPort,
    ServiceType,
    FramedProtocol,
    FramedIpAddress,
    FramedIpNetmask,
    FramedRouting,
    FilterId,
    FramedMtu,
    FramedCompression,
    LoginIpHost,
    LoginService,
    LoginTcpPort,
    ReplyMessage,
    CallbackNumber,
    CallbackId,
    FramedRoute,
    FramedIpxNetwork,
    State,
    Class,
    VendorSpecific,
    SessionTimeout,
    IdleTimeout,
    TerminationAction,
    CalledStationId,
    CallingStationId,
    NasIdentifier,
    ProxyState,
    LoginLatService,
    LoginLatNode,
    LoginLatGroup,
    FramedAppleTalkLink,
    FramedAppleTalkNetwork,
    FramedAppleTalkZone,
    AcctStatusType,
    AcctDelayTime,
    AcctInputOctets,
    AcctOutputOctets,
    AcctSessionId,
    AcctAuthentic,
    AcctSessionTime,
    AcctInputPackets,
    AcctOutputPackets,
    AcctTerminateCause,
    AcctMultiSessionId,
    AcctLinkCount,
    AcctInputGigawords,
    AcctOutputGigawords,
    EventTimestamp,
    EgressVlanId,
    IngressFilters,
    EgressVlanName,
    UserPriorityTable,
    ChapChallenge,
    NasPortType,
    PortLimit,
    LoginLatPort,
    TunnelType,
    TunnelMediumType,
    TunnelClientEndpoint,
    TunnelServerEndpoint,
    AcctTunnelConnection,
    TunnelPassword,
    ArapPassword,
    ArapFeatures,
    ArapZoneAccess,
    ArapSecurity,
    ArapSecurityData,
    PasswordRetry,
    Prompt,
    ConnectInfo,
    ConfigurationToken,
    EapMessage,
    MessageAuthenticator,
    TunnelPrivateGroupId,
    TunnelAssignmentId,
    TunnelPreference,
    ArapChallengeResponse,
    AcctInterimInterval,
    AcctTunnelPacketsLost,
    NasPortId,
    FramedPool,
    ChargeableUserIdentity,
    TunnelClientAuthId,
    TunnelServerAuthId,
    NasFilterRule,
    OriginatingLineInfo,
    NasIpv6Address,
    FramedInterfaceId,
    FramedIpv6Prefix,
    LoginIpv6Host,
    FramedIpv6Route,
    FramedIpv6Pool,
    ErrorCause,
    EapKeyName,
    DigestResponse,
    DigestRealm,
    DigestNonce,
    DigestResponseAuth,
    DigestNextnonce,
    DigestMethod,
    DigestUri,
    DigestQop,
    DigestAlgorithm,
    DigestEntityBodyHash,
    DigestCnonce,
    DigestNonceCount,
    DigestUsername,
    DigestOpaque,
    DigestAuthParam,
    DigestAkaAuts,
    DigestDomain,
    DigestStale,
    DigestHa1,
    SipAor,
    DelegatedIpv6Prefix,
    MipHomeAgentAddress,
    MipHomeAgentHost,
    ExtendedType1,
    ExtendedType2,
    ExtendedType3,
    ExtendedType4,
    LongExtendedType1,
    LongExtendedType2,
}

impl AttributeType {
    pub fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::UserName,
            2 => Self::UserPassword,
            3 => Self::ChapPassword,
            4 => Self::NasIpAddress,
            5 => Self::NasPort,
            6 => Self::ServiceType,
            7 => Self::FramedProtocol,
            8 => Self::FramedIpAddress,
            9 => Self::FramedIpNetmask,
            10 => Self::FramedRouting,
            11 => Self::FilterId,
            12 => Self::FramedMtu,
            13 => Self::FramedCompression,
            14 => Self::LoginIpHost,
            15 => Self::LoginService,
            16 => Self::LoginTcpPort,
            18 => Self::ReplyMessage,
            19 => Self::CallbackNumber,
            20 => Self::CallbackId,
            22 => Self::FramedRoute,
            23 => Self::FramedIpxNetwork,
            24 => Self::State,
            25 => Self::Class,
            26 => Self::VendorSpecific,
            27 => Self::SessionTimeout,
            28 => Self::IdleTimeout,
            29 => Self::TerminationAction,
            30 => Self::CalledStationId,
            31 => Self::CallingStationId,
            32 => Self::NasIdentifier,
            33 => Self::ProxyState,
            34 => Self::LoginLatService,
            35 => Self::LoginLatNode,
            36 => Self::LoginLatGroup,
            37 => Self::FramedAppleTalkLink,
            38 => Self::FramedAppleTalkNetwork,
            39 => Self::FramedAppleTalkZone,
            40 => Self::AcctStatusType,
            41 => Self::AcctDelayTime,
            42 => Self::AcctInputOctets,
            43 => Self::AcctOutputOctets,
            44 => Self::AcctSessionId,
            45 => Self::AcctAuthentic,
            46 => Self::AcctSessionTime,
            47 => Self::AcctInputPackets,
            48 => Self::AcctOutputPackets,
            49 => Self::AcctTerminateCause,
            50 => Self::AcctMultiSessionId,
            51 => Self::AcctLinkCount,
            52 => Self::AcctInputGigawords,
            53 => Self::AcctOutputGigawords,
            55 => Self::EventTimestamp,
            56 => Self::EgressVlanId,
            57 => Self::IngressFilters,
            58 => Self::EgressVlanName,
            59 => Self::UserPriorityTable,
            60 => Self::ChapChallenge,
            61 => Self::NasPortType,
            62 => Self::PortLimit,
            63 => Self::LoginLatPort,
            64 => Self::TunnelType,
            65 => Self::TunnelMediumType,
            66 => Self::TunnelClientEndpoint,
            67 => Self::TunnelServerEndpoint,
            68 => Self::AcctTunnelConnection,
            69 => Self::TunnelPassword,
            70 => Self::ArapPassword,
            71 => Self::ArapFeatures,
            72 => Self::ArapZoneAccess,
            73 => Self::ArapSecurity,
            74 => Self::ArapSecurityData,
            75 => Self::PasswordRetry,
            76 => Self::Prompt,
            77 => Self::ConnectInfo,
            78 => Self::ConfigurationToken,
            79 => Self::EapMessage,
            80 => Self::MessageAuthenticator,
            81 => Self::TunnelPrivateGroupId,
            82 => Self::TunnelAssignmentId,
            83 => Self::TunnelPreference,
            84 => Self::ArapChallengeResponse,
            85 => Self::AcctInterimInterval,
            86 => Self::AcctTunnelPacketsLost,
            87 => Self::NasPortId,
            88 => Self::FramedPool,
            89 => Self::ChargeableUserIdentity,
            90 => Self::TunnelClientAuthId,
            91 => Self::TunnelServerAuthId,
            92 => Self::NasFilterRule,
            94 => Self::OriginatingLineInfo,
            95 => Self::NasIpv6Address,
            96 => Self::FramedInterfaceId,
            97 => Self::FramedIpv6Prefix,
            98 => Self::LoginIpv6Host,
            99 => Self::FramedIpv6Route,
            100 => Self::FramedIpv6Pool,
            101 => Self::ErrorCause,
            102 => Self::EapKeyName,
            103 => Self::DigestResponse,
            104 => Self::DigestRealm,
            105 => Self::DigestNonce,
            106 => Self::DigestResponseAuth,
            107 => Self::DigestNextnonce,
            108 => Self::DigestMethod,
            109 => Self::DigestUri,
            110 => Self::DigestQop,
            111 => Self::DigestAlgorithm,
            112 => Self::DigestEntityBodyHash,
            113 => Self::DigestCnonce,
            114 => Self::DigestNonceCount,
            115 => Self::DigestUsername,
            116 => Self::DigestOpaque,
            117 => Self::DigestAuthParam,
            118 => Self::DigestAkaAuts,
            119 => Self::DigestDomain,
            120 => Self::DigestStale,
            121 => Self::DigestHa1,
            122 => Self::SipAor,
            123 => Self::DelegatedIpv6Prefix,
            124 => Self::MipHomeAgentAddress,
            125 => Self::MipHomeAgentHost,
            241 => Self::ExtendedType1,
            242 => Self::ExtendedType2,
            243 => Self::ExtendedType3,
            244 => Self::ExtendedType4,
            245 => Self::LongExtendedType1,
            246 => Self::LongExtendedType2,
            _ => return None,
        })
    }
}

/// Un attribut (RFC 2865 §5) : type, longueur, valeur.
///
/// ```mermaid
/// ---
/// title: RadiusAttribute
/// ---
/// packet-beta
/// 0-7: "Type u8"
/// 8-15: "Length u8"
/// 16-63: "Value (length - 2 bytes)"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct RadiusAttribute<'a> {
    pub attribute_type: u8,
    /// Le type nomme, quand le registre le connait.
    pub kind: Option<AttributeType>,
    /// Longueur declaree, en-tete compris.
    pub length: u8,
    pub value: &'a [u8],
}

impl<'a> RadiusAttribute<'a> {
    /// Un entier ou une enumeration de quatre octets (NAS-Port,
    /// Service-Type, Acct-Status-Type…).
    pub fn as_u32(&self) -> Option<u32> {
        let [a, b, c, d] = self.value else {
            return None;
        };
        Some(u32::from_be_bytes([*a, *b, *c, *d]))
    }

    /// Une adresse IPv4 (NAS-IP-Address, Framed-IP-Address…).
    pub fn as_ipv4(&self) -> Option<Ipv4Addr> {
        let [a, b, c, d] = self.value else {
            return None;
        };
        Some(Ipv4Addr::new(*a, *b, *c, *d))
    }

    /// Un texte UTF-8 (User-Name, NAS-Identifier, Reply-Message…).
    pub fn as_text(&self) -> Option<&'a str> {
        std::str::from_utf8(self.value).ok()
    }

    /// Vendor-Specific : l'identifiant de vendeur (registre IANA « Private
    /// Enterprise Numbers »), puis les attributs propres au vendeur.
    pub fn vendor(&self) -> Option<(u32, &'a [u8])> {
        if self.kind != Some(AttributeType::VendorSpecific) {
            return None;
        }
        let (id, rest) = self.value.split_at_checked(RADIUS_VENDOR_ID_LENGTH)?;
        Some((u32::from_be_bytes([id[0], id[1], id[2], id[3]]), rest))
    }
}

/// Un paquet RADIUS (RFC 2865 §3).
///
/// ```mermaid
/// ---
/// title: RadiusPacket
/// ---
/// packet-beta
/// 0-7: "Code u8"
/// 8-15: "Identifier u8"
/// 16-31: "Length u16"
/// 32-159: "Authenticator (16 bytes)"
/// 160-191: "Attributes (variable)"
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RadiusPacket<'a> {
    pub code: u8,
    /// Le code nomme ; toujours connu, le decodeur refuse les autres.
    pub kind: RadiusCode,
    /// Apparie requete et reponse.
    pub identifier: u8,
    /// Longueur declaree, egale au datagramme.
    pub length: u16,
    /// Request Authenticator (aleatoire) ou Response Authenticator (MD5 du
    /// secret partage) : seize octets, tels quels.
    pub authenticator: [u8; 16],
    pub attributes: Vec<RadiusAttribute<'a>>,
}

impl<'a> RadiusPacket<'a> {
    /// Le premier attribut d'un type donne.
    pub fn attribute(&self, kind: AttributeType) -> Option<&RadiusAttribute<'a>> {
        self.attributes
            .iter()
            .find(|attribute| attribute.kind == Some(kind))
    }
}

impl<'a> TryFrom<&'a [u8]> for RadiusPacket<'a> {
    type Error = RadiusParseError;

    fn try_from(payload: &'a [u8]) -> Result<Self, Self::Error> {
        ensure_len(payload, RADIUS_HEADER_LENGTH)?;
        let code = payload[0];
        validate_code(code)?;
        let kind = RadiusCode::from_code(code).ok_or(RadiusParseError::UnknownCode(code))?;
        let length = u16::from_be_bytes([payload[2], payload[3]]);
        validate_length(length, payload.len())?;
        let mut authenticator = [0u8; 16];
        authenticator.copy_from_slice(&payload[4..RADIUS_HEADER_LENGTH]);

        let mut attributes = Vec::with_capacity(bounded_capacity(
            16,
            payload.len() - RADIUS_HEADER_LENGTH,
            RADIUS_ATTRIBUTE_HEADER_LENGTH,
        ));
        let mut offset = RADIUS_HEADER_LENGTH;
        while offset < payload.len() {
            let available = payload.len() - offset;
            if available < RADIUS_ATTRIBUTE_HEADER_LENGTH {
                return Err(RadiusParseError::AttributeOverflow {
                    attribute_type: payload[offset],
                    needed: RADIUS_ATTRIBUTE_HEADER_LENGTH,
                    available,
                });
            }
            let attribute_type = payload[offset];
            let declared = payload[offset + 1];
            let total = validate_attribute_length(attribute_type, declared, available)?;
            attributes.push(RadiusAttribute {
                attribute_type,
                kind: AttributeType::from_code(attribute_type),
                length: declared,
                value: &payload[offset + RADIUS_ATTRIBUTE_HEADER_LENGTH..offset + total],
            });
            offset += total;
        }
        Ok(RadiusPacket {
            code,
            kind,
            identifier: payload[1],
            length,
            authenticator,
            attributes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// pcaps_exemple/protocols/radius/radius.pcap, trame 1 (UDP 1645 ->
    /// 1812) : Access-Request d'un commutateur Cisco pour John.McGuirk,
    /// dix attributs (tshark 4.6.6).
    const ACCESS_REQUEST: &str = concat!(
        "0105008becfe3d2fe4473ec6299095ee46aedf7704060a00000105060000c35c3d06",
        "0000000f010e4a6f686e2e4d63477569726b1e1330302d31392d30362d45412d4238",
        "2d38431f1330302d31342d32322d45392d35342d35450606000000020c06000005dc",
        "4f1302000011014a6f686e2e4d63477569726b501228c5beb8842486da70db51316f",
        "9d7889"
    );

    /// Meme capture, trame 2 : l'Access-Challenge du serveur, sept attributs.
    const ACCESS_CHALLENGE: &str = concat!(
        "0b05006df050649184625d36f14c9075b7a48b830806fffffffe0c060000024006",
        "0600000002120b48656c6c6f2c2025754f18010100160410266b0e9a58322f4d01",
        "ab25b35f879464501211b5043c8a288758173133a5e07434cf1812c6d195032fdc",
        "30240f7313b231ef1d77"
    );

    /// pcaps_exemple/protocols/radius/radius_localhost.pcap, trame 4 :
    /// Access-Reject, EAP-Message et Message-Authenticator.
    const ACCESS_REJECT: &str = concat!(
        "0368002c71624da25c0b5897f70539e019a81eae4f06046700045012ce70fe87a9",
        "97b44de583cd19bea29321"
    );

    #[test]
    fn test_decodes_an_access_request_against_tshark() {
        let bytes = hex::decode(ACCESS_REQUEST).unwrap();
        assert_eq!(bytes.len(), 139);
        let packet = RadiusPacket::try_from(bytes.as_slice()).expect("Access-Request");
        assert_eq!(packet.kind, RadiusCode::AccessRequest);
        assert_eq!((packet.code, packet.identifier, packet.length), (1, 5, 139));
        assert_eq!(packet.authenticator[..4], [0xec, 0xfe, 0x3d, 0x2f]);
        let types: Vec<u8> = packet.attributes.iter().map(|a| a.attribute_type).collect();
        assert_eq!(types, [4, 5, 61, 1, 30, 31, 6, 12, 79, 80]);
        let lengths: Vec<u8> = packet.attributes.iter().map(|a| a.length).collect();
        assert_eq!(lengths, [6, 6, 6, 14, 19, 19, 6, 6, 19, 18]);
        assert_eq!(
            packet
                .attribute(AttributeType::NasIpAddress)
                .and_then(RadiusAttribute::as_ipv4),
            Some(Ipv4Addr::new(10, 0, 0, 1))
        );
        assert_eq!(
            packet
                .attribute(AttributeType::NasPort)
                .and_then(RadiusAttribute::as_u32),
            Some(50012)
        );
        assert_eq!(
            packet
                .attribute(AttributeType::UserName)
                .and_then(RadiusAttribute::as_text),
            Some("John.McGuirk")
        );
        assert_eq!(
            packet
                .attribute(AttributeType::CallingStationId)
                .and_then(RadiusAttribute::as_text),
            Some("00-14-22-E9-54-5E")
        );
        assert_eq!(
            packet
                .attribute(AttributeType::FramedMtu)
                .and_then(RadiusAttribute::as_u32),
            Some(1500)
        );
        assert_eq!(
            packet
                .attribute(AttributeType::EapMessage)
                .map(|a| a.value.len()),
            Some(17)
        );
        assert_eq!(packet.attribute(AttributeType::VendorSpecific), None);
        assert!(
            bytes
                .as_ptr_range()
                .contains(&packet.attributes[0].value.as_ptr())
        );
    }

    #[test]
    fn test_decodes_challenge_and_reject() {
        let bytes = hex::decode(ACCESS_CHALLENGE).unwrap();
        let packet = RadiusPacket::try_from(bytes.as_slice()).expect("Access-Challenge");
        assert_eq!(packet.kind, RadiusCode::AccessChallenge);
        assert_eq!(packet.identifier, 5);
        let types: Vec<u8> = packet.attributes.iter().map(|a| a.attribute_type).collect();
        assert_eq!(types, [8, 12, 6, 18, 79, 80, 24]);
        assert_eq!(
            packet
                .attribute(AttributeType::FramedIpAddress)
                .and_then(RadiusAttribute::as_ipv4),
            Some(Ipv4Addr::new(255, 255, 255, 254))
        );
        assert_eq!(
            packet
                .attribute(AttributeType::ReplyMessage)
                .and_then(RadiusAttribute::as_text),
            Some("Hello, %u")
        );
        assert_eq!(
            packet
                .attribute(AttributeType::State)
                .map(|a| a.value.len()),
            Some(16)
        );

        let bytes = hex::decode(ACCESS_REJECT).unwrap();
        let packet = RadiusPacket::try_from(bytes.as_slice()).expect("Access-Reject");
        assert_eq!(packet.kind, RadiusCode::AccessReject);
        assert_eq!((packet.identifier, packet.length), (104, 44));
        assert_eq!(packet.attributes.len(), 2);
    }

    /// Un Vendor-Specific synthetique (Microsoft, 311) dans un Access-Accept
    /// minimal, et un attribut de type inconnu, garde sans nom.
    #[test]
    fn test_vendor_specific_and_unknown_attribute() {
        let mut bytes = vec![2, 7, 0, 0];
        bytes.extend_from_slice(&[0xaa; 16]);
        bytes.extend_from_slice(&[26, 12, 0, 0, 1, 55, 16, 6, 0, 0, 0, 1]);
        bytes.extend_from_slice(&[200, 3, 0xff]);
        let len = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&len.to_be_bytes());
        let packet = RadiusPacket::try_from(bytes.as_slice()).expect("Access-Accept");
        assert_eq!(packet.kind, RadiusCode::AccessAccept);
        let vendor = packet
            .attribute(AttributeType::VendorSpecific)
            .expect("VSA");
        assert_eq!(vendor.vendor(), Some((311, &[16u8, 6, 0, 0, 0, 1][..])));
        assert_eq!(packet.attributes[1].kind, None);
        assert_eq!(packet.attributes[1].value, &[0xff]);
        assert_eq!(packet.attributes[0].as_u32(), None);
    }

    #[test]
    fn test_rejects_bad_headers_and_attributes() {
        let bytes = hex::decode(ACCESS_REQUEST).unwrap();
        assert_eq!(
            RadiusPacket::try_from(&bytes[..19]),
            Err(RadiusParseError::Truncated {
                expected: 20,
                actual: 19
            })
        );
        let mut code = bytes.clone();
        code[0] = 6;
        assert_eq!(
            RadiusPacket::try_from(code.as_slice()),
            Err(RadiusParseError::UnknownCode(6))
        );
        assert_eq!(
            RadiusPacket::try_from(&bytes[..138]),
            Err(RadiusParseError::LengthMismatch {
                declared: 139,
                actual: 138
            })
        );
        let mut short = bytes.clone();
        short[2..4].copy_from_slice(&19u16.to_be_bytes());
        assert_eq!(
            RadiusPacket::try_from(&short[..19]),
            Err(RadiusParseError::Truncated {
                expected: 20,
                actual: 19
            })
        );
        let mut tiny = bytes.clone();
        tiny[21] = 1;
        assert_eq!(
            RadiusPacket::try_from(tiny.as_slice()),
            Err(RadiusParseError::AttributeTooShort {
                attribute_type: 4,
                length: 1
            })
        );
        let mut overflow = bytes.clone();
        overflow[21] = 200;
        assert_eq!(
            RadiusPacket::try_from(overflow.as_slice()),
            Err(RadiusParseError::AttributeOverflow {
                attribute_type: 4,
                needed: 200,
                available: 119
            })
        );
        // Un octet orphelin apres le dernier attribut.
        let mut orphan = bytes.clone();
        orphan.push(0);
        orphan[2..4].copy_from_slice(&140u16.to_be_bytes());
        assert_eq!(
            RadiusPacket::try_from(orphan.as_slice()),
            Err(RadiusParseError::AttributeOverflow {
                attribute_type: 0,
                needed: 2,
                available: 1
            })
        );
    }
}
