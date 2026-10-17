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

/// Types d'attributs du registre IANA « RADIUS Attribute Types » : tous les
/// codes assignes, 1 a 190 (sauf 17, 21, 54 et 93, non assignes) et 241 a
/// 246, definis par les RFC 2865, 2866, 2867, 2868, 2869, 3162, 4072, 4372,
/// 4675, 4818, 4849, 5090, 5176 (Error-Cause, que le registre rattache a la
/// RFC 3576, qu'elle remplace), 5447, 5580, 5607, 5904, 6519, 6572, 6677,
/// 6911, 6929, 6930, 7055, 7155 et 7268. Les codes 191 (non assigne), 192 a
/// 223 (experimentaux), 224 a 240 (propres a chaque implementation) et 247 a
/// 255 (reserves) rendent `None`.
///
/// Les variantes portent les noms du registre, sauf pour dix types : 89, 101
/// et 241 a 246 portent ceux de leur RFC (Chargeable-User-Identity, RFC 4372
/// §2.1 ; Error-Cause, RFC 5176 §3.5, que le registre ecrit « Error-Cause
/// Attribute » ; Extended-Type-1 a -4, Long-Extended-Type-1 et -2, RFC 6929
/// §3), 124 et 125 ceux de deux AVP Diameter (voir
/// [`AttributeType::MipHomeAgentAddress`] et
/// [`AttributeType::MipHomeAgentHost`], depreciees au profit des constantes
/// [`AttributeType::Mip6FeatureVector`] et
/// [`AttributeType::Mip6HomeLinkPrefix`]). Le nom que le registre donne a
/// 89, 124, 125, 173 et 241 a 246 est un alias de recherche de la
/// documentation. Les variantes ajoutees apres la 11.6.0 (126 a 190) sont
/// en fin d'enum, apres 241 a 246, pour garder les discriminants.
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
    #[doc(alias = "CUI")]
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
    /// Type 124, MIP6-Feature-Vector au registre IANA (RFC 5447 §4.2.5 et
    /// §7.1) : un champ de 64 drapeaux, les capacites Mobile IPv6 du NAS
    /// (`MIP6_INTEGRATED` 1, `LOCAL_HOME_AGENT_ASSIGNMENT` 2, §7.2). Le nom
    /// de la variante est celui d'une AVP Diameter que la meme RFC decrit,
    /// MIP-Home-Agent-Address (code 334 de la RFC 4004, §4.2.2), qui n'existe
    /// pas en RADIUS : la valeur n'est pas une adresse.
    #[doc(alias = "MIP6-Feature-Vector")]
    #[deprecated(
        since = "11.7.0",
        note = "le type 124 est MIP6-Feature-Vector (RFC 5447), pas une adresse ; utiliser `AttributeType::Mip6FeatureVector`"
    )]
    MipHomeAgentAddress,
    /// Type 125, MIP6-Home-Link-Prefix au registre IANA (RFC 5447 §4.2.4 et
    /// §7.1) : la longueur du prefixe sur un octet, puis les seize octets du
    /// prefixe IPv6 du reseau d'origine. Le nom de la variante est celui d'une
    /// AVP Diameter que la meme RFC decrit, MIP-Home-Agent-Host (code 348 de
    /// la RFC 4004, §4.2.3), qui n'existe pas en RADIUS : la valeur n'est pas
    /// un nom d'hote.
    #[doc(alias = "MIP6-Home-Link-Prefix")]
    #[deprecated(
        since = "11.7.0",
        note = "le type 125 est MIP6-Home-Link-Prefix (RFC 5447), pas un nom d'hote ; utiliser `AttributeType::Mip6HomeLinkPrefix`"
    )]
    MipHomeAgentHost,
    #[doc(alias = "Extended-Attribute-1")]
    ExtendedType1,
    #[doc(alias = "Extended-Attribute-2")]
    ExtendedType2,
    #[doc(alias = "Extended-Attribute-3")]
    ExtendedType3,
    #[doc(alias = "Extended-Attribute-4")]
    ExtendedType4,
    #[doc(alias = "Extended-Attribute-5")]
    LongExtendedType1,
    #[doc(alias = "Extended-Attribute-6")]
    LongExtendedType2,
    // Variantes ajoutees apres la 11.6.0 (#192), en fin d'enum pour garder
    // les discriminants : leur place logique est entre 125 et 241.
    /// RFC 5580 (126 a 132).
    OperatorName,
    LocationInformation,
    LocationData,
    BasicLocationPolicyRules,
    ExtendedLocationPolicyRules,
    LocationCapable,
    RequestedLocationInfo,
    /// RFC 5607 (133 a 136).
    /// tshark 4.6.6 l'abrege « Framed-Management ».
    #[doc(alias = "Framed-Management")]
    FramedManagementProtocol,
    ManagementTransportProtection,
    ManagementPolicyId,
    ManagementPrivilegeLevel,
    /// RFC 5904 (137 a 143).
    PkmSsCert,
    PkmCaCert,
    PkmConfigSettings,
    PkmCryptosuiteList,
    PkmSaid,
    PkmSaDescriptor,
    PkmAuthKey,
    /// RFC 6519 (144).
    DsLiteTunnelName,
    /// RFC 6572 (145 a 162).
    MobileNodeIdentifier,
    ServiceSelection,
    Pmip6HomeLmaIpv6Address,
    Pmip6VisitedLmaIpv6Address,
    Pmip6HomeLmaIpv4Address,
    Pmip6VisitedLmaIpv4Address,
    Pmip6HomeHnPrefix,
    Pmip6VisitedHnPrefix,
    Pmip6HomeInterfaceId,
    Pmip6VisitedInterfaceId,
    Pmip6HomeIpv4Hoa,
    Pmip6VisitedIpv4Hoa,
    Pmip6HomeDhcp4ServerAddress,
    Pmip6VisitedDhcp4ServerAddress,
    Pmip6HomeDhcp6ServerAddress,
    Pmip6VisitedDhcp6ServerAddress,
    Pmip6HomeIpv4Gateway,
    Pmip6VisitedIpv4Gateway,
    /// RFC 6677 (163).
    EapLowerLayer,
    /// RFC 7055 (164 a 167).
    GssAcceptorServiceName,
    GssAcceptorHostName,
    GssAcceptorServiceSpecifics,
    GssAcceptorRealmName,
    /// RFC 6911 (168 a 172).
    FramedIpv6Address,
    DnsServerIpv6Address,
    RouteIpv6Information,
    DelegatedIpv6PrefixPool,
    StatefulIpv6AddressPool,
    /// RFC 6930 (173).
    #[doc(alias = "IPv6-6rd-Configuration")]
    Ipv6SixRdConfiguration,
    /// RFC 7268 (174 a 190).
    AllowedCalledStationId,
    EapPeerId,
    EapServerId,
    MobilityDomainId,
    PreauthTimeout,
    NetworkIdName,
    EapolAnnouncement,
    WlanHessid,
    WlanVenueInfo,
    WlanVenueLanguage,
    WlanVenueName,
    WlanReasonCode,
    WlanPairwiseCipher,
    WlanGroupCipher,
    WlanAkmSuite,
    WlanGroupMgmtCipher,
    WlanRfBand,
}

impl AttributeType {
    /// Type 124, MIP6-Feature-Vector (RFC 5447 §4.2.5) : le nom que prendra
    /// la variante en 12.0, utilisable des maintenant en argument comme en
    /// motif de `match`.
    #[allow(non_upper_case_globals, deprecated)]
    pub const Mip6FeatureVector: Self = Self::MipHomeAgentAddress;
    /// Type 125, MIP6-Home-Link-Prefix (RFC 5447 §4.2.4) : le nom que
    /// prendra la variante en 12.0.
    #[allow(non_upper_case_globals, deprecated)]
    pub const Mip6HomeLinkPrefix: Self = Self::MipHomeAgentHost;

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
            124 => Self::Mip6FeatureVector,
            125 => Self::Mip6HomeLinkPrefix,
            241 => Self::ExtendedType1,
            242 => Self::ExtendedType2,
            243 => Self::ExtendedType3,
            244 => Self::ExtendedType4,
            245 => Self::LongExtendedType1,
            246 => Self::LongExtendedType2,
            126 => Self::OperatorName,
            127 => Self::LocationInformation,
            128 => Self::LocationData,
            129 => Self::BasicLocationPolicyRules,
            130 => Self::ExtendedLocationPolicyRules,
            131 => Self::LocationCapable,
            132 => Self::RequestedLocationInfo,
            133 => Self::FramedManagementProtocol,
            134 => Self::ManagementTransportProtection,
            135 => Self::ManagementPolicyId,
            136 => Self::ManagementPrivilegeLevel,
            137 => Self::PkmSsCert,
            138 => Self::PkmCaCert,
            139 => Self::PkmConfigSettings,
            140 => Self::PkmCryptosuiteList,
            141 => Self::PkmSaid,
            142 => Self::PkmSaDescriptor,
            143 => Self::PkmAuthKey,
            144 => Self::DsLiteTunnelName,
            145 => Self::MobileNodeIdentifier,
            146 => Self::ServiceSelection,
            147 => Self::Pmip6HomeLmaIpv6Address,
            148 => Self::Pmip6VisitedLmaIpv6Address,
            149 => Self::Pmip6HomeLmaIpv4Address,
            150 => Self::Pmip6VisitedLmaIpv4Address,
            151 => Self::Pmip6HomeHnPrefix,
            152 => Self::Pmip6VisitedHnPrefix,
            153 => Self::Pmip6HomeInterfaceId,
            154 => Self::Pmip6VisitedInterfaceId,
            155 => Self::Pmip6HomeIpv4Hoa,
            156 => Self::Pmip6VisitedIpv4Hoa,
            157 => Self::Pmip6HomeDhcp4ServerAddress,
            158 => Self::Pmip6VisitedDhcp4ServerAddress,
            159 => Self::Pmip6HomeDhcp6ServerAddress,
            160 => Self::Pmip6VisitedDhcp6ServerAddress,
            161 => Self::Pmip6HomeIpv4Gateway,
            162 => Self::Pmip6VisitedIpv4Gateway,
            163 => Self::EapLowerLayer,
            164 => Self::GssAcceptorServiceName,
            165 => Self::GssAcceptorHostName,
            166 => Self::GssAcceptorServiceSpecifics,
            167 => Self::GssAcceptorRealmName,
            168 => Self::FramedIpv6Address,
            169 => Self::DnsServerIpv6Address,
            170 => Self::RouteIpv6Information,
            171 => Self::DelegatedIpv6PrefixPool,
            172 => Self::StatefulIpv6AddressPool,
            173 => Self::Ipv6SixRdConfiguration,
            174 => Self::AllowedCalledStationId,
            175 => Self::EapPeerId,
            176 => Self::EapServerId,
            177 => Self::MobilityDomainId,
            178 => Self::PreauthTimeout,
            179 => Self::NetworkIdName,
            180 => Self::EapolAnnouncement,
            181 => Self::WlanHessid,
            182 => Self::WlanVenueInfo,
            183 => Self::WlanVenueLanguage,
            184 => Self::WlanVenueName,
            185 => Self::WlanReasonCode,
            186 => Self::WlanPairwiseCipher,
            187 => Self::WlanGroupCipher,
            188 => Self::WlanAkmSuite,
            189 => Self::WlanGroupMgmtCipher,
            190 => Self::WlanRfBand,
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
    /// Le type nomme, quand [`AttributeType`] le connait ; `None` pour tout
    /// autre code, dont les types 126 a 190 du registre.
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

    /// #191 : Access-Request synthetique (UDP 50000 -> 1812) qui porte
    /// MIP6-Feature-Vector (124) et MIP6-Home-Link-Prefix (125) ; tshark
    /// 4.6.6 : `t=MIP6-Feature-Vector(124) l=10`,
    /// `t=MIP6-Home-Link-Prefix(125) l=19`.
    const MIP6_ACCESS_REQUEST: &str = concat!(
        "01010031000102030405060708090a0b0c0d0e0f7c0a00000000000000017d13402001",
        "0db8000100000000000000000000"
    );
    /// #192 : Access-Accept synthetique (UDP 1812 -> 50000) qui porte
    /// Operator-Name (126), Framed-IPv6-Address (168) et WLAN-RF-Band (190) ;
    /// tshark 4.6.6 les nomme tous trois.
    const ACCESS_ACCEPT_126_168_190: &str = concat!(
        "0207003a000102030405060708090a0b0c0d0e0f7e0e316578616d706c652e6e6574a8",
        "1220010db8000000000000000000000001be0600000001"
    );

    /// Registre IANA « RADIUS Attribute Types » (version du 2026-10-09),
    /// codes 126 a 190 : le nom de la variante est celui du registre, tirets
    /// et casse mis a part, sauf 173 (IPv6-6rd-Configuration, dont le nom
    /// ne peut pas commencer par un chiffre apres `Ipv6`).
    const IANA_126_TO_190: [(u8, &str); 65] = [
        (126, "Operator-Name"),
        (127, "Location-Information"),
        (128, "Location-Data"),
        (129, "Basic-Location-Policy-Rules"),
        (130, "Extended-Location-Policy-Rules"),
        (131, "Location-Capable"),
        (132, "Requested-Location-Info"),
        (133, "Framed-Management-Protocol"),
        (134, "Management-Transport-Protection"),
        (135, "Management-Policy-Id"),
        (136, "Management-Privilege-Level"),
        (137, "PKM-SS-Cert"),
        (138, "PKM-CA-Cert"),
        (139, "PKM-Config-Settings"),
        (140, "PKM-Cryptosuite-List"),
        (141, "PKM-SAID"),
        (142, "PKM-SA-Descriptor"),
        (143, "PKM-Auth-Key"),
        (144, "DS-Lite-Tunnel-Name"),
        (145, "Mobile-Node-Identifier"),
        (146, "Service-Selection"),
        (147, "PMIP6-Home-LMA-IPv6-Address"),
        (148, "PMIP6-Visited-LMA-IPv6-Address"),
        (149, "PMIP6-Home-LMA-IPv4-Address"),
        (150, "PMIP6-Visited-LMA-IPv4-Address"),
        (151, "PMIP6-Home-HN-Prefix"),
        (152, "PMIP6-Visited-HN-Prefix"),
        (153, "PMIP6-Home-Interface-ID"),
        (154, "PMIP6-Visited-Interface-ID"),
        (155, "PMIP6-Home-IPv4-HoA"),
        (156, "PMIP6-Visited-IPv4-HoA"),
        (157, "PMIP6-Home-DHCP4-Server-Address"),
        (158, "PMIP6-Visited-DHCP4-Server-Address"),
        (159, "PMIP6-Home-DHCP6-Server-Address"),
        (160, "PMIP6-Visited-DHCP6-Server-Address"),
        (161, "PMIP6-Home-IPv4-Gateway"),
        (162, "PMIP6-Visited-IPv4-Gateway"),
        (163, "EAP-Lower-Layer"),
        (164, "GSS-Acceptor-Service-Name"),
        (165, "GSS-Acceptor-Host-Name"),
        (166, "GSS-Acceptor-Service-Specifics"),
        (167, "GSS-Acceptor-Realm-Name"),
        (168, "Framed-IPv6-Address"),
        (169, "DNS-Server-IPv6-Address"),
        (170, "Route-IPv6-Information"),
        (171, "Delegated-IPv6-Prefix-Pool"),
        (172, "Stateful-IPv6-Address-Pool"),
        (173, "IPv6-6rd-Configuration"),
        (174, "Allowed-Called-Station-Id"),
        (175, "EAP-Peer-Id"),
        (176, "EAP-Server-Id"),
        (177, "Mobility-Domain-Id"),
        (178, "Preauth-Timeout"),
        (179, "Network-Id-Name"),
        (180, "EAPoL-Announcement"),
        (181, "WLAN-HESSID"),
        (182, "WLAN-Venue-Info"),
        (183, "WLAN-Venue-Language"),
        (184, "WLAN-Venue-Name"),
        (185, "WLAN-Reason-Code"),
        (186, "WLAN-Pairwise-Cipher"),
        (187, "WLAN-Group-Cipher"),
        (188, "WLAN-AKM-Suite"),
        (189, "WLAN-Group-Mgmt-Cipher"),
        (190, "WLAN-RF-Band"),
    ];

    #[test]
    fn test_attribute_types_126_to_190_follow_the_iana_registry() {
        for (code, iana_name) in IANA_126_TO_190 {
            let kind = AttributeType::from_code(code).unwrap_or_else(|| panic!("{code}"));
            let expected = match iana_name {
                "IPv6-6rd-Configuration" => "ipv6sixrdconfiguration".to_string(),
                name => name.replace('-', "").to_ascii_lowercase(),
            };
            assert_eq!(format!("{kind:?}").to_ascii_lowercase(), expected, "{code}");
        }
        // Ni les non assignes, ni les experimentaux, ni les reserves.
        for code in [0, 17, 21, 54, 93]
            .into_iter()
            .chain(191..=240)
            .chain(247..=255)
        {
            assert_eq!(AttributeType::from_code(code), None, "{code}");
        }

        let bytes = hex::decode(ACCESS_ACCEPT_126_168_190).unwrap();
        assert_eq!(bytes.len(), 58);
        let packet = RadiusPacket::try_from(bytes.as_slice()).expect("Access-Accept");
        assert_eq!(packet.kind, RadiusCode::AccessAccept);
        let kinds: Vec<_> = packet
            .attributes
            .iter()
            .map(|a| (a.attribute_type, a.length, a.kind))
            .collect();
        assert_eq!(
            kinds,
            [
                (126, 14, Some(AttributeType::OperatorName)),
                (168, 18, Some(AttributeType::FramedIpv6Address)),
                (190, 6, Some(AttributeType::WlanRfBand)),
            ]
        );
        assert_eq!(
            packet
                .attribute(AttributeType::OperatorName)
                .and_then(|a| a.as_text()),
            Some("1example.net")
        );
        assert_eq!(
            packet
                .attribute(AttributeType::WlanRfBand)
                .and_then(|a| a.as_u32()),
            Some(1)
        );
    }

    #[test]
    fn test_types_124_and_125_are_mip6_feature_vector_and_home_link_prefix() {
        let bytes = hex::decode(MIP6_ACCESS_REQUEST).unwrap();
        assert_eq!(bytes.len(), 49);
        let packet = RadiusPacket::try_from(bytes.as_slice()).expect("Access-Request");
        assert_eq!(
            AttributeType::from_code(124),
            Some(AttributeType::Mip6FeatureVector)
        );
        assert_eq!(
            AttributeType::from_code(125),
            Some(AttributeType::Mip6HomeLinkPrefix)
        );
        // Les anciens noms restent les memes valeurs jusqu'a la 12.0.
        #[allow(deprecated)]
        {
            assert_eq!(
                AttributeType::Mip6FeatureVector,
                AttributeType::MipHomeAgentAddress
            );
            assert_eq!(
                AttributeType::Mip6HomeLinkPrefix,
                AttributeType::MipHomeAgentHost
            );
        }
        let feature_vector = packet
            .attribute(AttributeType::Mip6FeatureVector)
            .expect("124");
        assert_eq!((feature_vector.length, feature_vector.value.len()), (10, 8));
        assert_eq!(feature_vector.value, [0, 0, 0, 0, 0, 0, 0, 1]);
        let prefix = packet
            .attribute(AttributeType::Mip6HomeLinkPrefix)
            .expect("125");
        assert_eq!((prefix.length, prefix.value.len()), (19, 17));
        assert_eq!(prefix.value[0], 64);
        assert_eq!(prefix.as_text(), None);
        // En motif de `match`, comme le fera la variante de la 12.0.
        let names: Vec<&str> = packet
            .attributes
            .iter()
            .map(|a| match a.kind {
                Some(AttributeType::Mip6FeatureVector) => "MIP6-Feature-Vector",
                Some(AttributeType::Mip6HomeLinkPrefix) => "MIP6-Home-Link-Prefix",
                _ => "?",
            })
            .collect();
        assert_eq!(names, ["MIP6-Feature-Vector", "MIP6-Home-Link-Prefix"]);
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
