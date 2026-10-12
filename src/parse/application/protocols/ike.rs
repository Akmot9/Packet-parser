// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! IKE, Internet Key Exchange — ISAKMP/IKEv1 (RFC 2408, RFC 2409) et IKEv2
//! (RFC 7296) : la negociation des associations de securite IPsec, sur UDP
//! 500, et sur UDP 4500 derriere un NAT (RFC 3948) ou par choix de
//! l'implementation. Le decodeur lit l'en-tete de vingt-huit octets et la
//! chaine des payloads de premier niveau sans entrer dans leur contenu :
//! les SPI, le type d'echange, le sens et la suite des payloads suffisent a
//! cartographier qui negocie avec qui. Les payloads chiffres (drapeau E
//! d'IKEv1, payload SK d'IKEv2) restent des octets.
//!
//! [`UdpEncapsulation`] demultiplexe un datagramme UDP 4500 (RFC 3948 §2) :
//! marqueur non-ESP puis IKE, NAT-keepalive d'un octet, ou ESP.

use std::convert::TryFrom;

use crate::{
    checks::{
        application::ike::{
            IKE_HEADER_LENGTH, IKE_MAJOR_V1, IKE_MAJOR_V2, IKE_PAYLOAD_FLAG_CRITICAL,
            IKE_PAYLOAD_HEADER_LENGTH, IKEV1_FLAG_AUTHENTICATION_ONLY, IKEV1_FLAG_COMMIT,
            IKEV1_FLAG_ENCRYPTION, IKEV2_FLAG_INITIATOR, IKEV2_FLAG_RESPONSE, IKEV2_FLAG_VERSION,
            IKEV2_PAYLOAD_ENCRYPTED, IKEV2_PAYLOAD_ENCRYPTED_FRAGMENT, NAT_KEEPALIVE,
            NON_ESP_MARKER, ensure_len, extract_major_version, validate_initiator_spi,
            validate_length, validate_no_trailing, validate_payload_length,
        },
        transport::esp::ESP_HEADER_SIZE,
    },
    errors::application::ike::IkeParseError,
    parse::application::protocols::bounded_capacity,
};

/// En-tete IKE (RFC 7296 §3.1 ; ISAKMP RFC 2408 §3.1, meme forme).
///
/// ```mermaid
/// ---
/// title: IkeHeader
/// ---
/// packet-beta
/// 0-63: "IKE SA Initiator's SPI u64"
/// 64-127: "IKE SA Responder's SPI u64"
/// 128-135: "Next Payload u8"
/// 136-139: "MjVer"
/// 140-143: "MnVer"
/// 144-151: "Exchange Type u8"
/// 152-159: "Flags u8"
/// 160-191: "Message ID u32"
/// 192-223: "Length u32"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct IkeHeader {
    /// IKEv1 : cookie de l'initiateur.
    pub initiator_spi: u64,
    /// Zero dans le premier message d'un echange initial.
    pub responder_spi: u64,
    /// Type du premier payload ; en IKEv1 chiffre, celui du premier payload
    /// sous le chiffre.
    pub next_payload: u8,
    /// Octet brut : majeure sur le quartet haut, mineure sur le bas.
    pub version: u8,
    /// Brut ; [`IkeHeader::exchange`] le nomme.
    pub exchange_type: u8,
    /// Brut ; IKEv1 : E 0x01, C 0x02, A 0x04. IKEv2 : I 0x08, V 0x10, R 0x20.
    pub flags: u8,
    pub message_id: u32,
    /// Longueur du message, en-tete compris.
    pub length: u32,
}

impl IkeHeader {
    pub fn major_version(&self) -> u8 {
        self.version >> 4
    }

    pub fn minor_version(&self) -> u8 {
        self.version & 0x0f
    }

    pub fn exchange(&self) -> Option<ExchangeType> {
        ExchangeType::from_code(self.major_version(), self.exchange_type)
    }

    /// IKEv1, drapeau E : les payloads sont chiffres. Faux en IKEv2, dont le
    /// chiffrement est un payload (SK).
    pub fn encryption_flag(&self) -> bool {
        self.major_version() == IKE_MAJOR_V1 && self.flags & IKEV1_FLAG_ENCRYPTION != 0
    }

    /// IKEv1, drapeau C : l'emetteur attend une confirmation avant d'user
    /// de la SA. Faux en IKEv2.
    pub fn commit_flag(&self) -> bool {
        self.major_version() == IKE_MAJOR_V1 && self.flags & IKEV1_FLAG_COMMIT != 0
    }

    /// IKEv1, drapeau A : authentification seule, sans chiffrement. Faux en
    /// IKEv2.
    pub fn authentication_only_flag(&self) -> bool {
        self.major_version() == IKE_MAJOR_V1 && self.flags & IKEV1_FLAG_AUTHENTICATION_ONLY != 0
    }

    /// IKEv2, drapeau I : emis par l'initiateur de l'IKE SA. Faux en IKEv1.
    pub fn initiator_flag(&self) -> bool {
        self.major_version() == IKE_MAJOR_V2 && self.flags & IKEV2_FLAG_INITIATOR != 0
    }

    /// IKEv2, drapeau R : une reponse. Faux en IKEv1.
    pub fn response_flag(&self) -> bool {
        self.major_version() == IKE_MAJOR_V2 && self.flags & IKEV2_FLAG_RESPONSE != 0
    }

    /// IKEv2, drapeau V : l'emetteur parle une version majeure superieure.
    pub fn version_flag(&self) -> bool {
        self.major_version() == IKE_MAJOR_V2 && self.flags & IKEV2_FLAG_VERSION != 0
    }
}

/// Type d'echange, selon la version (RFC 2408 §3.1, RFC 7296 §3.1 et le
/// registre IANA IKEv2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ExchangeType {
    // IKEv1
    Base,
    /// Main mode.
    IdentityProtection,
    AuthenticationOnly,
    Aggressive,
    /// IKEv1 (5) comme IKEv2 (37).
    Informational,
    QuickMode,
    NewGroupMode,
    // IKEv2
    IkeSaInit,
    IkeAuth,
    CreateChildSa,
    IkeSessionResume,
    GsaAuth,
    GsaRegistration,
    GsaRekey,
    IkeIntermediate,
    IkeFollowupKe,
}

impl ExchangeType {
    pub fn from_code(major: u8, code: u8) -> Option<Self> {
        Some(match (major, code) {
            (IKE_MAJOR_V1, 1) => Self::Base,
            (IKE_MAJOR_V1, 2) => Self::IdentityProtection,
            (IKE_MAJOR_V1, 3) => Self::AuthenticationOnly,
            (IKE_MAJOR_V1, 4) => Self::Aggressive,
            (IKE_MAJOR_V1, 5) => Self::Informational,
            (IKE_MAJOR_V1, 32) => Self::QuickMode,
            (IKE_MAJOR_V1, 33) => Self::NewGroupMode,
            (IKE_MAJOR_V2, 34) => Self::IkeSaInit,
            (IKE_MAJOR_V2, 35) => Self::IkeAuth,
            (IKE_MAJOR_V2, 36) => Self::CreateChildSa,
            (IKE_MAJOR_V2, 37) => Self::Informational,
            (IKE_MAJOR_V2, 38) => Self::IkeSessionResume,
            (IKE_MAJOR_V2, 39) => Self::GsaAuth,
            (IKE_MAJOR_V2, 40) => Self::GsaRegistration,
            (IKE_MAJOR_V2, 41) => Self::GsaRekey,
            (IKE_MAJOR_V2, 43) => Self::IkeIntermediate,
            (IKE_MAJOR_V2, 44) => Self::IkeFollowupKe,
            _ => return None,
        })
    }
}

/// Type de payload, selon la version (RFC 2408 §3.1, RFC 3947 et le
/// registre IANA IKEv2). Proposal et Transform n'apparaissent qu'a
/// l'interieur d'un Security Association.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PayloadType {
    SecurityAssociation,
    Proposal,
    Transform,
    KeyExchange,
    /// IKEv1 (5).
    Identification,
    Certificate,
    CertificateRequest,
    Hash,
    Signature,
    Nonce,
    Notification,
    Delete,
    VendorId,
    /// IKEv1 (14, RFC 3547 et mode-config).
    Attributes,
    /// IKEv1 (15 brouillon, 20 RFC 3947, 130 brouillon).
    NatDetection,
    /// IKEv1 (16 brouillon, 21 RFC 3947, 131 brouillon).
    NatOriginalAddress,
    // IKEv2
    IdentificationInitiator,
    IdentificationResponder,
    Authentication,
    TrafficSelectorInitiator,
    TrafficSelectorResponder,
    /// SK : chiffre et authentifie, toujours le dernier du message.
    Encrypted,
    Configuration,
    ExtensibleAuthentication,
    GenericSecurePasswordMethod,
    GroupIdentification,
    GroupSecurityAssociation,
    KeyDownload,
    /// SKF (RFC 7383).
    EncryptedFragment,
    PuzzleSolution,
}

impl PayloadType {
    pub fn from_code(major: u8, code: u8) -> Option<Self> {
        Some(match (major, code) {
            (IKE_MAJOR_V1, 1) => Self::SecurityAssociation,
            (IKE_MAJOR_V1, 2) => Self::Proposal,
            (IKE_MAJOR_V1, 3) => Self::Transform,
            (IKE_MAJOR_V1, 4) => Self::KeyExchange,
            (IKE_MAJOR_V1, 5) => Self::Identification,
            (IKE_MAJOR_V1, 6) => Self::Certificate,
            (IKE_MAJOR_V1, 7) => Self::CertificateRequest,
            (IKE_MAJOR_V1, 8) => Self::Hash,
            (IKE_MAJOR_V1, 9) => Self::Signature,
            (IKE_MAJOR_V1, 10) => Self::Nonce,
            (IKE_MAJOR_V1, 11) => Self::Notification,
            (IKE_MAJOR_V1, 12) => Self::Delete,
            (IKE_MAJOR_V1, 13) => Self::VendorId,
            (IKE_MAJOR_V1, 14) => Self::Attributes,
            (IKE_MAJOR_V1, 15 | 20 | 130) => Self::NatDetection,
            (IKE_MAJOR_V1, 16 | 21 | 131) => Self::NatOriginalAddress,
            (IKE_MAJOR_V2, 33) => Self::SecurityAssociation,
            (IKE_MAJOR_V2, 34) => Self::KeyExchange,
            (IKE_MAJOR_V2, 35) => Self::IdentificationInitiator,
            (IKE_MAJOR_V2, 36) => Self::IdentificationResponder,
            (IKE_MAJOR_V2, 37) => Self::Certificate,
            (IKE_MAJOR_V2, 38) => Self::CertificateRequest,
            (IKE_MAJOR_V2, 39) => Self::Authentication,
            (IKE_MAJOR_V2, 40) => Self::Nonce,
            (IKE_MAJOR_V2, 41) => Self::Notification,
            (IKE_MAJOR_V2, 42) => Self::Delete,
            (IKE_MAJOR_V2, 43) => Self::VendorId,
            (IKE_MAJOR_V2, 44) => Self::TrafficSelectorInitiator,
            (IKE_MAJOR_V2, 45) => Self::TrafficSelectorResponder,
            (IKE_MAJOR_V2, 46) => Self::Encrypted,
            (IKE_MAJOR_V2, 47) => Self::Configuration,
            (IKE_MAJOR_V2, 48) => Self::ExtensibleAuthentication,
            (IKE_MAJOR_V2, 49) => Self::GenericSecurePasswordMethod,
            (IKE_MAJOR_V2, 50) => Self::GroupIdentification,
            (IKE_MAJOR_V2, 51) => Self::GroupSecurityAssociation,
            (IKE_MAJOR_V2, 52) => Self::KeyDownload,
            (IKE_MAJOR_V2, 53) => Self::EncryptedFragment,
            (IKE_MAJOR_V2, 54) => Self::PuzzleSolution,
            _ => return None,
        })
    }
}

/// Un payload de premier niveau : son en-tete generique (RFC 7296 §3.2,
/// RFC 2408 §3.2) et son corps tel quel.
///
/// ```mermaid
/// ---
/// title: IkePayload header
/// ---
/// packet-beta
/// 0-7: "Next Payload u8"
/// 8-8: "C"
/// 9-15: "Reserved"
/// 16-31: "Payload Length u16"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct IkePayload<'a> {
    /// Code brut du type, tel que le payload precedent (ou l'en-tete) le
    /// nomme.
    pub payload_type: u8,
    /// Le type nomme, selon la version du message.
    pub kind: Option<PayloadType>,
    /// Type du payload suivant, zero pour le dernier ; pour un SK d'IKEv2,
    /// celui du premier payload sous le chiffre.
    pub next_payload: u8,
    /// IKEv2 : le destinataire doit rejeter le message s'il ne comprend pas
    /// ce payload. Toujours faux en IKEv1 (octet reserve).
    pub critical: bool,
    /// Longueur declaree, en-tete generique compris.
    pub length: u16,
    /// Le corps, apres les quatre octets de l'en-tete generique.
    pub body: &'a [u8],
}

/// Un message IKE : en-tete, payloads de premier niveau, et ce qui est
/// chiffre.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct IkePacket<'a> {
    pub header: IkeHeader,
    /// Les payloads de premier niveau, dans l'ordre du message. Vide quand
    /// IKEv1 chiffre tout (drapeau E).
    pub payloads: Vec<IkePayload<'a>>,
    /// Les octets chiffres : tout ce qui suit l'en-tete en IKEv1 sous le
    /// drapeau E, le corps du payload SK (ou SKF) en IKEv2, qui est alors
    /// aussi le dernier de `payloads`.
    pub encrypted_body: Option<&'a [u8]>,
}

impl<'a> TryFrom<&'a [u8]> for IkePacket<'a> {
    type Error = IkeParseError;

    /// Un message IKE nu, tel qu'il circule sur UDP 500. Sur UDP 4500,
    /// retirer d'abord le marqueur non-ESP : [`IkePacket::from_udp`].
    fn try_from(payload: &'a [u8]) -> Result<Self, Self::Error> {
        ensure_len(payload, IKE_HEADER_LENGTH)?;
        let major = extract_major_version(payload[17])?;
        let header = IkeHeader {
            initiator_spi: u64_at(payload, 0),
            responder_spi: u64_at(payload, 8),
            next_payload: payload[16],
            version: payload[17],
            exchange_type: payload[18],
            flags: payload[19],
            message_id: u32_at(payload, 20),
            length: u32_at(payload, 24),
        };
        validate_initiator_spi(major, header.initiator_spi)?;
        validate_length(header.length, payload.len())?;

        if header.encryption_flag() {
            return Ok(IkePacket {
                header,
                payloads: Vec::new(),
                encrypted_body: Some(&payload[IKE_HEADER_LENGTH..]),
            });
        }

        let mut payloads = Vec::with_capacity(bounded_capacity(
            16,
            payload.len() - IKE_HEADER_LENGTH,
            IKE_PAYLOAD_HEADER_LENGTH,
        ));
        let mut encrypted_body = None;
        let mut next = header.next_payload;
        let mut offset = IKE_HEADER_LENGTH;
        // Comme tshark, la chaine s'arrete a la fin du message, meme si le
        // dernier payload en annonce un autre (trame 192 du corpus nDPI : un
        // payload prive 127 de 784 octets qui annonce 35).
        while next != 0 && offset < payload.len() {
            let payload_type = next;
            let available = payload.len() - offset;
            if available < IKE_PAYLOAD_HEADER_LENGTH {
                return Err(IkeParseError::PayloadOverflow {
                    payload_type,
                    needed: IKE_PAYLOAD_HEADER_LENGTH,
                    available,
                });
            }
            let next_payload = payload[offset];
            let critical =
                major == IKE_MAJOR_V2 && payload[offset + 1] & IKE_PAYLOAD_FLAG_CRITICAL != 0;
            let declared = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]);
            let length = validate_payload_length(payload_type, declared, available)?;
            let body = &payload[offset + IKE_PAYLOAD_HEADER_LENGTH..offset + length];
            payloads.push(IkePayload {
                payload_type,
                kind: PayloadType::from_code(major, payload_type),
                next_payload,
                critical,
                length: declared,
                body,
            });
            offset += length;
            // Le payload chiffre d'IKEv2 est le dernier (RFC 7296 §3.14) ;
            // son champ « next payload » nomme le premier payload sous le
            // chiffre, pas un payload de premier niveau.
            if major == IKE_MAJOR_V2
                && matches!(
                    payload_type,
                    IKEV2_PAYLOAD_ENCRYPTED | IKEV2_PAYLOAD_ENCRYPTED_FRAGMENT
                )
            {
                encrypted_body = Some(body);
                break;
            }
            next = next_payload;
        }
        validate_no_trailing(payload.len() - offset)?;
        Ok(IkePacket {
            header,
            payloads,
            encrypted_body,
        })
    }
}

impl<'a> IkePacket<'a> {
    /// Un datagramme UDP : nu (UDP 500), ou precede du marqueur non-ESP de
    /// quatre octets nuls (UDP 4500, RFC 3948 §2.2). Le message nu est
    /// essaye d'abord, puis, s'il echoue et que le marqueur est la, le
    /// message qui le suit.
    pub fn from_udp(payload: &'a [u8]) -> Result<Self, IkeParseError> {
        match Self::try_from(payload) {
            Ok(packet) => Ok(packet),
            Err(error) => match payload.strip_prefix(&NON_ESP_MARKER) {
                Some(rest) if !rest.is_empty() => Self::try_from(rest),
                _ => Err(error),
            },
        }
    }

    /// Les codes des payloads de premier niveau, dans l'ordre.
    pub fn payload_types(&self) -> impl Iterator<Item = u8> + '_ {
        self.payloads.iter().map(|payload| payload.payload_type)
    }
}

/// Ce que porte un datagramme UDP 4500 (RFC 3948 §2) : le port partage
/// entre IKE, ESP et les keepalives qui tiennent la traduction d'adresse
/// ouverte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UdpEncapsulation<'a> {
    /// Marqueur non-ESP, puis un message IKE : les octets apres le marqueur.
    Ike(&'a [u8]),
    /// Un paquet ESP : SPI non nul en tete, tout le datagramme.
    Esp(&'a [u8]),
    /// NAT-keepalive : un seul octet 0xFF.
    Keepalive,
}

impl<'a> UdpEncapsulation<'a> {
    pub fn classify(payload: &'a [u8]) -> Result<Self, IkeParseError> {
        if payload == NAT_KEEPALIVE {
            return Ok(Self::Keepalive);
        }
        if let Some(rest) = payload.strip_prefix(&NON_ESP_MARKER) {
            if rest.is_empty() {
                return Err(IkeParseError::InvalidUdpEncapsulation {
                    length: payload.len(),
                });
            }
            return Ok(Self::Ike(rest));
        }
        if payload.len() < ESP_HEADER_SIZE {
            return Err(IkeParseError::InvalidUdpEncapsulation {
                length: payload.len(),
            });
        }
        Ok(Self::Esp(payload))
    }
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_be_bytes(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// pcaps_exemple/protocols/ipsec/ikev2_s2s_ipsec_vpn_aes_gcm.pcapng,
    /// trame 1 (UDP 500) : IKE_SA_INIT de l'initiateur, 374 octets, neuf
    /// payloads (tshark 4.6.6).
    const IKEV2_SA_INIT: &str = concat!(
        "62f94c9887715a3400000000000000002120220800000000000001762200002800000024",
        "010100030300000c01000014800e0100030000080200000500000008040000132800004800",
        "1300004b59d6332b28b9e9d8c9f16e1f49614e5ea32b06f928a872a9435a16c00f16b0ceb9",
        "51c06a6c69d1e1383926e5e72ed73c04e412e0b8da0fcaf1800fef6531842b0000448e0fff",
        "b0d754b65d52da18adfdc1a9f2b8c9284ca26fafb389b925c318483a13cf7b62489b15d382",
        "81aabab28a84b301385b1e04b37797764c0aa79bce3143462b000017434953434f2d44454c",
        "4554452d524541534f4e2900003b434953434f28434f505952494748542926436f70797269",
        "6768742028632920323030392043697363",
        "6f2053797374656d732c20496e632e2900001c010040045332b489ab0b4e69d77aca5453cf",
        "e6bc1528d7982900001c0100400531c1256e8602c28d9ba17c9c07201b9906ed6bc92b0000",
        "080000402e000000144048b7d56ebce88525e7de7f00d6c2d3"
    );

    /// Meme capture, trame 4 : reponse IKE_AUTH, un seul payload SK de 201
    /// octets.
    const IKEV2_IKE_AUTH: &str = concat!(
        "62f94c9887715a34f05534eef373dc1b2e20232000000001000000e52b0000c9000000000000",
        "0000a313da87397423dd5648a1483d91b34eeed79295b89f69ca1dfb868e2e5d28f9f7834b23",
        "58940a4c57bc4f5c65c9dac3175905726607549ef6d42d8c05606bcce9f5d8af98ea44851c7a",
        "889e2bb2111f41665e0b077252cb3f65417e7e668cb8d537f6c08ef80dc7d6082fecd4b6c971",
        "1069cca44ea3f26fa0e9828c446f44d7ae7e93e265e4e36a3971b874617682060fd99162609c",
        "4f49bad34f4c3d615709624025a35444a06c7b6e065684b11bc60a848b5e0651b3bad3c6f40f02"
    );

    /// pcaps_exemple/protocols/ipsec/attachment_ikev1_main_mode.pcap, trame
    /// 1 : IKEv1 main mode, premier message, SA puis deux Vendor ID.
    const IKEV1_MAIN_MODE: &str = concat!(
        "b31615b5ec7a4faf000000000000000001100200000000000000007c0d00003800000001",
        "000000010000002c010100010000002401010000800b0001800c708080010007800e0080",
        "8003000180020002800400020d000014afcad71368a1f1c96b8696fc7757010000000014",
        "a9b9b1034f7e50a2513b47b100bb85a9"
    );

    /// Meme capture, trame 5 : drapeau E, tout est chiffre apres l'en-tete.
    const IKEV1_ENCRYPTED: &str = concat!(
        "b31615b5ec7a4faf71cdf256f717b6e805100201000000000000004ce8e4fab1304e637f",
        "199b726453526619cea379a8aadd755073722dbc2c6cbc872ca140c3b79ec64a4bfe2a8e",
        "a8d34e5b"
    );

    /// pcaps_exemple/protocols/ipsec/ipsec_isakmp_esp.pcap, trame 42 (UDP
    /// 4500 -> 14500) : marqueur non-ESP puis un INFORMATIONAL chiffre.
    const NAT_T_INFORMATIONAL: &str = concat!(
        "00000000de648338c613aa68d8b3038904240d4b2e202500000000000000004c2a000030",
        "7249ae95a1dd31844a69f8046dd89aa167d28a139c9c0ae217f4d63e5cb8b81e4c526cff",
        "390679acabb28be2"
    );

    fn types_and_lengths(packet: &IkePacket<'_>) -> (Vec<u8>, Vec<u16>) {
        (
            packet.payload_types().collect(),
            packet
                .payloads
                .iter()
                .map(|payload| payload.length)
                .collect(),
        )
    }

    #[test]
    fn test_decodes_an_ikev2_sa_init_against_tshark() {
        let bytes = hex::decode(IKEV2_SA_INIT).unwrap();
        assert_eq!(bytes.len(), 374);
        let packet = IkePacket::try_from(bytes.as_slice()).expect("IKE_SA_INIT");
        let header = packet.header;
        assert_eq!(header.initiator_spi, 0x62f9_4c98_8771_5a34);
        assert_eq!(header.responder_spi, 0);
        assert_eq!(header.next_payload, 33);
        assert_eq!((header.major_version(), header.minor_version()), (2, 0));
        assert_eq!(header.exchange(), Some(ExchangeType::IkeSaInit));
        assert_eq!(header.flags, 0x08);
        assert!(header.initiator_flag());
        assert!(!header.response_flag());
        assert!(!header.version_flag());
        assert!(!header.encryption_flag());
        assert_eq!((header.message_id, header.length), (0, 374));
        let (types, lengths) = types_and_lengths(&packet);
        assert_eq!(types, [33, 34, 40, 43, 43, 41, 41, 41, 43]);
        assert_eq!(lengths, [40, 72, 68, 23, 59, 28, 28, 8, 20]);
        assert_eq!(
            packet
                .payloads
                .iter()
                .map(|payload| payload.kind)
                .collect::<Vec<_>>(),
            [
                Some(PayloadType::SecurityAssociation),
                Some(PayloadType::KeyExchange),
                Some(PayloadType::Nonce),
                Some(PayloadType::VendorId),
                Some(PayloadType::VendorId),
                Some(PayloadType::Notification),
                Some(PayloadType::Notification),
                Some(PayloadType::Notification),
                Some(PayloadType::VendorId),
            ]
        );
        assert_eq!(packet.payloads[3].body, b"CISCO-DELETE-REASON");
        assert!(packet.payloads.iter().all(|payload| !payload.critical));
        assert_eq!(packet.payloads[8].next_payload, 0);
        assert_eq!(packet.encrypted_body, None);
        assert!(
            bytes
                .as_ptr_range()
                .contains(&packet.payloads[0].body.as_ptr())
        );
    }

    #[test]
    fn test_ikev2_encrypted_payload_is_the_last() {
        let bytes = hex::decode(IKEV2_IKE_AUTH).unwrap();
        assert_eq!(bytes.len(), 229);
        let packet = IkePacket::try_from(bytes.as_slice()).expect("IKE_AUTH");
        assert_eq!(packet.header.responder_spi, 0xf055_34ee_f373_dc1b);
        assert_eq!(packet.header.exchange(), Some(ExchangeType::IkeAuth));
        assert!(packet.header.response_flag());
        assert_eq!(packet.header.message_id, 1);
        assert_eq!(types_and_lengths(&packet), (vec![46], vec![201]));
        assert_eq!(packet.payloads[0].kind, Some(PayloadType::Encrypted));
        // Le « next payload » du SK nomme le premier payload sous le chiffre.
        assert_eq!(packet.payloads[0].next_payload, 43);
        assert_eq!(packet.encrypted_body.map(<[u8]>::len), Some(197));

        // Un SK qui n'est pas le dernier : ce qui suit est de trop.
        let mut shorter = bytes.clone();
        shorter[30..32].copy_from_slice(&191u16.to_be_bytes());
        assert_eq!(
            IkePacket::try_from(shorter.as_slice()),
            Err(IkeParseError::UnexpectedTrailingBytes { trailing: 10 })
        );
    }

    #[test]
    fn test_decodes_ikev1_main_mode_in_clear_and_encrypted() {
        let bytes = hex::decode(IKEV1_MAIN_MODE).unwrap();
        assert_eq!(bytes.len(), 124);
        let packet = IkePacket::try_from(bytes.as_slice()).expect("main mode");
        let header = packet.header;
        assert_eq!(header.initiator_spi, 0xb316_15b5_ec7a_4faf);
        assert_eq!(header.responder_spi, 0);
        assert_eq!((header.major_version(), header.minor_version()), (1, 0));
        assert_eq!(header.exchange(), Some(ExchangeType::IdentityProtection));
        assert_eq!(header.flags, 0);
        assert!(!header.initiator_flag());
        assert!(!header.commit_flag() && !header.authentication_only_flag());
        assert_eq!(
            types_and_lengths(&packet),
            (vec![1, 13, 13], vec![56, 20, 20])
        );
        assert_eq!(
            packet.payloads[0].kind,
            Some(PayloadType::SecurityAssociation)
        );
        assert_eq!(packet.payloads[1].kind, Some(PayloadType::VendorId));
        assert_eq!(packet.encrypted_body, None);

        let bytes = hex::decode(IKEV1_ENCRYPTED).unwrap();
        assert_eq!(bytes.len(), 76);
        let packet = IkePacket::try_from(bytes.as_slice()).expect("chiffre");
        assert!(packet.header.encryption_flag());
        assert_eq!(packet.header.next_payload, 5);
        assert!(packet.payloads.is_empty());
        assert_eq!(packet.encrypted_body.map(<[u8]>::len), Some(48));
    }

    #[test]
    fn test_udp_4500_demultiplexing() {
        let bytes = hex::decode(NAT_T_INFORMATIONAL).unwrap();
        assert_eq!(bytes.len(), 80);
        // Nu, le marqueur est pris pour un SPI et la version ne colle pas.
        assert!(IkePacket::try_from(bytes.as_slice()).is_err());
        let Ok(UdpEncapsulation::Ike(rest)) = UdpEncapsulation::classify(&bytes) else {
            panic!("marqueur non-ESP attendu");
        };
        assert_eq!(rest.len(), 76);
        let packet = IkePacket::from_udp(bytes.as_slice()).expect("apres le marqueur");
        assert_eq!(packet.header.initiator_spi, 0xde64_8338_c613_aa68);
        assert_eq!(packet.header.responder_spi, 0xd8b3_0389_0424_0d4b);
        assert_eq!(packet.header.exchange(), Some(ExchangeType::Informational));
        assert_eq!(packet.header.flags, 0);
        assert_eq!(packet.header.length, 76);
        assert_eq!(types_and_lengths(&packet), (vec![46], vec![48]));

        assert_eq!(
            UdpEncapsulation::classify(&[0xff]),
            Ok(UdpEncapsulation::Keepalive)
        );
        let esp = hex::decode("5fbd60dc00000001a0b1c2d3").unwrap();
        assert_eq!(
            UdpEncapsulation::classify(&esp),
            Ok(UdpEncapsulation::Esp(esp.as_slice()))
        );
        for short in [&[][..], &[0, 0, 0, 0][..], &[1, 2, 3, 4, 5, 6, 7][..]] {
            assert_eq!(
                UdpEncapsulation::classify(short),
                Err(IkeParseError::InvalidUdpEncapsulation {
                    length: short.len()
                })
            );
        }
        // Sur UDP 500, un message nu reste accepte par from_udp.
        let bytes = hex::decode(IKEV1_MAIN_MODE).unwrap();
        assert_eq!(
            IkePacket::from_udp(bytes.as_slice()),
            IkePacket::try_from(bytes.as_slice())
        );
    }

    #[test]
    fn test_rejects_bad_headers_and_payload_chains() {
        let bytes = hex::decode(IKEV2_SA_INIT).unwrap();
        assert_eq!(
            IkePacket::try_from(&bytes[..27]),
            Err(IkeParseError::Truncated {
                expected: 28,
                actual: 27
            })
        );
        let mut version = bytes.clone();
        version[17] = 0x30;
        assert_eq!(
            IkePacket::try_from(version.as_slice()),
            Err(IkeParseError::UnsupportedVersion(3))
        );
        let mut zero_spi = bytes.clone();
        zero_spi[..8].copy_from_slice(&[0; 8]);
        assert_eq!(
            IkePacket::try_from(zero_spi.as_slice()),
            Err(IkeParseError::ZeroInitiatorSpi)
        );
        assert_eq!(
            IkePacket::try_from(&bytes[..373]),
            Err(IkeParseError::LengthMismatch {
                declared: 374,
                actual: 373
            })
        );
        let mut longer = bytes.clone();
        longer.push(0);
        longer[24..28].copy_from_slice(&375u32.to_be_bytes());
        assert_eq!(
            IkePacket::try_from(longer.as_slice()),
            Err(IkeParseError::UnexpectedTrailingBytes { trailing: 1 })
        );
        let mut tiny = bytes.clone();
        tiny[30..32].copy_from_slice(&3u16.to_be_bytes());
        assert_eq!(
            IkePacket::try_from(tiny.as_slice()),
            Err(IkeParseError::InvalidPayloadLength {
                payload_type: 33,
                length: 3
            })
        );
        let mut overflow = bytes.clone();
        overflow[30..32].copy_from_slice(&400u16.to_be_bytes());
        assert_eq!(
            IkePacket::try_from(overflow.as_slice()),
            Err(IkeParseError::PayloadOverflow {
                payload_type: 33,
                needed: 400,
                available: 346
            })
        );
        // Le dernier payload annonce un suivant sans place pour lui : comme
        // tshark, la chaine s'arrete a la fin du message (trame 192 du corpus
        // nDPI, payload prive 127 qui annonce 35).
        let mut dangling = bytes.clone();
        dangling[354] = 41;
        let packet = IkePacket::try_from(dangling.as_slice()).expect("suivant pendant");
        assert_eq!(packet.payloads.len(), 9);
        assert_eq!(packet.payloads[8].next_payload, 41);
        // Mais un suivant annonce avec un, deux ou trois octets restants
        // n'a pas d'en-tete : rejet.
        let mut stub = dangling.clone();
        stub.extend_from_slice(&[0, 0]);
        stub[24..28].copy_from_slice(&376u32.to_be_bytes());
        assert_eq!(
            IkePacket::try_from(stub.as_slice()),
            Err(IkeParseError::PayloadOverflow {
                payload_type: 41,
                needed: 4,
                available: 2
            })
        );
        // Un type d'echange ou de payload inconnu reste decode, sans nom.
        let mut unknown = bytes.clone();
        unknown[18] = 60;
        unknown[16] = 60;
        let packet = IkePacket::try_from(unknown.as_slice()).expect("codes inconnus");
        assert_eq!(packet.header.exchange(), None);
        assert_eq!(packet.payloads[0].kind, None);
    }
}
