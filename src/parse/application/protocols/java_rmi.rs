// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Java RMI : le protocole de transport JRMP (*Java RMI Specification*,
//! chapitre 10, « RMI Wire Protocol »), sur TCP.
//!
//! Un client ouvre une connexion par un en-tete de flux (`JRMI`, version,
//! protocole). En StreamProtocol, le serveur repond par un ProtocolAck qui
//! porte l'adresse du client telle qu'il la voit, puis les deux cotes
//! echangent des messages identifies par leur premier octet : Call et Ping
//! du client, Return et PingAck du serveur, DgcAck du client qui acquitte
//! les references distantes recues. En SingleOpProtocol, l'appel suit
//! l'en-tete dans le meme segment et la connexion ne sert qu'une fois.
//!
//! Le Call et le Return ouvrent un flux de serialisation Java (`AC ED 00
//! 05`) dont le premier bloc de donnees porte leur en-tete : l'objet vise
//! (`ObjID`), l'operation et le hash de la methode pour un appel ; le type
//! de retour et un UID d'acquittement pour un retour. Les arguments et la
//! valeur de retour qui suivent restent des octets serialises, rendus en
//! tranche de l'entree.
//!
//! Ce que le decodeur ne lit pas, faute d'etat de connexion :
//!
//! - l'EndpointIdentifier que le client envoie apres le ProtocolAck : il n'a
//!   pas d'octet de type (tshark l'affiche « Continuation ») ;
//! - les segments de suite d'un Call ou d'un Return plus long qu'un segment ;
//! - les operations du MultiplexProtocol, dont seul l'en-tete est reconnu.
//!
//! Detection : l'en-tete de flux, le Call et le Return ont une signature
//! assez forte pour etre reconnus sur tout port TCP. Les messages d'un
//! octet (Ping, PingAck, ProtocolNotSupported), le DgcAck et le ProtocolAck
//! ne le sont que sur TCP 1099 (`rmiregistry`) ou par Decode As
//! ([`JavaRmiPacket::is_self_identifying`]).

use std::fmt;

use crate::checks::application::java_rmi::{
    JAVA_RMI_CALL_HEADER_LEN, JAVA_RMI_DGC_ACK_LEN, JAVA_RMI_HEADER_LEN,
    JAVA_RMI_RETURN_HEADER_LEN, MESSAGE_CALL, MESSAGE_DGC_ACK, MESSAGE_HEADER, MESSAGE_PING,
    MESSAGE_PING_ACK, MESSAGE_PROTOCOL_ACK, MESSAGE_PROTOCOL_NOT_SUPPORTED, MESSAGE_RETURN,
    extract_java_rmi_block, extract_java_rmi_port, extract_java_rmi_protocol,
    extract_java_rmi_return_type, extract_java_rmi_version, validate_java_rmi_exact_length,
    validate_java_rmi_magic, validate_java_rmi_min_length, validate_java_rmi_stream_header,
};
use crate::errors::application::java_rmi::JavaRmiError;

/// Hash d'interface de `java.rmi.registry.Registry`, que portent les appels
/// du stub du registre (`RegistryImpl_Stub`, protocole des stubs 1.1).
pub const JAVA_RMI_REGISTRY_INTERFACE_HASH: i64 = 0x4415_4dc9_d4e6_3bdf;
/// Hash d'interface de `java.rmi.dgc.DGC` (`DGCImpl_Stub`).
pub const JAVA_RMI_DGC_INTERFACE_HASH: i64 = 0xf6b6_898d_8bf2_8643_u64 as i64;

/// Operations du registre, par numero (`RegistryImpl_Stub`).
const REGISTRY_OPERATIONS: [&str; 5] = ["bind", "list", "lookup", "rebind", "unbind"];
/// Operations du DGC, par numero (`DGCImpl_Stub`).
const DGC_OPERATIONS: [&str; 2] = ["clean", "dirty"];

/// Un message JRMP, tel que l'ouvre un segment TCP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JavaRmiPacket<'a> {
    /// Ouverture de connexion par le client.
    Header(JavaRmiHeader<'a>),
    /// Reponse du serveur a un en-tete StreamProtocol (`0x4e`).
    ProtocolAck(JavaRmiEndpoint<'a>),
    /// Refus du protocole demande (`0x4f`).
    ProtocolNotSupported,
    /// Appel de methode distante (`0x50`).
    Call(JavaRmiCall<'a>),
    /// Retour d'un appel (`0x51`).
    Return(JavaRmiReturn<'a>),
    /// Sonde de connexion du client (`0x52`), avant de reutiliser une
    /// connexion restee inactive.
    Ping,
    /// Reponse du serveur a un Ping (`0x53`).
    PingAck,
    /// Acquittement des references distantes recues dans un Return
    /// (`0x54`) : l'UID repete celui de ce retour.
    DgcAck(JavaRmiUid),
}

/// En-tete de flux : magie, version, protocole.
///
/// ```mermaid
/// ---
/// title: JavaRmiHeader
/// ---
/// packet-beta
/// 0-31: "Magic JRMI u32"
/// 32-47: "Version u16"
/// 48-55: "Protocol u8"
/// 56-63: "Messages (variable)"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct JavaRmiHeader<'a> {
    /// 2 pour tout JDK depuis 1.2.
    pub version: u16,
    pub protocol: JavaRmiProtocol,
    /// Ce qui suit l'en-tete dans le segment : vide en StreamProtocol, le
    /// client attendant le ProtocolAck ; le Call en SingleOpProtocol.
    pub messages: &'a [u8],
}

impl<'a> JavaRmiHeader<'a> {
    /// Le message qui suit l'en-tete dans le segment, decode a la demande ;
    /// `None` s'il n'y en a pas.
    pub fn message(&self) -> Option<Result<JavaRmiPacket<'a>, JavaRmiError>> {
        (!self.messages.is_empty()).then(|| JavaRmiPacket::try_from(self.messages))
    }
}

/// Protocole demande par l'en-tete de flux.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum JavaRmiProtocol {
    /// `0x4b` : connexion reutilisable, ouverte par un ProtocolAck.
    Stream,
    /// `0x4c` : un seul appel, sans ProtocolAck (tunnel HTTP).
    SingleOp,
    /// `0x4d` : plusieurs flux sur une connexion (JDK 1.1).
    Multiplex,
}

impl JavaRmiProtocol {
    /// L'octet du protocole dans l'en-tete de flux.
    pub const fn code(self) -> u8 {
        match self {
            Self::Stream => 0x4b,
            Self::SingleOp => 0x4c,
            Self::Multiplex => 0x4d,
        }
    }

    /// Le nom de la specification et de tshark.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Stream => "StreamProtocol",
            Self::SingleOp => "SingleOpProtocol",
            Self::Multiplex => "MultiplexProtocol",
        }
    }
}

/// EndpointIdentifier d'un ProtocolAck : l'adresse du client vue du
/// serveur.
///
/// ```mermaid
/// ---
/// title: ProtocolAck
/// ---
/// packet-beta
/// 0-7: "Type 0x4e"
/// 8-23: "Hostname length u16"
/// 24-55: "Hostname (variable)"
/// 56-87: "Port u32"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct JavaRmiEndpoint<'a> {
    /// Ecrit par `writeUTF` : UTF-8 modifie, une adresse IP ou un nom
    /// d'hote en pratique.
    pub hostname: &'a [u8],
    pub port: u16,
}

impl<'a> JavaRmiEndpoint<'a> {
    /// Le nom d'hote, s'il est de l'UTF-8 valide.
    pub fn hostname_str(&self) -> Option<&'a str> {
        std::str::from_utf8(self.hostname).ok()
    }
}

/// `java.rmi.server.UID` : identifie un espace d'objets (dans un
/// [`JavaRmiObjId`]) ou un retour a acquitter (dans un [`JavaRmiReturn`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct JavaRmiUid {
    pub unique: i32,
    /// Millisecondes depuis l'epoque Unix, a la creation de la JVM.
    pub time: i64,
    pub count: i16,
}

impl JavaRmiUid {
    /// L'UID nul des objets bien connus (`new UID((short) 0)`).
    pub const fn is_zero(&self) -> bool {
        self.unique == 0 && self.time == 0 && self.count == 0
    }
}

/// `java.rmi.server.ObjID` : l'objet distant vise par un appel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct JavaRmiObjId {
    pub object_number: i64,
    pub space: JavaRmiUid,
}

/// Objets que tout serveur RMI exporte a un numero fixe, dans l'espace nul.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum JavaRmiWellKnownObject {
    /// `ObjID.REGISTRY_ID` (0).
    Registry,
    /// `ObjID.ACTIVATOR_ID` (1).
    Activator,
    /// `ObjID.DGC_ID` (2) : le ramasse-miettes distribue.
    Dgc,
}

impl JavaRmiWellKnownObject {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Registry => "Registry",
            Self::Activator => "Activator",
            Self::Dgc => "DGC",
        }
    }
}

impl JavaRmiObjId {
    /// L'objet bien connu que designe cet identifiant, s'il en est un.
    pub const fn well_known(&self) -> Option<JavaRmiWellKnownObject> {
        if !self.space.is_zero() {
            return None;
        }
        match self.object_number {
            0 => Some(JavaRmiWellKnownObject::Registry),
            1 => Some(JavaRmiWellKnownObject::Activator),
            2 => Some(JavaRmiWellKnownObject::Dgc),
            _ => None,
        }
    }
}

/// Appel de methode distante : l'en-tete d'appel, dans le premier bloc du
/// flux de serialisation.
///
/// ```mermaid
/// ---
/// title: JavaRmiCall
/// ---
/// packet-beta
/// 0-7: "Type 0x50"
/// 8-23: "Stream magic 0xaced"
/// 24-39: "Stream version 5"
/// 40-47: "TC_BLOCKDATA 0x77"
/// 48-55: "Block length u8"
/// 56-119: "Object number i64"
/// 120-151: "Space unique i32"
/// 152-215: "Space time i64"
/// 216-231: "Space count i16"
/// 232-263: "Operation i32"
/// 264-327: "Method hash i64"
/// 328-359: "Arguments (variable)"
/// ```
///
/// Un bloc de plus de 255 octets s'ouvre par `TC_BLOCKDATALONG` (`0x7a`)
/// et une longueur sur quatre octets : l'en-tete d'appel commence alors
/// trois octets plus loin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct JavaRmiCall<'a> {
    pub object: JavaRmiObjId,
    /// Numero de methode du stub 1.1 (registre, DGC) ; -1 quand le hash
    /// designe la methode (stubs 1.2 et proxys dynamiques).
    pub operation: i32,
    /// Hash d'interface (stub 1.1) ou hash de methode.
    pub hash: i64,
    /// Ce qui suit l'en-tete d'appel dans le segment : le reste du bloc
    /// (arguments primitifs) et les objets serialises.
    pub arguments: &'a [u8],
}

impl JavaRmiCall<'_> {
    /// `Registry.lookup`, `DGC.dirty`... : la methode d'un objet bien connu,
    /// quand l'appel passe par son stub 1.1.
    pub fn well_known_method(&self) -> Option<(JavaRmiWellKnownObject, &'static str)> {
        let object = self.object.well_known()?;
        let operations: &[&str] = match (object, self.hash) {
            (JavaRmiWellKnownObject::Registry, JAVA_RMI_REGISTRY_INTERFACE_HASH) => {
                &REGISTRY_OPERATIONS
            }
            (JavaRmiWellKnownObject::Dgc, JAVA_RMI_DGC_INTERFACE_HASH) => &DGC_OPERATIONS,
            _ => return None,
        };
        let index = usize::try_from(self.operation).ok()?;
        operations.get(index).map(|name| (object, *name))
    }
}

/// Retour d'un appel : type et UID d'acquittement, dans le premier bloc du
/// flux de serialisation.
///
/// ```mermaid
/// ---
/// title: JavaRmiReturn
/// ---
/// packet-beta
/// 0-7: "Type 0x51"
/// 8-23: "Stream magic 0xaced"
/// 24-39: "Stream version 5"
/// 40-47: "TC_BLOCKDATA 0x77"
/// 48-55: "Block length u8"
/// 56-63: "Return type u8"
/// 64-95: "Ack unique i32"
/// 96-159: "Ack time i64"
/// 160-175: "Ack count i16"
/// 176-207: "Value (variable)"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct JavaRmiReturn<'a> {
    pub return_type: JavaRmiReturnType,
    /// Repete par le DgcAck du client si la valeur porte des references
    /// distantes.
    pub ack_id: JavaRmiUid,
    /// Ce qui suit l'en-tete de retour dans le segment : le reste du bloc
    /// (valeur primitive) et les objets serialises (valeur ou exception).
    pub value: &'a [u8],
}

/// Issue de l'appel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum JavaRmiReturnType {
    /// `NormalReturn` (1) : la valeur de retour suit.
    Normal,
    /// `ExceptionalReturn` (2) : l'exception levee suit.
    Exceptional,
}

impl JavaRmiPacket<'_> {
    /// L'octet de type du message : `0x4a` (le `J` de `JRMI`) pour un
    /// en-tete de flux, `0x4e` a `0x54` pour les autres.
    pub const fn message_type(&self) -> u8 {
        match self {
            Self::Header(_) => MESSAGE_HEADER,
            Self::ProtocolAck(_) => MESSAGE_PROTOCOL_ACK,
            Self::ProtocolNotSupported => MESSAGE_PROTOCOL_NOT_SUPPORTED,
            Self::Call(_) => MESSAGE_CALL,
            Self::Return(_) => MESSAGE_RETURN,
            Self::Ping => MESSAGE_PING,
            Self::PingAck => MESSAGE_PING_ACK,
            Self::DgcAck(_) => MESSAGE_DGC_ACK,
        }
    }

    /// L'en-tete de flux, le Call et le Return : les messages dont les
    /// octets suffisent a reconnaitre JRMP hors de son port. Les autres
    /// tiennent en un octet, ou en un octet et quelques champs libres.
    pub const fn is_self_identifying(&self) -> bool {
        matches!(self, Self::Header(_) | Self::Call(_) | Self::Return(_))
    }
}

impl<'a> TryFrom<&'a [u8]> for JavaRmiPacket<'a> {
    type Error = JavaRmiError;

    fn try_from(packet: &'a [u8]) -> Result<Self, Self::Error> {
        validate_java_rmi_min_length(packet, 1)?;
        match packet[0] {
            MESSAGE_HEADER => parse_header(packet).map(Self::Header),
            MESSAGE_PROTOCOL_ACK => parse_protocol_ack(packet).map(Self::ProtocolAck),
            MESSAGE_PROTOCOL_NOT_SUPPORTED => {
                validate_java_rmi_exact_length(packet, MESSAGE_PROTOCOL_NOT_SUPPORTED, 1)?;
                Ok(Self::ProtocolNotSupported)
            }
            MESSAGE_CALL => parse_call(packet).map(Self::Call),
            MESSAGE_RETURN => parse_return(packet).map(Self::Return),
            MESSAGE_PING => {
                validate_java_rmi_exact_length(packet, MESSAGE_PING, 1)?;
                Ok(Self::Ping)
            }
            MESSAGE_PING_ACK => {
                validate_java_rmi_exact_length(packet, MESSAGE_PING_ACK, 1)?;
                Ok(Self::PingAck)
            }
            MESSAGE_DGC_ACK => {
                validate_java_rmi_exact_length(packet, MESSAGE_DGC_ACK, JAVA_RMI_DGC_ACK_LEN)?;
                Ok(Self::DgcAck(read_uid(packet, 1)))
            }
            other => Err(JavaRmiError::UnknownMessageType(other)),
        }
    }
}

fn parse_header(packet: &[u8]) -> Result<JavaRmiHeader<'_>, JavaRmiError> {
    validate_java_rmi_min_length(packet, JAVA_RMI_HEADER_LEN)?;
    validate_java_rmi_magic(packet)?;
    let version = extract_java_rmi_version(u16::from_be_bytes([packet[4], packet[5]]))?;
    let protocol = extract_java_rmi_protocol(packet[6])?;
    Ok(JavaRmiHeader {
        version,
        protocol,
        messages: &packet[JAVA_RMI_HEADER_LEN..],
    })
}

fn parse_protocol_ack(packet: &[u8]) -> Result<JavaRmiEndpoint<'_>, JavaRmiError> {
    validate_java_rmi_min_length(packet, 3)?;
    let hostname_len = usize::from(u16::from_be_bytes([packet[1], packet[2]]));
    let port_offset = 3 + hostname_len;
    validate_java_rmi_exact_length(packet, MESSAGE_PROTOCOL_ACK, port_offset + 4)?;
    let port = extract_java_rmi_port(u32::from_be_bytes(be(packet, port_offset)))?;
    Ok(JavaRmiEndpoint {
        hostname: &packet[3..port_offset],
        port,
    })
}

fn parse_call(packet: &[u8]) -> Result<JavaRmiCall<'_>, JavaRmiError> {
    validate_java_rmi_min_length(packet, 5)?;
    validate_java_rmi_stream_header(packet)?;
    let start = extract_java_rmi_block(packet, 5, JAVA_RMI_CALL_HEADER_LEN)?;
    Ok(JavaRmiCall {
        object: JavaRmiObjId {
            object_number: i64::from_be_bytes(be(packet, start)),
            space: read_uid(packet, start + 8),
        },
        operation: i32::from_be_bytes(be(packet, start + 22)),
        hash: i64::from_be_bytes(be(packet, start + 26)),
        arguments: &packet[start + JAVA_RMI_CALL_HEADER_LEN..],
    })
}

fn parse_return(packet: &[u8]) -> Result<JavaRmiReturn<'_>, JavaRmiError> {
    validate_java_rmi_min_length(packet, 5)?;
    validate_java_rmi_stream_header(packet)?;
    let start = extract_java_rmi_block(packet, 5, JAVA_RMI_RETURN_HEADER_LEN)?;
    Ok(JavaRmiReturn {
        return_type: extract_java_rmi_return_type(packet[start])?,
        ack_id: read_uid(packet, start + 1),
        value: &packet[start + JAVA_RMI_RETURN_HEADER_LEN..],
    })
}

/// `N` octets a partir de `offset`. Appelant : longueur deja verifiee.
fn be<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    std::array::from_fn(|index| bytes[offset + index])
}

/// Un UID a `offset`. Appelant : quatorze octets presents.
fn read_uid(bytes: &[u8], offset: usize) -> JavaRmiUid {
    JavaRmiUid {
        unique: i32::from_be_bytes(be(bytes, offset)),
        time: i64::from_be_bytes(be(bytes, offset + 4)),
        count: i16::from_be_bytes(be(bytes, offset + 12)),
    }
}

impl fmt::Display for JavaRmiPacket<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Header(header) => write!(
                f,
                "JRMI, Version: {}, {}",
                header.version,
                header.protocol.name()
            ),
            Self::ProtocolAck(endpoint) => write!(
                f,
                "ProtocolAck {}:{}",
                String::from_utf8_lossy(endpoint.hostname),
                endpoint.port
            ),
            Self::ProtocolNotSupported => f.write_str("ProtocolNotSupported"),
            Self::Call(call) => match call.well_known_method() {
                Some((object, method)) => write!(f, "Call {}.{}", object.name(), method),
                None => write!(
                    f,
                    "Call object {} operation {} hash 0x{:016x}",
                    call.object.object_number, call.operation, call.hash
                ),
            },
            Self::Return(ret) => match ret.return_type {
                JavaRmiReturnType::Normal => f.write_str("ReturnData"),
                JavaRmiReturnType::Exceptional => f.write_str("ReturnData (exception)"),
            },
            Self::Ping => f.write_str("Ping"),
            Self::PingAck => f.write_str("PingAck"),
            Self::DgcAck(_) => f.write_str("DgcAck"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trames de `pcaps_exemple/protocols/java_rmi/jdk11-loopback.pcap`.
    mod capture {
        /// Trame 4 : en-tete StreamProtocol du client vers le registre.
        pub const STREAM_HEADER: &str = "4a524d4900024b";
        /// Trame 6 : ProtocolAck du registre, client 127.0.0.1:36556.
        pub const PROTOCOL_ACK: &str = "4e00093132372e302e302e3100008ecc";
        /// Trame 8 : EndpointIdentifier du client, sans octet de type.
        pub const CLIENT_ENDPOINT: &str = "00093132372e302e302e3100000000";
        /// Trame 33 : `Registry.list()`.
        pub const REGISTRY_LIST: &str = concat!(
            "50aced0005",
            "7722",
            "0000000000000000",
            "00000000",
            "0000000000000000",
            "0000",
            "00000001",
            "44154dc9d4e63bdf",
        );
        /// Trame 35 : retour de `list()`, le tableau `["station", "jmxrmi"]`.
        pub const REGISTRY_LIST_RETURN: &str = concat!(
            "51aced0005",
            "770f",
            "01",
            "bfcb98ab",
            "000001a1e8ed9c5b",
            "8006",
            "757200135b4c6a6176612e6c616e672e537472696e673badd256e7e91d7b47",
            "0200007078700000000274000773746174696f6e7400066a6d78726d69",
        );
        /// Trame 53 : DgcAck de l'UID du retour de `lookup` (trame 39).
        pub const DGC_ACK: &str = "54bfcb98ab000001a1e8ed9c5b8007";
        /// Trame 60 : `Station.add(2, 3)` : hash de methode, deux entiers
        /// dans le bloc de 42 octets.
        pub const STATION_ADD: &str = concat!(
            "50aced0005",
            "772a",
            "18ab9a4555f8f98a",
            "bfcb98ab",
            "000001a1e8ed9c5b",
            "8001",
            "ffffffff",
            "94a9af306652c3a6",
            "00000002",
            "00000003",
        );
        /// Trame 61 : retour de `add`, la valeur 5 dans le bloc.
        pub const STATION_ADD_RETURN: &str = "51aced0005771301bfcb98ab000001a1e8ed9c5b800a00000005";
        /// Trame 319 : en-tete SingleOpProtocol suivi de `Registry.list()`.
        pub const SINGLE_OP_LIST: &str = concat!(
            "4a524d4900024c",
            "50aced0005",
            "7722",
            "0000000000000000",
            "00000000",
            "0000000000000000",
            "0000",
            "00000001",
            "44154dc9d4e63bdf",
        );
        /// Trame 329 : en-tete au protocole inconnu `0x4e`.
        pub const UNKNOWN_PROTOCOL: &str = "4a524d4900024e";
    }

    fn bytes(hex_frame: &str) -> Vec<u8> {
        hex::decode(hex_frame).expect("fixture hexadecimale")
    }

    #[test]
    fn stream_header_from_capture() {
        let frame = bytes(capture::STREAM_HEADER);
        let packet = JavaRmiPacket::try_from(frame.as_slice()).unwrap();
        let JavaRmiPacket::Header(header) = packet else {
            panic!("{packet:?}");
        };
        assert_eq!(header.version, 2);
        assert_eq!(header.protocol, JavaRmiProtocol::Stream);
        assert_eq!(header.protocol.code(), 0x4b);
        assert_eq!(packet.message_type(), 0x4a);
        assert!(header.messages.is_empty());
        assert!(header.message().is_none());
        assert!(packet.is_self_identifying());
        assert_eq!(packet.to_string(), "JRMI, Version: 2, StreamProtocol");
    }

    #[test]
    fn protocol_ack_from_capture() {
        let frame = bytes(capture::PROTOCOL_ACK);
        let packet = JavaRmiPacket::try_from(frame.as_slice()).unwrap();
        let JavaRmiPacket::ProtocolAck(endpoint) = packet else {
            panic!("{packet:?}");
        };
        assert_eq!(endpoint.hostname_str(), Some("127.0.0.1"));
        assert_eq!(endpoint.port, 36556);
        assert!(!packet.is_self_identifying());
        assert_eq!(packet.to_string(), "ProtocolAck 127.0.0.1:36556");
    }

    /// L'EndpointIdentifier du client commence par la longueur de son nom :
    /// aucun type de message ne vaut 0.
    #[test]
    fn client_endpoint_is_not_a_message() {
        let frame = bytes(capture::CLIENT_ENDPOINT);
        assert_eq!(
            JavaRmiPacket::try_from(frame.as_slice()),
            Err(JavaRmiError::UnknownMessageType(0))
        );
    }

    #[test]
    fn registry_call_and_return_from_capture() {
        let frame = bytes(capture::REGISTRY_LIST);
        let packet = JavaRmiPacket::try_from(frame.as_slice()).unwrap();
        let JavaRmiPacket::Call(call) = packet else {
            panic!("{packet:?}");
        };
        assert_eq!(call.object.object_number, 0);
        assert!(call.object.space.is_zero());
        assert_eq!(
            call.object.well_known(),
            Some(JavaRmiWellKnownObject::Registry)
        );
        assert_eq!(call.operation, 1);
        assert_eq!(call.hash, JAVA_RMI_REGISTRY_INTERFACE_HASH);
        assert!(call.arguments.is_empty());
        assert_eq!(
            call.well_known_method(),
            Some((JavaRmiWellKnownObject::Registry, "list"))
        );
        assert_eq!(packet.to_string(), "Call Registry.list");

        let frame = bytes(capture::REGISTRY_LIST_RETURN);
        let packet = JavaRmiPacket::try_from(frame.as_slice()).unwrap();
        let JavaRmiPacket::Return(ret) = packet else {
            panic!("{packet:?}");
        };
        assert_eq!(ret.return_type, JavaRmiReturnType::Normal);
        assert_eq!(
            ret.ack_id,
            JavaRmiUid {
                unique: 0xbfcb98ab_u32 as i32,
                time: 0x01a1_e8ed_9c5b,
                count: 0x8006_u16 as i16,
            }
        );
        // TC_ARRAY (0x75), puis les deux chaines du tableau.
        assert_eq!(ret.value[0], 0x75);
        assert!(
            ret.value
                .ends_with(b"\x74\x00\x07station\x74\x00\x06jmxrmi")
        );
        assert_eq!(packet.to_string(), "ReturnData");
    }

    #[test]
    fn method_call_with_primitive_arguments_from_capture() {
        let frame = bytes(capture::STATION_ADD);
        let JavaRmiPacket::Call(call) = JavaRmiPacket::try_from(frame.as_slice()).unwrap() else {
            panic!("Call attendu");
        };
        assert_eq!(call.object.object_number, 0x18ab_9a45_55f8_f98a);
        assert_eq!(call.object.well_known(), None);
        assert_eq!(call.operation, -1);
        assert_eq!(call.hash, 0x94a9_af30_6652_c3a6_u64 as i64);
        assert_eq!(call.arguments, [0, 0, 0, 2, 0, 0, 0, 3]);
        assert_eq!(call.well_known_method(), None);
        assert_eq!(
            JavaRmiPacket::Call(call).to_string(),
            "Call object 1777684100513593738 operation -1 hash 0x94a9af306652c3a6"
        );

        let frame = bytes(capture::STATION_ADD_RETURN);
        let JavaRmiPacket::Return(ret) = JavaRmiPacket::try_from(frame.as_slice()).unwrap() else {
            panic!("Return attendu");
        };
        assert_eq!(ret.value, [0, 0, 0, 5]);
    }

    #[test]
    fn dgc_ack_from_capture() {
        let frame = bytes(capture::DGC_ACK);
        let packet = JavaRmiPacket::try_from(frame.as_slice()).unwrap();
        assert_eq!(
            packet,
            JavaRmiPacket::DgcAck(JavaRmiUid {
                unique: 0xbfcb98ab_u32 as i32,
                time: 0x01a1_e8ed_9c5b,
                count: 0x8007_u16 as i16,
            })
        );
        assert!(!packet.is_self_identifying());
    }

    #[test]
    fn single_op_header_carries_its_call() {
        let frame = bytes(capture::SINGLE_OP_LIST);
        let JavaRmiPacket::Header(header) = JavaRmiPacket::try_from(frame.as_slice()).unwrap()
        else {
            panic!("Header attendu");
        };
        assert_eq!(header.protocol, JavaRmiProtocol::SingleOp);
        let Some(Ok(JavaRmiPacket::Call(call))) = header.message() else {
            panic!("{:?}", header.message());
        };
        assert_eq!(
            call.well_known_method(),
            Some((JavaRmiWellKnownObject::Registry, "list"))
        );
    }

    #[test]
    fn unknown_protocol_from_capture() {
        let frame = bytes(capture::UNKNOWN_PROTOCOL);
        assert_eq!(
            JavaRmiPacket::try_from(frame.as_slice()),
            Err(JavaRmiError::UnknownProtocol(0x4e))
        );
    }

    /// Ping (trame 36), PingAck (37) et ProtocolNotSupported (331) tiennent
    /// en un octet.
    #[test]
    fn one_byte_messages_from_capture() {
        assert_eq!(
            JavaRmiPacket::try_from(&[0x52][..]),
            Ok(JavaRmiPacket::Ping)
        );
        assert_eq!(
            JavaRmiPacket::try_from(&[0x53][..]),
            Ok(JavaRmiPacket::PingAck)
        );
        assert_eq!(
            JavaRmiPacket::try_from(&[0x4f][..]),
            Ok(JavaRmiPacket::ProtocolNotSupported)
        );
    }

    /// Octets synthetiques : chaque refus, un par champ contraint.
    #[test]
    fn rejects_malformed_messages() {
        let cases: [(&[u8], JavaRmiError); 10] = [
            (
                &[],
                JavaRmiError::TooShort {
                    expected: 1,
                    actual: 0,
                },
            ),
            (&[0x55], JavaRmiError::UnknownMessageType(0x55)),
            (
                b"JRMX\x00\x02\x4b",
                JavaRmiError::InvalidHeaderMagic(0x4a52_4d58),
            ),
            (b"JRMI\x00\x03\x4b", JavaRmiError::InvalidVersion(3)),
            (
                b"JRMI\x00\x02",
                JavaRmiError::TooShort {
                    expected: 7,
                    actual: 6,
                },
            ),
            (
                &[0x52, 0x52],
                JavaRmiError::UnexpectedLength {
                    message: 0x52,
                    expected: 1,
                    actual: 2,
                },
            ),
            (
                &[0x54, 0, 0],
                JavaRmiError::UnexpectedLength {
                    message: 0x54,
                    expected: 15,
                    actual: 3,
                },
            ),
            (
                &[0x4e, 0, 1, b'h', 0, 1, 0, 0],
                JavaRmiError::InvalidPort(0x0001_0000),
            ),
            (
                &[0x4e, 0, 2, b'h', 0, 0, 0, 1],
                JavaRmiError::UnexpectedLength {
                    message: 0x4e,
                    expected: 9,
                    actual: 8,
                },
            ),
            (
                &[
                    0x51, 0xac, 0xed, 0x00, 0x05, 0x77, 0x0f, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0,
                ],
                JavaRmiError::InvalidReturnType(3),
            ),
        ];
        for (input, error) in cases {
            assert_eq!(JavaRmiPacket::try_from(input), Err(error), "{input:02x?}");
        }
    }

    /// Octets synthetiques : un Call dont le bloc s'ouvre par
    /// `TC_BLOCKDATALONG`, et un Call coupe dans son en-tete.
    #[test]
    fn call_header_in_a_long_block_and_truncated_call() {
        let mut long = vec![0x50, 0xac, 0xed, 0x00, 0x05, 0x7a, 0, 0, 1, 0];
        long.extend_from_slice(&[0; 22]);
        long.extend_from_slice(&2i32.to_be_bytes());
        long.extend_from_slice(&JAVA_RMI_REGISTRY_INTERFACE_HASH.to_be_bytes());
        long.push(0x70);
        let JavaRmiPacket::Call(call) = JavaRmiPacket::try_from(long.as_slice()).unwrap() else {
            panic!("Call attendu");
        };
        assert_eq!(call.operation, 2);
        assert_eq!(call.arguments, [0x70]);

        let frame = bytes(capture::REGISTRY_LIST);
        assert_eq!(
            JavaRmiPacket::try_from(&frame[..40]),
            Err(JavaRmiError::TooShort {
                expected: 41,
                actual: 40
            })
        );
    }

    #[test]
    fn dgc_hash_names_its_methods() {
        let mut frame = bytes(capture::REGISTRY_LIST);
        frame[14] = 2; // objet 2 : DGC
        frame[33..41].copy_from_slice(&JAVA_RMI_DGC_INTERFACE_HASH.to_be_bytes());
        let JavaRmiPacket::Call(call) = JavaRmiPacket::try_from(frame.as_slice()).unwrap() else {
            panic!("Call attendu");
        };
        assert_eq!(
            call.well_known_method(),
            Some((JavaRmiWellKnownObject::Dgc, "dirty"))
        );
        assert_eq!(JAVA_RMI_DGC_INTERFACE_HASH, -669_196_253_586_618_813);
    }
}
