// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Verifications du decodeur Java RMI (JRMP).
//!
//! Les valeurs viennent de la *Java RMI Specification*, chapitre 10 (« RMI
//! Wire Protocol »), et de `sun.rmi.transport.TransportConstants` du JDK ;
//! celles du flux de serialisation, de la *Java Object Serialization
//! Specification*, §6.4.

use crate::errors::application::java_rmi::JavaRmiError;
use crate::parse::application::protocols::java_rmi::{JavaRmiProtocol, JavaRmiReturnType};

/// Magie de l'en-tete de flux : `JRMI`.
pub const JAVA_RMI_MAGIC: u32 = 0x4a52_4d49;
/// Magie, version (u16) et protocole (u8).
pub const JAVA_RMI_HEADER_LEN: usize = 7;

/// Premier octet de l'en-tete de flux, `J` de la magie.
pub const MESSAGE_HEADER: u8 = 0x4a;
pub const MESSAGE_PROTOCOL_ACK: u8 = 0x4e;
pub const MESSAGE_PROTOCOL_NOT_SUPPORTED: u8 = 0x4f;
pub const MESSAGE_CALL: u8 = 0x50;
pub const MESSAGE_RETURN: u8 = 0x51;
pub const MESSAGE_PING: u8 = 0x52;
pub const MESSAGE_PING_ACK: u8 = 0x53;
pub const MESSAGE_DGC_ACK: u8 = 0x54;

/// `java.rmi.server.UID` : `unique` (i32), `time` (i64), `count` (i16).
pub const JAVA_RMI_UID_LEN: usize = 14;
/// `java.rmi.server.ObjID` : numero d'objet (i64), puis l'UID de son espace.
pub const JAVA_RMI_OBJID_LEN: usize = 8 + JAVA_RMI_UID_LEN;
/// En-tete d'appel : ObjID, operation (i32), hash de methode (i64).
pub const JAVA_RMI_CALL_HEADER_LEN: usize = JAVA_RMI_OBJID_LEN + 4 + 8;
/// En-tete de retour : type de retour (u8), puis l'UID d'acquittement.
pub const JAVA_RMI_RETURN_HEADER_LEN: usize = 1 + JAVA_RMI_UID_LEN;
/// Octet de type, puis l'UID : la taille exacte d'un DgcAck.
pub const JAVA_RMI_DGC_ACK_LEN: usize = 1 + JAVA_RMI_UID_LEN;

/// `STREAM_MAGIC` et `STREAM_VERSION` du flux de serialisation.
const STREAM_MAGIC: u16 = 0xaced;
const STREAM_VERSION: u16 = 5;
/// `TC_BLOCKDATA` : longueur sur un octet.
const TC_BLOCKDATA: u8 = 0x77;
/// `TC_BLOCKDATALONG` : longueur sur quatre octets.
const TC_BLOCKDATALONG: u8 = 0x7a;

const VERSIONS: [u16; 2] = [1, 2];

pub fn validate_java_rmi_min_length(packet: &[u8], expected: usize) -> Result<(), JavaRmiError> {
    if packet.len() < expected {
        return Err(JavaRmiError::TooShort {
            expected,
            actual: packet.len(),
        });
    }
    Ok(())
}

/// Les messages a taille fixe, et le ProtocolAck dont la taille suit le nom
/// d'hote, occupent le segment entier.
pub fn validate_java_rmi_exact_length(
    packet: &[u8],
    message: u8,
    expected: usize,
) -> Result<(), JavaRmiError> {
    if packet.len() != expected {
        return Err(JavaRmiError::UnexpectedLength {
            message,
            expected,
            actual: packet.len(),
        });
    }
    Ok(())
}

/// Les quatre premiers octets valent `JRMI`. Appelant : au moins
/// [`JAVA_RMI_HEADER_LEN`] octets.
pub fn validate_java_rmi_magic(packet: &[u8]) -> Result<(), JavaRmiError> {
    let magic = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]);
    if magic != JAVA_RMI_MAGIC {
        return Err(JavaRmiError::InvalidHeaderMagic(magic));
    }
    Ok(())
}

/// Version 2 pour tout JDK depuis 1.2 (`TransportConstants.Version`), 1
/// dans la grammaire de la specification.
pub fn extract_java_rmi_version(version: u16) -> Result<u16, JavaRmiError> {
    if !VERSIONS.contains(&version) {
        return Err(JavaRmiError::InvalidVersion(version));
    }
    Ok(version)
}

pub fn extract_java_rmi_protocol(byte: u8) -> Result<JavaRmiProtocol, JavaRmiError> {
    match byte {
        0x4b => Ok(JavaRmiProtocol::Stream),
        0x4c => Ok(JavaRmiProtocol::SingleOp),
        0x4d => Ok(JavaRmiProtocol::Multiplex),
        other => Err(JavaRmiError::UnknownProtocol(other)),
    }
}

/// Le port d'un EndpointIdentifier est ecrit par `writeInt` : un entier de
/// 32 bits, qui porte un port TCP.
pub fn extract_java_rmi_port(port: u32) -> Result<u16, JavaRmiError> {
    u16::try_from(port).map_err(|_| JavaRmiError::InvalidPort(port))
}

/// Un Call ou un Return ouvre un flux de serialisation juste apres son
/// octet de type : `AC ED 00 05`. Appelant : au moins cinq octets.
pub fn validate_java_rmi_stream_header(packet: &[u8]) -> Result<(), JavaRmiError> {
    let magic = u16::from_be_bytes([packet[1], packet[2]]);
    if magic != STREAM_MAGIC {
        return Err(JavaRmiError::InvalidStreamMagic(magic));
    }
    let version = u16::from_be_bytes([packet[3], packet[4]]);
    if version != STREAM_VERSION {
        return Err(JavaRmiError::InvalidStreamVersion(version));
    }
    Ok(())
}

/// Le bloc de donnees qui ouvre le flux, a `offset` : marqueur, longueur,
/// au moins `min` octets annonces et presents dans le segment. Rend l'offset
/// du premier octet du bloc. Le bloc peut continuer au-dela du segment :
/// les octets d'apres l'en-tete ne sont pas exiges.
pub fn extract_java_rmi_block(
    packet: &[u8],
    offset: usize,
    min: usize,
) -> Result<usize, JavaRmiError> {
    validate_java_rmi_min_length(packet, offset + 1)?;
    let (length, start) = match packet[offset] {
        TC_BLOCKDATA => {
            validate_java_rmi_min_length(packet, offset + 2)?;
            (u32::from(packet[offset + 1]), offset + 2)
        }
        TC_BLOCKDATALONG => {
            validate_java_rmi_min_length(packet, offset + 5)?;
            let length = u32::from_be_bytes([
                packet[offset + 1],
                packet[offset + 2],
                packet[offset + 3],
                packet[offset + 4],
            ]);
            (length, offset + 5)
        }
        other => return Err(JavaRmiError::ExpectedBlockData(other)),
    };
    if (length as usize) < min {
        return Err(JavaRmiError::BlockTooShort {
            expected: min,
            actual: length,
        });
    }
    validate_java_rmi_min_length(packet, start + min)?;
    Ok(start)
}

/// `NormalReturn` (1) ou `ExceptionalReturn` (2).
pub fn extract_java_rmi_return_type(byte: u8) -> Result<JavaRmiReturnType, JavaRmiError> {
    match byte {
        1 => Ok(JavaRmiReturnType::Normal),
        2 => Ok(JavaRmiReturnType::Exceptional),
        other => Err(JavaRmiError::InvalidReturnType(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_length_names_the_message() {
        assert_eq!(
            validate_java_rmi_exact_length(&[MESSAGE_PING], MESSAGE_PING, 1),
            Ok(())
        );
        assert_eq!(
            validate_java_rmi_exact_length(&[MESSAGE_PING, 0], MESSAGE_PING, 1),
            Err(JavaRmiError::UnexpectedLength {
                message: MESSAGE_PING,
                expected: 1,
                actual: 2
            })
        );
    }

    #[test]
    fn versions_and_protocols_of_the_specification() {
        assert_eq!(extract_java_rmi_version(2), Ok(2));
        assert_eq!(extract_java_rmi_version(1), Ok(1));
        assert_eq!(
            extract_java_rmi_version(3),
            Err(JavaRmiError::InvalidVersion(3))
        );
        assert_eq!(extract_java_rmi_protocol(0x4b), Ok(JavaRmiProtocol::Stream));
        assert_eq!(
            extract_java_rmi_protocol(0x4c),
            Ok(JavaRmiProtocol::SingleOp)
        );
        assert_eq!(
            extract_java_rmi_protocol(0x4d),
            Ok(JavaRmiProtocol::Multiplex)
        );
        assert_eq!(
            extract_java_rmi_protocol(0x4e),
            Err(JavaRmiError::UnknownProtocol(0x4e))
        );
    }

    #[test]
    fn port_is_a_tcp_port() {
        assert_eq!(extract_java_rmi_port(60276), Ok(60276));
        assert_eq!(
            extract_java_rmi_port(65536),
            Err(JavaRmiError::InvalidPort(65536))
        );
    }

    /// Octets synthetiques : chaque defaut de l'en-tete du flux de
    /// serialisation.
    #[test]
    fn stream_header_is_aced_0005() {
        assert_eq!(
            validate_java_rmi_stream_header(&[0x50, 0xac, 0xed, 0x00, 0x05]),
            Ok(())
        );
        assert_eq!(
            validate_java_rmi_stream_header(&[0x50, 0xac, 0xee, 0x00, 0x05]),
            Err(JavaRmiError::InvalidStreamMagic(0xacee))
        );
        assert_eq!(
            validate_java_rmi_stream_header(&[0x50, 0xac, 0xed, 0x00, 0x04]),
            Err(JavaRmiError::InvalidStreamVersion(4))
        );
    }

    /// Octets synthetiques : bloc court, bloc long, marqueur absent, bloc
    /// annonce trop petit, en-tete coupe par la fin du segment.
    #[test]
    fn block_data_holds_the_header() {
        let mut short = vec![0x77, 15];
        short.extend_from_slice(&[0; 15]);
        assert_eq!(extract_java_rmi_block(&short, 0, 15), Ok(2));

        let mut long = vec![0x7a, 0, 0, 1, 0];
        long.extend_from_slice(&[0; 34]);
        assert_eq!(extract_java_rmi_block(&long, 0, 34), Ok(5));

        assert_eq!(
            extract_java_rmi_block(&[0x73, 0x72], 0, 15),
            Err(JavaRmiError::ExpectedBlockData(0x73))
        );
        assert_eq!(
            extract_java_rmi_block(&[0x77, 14, 0, 0], 0, 15),
            Err(JavaRmiError::BlockTooShort {
                expected: 15,
                actual: 14
            })
        );
        assert_eq!(
            extract_java_rmi_block(&[0x77, 34, 0, 0], 0, 34),
            Err(JavaRmiError::TooShort {
                expected: 36,
                actual: 4
            })
        );
        assert_eq!(
            extract_java_rmi_block(&[0x7a, 0, 0], 0, 34),
            Err(JavaRmiError::TooShort {
                expected: 5,
                actual: 3
            })
        );
    }

    #[test]
    fn return_types() {
        assert_eq!(
            extract_java_rmi_return_type(1),
            Ok(JavaRmiReturnType::Normal)
        );
        assert_eq!(
            extract_java_rmi_return_type(2),
            Ok(JavaRmiReturnType::Exceptional)
        );
        assert_eq!(
            extract_java_rmi_return_type(0),
            Err(JavaRmiError::InvalidReturnType(0))
        );
    }
}
