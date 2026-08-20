// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Validations et extractions controlees des BPDU Spanning Tree.
//!
//! Le parseur (`src/parse/data_link/stp.rs`) enchaine ces fonctions champ
//! par champ ; aucune validation inline ne vit dans le fichier de parsing.

use crate::{
    errors::data_link::stp::StpError,
    parse::data_link::{
        mac_addres::MacAddress,
        stp::{BpduType, BridgeId, StpVersion},
    },
};

/// Adresse multicast reservee au groupe bridge, destination des BPDU.
pub const BRIDGE_GROUP_ADDRESS: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x00];

/// En-tete LLC des BPDU : DSAP 0x42, SSAP 0x42, controle UI 0x03.
/// Exclut notamment PVST+ qui circule en SNAP (DSAP/SSAP 0xAA).
pub const LLC_STP_HEADER: [u8; 3] = [0x42, 0x42, 0x03];

/// Au-dela de cette valeur, le champ apres les MAC est un EtherType ;
/// en dessous ou egal, c'est une longueur 802.3 et une trame LLC suit.
pub const MAX_IEEE_802_3_LENGTH: u16 = 0x05DC;

/// En-tete commun a tous les BPDU : protocol id (2), version (1), type (1).
pub const BPDU_HEADER_LEN: usize = 4;

/// Configuration BPDU STP : en-tete + corps de 31 octets.
pub const CONFIG_BPDU_LEN: usize = 35;

/// RST BPDU : configuration + octet version 1 length.
pub const RST_BPDU_LEN: usize = 36;

/// MST BPDU minimal : RST + version 3 length (u16), avant la partie MST.
pub const MST_BPDU_MIN_LEN: usize = 38;

const BRIDGE_ID_LEN: usize = 8;

/// Identifiant de protocole des BPDU, toujours 0x0000.
const STP_PROTOCOL_IDENTIFIER: u16 = 0x0000;

pub fn validate_bpdu_header_length(payload: &[u8]) -> Result<(), StpError> {
    if payload.len() < BPDU_HEADER_LEN {
        return Err(StpError::InvalidLength {
            expected: BPDU_HEADER_LEN,
            actual: payload.len(),
        });
    }
    Ok(())
}

pub fn validate_configuration_length(payload: &[u8]) -> Result<(), StpError> {
    if payload.len() < CONFIG_BPDU_LEN {
        return Err(StpError::InvalidLength {
            expected: CONFIG_BPDU_LEN,
            actual: payload.len(),
        });
    }
    Ok(())
}

pub fn validate_rst_length(payload: &[u8]) -> Result<(), StpError> {
    if payload.len() < RST_BPDU_LEN {
        return Err(StpError::InvalidLength {
            expected: RST_BPDU_LEN,
            actual: payload.len(),
        });
    }
    Ok(())
}

pub fn extract_protocol_identifier(payload: &[u8]) -> Result<u16, StpError> {
    let protocol_identifier = u16::from_be_bytes([payload[0], payload[1]]);
    if protocol_identifier != STP_PROTOCOL_IDENTIFIER {
        return Err(StpError::InvalidProtocolIdentifier(protocol_identifier));
    }
    Ok(protocol_identifier)
}

pub fn extract_stp_version(byte: u8) -> Result<StpVersion, StpError> {
    match byte {
        0 => Ok(StpVersion::Stp),
        2 => Ok(StpVersion::Rstp),
        3 => Ok(StpVersion::Mstp),
        other => Err(StpError::InvalidVersion(other)),
    }
}

pub fn extract_bpdu_type(byte: u8) -> Result<BpduType, StpError> {
    match byte {
        0x00 => Ok(BpduType::Configuration),
        0x80 => Ok(BpduType::TopologyChangeNotification),
        0x02 => Ok(BpduType::RapidSpanningTree),
        other => Err(StpError::InvalidBpduType(other)),
    }
}

/// Verifie que la version annoncee et le type de BPDU sont definis ensemble :
/// config et TCN n'existent qu'en version 0, RST en versions 2 (RSTP) et
/// 3 (MSTP).
pub fn validate_version_type_coherence(
    version: StpVersion,
    bpdu_type: BpduType,
) -> Result<(), StpError> {
    let coherent = match bpdu_type {
        BpduType::Configuration | BpduType::TopologyChangeNotification => {
            version == StpVersion::Stp
        }
        BpduType::RapidSpanningTree => version == StpVersion::Rstp || version == StpVersion::Mstp,
    };
    if !coherent {
        return Err(StpError::IncoherentVersionType {
            version: version.wire_value(),
            bpdu_type: bpdu_type.wire_value(),
        });
    }
    Ok(())
}

/// Lit un identifiant de bridge (2 octets priorite + extension, 6 octets MAC).
pub fn extract_bridge_id(bytes: &[u8]) -> Result<BridgeId, StpError> {
    if bytes.len() < BRIDGE_ID_LEN {
        return Err(StpError::InvalidLength {
            expected: BRIDGE_ID_LEN,
            actual: bytes.len(),
        });
    }
    Ok(BridgeId {
        raw_priority: u16::from_be_bytes([bytes[0], bytes[1]]),
        mac: MacAddress([bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]]),
    })
}

/// La longueur version 1 des RST/MST BPDU doit valoir 0 (802.1D-2004 §9.3.3).
pub fn extract_version_1_length(byte: u8) -> Result<u8, StpError> {
    if byte != 0 {
        return Err(StpError::InvalidVersion1Length(byte));
    }
    Ok(byte)
}

/// Extrait la partie MST d'un MST BPDU, bornee par la longueur version 3
/// annoncee. Le contenu (MST configuration id, CIST, MSTI records) reste brut.
pub fn extract_version_3_extension(payload: &[u8]) -> Result<&[u8], StpError> {
    if payload.len() < MST_BPDU_MIN_LEN {
        return Err(StpError::InvalidLength {
            expected: MST_BPDU_MIN_LEN,
            actual: payload.len(),
        });
    }
    let announced = u16::from_be_bytes([payload[36], payload[37]]) as usize;
    let available = payload.len() - MST_BPDU_MIN_LEN;
    if announced > available {
        return Err(StpError::InvalidVersion3Length {
            announced,
            available,
        });
    }
    Ok(&payload[MST_BPDU_MIN_LEN..MST_BPDU_MIN_LEN + announced])
}
