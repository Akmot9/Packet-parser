// Copyright (c) 2024 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

pub mod stp;

use crate::{
    errors::data_link::{DataLinkError, mac_addres::MacParseError},
    parse::data_link::mac_addres::MAC_LEN,
};

const DATALINK_HEADER_LEN: usize = 14;
const DATALINK_VLAN_HEADER_LEN: usize = 18;
const VLAN_TAG_LEN: usize = 4;

pub fn validate_data_link_length(packets: &[u8]) -> Result<(), DataLinkError> {
    if packets.len() < DATALINK_HEADER_LEN {
        return Err(DataLinkError::DataLinkTooShort(packets.len() as u8));
    }
    Ok(())
}

pub fn validate_data_link_vlan_length(packets: &[u8]) -> Result<(), DataLinkError> {
    if packets.len() < DATALINK_VLAN_HEADER_LEN {
        return Err(DataLinkError::DataLinkTooShort(packets.len() as u8));
    }
    Ok(())
}

/// Longueur minimale d'une trame Ethernet portant `tags` tags VLAN empiles
/// (802.1Q simple : 1 ; 802.1ad/QinQ : 2) : en-tete de 14 octets plus 4
/// octets par tag. Appele a chaque tag consomme, de sorte qu'une trame
/// tronquee au milieu de la pile remonte `DataLinkTooShort` au lieu d'un
/// acces hors borne. Un nombre de tags que la taille requise ne peut pas
/// representer est traite comme trop court : aucune entree ne fait paniquer
/// ni ne contourne le controle.
pub fn validate_data_link_vlan_stack_length(
    packets: &[u8],
    tags: usize,
) -> Result<(), DataLinkError> {
    let required = VLAN_TAG_LEN
        .checked_mul(tags)
        .and_then(|stack| stack.checked_add(DATALINK_HEADER_LEN));
    match required {
        Some(required) if packets.len() >= required => Ok(()),
        _ => Err(DataLinkError::DataLinkTooShort(packets.len() as u8)),
    }
}

pub fn validate_vlan_tag_length(bytes: &[u8]) -> Result<(), DataLinkError> {
    if bytes.len() < VLAN_TAG_LEN {
        return Err(DataLinkError::DataLinkTooShort(bytes.len() as u8));
    }
    Ok(())
}

pub fn validate_mac_length(packets: &[u8]) -> Result<(), MacParseError> {
    if packets.len() != MAC_LEN {
        return Err(MacParseError::InvalidLength {
            actual: packets.len(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vlan_stack_length_accepts_exact_and_rejects_short_frames() {
        let two_tags = [0u8; 22];
        assert!(validate_data_link_vlan_stack_length(&two_tags, 2).is_ok());
        assert!(validate_data_link_vlan_stack_length(&two_tags, 1).is_ok());
        assert!(matches!(
            validate_data_link_vlan_stack_length(&two_tags[..21], 2),
            Err(DataLinkError::DataLinkTooShort(21))
        ));
    }

    /// Un nombre de tags dont la taille requise deborde `usize` ne panique
    /// pas et ne fait pas passer la trame (revue Codex sur #83).
    #[test]
    fn vlan_stack_length_treats_overflowing_tag_count_as_too_short() {
        let frame = [0u8; 64];
        for tags in [usize::MAX, usize::MAX / VLAN_TAG_LEN, 1 << 62] {
            assert!(matches!(
                validate_data_link_vlan_stack_length(&frame, tags),
                Err(DataLinkError::DataLinkTooShort(64))
            ));
        }
    }
}
