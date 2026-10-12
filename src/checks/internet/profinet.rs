// Copyright (c) 2024 Cyprien Avico <avicocyprien@yahoo.com>
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Controles du decodeur PROFINET : Frame ID d'une trame RT, puis en-tete et
//! blocs d'un message DCP.

use crate::{
    errors::internet::profinet::ProfinetPacketError, parse::internet::protocols::profinet::FrameId,
};

/// En-tete fixe d'un message DCP : Frame ID (2), ServiceID (1), ServiceType
/// (1), Xid (4), ResponseDelay (2), DCPDataLength (2).
pub const DCP_HEADER_LEN: usize = 12;

/// En-tete d'un bloc DCP : Option (1), Suboption (1), DCPBlockLength (2).
pub const DCP_BLOCK_HEADER_LEN: usize = 4;

/// Lit le Frame ID (deux premiers octets de toute trame PROFINET RT) et le
/// classe dans sa plage. Une valeur hors des plages attribuees est
/// `UnknownFrameId`.
pub fn validate_frame_id(data: &[u8]) -> Result<FrameId, ProfinetPacketError> {
    let [high, low, ..] = data else {
        return Err(ProfinetPacketError::FrameTooShort(data.len()));
    };
    let value = u16::from_be_bytes([*high, *low]);
    FrameId::from_u16(value).ok_or(ProfinetPacketError::UnknownFrameId(value))
}

/// Le message porte au moins l'en-tete fixe DCP.
pub fn validate_packet_length(data: &[u8]) -> Result<(), ProfinetPacketError> {
    if data.len() < DCP_HEADER_LEN {
        return Err(ProfinetPacketError::PacketTooShort(data.len()));
    }
    Ok(())
}

/// Les `declared` octets de blocs annonces par DCPDataLength tiennent apres
/// l'en-tete ; rend la tranche des blocs, bourrage Ethernet exclu.
///
/// A appeler apres [`validate_packet_length`].
pub fn extract_dcp_blocks_data(data: &[u8], declared: u16) -> Result<&[u8], ProfinetPacketError> {
    let available = data.len().saturating_sub(DCP_HEADER_LEN);
    let declared_len = usize::from(declared);
    if declared_len > available {
        return Err(ProfinetPacketError::DcpDataOverflow {
            declared,
            available,
        });
    }
    Ok(&data[DCP_HEADER_LEN..DCP_HEADER_LEN + declared_len])
}

/// En-tete d'un bloc : (option, suboption, DCPBlockLength).
pub fn extract_dcp_block_header(block: &[u8]) -> Result<(u8, u8, u16), ProfinetPacketError> {
    let [option, suboption, high, low, ..] = block else {
        return Err(ProfinetPacketError::InvalidDcpBlockLength(block.len()));
    };
    Ok((*option, *suboption, u16::from_be_bytes([*high, *low])))
}

/// Les `declared` octets du bloc tiennent dans ce qui reste apres son
/// en-tete.
pub fn validate_dcp_block_fits(
    option: u8,
    suboption: u8,
    declared: u16,
    available: usize,
) -> Result<(), ProfinetPacketError> {
    if usize::from(declared) > available {
        return Err(ProfinetPacketError::DcpBlockOverflow {
            option,
            suboption,
            declared,
            available,
        });
    }
    Ok(())
}

/// Le bloc porte au moins les `needed` octets de BlockInfo ou de
/// BlockQualifier que son service impose.
pub fn validate_dcp_block_prefix(
    option: u8,
    suboption: u8,
    declared: u16,
    needed: u16,
) -> Result<(), ProfinetPacketError> {
    if declared < needed {
        return Err(ProfinetPacketError::DcpBlockTooShort {
            option,
            suboption,
            declared,
            needed,
        });
    }
    Ok(())
}

/// Le NameOfStation porte par son bloc : de l'UTF-8 (le nom est de l'ASCII),
/// lu jusqu'au premier octet nul comme le fait tshark. Le bloc entier reste
/// dans `DcpBlock::data`.
pub fn extract_name_of_station(data: &[u8]) -> Result<&str, ProfinetPacketError> {
    let end = data
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(data.len());
    std::str::from_utf8(&data[..end]).map_err(|_| ProfinetPacketError::InvalidNameOfStation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_id_needs_two_bytes() {
        assert_eq!(
            validate_frame_id(&[0xfe]),
            Err(ProfinetPacketError::FrameTooShort(1))
        );
        assert_eq!(validate_frame_id(&[0xfe, 0xfe]), Ok(FrameId::IdentifyReq));
        assert_eq!(
            validate_frame_id(&[0x00, 0x00]),
            Err(ProfinetPacketError::UnknownFrameId(0))
        );
    }

    #[test]
    fn blocks_data_is_bounded_by_the_declared_length() {
        let mut data = vec![0u8; DCP_HEADER_LEN];
        data.extend_from_slice(&[1, 2, 3, 4]);
        assert_eq!(extract_dcp_blocks_data(&data, 4), Ok(&[1u8, 2, 3, 4][..]));
        assert_eq!(extract_dcp_blocks_data(&data, 2), Ok(&[1u8, 2][..]));
        assert_eq!(
            extract_dcp_blocks_data(&data, 5),
            Err(ProfinetPacketError::DcpDataOverflow {
                declared: 5,
                available: 4
            })
        );
    }

    #[test]
    fn block_header_and_bounds() {
        assert_eq!(extract_dcp_block_header(&[2, 2, 0, 4, b'p']), Ok((2, 2, 4)));
        assert_eq!(
            extract_dcp_block_header(&[2, 2, 0]),
            Err(ProfinetPacketError::InvalidDcpBlockLength(3))
        );
        assert_eq!(validate_dcp_block_fits(2, 2, 4, 4), Ok(()));
        assert_eq!(
            validate_dcp_block_fits(2, 2, 4, 3),
            Err(ProfinetPacketError::DcpBlockOverflow {
                option: 2,
                suboption: 2,
                declared: 4,
                available: 3
            })
        );
        assert_eq!(
            validate_dcp_block_prefix(1, 2, 1, 2),
            Err(ProfinetPacketError::DcpBlockTooShort {
                option: 1,
                suboption: 2,
                declared: 1,
                needed: 2
            })
        );
    }

    #[test]
    fn name_of_station_must_be_utf8() {
        assert_eq!(extract_name_of_station(b"plc1"), Ok("plc1"));
        // Jusqu'au premier octet nul, comme tshark : un bloc bourre de zeros
        // (ou une chaine d'attaque suivie de zeros) donne le nom seul.
        assert_eq!(extract_name_of_station(b"%n%n%n \0\0\0"), Ok("%n%n%n "));
        assert_eq!(
            extract_name_of_station(&[0xc0, 0xa8]),
            Err(ProfinetPacketError::InvalidNameOfStation)
        );
    }
}
