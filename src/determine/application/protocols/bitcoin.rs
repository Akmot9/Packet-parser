use std::convert::TryFrom;

use crate::utils::application::bitcoin::{
    extract_and_validate_command, extract_checksum, extract_length, validate_magic_number,
    validate_payload_consistency, validate_payload_length,
};

use crate::errors::application::bitcoin::BitcoinPacketError;

#[derive(Debug)]
pub struct BitcoinPacket {
    pub magic: u32,
    pub command: String,
    pub length: u32,
    pub checksum: [u8; 4],
    pub payload: Vec<u8>,
}

impl TryFrom<&[u8]> for BitcoinPacket {
    type Error = BitcoinPacketError;

    fn try_from(payload: &[u8]) -> Result<Self, Self::Error> {
        validate_payload_length(payload)?;

        let magic = validate_magic_number(payload)?;
        let command = extract_and_validate_command(payload)?;
        let length = extract_length(payload);
        let checksum = extract_checksum(payload);

        let actual_payload = payload[24..].to_vec();
        validate_payload_consistency(payload, length)?;

        Ok(BitcoinPacket {
            magic,
            command,
            length,
            checksum,
            payload: actual_payload,
        })
    }
}
