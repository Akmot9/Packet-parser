use crate::errors::application::bitcoin::BitcoinPacketError;

const VALID_MAGIC_NUMBERS: [u32; 5] = [
    0xD9B4BEF9, // Mainnet
    0x0709110B, // Testnet
    0x0B110907, // Testnet3
    0xFABFB5DA, // Regtest
    0x40CF030A, // Signet
];

const MINIMUM_LENGTH: usize = 24;

/// Vérifie si le payload respecte la taille minimale requise.
pub fn validate_payload_length(payload: &[u8]) -> Result<(), BitcoinPacketError> {
    if payload.len() < MINIMUM_LENGTH {
        Err(BitcoinPacketError::PayloadTooShort(payload.len()))
    } else {
        Ok(())
    }
}

/// Vérifie si le magic number est valide.
pub fn validate_magic_number(payload: &[u8]) -> Result<u32, BitcoinPacketError> {
    let magic = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    if VALID_MAGIC_NUMBERS.contains(&magic) {
        Ok(magic)
    } else {
        Err(BitcoinPacketError::InvalidMagicNumber(magic))
    }
}

/// Extrait la commande et vérifie qu'elle est valide.
pub fn extract_and_validate_command(payload: &[u8]) -> Result<String, BitcoinPacketError> {
    let command_bytes = &payload[4..16];
    let command_string = String::from_utf8(command_bytes.to_vec())?;
    let command_trimmed = command_string.trim_end_matches('\0').to_string();

    if command_trimmed.chars().all(|c| c.is_ascii_alphanumeric()) {
        Ok(command_trimmed)
    } else {
        Err(BitcoinPacketError::InvalidCommand(command_trimmed))
    }
}

/// Extrait la longueur du payload à partir du header.
pub fn extract_length(payload: &[u8]) -> u32 {
    u32::from_le_bytes([payload[16], payload[17], payload[18], payload[19]])
}

/// Extrait le checksum du header.
pub fn extract_checksum(payload: &[u8]) -> [u8; 4] {
    [payload[20], payload[21], payload[22], payload[23]]
}

/// Vérifie que la longueur du payload correspond à la longueur indiquée.
pub fn validate_payload_consistency(
    payload: &[u8],
    expected_length: u32,
) -> Result<(), BitcoinPacketError> {
    let actual_length = payload[24..].len();
    if actual_length != expected_length as usize {
        Err(BitcoinPacketError::LengthMismatch {
            expected: expected_length,
            found: actual_length,
        })
    } else {
        Ok(())
    }
}
