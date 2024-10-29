use crate::errors::parse::ParsedPacketError;

pub fn validate_packet_length(packets: &[u8]) -> Result<(), ParsedPacketError> {
    if packets.len() < 14 {
        return Err(ParsedPacketError::PacketTooShort(packets.len() as u8));
    }
    Ok(())
}

// Exemple pour une autre validation
pub fn validate_data_link(data_link: &[u8]) -> Result<(), ParsedPacketError> {
    if data_link.is_empty() {
        return Err(ParsedPacketError::InvalidDataLink);
    }
    Ok(())
}