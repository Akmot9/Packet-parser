use crate::errors::ParsedPacketError;
pub mod application;
pub fn validate_packet_length(packets: &[u8]) -> Result<(), ParsedPacketError> {
    if packets.len() < 14 {
        return Err(ParsedPacketError::PacketTooShort(packets.len() as u8));
    }
    Ok(())
}