use crate::{errors::application::ntp::NtpPacketParseError, 
    protocols::application::ntp::*};

/// The `NtpPacket` struct represents a parsed NTP packet.
#[derive(Debug)]
pub struct NtpPacket {
    /// The first byte containing LI, Version, et Mode.
    pub li_vn_mode: u8,
    /// The stratum level of the local clock.
    pub stratum: u8,
    /// The maximum interval between successive messages.
    pub poll: u8,
    /// The precision of the local clock.
    pub precision: i8,
    /// The total round-trip delay to the primary reference source.
    pub root_delay: u32,
    /// The nominal error relative to the primary reference source.
    pub root_dispersion: u32,
    /// The reference identifier depending on the stratum level.
    pub reference_id: u32,
    /// The time at which the local clock was last set or corrected.
    pub reference_timestamp: u64,
    /// The time at which the request departed the client for the server.
    pub originate_timestamp: u64,
    /// The time at which the request arrived at the server.
    pub receive_timestamp: u64,
    /// The time at which the reply departed the server for the client.
    pub transmit_timestamp: u64,
}

/// Checks if the first byte is consistent with an NTP packet
fn check_ntp_packet(payload: &[u8]) -> Result<(), bool> {
    if payload.len() < 48 {
        return Err(false);
    }

    // Extract the first byte
    let li_vn_mode = payload[0];

    // Extract the version (bits 3-5)
    let version = (li_vn_mode >> 3) & 0x07;

    // Extract the mode (bits 6-8)
    let mode = li_vn_mode & 0x07;

    // Check if version is between 1 and 4
    if !(1..=4).contains(&version) {
        return Err(false);
    }

    // Check if mode is between 1 and 5
    if !(1..=5).contains(&mode) {
        return Err(false);
    }

    Ok(())
}

fn check_stratum(stratum: u8) -> Result<(), bool> {
    if stratum > 15 {
        return Err(false);
    }
    Ok(())
}

fn check_poll(poll: u8) -> Result<(), bool> {
    if poll > 17 {
        return Err(false);
    }
    Ok(())
}

fn check_root_delay_dispersion(_root_delay: u32, _root_dispersion: u32) -> Result<(), bool> {
    // These checks are removed because u32 cannot exceed its own bounds
    Ok(())
}

impl TryFrom<&[u8]> for NtpPacket {
    type Error = NtpPacketParseError;

    fn try_from(payload: &[u8]) -> Result<Self, Self::Error> {
        validate_ntp_packet(payload)?;

        let li_vn_mode = extract_li_vn_mode(payload)?;
        let stratum = extract_stratum(payload)?;
        let poll = extract_poll(payload)?;
        let precision = extract_precision(payload)?;
        let root_delay = extract_root_delay(payload)?;
        let root_dispersion = extract_root_dispersion(payload)?;
        let reference_id = extract_reference_id(payload)?;
        let reference_timestamp = extract_reference_timestamp(payload)?;
        let originate_timestamp = extract_originate_timestamp(payload)?;
        let receive_timestamp = extract_receive_timestamp(payload)?;
        let transmit_timestamp = extract_transmit_timestamp(payload)?;

        Ok(NtpPacket {
            li_vn_mode,
            stratum,
            poll,
            precision,
            root_delay,
            root_dispersion,
            reference_id,
            reference_timestamp,
            originate_timestamp,
            receive_timestamp,
            transmit_timestamp,
        })
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_valid_ntp_packet() {
        let payload = vec![
            0x1B, 0x00, 0x04, 0xFA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4E, 0x49,
            0x4E, 0x00, 0xDC, 0xC0, 0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0, 0x00, 0x00,
            0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0, 0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0,
            0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71,
        ];
        let result = NtpPacket::try_from(payload.as_slice()).expect("Expected a valid NTP packet");

        assert_eq!(result.li_vn_mode, 0x1B);
        assert_eq!(result.stratum, 0x00);
        assert_eq!(result.poll, 0x04);
        assert_eq!(result.precision, -6);
        assert_eq!(result.root_delay, 0x00000000);
        assert_eq!(result.root_dispersion, 0x00000000);
        assert_eq!(result.reference_id, 0x4E494E00);
        assert_eq!(result.reference_timestamp, 0xDCC00000E144C671);
        assert_eq!(result.originate_timestamp, 0xDCC00000E144C671);
        assert_eq!(result.receive_timestamp, 0xDCC00000E144C671);
        assert_eq!(result.transmit_timestamp, 0xDCC00000E144C671);
    }
    #[test]
    fn test_invalid_ntp_packet_length() {
        let short_payload = vec![0x1B, 0x00, 0x04];
        let result = NtpPacket::try_from(short_payload.as_slice());
        assert!(matches!(result, Err(NtpPacketParseError::InvalidPacketLength)));
    }

    #[test]
    fn test_invalid_ntp_version() {
        let invalid_version_payload = vec![
            0x7B, 0x00, 0x04, 0xFA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4E, 0x49,
            0x4E, 0x00, 0xDC, 0xC0, 0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0, 0x00, 0x00,
            0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0, 0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0,
            0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71,
        ];
        let result = NtpPacket::try_from(invalid_version_payload.as_slice());
        assert!(matches!(result, Err(NtpPacketParseError::InvalidVersion)));
    }

    #[test]
    fn test_invalid_ntp_mode() {
        let invalid_mode_payload = vec![
            0x18, 0x00, 0x04, 0xFA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4E, 0x49,
            0x4E, 0x00, 0xDC, 0xC0, 0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0, 0x00, 0x00,
            0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0, 0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0,
            0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71,
        ];
        let result = NtpPacket::try_from(invalid_mode_payload.as_slice());
        assert!(matches!(result, Err(NtpPacketParseError::InvalidMode)));
    }

    #[test]
    fn test_check_ntp_packet() {
        // Valid NTP packet
        let valid_ntp_packet = vec![
            0x1B, 0x00, 0x04, 0xFA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4E, 0x49,
            0x4E, 0x00, 0xDC, 0xC0, 0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0, 0x00, 0x00,
            0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0, 0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0,
            0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71,
        ];
        assert!(check_ntp_packet(&valid_ntp_packet).is_ok());

        // Invalid NTP packet (short length)
        let short_ntp_packet = vec![0x1B, 0x00, 0x04];
        assert!(check_ntp_packet(&short_ntp_packet).is_err());

        // Invalid NTP packet (invalid version)
        let invalid_version_packet = vec![
            0x7B, 0x00, 0x04, 0xFA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4E, 0x49,
            0x4E, 0x00, 0xDC, 0xC0, 0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0, 0x00, 0x00,
            0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0, 0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0,
            0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71,
        ];
        assert!(check_ntp_packet(&invalid_version_packet).is_err());

        // Invalid NTP packet (invalid mode)
        let invalid_mode_packet = vec![
            0x18, 0x00, 0x04, 0xFA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4E, 0x49,
            0x4E, 0x00, 0xDC, 0xC0, 0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0, 0x00, 0x00,
            0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0, 0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0,
            0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71,
        ];
        assert!(check_ntp_packet(&invalid_mode_packet).is_err());
    }
}
