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

/// Parses an NTP packet from a given payload.
///
/// # Arguments
///
/// * `payload` - A byte slice representing the raw NTP packet data.
///
/// # Returns
///
/// * `Result<NtpPacket, bool>` - Returns `Ok(NtpPacket)` if parsing is successful,
///   otherwise returns `Err(false)` indicating an invalid NTP packet.
pub fn parse_ntp_packet(payload: &[u8]) -> Result<NtpPacket, bool> {
    check_ntp_packet(payload)?;

    let li_vn_mode = payload[0];
    let stratum = payload[1];
    let poll = payload[2];
    let precision = payload[3] as i8;
    let root_delay = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let root_dispersion = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
    let reference_id = u32::from_be_bytes([payload[12], payload[13], payload[14], payload[15]]);
    let reference_timestamp = u64::from_be_bytes([
        payload[16],
        payload[17],
        payload[18],
        payload[19],
        payload[20],
        payload[21],
        payload[22],
        payload[23],
    ]);
    let originate_timestamp = u64::from_be_bytes([
        payload[24],
        payload[25],
        payload[26],
        payload[27],
        payload[28],
        payload[29],
        payload[30],
        payload[31],
    ]);
    let receive_timestamp = u64::from_be_bytes([
        payload[32],
        payload[33],
        payload[34],
        payload[35],
        payload[36],
        payload[37],
        payload[38],
        payload[39],
    ]);
    let transmit_timestamp = u64::from_be_bytes([
        payload[40],
        payload[41],
        payload[42],
        payload[43],
        payload[44],
        payload[45],
        payload[46],
        payload[47],
    ]);

    check_stratum(stratum)?;
    check_poll(poll)?;
    check_root_delay_dispersion(root_delay, root_dispersion)?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ntp_packet() {
        // Test with a valid NTP packet
        let ntp_payload = vec![
            0x1B, 0x00, 0x04, 0xFA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4E, 0x49,
            0x4E, 0x00, 0xDC, 0xC0, 0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0, 0x00, 0x00,
            0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0, 0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0,
            0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71,
        ];
        match parse_ntp_packet(&ntp_payload) {
            Ok(packet) => {
                assert_eq!(packet.li_vn_mode, 0x1B);
                assert_eq!(packet.stratum, 0x00);
                assert_eq!(packet.poll, 0x04);
                assert_eq!(packet.precision, -6);
                assert_eq!(packet.root_delay, 0x00000000);
                assert_eq!(packet.root_dispersion, 0x00000000);
                assert_eq!(packet.reference_id, 0x4E494E00);
                assert_eq!(packet.reference_timestamp, 0xDCC00000E144C671);
                assert_eq!(packet.originate_timestamp, 0xDCC00000E144C671);
                assert_eq!(packet.receive_timestamp, 0xDCC00000E144C671);
                assert_eq!(packet.transmit_timestamp, 0xDCC00000E144C671);
            }
            Err(_) => panic!("Expected NTP packet"),
        }

        // Test with an invalid NTP packet (too short)
        let short_payload = vec![0x1B, 0x00, 0x04];
        match parse_ntp_packet(&short_payload) {
            Ok(_) => panic!("Expected non-NTP packet due to short payload"),
            Err(is_ntp) => assert!(!is_ntp),
        }

        // Test with an invalid NTP packet (invalid version)
        let invalid_version_payload = vec![
            0x7B, 0x00, 0x04, 0xFA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4E, 0x49,
            0x4E, 0x00, 0xDC, 0xC0, 0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0, 0x00, 0x00,
            0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0, 0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0,
            0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71,
        ];
        match parse_ntp_packet(&invalid_version_payload) {
            Ok(_) => panic!("Expected non-NTP packet due to invalid version"),
            Err(is_ntp) => assert!(!is_ntp),
        }

        // Test with an invalid NTP packet (invalid mode)
        let invalid_mode_payload = vec![
            0x18, 0x00, 0x04, 0xFA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4E, 0x49,
            0x4E, 0x00, 0xDC, 0xC0, 0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0, 0x00, 0x00,
            0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0, 0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0,
            0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71,
        ];
        match parse_ntp_packet(&invalid_mode_payload) {
            Ok(_) => panic!("Expected non-NTP packet due to invalid mode"),
            Err(is_ntp) => assert!(!is_ntp),
        }
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
