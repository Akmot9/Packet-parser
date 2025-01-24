use crate::{
    checks::application::ntp::*, 
    errors::application::ntp::NtpPacketParseError};

/// # NTP Packet Parser
///
/// This module provides a way to determine whether a raw network packet is an
/// NTP packet and extract relevant fields.
///
/// ## Reference
/// - RFC 5905: [Network Time Protocol Version 4](https://datatracker.ietf.org/doc/html/rfc5905)
///
/// ## Overview
///
/// The parser verifies if a given raw network packet conforms to the **NTP packet format**.
/// If the packet meets the expected structure and validation rules, it is parsed into an
/// `NtpPacket` struct. Otherwise, an `NtpPacketParseError` is returned, detailing why
/// the packet is not considered a valid NTP packet.
///
/// ## Return Values
///
/// - ✅ **Valid NTP Packet** → Returns an instance of [`NtpPacket`].
/// - ❌ **Invalid Packet** → Returns an [`NtpPacketParseError`] explaining the validation failure.
///
/// ## NTP Packet Structure
///
/// The following table describes the structure of an NTP packet:
///
/// | Field                  | Size (bytes) | Description |
/// |------------------------|-------------|-------------|
/// | `flags`                | 1           | Contains LI, Version, and Mode (first byte). |
/// | `stratum`              | 1           | Stratum level of the local clock. |
/// | `poll`                 | 1           | Maximum interval between successive messages. |
/// | `precision`            | 1           | Precision of the local clock. |
/// | `root_delay`           | 4           | Total round-trip delay to the primary reference source. |
/// | `root_dispersion`      | 4           | Nominal error relative to the primary reference source. |
/// | `reference_id`         | 4           | Reference identifier depending on the stratum level. |
/// | `reference_timestamp`  | 8           | Time at which the local clock was last set or corrected. |
/// | `originate_timestamp`  | 8           | Time at which the request departed the client for the server. |
/// | `receive_timestamp`    | 8           | Time at which the request arrived at the server. |
/// | `transmit_timestamp`   | 8           | Time at which the reply departed the server for the client. |
///
/// ## Validation Process
///
/// 1. The packet must be at least **48 bytes** long.
/// 2. The **Version Number (VN)** in the first byte must be between `0` and `4`.
/// 3. The **Mode field** (first byte) must be in `[1, 2, 3, 4, 5]` (Client, Server, Broadcast, etc.).
/// 4. The **Stratum field** must be between `0` and `15` for valid servers.
/// 5. The **Timestamps** must be logically consistent.
///
/// If any of these conditions are not met, an `NtpPacketParseError` is returned.
///
/// ## Usage
///
/// ```rust
/// use ntp_parser::NtpPacket;
///
/// let packet: &[u8] = &[
///     0x3B, 0x00, 0x00, 0x00, // LI, Version, Mode | Stratum | Poll | Precision
///     0x00, 0x00, 0x00, 0x00, // Root Delay
///     0x00, 0x00, 0x00, 0x00, // Root Dispersion
///     0x00, 0x00, 0x00, 0x00, // Reference ID
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reference Timestamp
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Originate Timestamp
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Receive Timestamp
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // Transmit Timestamp
/// ];
///
/// match NtpPacket::from_bytes(&packet) {
///     Ok(ntp) => println!("Parsed NTP Packet: {:?}", ntp),
///     Err(e) => println!("Invalid NTP packet: {:?}", e),
/// }
/// ```
///
/// ## Error Handling
///
/// The `NtpPacketParseError` provides an explanation of why a packet was rejected.
/// Possible errors include:
///
/// - **`InvalidSize`** → The packet is too short.
/// - **`InvalidVersion`** → The NTP version is out of range.
/// - **`InvalidMode`** → The mode is not recognized.
/// - **`InvalidStratum`** → The stratum field contains an invalid value.
/// - **`InvalidTimestamps`** → The timestamps are inconsistent.
///
/// These errors help diagnose malformed or unexpected packets.

/// The `NtpPacket` struct represents a parsed NTP packet.
#[derive(Debug)]
pub struct NtpPacket {
    /// The first byte containing LI, Version, and Mode.
    pub flags: (u8, u8, u8),
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
        // Check if payload has the minimum length required for an NTP packet
        validate_ntp_packet_length(payload)?;
        //
        let flags: (u8, u8, u8) = extract_flags(payload)?;
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
            flags,
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
    use crate::parse::application::NtpPacket;
    use crate::errors::application::ntp::NtpPacketParseError;
    use crate::parse::application::protocols::ntp::*;
    #[test]
    fn test_valid_ntp_packet() {
        let payload = vec![
            0x1B, 0x00, 0x04, 0xFA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4E, 0x49,
            0x4E, 0x00, 0xDC, 0xC0, 0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0, 0x00, 0x00,
            0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0, 0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0,
            0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71,
        ];
        let result = NtpPacket::try_from(payload.as_slice()).expect("Expected a valid NTP packet");

        assert_eq!(result.flags, (0, 3, 3));
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
        assert!(matches!(
            result,
            Err(NtpPacketParseError::InvalidPacketLength)
        ));
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
        assert!(matches!(result, Err(NtpPacketParseError::InvalidVersion { .. })));
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
        assert!(matches!(result, Err(NtpPacketParseError::InvalidMode { .. })));
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
