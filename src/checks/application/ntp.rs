use crate::errors::application::ntp::NtpPacketParseError;

/// ## NTP Validation Process
///
/// 1. The NTP packet must be at least **48 bytes** long.
/// 2. The **Version Number (VN)** in the first byte must be between `0` and `4`.
/// 3. The **Mode field** (first byte) must be in `[1, 2, 3, 4, 5]` (Client, Server, Broadcast, etc.).
/// 4. The **Stratum field** must be between `0` and `15` for valid servers.
/// 5. The **Timestamps** must be logically consistent.

const MINIMUM_NTP_PACKET_LENGTH: usize = 48;
pub fn validate_ntp_packet_length(payload: &[u8]) -> Result<(), NtpPacketParseError> {
    if payload.len() < MINIMUM_NTP_PACKET_LENGTH {
        return Err(NtpPacketParseError::InvalidPacketLength);
    }
    Ok(())
}

pub fn extract_flags(payload: &[u8]) -> Result<(u8, u8, u8), NtpPacketParseError> {
    // check the ntp flag coherence in the first byte then retun the flags if it is valid
    let li_vn_mode = payload[0];

    // Extract the version (bits 3-5)
    let version = (li_vn_mode >> 3) & 0x07;

    // Extract the mode (bits 6-8)
    let mode = li_vn_mode & 0x07;

    // Check if version is between 1 and 4
    if !version.is_between(1, 4) {
        return Err(NtpPacketParseError::InvalidVersion { version });
    }

    // Check if mode is between 1 and 5
    if !mode.is_between(1, 5) {
        return Err(NtpPacketParseError::InvalidMode { mode } );
    }

    // Extract Leap Indicator (LI)
    let li = (li_vn_mode >> 6) & 0b11;

    Ok((li, version, mode))
}

trait RangeExt<T> {
    fn is_between(self, min: T, max: T) -> bool
    where
        T: PartialOrd<T>;
}

impl<T> RangeExt<T> for T {
    fn is_between(self, min: T, max: T) -> bool
    where
        T: PartialOrd<T>,
    {
        self >= min && self <= max
    }
}

pub fn extract_stratum(payload: &[u8]) -> Result<u8, NtpPacketParseError> {
    let stratum = payload[1];
    if stratum > 15 {
        Err(NtpPacketParseError::InvalidStratum)
    } else {
        Ok(stratum)
    }
}

pub fn extract_poll(payload: &[u8]) -> Result<u8, NtpPacketParseError> {
    let poll = payload[2];
    if poll > 127 {
        Err(NtpPacketParseError::InvalidPoll)
    } else {
        Ok(poll)
    }
}

pub fn extract_precision(payload: &[u8]) -> Result<i8, NtpPacketParseError> {
    Ok(payload[3] as i8)
}

pub fn extract_root_delay(payload: &[u8]) -> Result<u32, NtpPacketParseError> {
    Ok(u32::from_be_bytes([
        payload[4], payload[5], payload[6], payload[7],
    ]))
}

pub fn extract_root_dispersion(payload: &[u8]) -> Result<u32, NtpPacketParseError> {
    Ok(u32::from_be_bytes([
        payload[8],
        payload[9],
        payload[10],
        payload[11],
    ]))
}

pub fn extract_reference_id(payload: &[u8]) -> Result<u32, NtpPacketParseError> {
    Ok(u32::from_be_bytes([
        payload[12],
        payload[13],
        payload[14],
        payload[15],
    ]))
}

pub fn extract_reference_timestamp(payload: &[u8]) -> Result<u64, NtpPacketParseError> {
    Ok(u64::from_be_bytes([
        payload[16],
        payload[17],
        payload[18],
        payload[19],
        payload[20],
        payload[21],
        payload[22],
        payload[23],
    ]))
}

pub fn extract_originate_timestamp(payload: &[u8]) -> Result<u64, NtpPacketParseError> {
    Ok(u64::from_be_bytes([
        payload[24],
        payload[25],
        payload[26],
        payload[27],
        payload[28],
        payload[29],
        payload[30],
        payload[31],
    ]))
}

pub fn extract_receive_timestamp(payload: &[u8]) -> Result<u64, NtpPacketParseError> {
    Ok(u64::from_be_bytes([
        payload[32],
        payload[33],
        payload[34],
        payload[35],
        payload[36],
        payload[37],
        payload[38],
        payload[39],
    ]))
}

pub fn extract_transmit_timestamp(payload: &[u8]) -> Result<u64, NtpPacketParseError> {
    Ok(u64::from_be_bytes([
        payload[40],
        payload[41],
        payload[42],
        payload[43],
        payload[44],
        payload[45],
        payload[46],
        payload[47],
    ]))
}
