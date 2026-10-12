// Copyright (c) 2024 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use std::net::Ipv4Addr;

use chrono::{DateTime, TimeZone, Utc};

use crate::{
    errors::application::ntp::NtpPacketParseError, parse::application::protocols::ntp::Refid,
};

const MINIMUM_NTP_PACKET_LENGTH: usize = 48;

/// ## NTP Validation Process
///
/// 1. The NTP packet must be at least **48 bytes** long.
/// 2. The **Version Number (VN)** in the first byte must be between `0` and `4`.
/// 3. The **Mode field** (first byte) must be in `[1, 2, 3, 4, 5]` (Client, Server, Broadcast, etc.).
/// 4. The **Stratum field** must be between `0` and `15` for valid servers.
/// 5. The **Receive** and **Transmit** timestamps, both taken on the sender's
///    clock, must be in order; the Originate timestamp is the client's clock
///    and is never compared (#161).
pub fn validate_ntp_packet_length(payload: &[u8]) -> Result<(), NtpPacketParseError> {
    if payload.len() < MINIMUM_NTP_PACKET_LENGTH {
        return Err(NtpPacketParseError::InvalidPacketLength);
    }
    Ok(())
}

pub fn extract_flags(li_vn_mode: &u8) -> Result<(u8, u8, u8), NtpPacketParseError> {
    // check the ntp flag coherence in the first byte then retun the flags if it is valid

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
        return Err(NtpPacketParseError::InvalidMode { mode });
    }

    // Extract Leap Indicator (LI)
    let li = (li_vn_mode >> 6) & 0b11;

    Ok((li, version, mode))
}

trait RangeExt<T> {
    fn is_between(&self, min: T, max: T) -> bool
    where
        T: PartialOrd<T>;
}

impl<T> RangeExt<T> for T {
    fn is_between(&self, min: T, max: T) -> bool
    where
        T: PartialOrd<T>,
    {
        *self >= min && *self <= max
    }
}

pub fn extract_stratum(stratum: &u8) -> Result<u8, NtpPacketParseError> {
    if *stratum > 15 {
        Err(NtpPacketParseError::InvalidStratum)
    } else {
        Ok(*stratum)
    }
}

pub fn extract_poll(poll: &u8) -> Result<u8, NtpPacketParseError> {
    if *poll > 127 {
        Err(NtpPacketParseError::InvalidPoll)
    } else {
        Ok(*poll)
    }
}

pub fn extract_precision(payload: &u8) -> Result<i8, NtpPacketParseError> {
    Ok(*payload as i8)
}

pub fn extract_root_delay(payload: &[u8]) -> Result<u32, NtpPacketParseError> {
    if payload.len() < 4 {
        return Err(NtpPacketParseError::InvalidPacketLength);
    }
    Ok(u32::from_be_bytes([
        payload[0], payload[1], payload[2], payload[3],
    ]))
}

pub fn extract_root_dispersion(payload: &[u8]) -> Result<u32, NtpPacketParseError> {
    if payload.len() < 4 {
        return Err(NtpPacketParseError::InvalidPacketLength);
    }
    Ok(u32::from_be_bytes([
        payload[0], payload[1], payload[2], payload[3],
    ]))
}

/// Returns the ASCII reference code held in a 4-byte NTP reference id,
/// trimmed of its trailing NUL/space padding.
///
/// Returns `None` if the non-padding bytes are not printable ASCII, without
/// allocating: the returned `&str` borrows from the input bytes.
pub fn reference_code_str(bytes: &[u8; 4]) -> Option<&str> {
    let end = bytes
        .iter()
        .rposition(|&b| b != 0 && b != b' ')
        .map_or(0, |i| i + 1);
    let trimmed = &bytes[..end];

    if !trimmed.iter().all(|b| b.is_ascii_graphic()) {
        return None;
    }

    std::str::from_utf8(trimmed).ok()
}

/// Extrait le Reference ID d’un paquet NTP en vérifiant le Stratum.
pub fn extract_reference_id(stratum: u8, payload: &[u8]) -> Result<Refid, NtpPacketParseError> {
    if payload.len() < 4 {
        return Err(NtpPacketParseError::InvalidReferenceIdForHigherStratum);
    }

    let ref_id_bytes = [payload[0], payload[1], payload[2], payload[3]];

    match stratum {
        0 => {
            // Stratum 0 may carry an all-zero ("NULL") reference id.
            if ref_id_bytes == [0u8; 4] {
                return Ok(Refid::KissCode(ref_id_bytes));
            }
            match reference_code_str(&ref_id_bytes) {
                Some(code) if KISS_CODES.contains(&code) => Ok(Refid::KissCode(ref_id_bytes)),
                _ => Err(NtpPacketParseError::InvalidReferenceIdForStratum0),
            }
        }
        // RFC 5905 §7.3 : quatre octets ASCII justifies a gauche et completes
        // de zeros, dont la liste, tenue par l'IANA, depasse l'extrait de la
        // RFC (GOES, GPS, GAL, PPS...) : ntpd emet aussi SHM, NMEA, LOCL...
        // Tout code imprimable non vide est accepte (#162).
        1 => match reference_code_str(&ref_id_bytes) {
            Some(code) if !code.is_empty() => Ok(Refid::ClockSource(ref_id_bytes)),
            _ => Err(NtpPacketParseError::InvalidReferenceIdForStratum1),
        },
        2..=15 => {
            let ip = Ipv4Addr::new(
                ref_id_bytes[0],
                ref_id_bytes[1],
                ref_id_bytes[2],
                ref_id_bytes[3],
            );
            if ip.is_unspecified() || ip.is_multicast() {
                Err(NtpPacketParseError::InvalidReferenceIdForHigherStratum)
            } else {
                Ok(Refid::Ipv4(ip))
            }
        }
        _ => Err(NtpPacketParseError::InvalidReferenceIdForHigherStratum),
    }
}

/// Liste des Kiss Codes valides
const KISS_CODES: &[&str] = &[
    "ACST", "AUTH", "AUTO", "BCST", "CRYP", "DENY", "DROP", "RSTR", "INIT", "MCST", "NKEY", "NTSN",
    "RATE", "RMOT", "STEP",
];

const NTP_TO_UNIX_EPOCH: i64 = 2_208_988_800;

/// Extracts an NTP timestamp (8 bytes) and returns a `DateTime<Utc>`.
pub fn extract_timestamp(payload: &[u8]) -> Result<DateTime<Utc>, NtpPacketParseError> {
    validate_timestamp_size(payload)?;

    // Extraction des 4 premiers octets pour obtenir les secondes NTP.
    let ntp_seconds = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);

    // Extraction des 4 derniers octets pour obtenir la fraction de seconde NTP.
    let ntp_fraction = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);

    // Conversion des secondes NTP en secondes UNIX. Un horodatage entierement
    // nul est « inconnu » (RFC 5905 §6) et rendu 1970-01-01 00:00:00 UTC.
    // Sinon le bit de poids fort choisit l'ere (RFC 4330 §3) : a 1, l'ere 0
    // (1968 a 2036) ; a 0, l'ere 1 (2036 a 2104) — comme tshark (#162).
    let unix_seconds = if ntp_seconds == 0 && ntp_fraction == 0 {
        0
    } else if ntp_seconds & 0x8000_0000 != 0 {
        i64::from(ntp_seconds) - NTP_TO_UNIX_EPOCH
    } else {
        i64::from(ntp_seconds) + (1_i64 << 32) - NTP_TO_UNIX_EPOCH
    };

    // Conversion de la fraction de seconde NTP en nanosecondes.
    let nanos = (((ntp_fraction as u64) * 1_000_000_000) / (1 << 32)) as u32;

    // Construction du `DateTime<Utc>` et validation de la date.
    Utc.timestamp_opt(unix_seconds, nanos).single().ok_or(
        NtpPacketParseError::TimestampConversionError {
            seconds: unix_seconds,
            nanos,
        },
    )
}

fn validate_timestamp_size(payload: &[u8]) -> Result<(), NtpPacketParseError> {
    if payload.len() != 8 {
        return Err(NtpPacketParseError::InvalidTimestampSize {
            received: payload.len(),
        });
    }

    Ok(())
}

/// Un horodatage NTP entierement nul (« unknown », RFC 5905 §6) : la crate
/// le rend comme l'epoque Unix.
pub fn is_null_timestamp(timestamp: DateTime<Utc>) -> bool {
    timestamp.timestamp() == 0 && timestamp.timestamp_subsec_nanos() == 0
}

/// Receive (T2) et Transmit (T3) sont pris sur l'horloge de l'emetteur :
/// T2 <= T3. Originate (T1) est l'horodatage du client, copie tel quel, et
/// Reference la derniere mise a l'heure : ni l'un ni l'autre ne se compare
/// a T2/T3 — un client en avance de quelques millisecondes (ce que NTP sert
/// a corriger) rendait `originate > receive` et faisait rejeter de vraies
/// reponses de serveur (#161). Un horodatage nul vaut « inconnu » et ne se
/// compare pas non plus.
pub fn validate_datetime_ordering(
    receive: DateTime<Utc>,
    transmit: DateTime<Utc>,
) -> Result<(), NtpPacketParseError> {
    if !is_null_timestamp(receive) && !is_null_timestamp(transmit) && receive > transmit {
        return Err(NtpPacketParseError::InconsistentTimestamps);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    #[test]
    fn test_validate_ntp_packet_length() {
        assert!(validate_ntp_packet_length(&[0u8; 48]).is_ok());
        assert!(validate_ntp_packet_length(&[0u8; 60]).is_ok());
        assert!(matches!(
            validate_ntp_packet_length(&[0u8; 47]),
            Err(NtpPacketParseError::InvalidPacketLength)
        ));
        assert!(matches!(
            validate_ntp_packet_length(&[]),
            Err(NtpPacketParseError::InvalidPacketLength)
        ));
    }

    #[test]
    fn test_valid_ordering() {
        let receive = Utc.timestamp_opt(1_700_000_002, 0).unwrap();
        let transmit = Utc.timestamp_opt(1_700_000_003, 0).unwrap();
        assert!(validate_datetime_ordering(receive, transmit).is_ok());
        assert!(validate_datetime_ordering(receive, receive).is_ok());
    }

    #[test]
    fn test_invalid_ordering() {
        // Transmis avant d'etre recu, sur la meme horloge.
        let receive = Utc.timestamp_opt(1_700_000_003, 0).unwrap();
        let transmit = Utc.timestamp_opt(1_700_000_002, 999_999_999).unwrap();
        assert!(matches!(
            validate_datetime_ordering(receive, transmit),
            Err(NtpPacketParseError::InconsistentTimestamps)
        ));
    }

    /// #161 : un horodatage nul est inconnu, pas anterieur a tout.
    #[test]
    fn test_null_timestamps_are_not_ordered() {
        let null = Utc.timestamp_opt(0, 0).unwrap();
        let later = Utc.timestamp_opt(1_700_000_003, 0).unwrap();
        assert!(is_null_timestamp(null));
        assert!(!is_null_timestamp(later));
        assert!(validate_datetime_ordering(later, null).is_ok());
        assert!(validate_datetime_ordering(null, later).is_ok());
        assert!(validate_datetime_ordering(null, null).is_ok());
    }

    #[test]
    fn test_reference_code_str_trims_padding() {
        assert_eq!(reference_code_str(b"GPS "), Some("GPS"));
        assert_eq!(reference_code_str(b"GPS\0"), Some("GPS"));
        assert_eq!(reference_code_str(b"RATE"), Some("RATE"));
        assert_eq!(reference_code_str(&[0, 0, 0, 0]), Some(""));
    }

    #[test]
    fn test_reference_code_str_rejects_non_ascii() {
        assert_eq!(reference_code_str(&[0x80, 0x00, 0x00, 0x00]), None);
        assert_eq!(reference_code_str(&[0xC3, 0xA9, 0xFF, 0xFE]), None);
        // Control characters are not printable ASCII either.
        assert_eq!(reference_code_str(&[0x01, 0x02, 0x03, 0x04]), None);
    }

    #[test]
    fn test_stratum_0_null_reference_id() {
        let result = extract_reference_id(0, &[0, 0, 0, 0]);
        assert_eq!(result, Ok(Refid::KissCode([0, 0, 0, 0])));
    }

    #[test]
    fn test_stratum_0_valid_kiss_code() {
        let result = extract_reference_id(0, b"RATE");
        assert_eq!(result, Ok(Refid::KissCode(*b"RATE")));
        assert_eq!(result.unwrap().code(), Some("RATE"));
    }

    #[test]
    fn test_stratum_1_valid_ascii() {
        let stratum = 1;
        let payload = b"GPS ";
        let result = extract_reference_id(stratum, payload);
        assert_eq!(result, Ok(Refid::ClockSource(*b"GPS ")));
        assert_eq!(result.unwrap().code(), Some("GPS"));
    }

    /// #162 : `SHM` (pilote memoire partagee de ntpd) n'est pas dans la
    /// RFC 5905, et pourtant stratum 1 ; un identifiant nul ou non justifie
    /// a gauche n'est pas un code.
    #[test]
    fn test_stratum_1_accepts_any_printable_code() {
        assert_eq!(
            extract_reference_id(1, b"SHM\0"),
            Ok(Refid::ClockSource(*b"SHM\0"))
        );
        assert_eq!(
            extract_reference_id(1, b"XGPS").unwrap().code(),
            Some("XGPS")
        );
        for bytes in [[0u8; 4], *b"G PS", *b" GPS"] {
            assert!(matches!(
                extract_reference_id(1, &bytes),
                Err(NtpPacketParseError::InvalidReferenceIdForStratum1)
            ));
        }
    }

    #[test]
    fn test_stratum_1_invalid_ascii() {
        let stratum = 1;
        let payload = [0x80, 0x00, 0x00, 0x00]; // Valeur non ASCII
        let result = extract_reference_id(stratum, &payload);
        assert!(matches!(
            result,
            Err(NtpPacketParseError::InvalidReferenceIdForStratum1)
        ));
    }

    #[test]
    fn test_stratum_0_non_ascii() {
        let payload = [0xC3, 0xA9, 0xFF, 0xFE]; // Non-ASCII reference id
        let result = extract_reference_id(0, &payload);
        assert!(matches!(
            result,
            Err(NtpPacketParseError::InvalidReferenceIdForStratum0)
        ));
    }

    #[test]
    fn test_stratum_2_valid_ipv4() {
        let stratum = 2;
        let payload = [8, 8, 8, 8]; // Adresse IPv4 valide (Google DNS)
        let result = extract_reference_id(stratum, &payload);
        assert_eq!(result, Ok(Refid::Ipv4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn test_stratum_2_invalid_ipv4() {
        let stratum = 2;
        let payload = [224, 0, 0, 1]; // Adresse multicast (invalide en NTP)
        let result = extract_reference_id(stratum, &payload);
        assert!(matches!(
            result,
            Err(NtpPacketParseError::InvalidReferenceIdForHigherStratum)
        ));
    }

    #[test]
    fn test_stratum_0_invalid() {
        let stratum = 0;
        let payload = [192, 168, 1, 1];
        let result = extract_reference_id(stratum, &payload);
        assert!(matches!(
            result,
            Err(NtpPacketParseError::InvalidReferenceIdForStratum0)
        ));
    }

    #[test]
    fn test_extract_reference_id_too_short() {
        let result = extract_reference_id(2, &[8, 8]);
        assert!(matches!(
            result,
            Err(NtpPacketParseError::InvalidReferenceIdForHigherStratum)
        ));
    }

    #[test]
    fn test_extract_timestamp_zero_is_unix_epoch() {
        let payload = [0u8; 8];
        let result = extract_timestamp(&payload).expect("zero timestamp must be valid");
        assert_eq!(result, Utc.timestamp_opt(0, 0).unwrap());
    }

    #[test]
    fn test_extract_timestamp_valid() {
        // NTP seconds for 2004-09-27T03:18:04Z (0xC50204EC).
        let payload = [0xC5, 0x02, 0x04, 0xEC, 0x00, 0x00, 0x00, 0x00];
        let result = extract_timestamp(&payload).expect("valid timestamp");
        assert_eq!(result.timestamp(), 0xC50204ECu32 as i64 - 2_208_988_800);
    }

    /// #162 : bit de poids fort a 0, ere 1 (RFC 4330 §3) — la requete du
    /// client Java de iec104/iti_JavaRMI_and_IEC_Misc.pcap, 37 s apres le
    /// 7 fevrier 2036 06:28:16 UTC, comme tshark la montre.
    #[test]
    fn test_extract_timestamp_era_1() {
        let payload = [0x00, 0x00, 0x00, 0x25, 0x00, 0x00, 0x00, 0x00];
        let result = extract_timestamp(&payload).expect("ere 1");
        assert_eq!(result, Utc.with_ymd_and_hms(2036, 2, 7, 6, 28, 53).unwrap());
        // La fin de l'ere 0 reste dans l'ere 0.
        let payload = [0xFF, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00];
        let result = extract_timestamp(&payload).expect("fin de l'ere 0");
        assert_eq!(result.timestamp(), 0xFFFF_FFFF_u32 as i64 - 2_208_988_800);
        assert_eq!(result.timestamp_subsec_nanos(), 500_000_000);
    }

    #[test]
    fn test_extract_timestamp_invalid_size() {
        let payload = [0u8; 4];
        let result = extract_timestamp(&payload);
        assert!(matches!(
            result,
            Err(NtpPacketParseError::InvalidTimestampSize { received: 4 })
        ));
    }

    #[test]
    fn test_extract_root_delay_and_dispersion_too_short() {
        assert!(matches!(
            extract_root_delay(&[0x00, 0x01]),
            Err(NtpPacketParseError::InvalidPacketLength)
        ));
        assert!(matches!(
            extract_root_dispersion(&[0x00]),
            Err(NtpPacketParseError::InvalidPacketLength)
        ));
    }

    #[test]
    fn test_extract_flags_valid() {
        // LI=3, VN=3, Mode=1 → 0b11_011_001 = 0xD9
        assert_eq!(extract_flags(&0xD9), Ok((3, 3, 1)));
    }
}
