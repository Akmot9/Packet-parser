// Copyright (c) 2024 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

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
/// 2. The **Version Number (VN)** in the first byte must be between `1` and `4`.
/// 3. The **Mode field** (first byte) must be in `[1, 2, 3, 4, 5]` (Client, Server, Broadcast, etc.).
/// 4. The **Stratum field** must be between `0` and `15` for valid servers.
/// 5. The **Poll field**, signed, must be at least `-7` (chrony's minimum).
/// 6. At stratum 1 the **Reference ID** must be a printable ASCII code; at
///    stratum 0 and from 2 to 15 any four bytes are accepted (a kiss code or
///    an unsynchronised client's id, an IPv4 address or the MD5 hash of an
///    IPv6 upstream).
///    If any of these conditions are not met, an `NtpPacketParseError` is returned.
///
/// The **Receive** and **Transmit** timestamps are taken on the sender's
/// clock, but their order is not checked here: in interleaved mode (chrony
/// `xleave`), Transmit is the departure time of the previous reply.
///
/// [`crate::parse::PacketFlow`] applies this decoder to UDP port 123. On any
/// other port it labels a datagram NTP only if, in addition, its poll,
/// precision and root delay are values an implementation emits, the bytes
/// after the 48-byte header are well-formed extension fields and MAC,
/// Receive does not follow Transmit, and a stratum 0 reference id is zero,
/// ASCII or `127.0.0.1`: the former decoder alone let about one random
/// datagram in 250 pass for NTP.
///
/// ## Usage
///
/// ```rust
/// use packet_parser::parse::application::protocols::ntp::NtpPacket;
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
/// match NtpPacket::try_from(packet) {
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
/// - **`InvalidReferenceIdForStratum1`** → A stratum 1 reference id is not a
///   printable ASCII code.
///
/// These errors help diagnose malformed or unexpected packets.
use std::cmp::Ordering;
use std::fmt;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime};

use crate::{checks::application::ntp::*, errors::application::ntp::NtpPacketParseError};

/// NTP Packet
///
/// ```mermaid
/// ---
/// title: NtpPacket
/// ---
/// packet-beta
/// 0-1: "Leap Indicator u2"
/// 2-4: "Version u3"
/// 5-7: "Mode u3"
/// 8-15: "Stratum u8"
/// 16-23: "Poll u8"
/// 24-31: "Precision i8"
/// 32-63: "Root Delay u32"
/// 64-95: "Root Dispersion u32"
/// 96-127: "Reference ID bytes[4]"
/// 128-191: "Reference Timestamp u64"
/// 192-255: "Originate Timestamp u64"
/// 256-319: "Receive Timestamp u64"
/// 320-383: "Transmit Timestamp u64"
/// ```
///
/// The `NtpPacket` struct represents a parsed NTP packet.
#[derive(Debug)]
#[non_exhaustive]
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
    pub reference_id: Refid,
    /// The time at which the local clock was last set or corrected.
    pub reference_timestamp: NtpTimestamp,
    /// The time at which the request departed the client for the server.
    pub originate_timestamp: NtpTimestamp,
    /// The time at which the request arrived at the server.
    pub receive_timestamp: NtpTimestamp,
    /// The time at which the reply departed the server for the client.
    pub transmit_timestamp: NtpTimestamp,
}

/// Seconds from 1900-01-01, the NTP epoch of era 0, to 1970-01-01, the Unix
/// epoch.
const NTP_TO_UNIX_EPOCH: i64 = 2_208_988_800;

/// An NTP timestamp (RFC 5905 §6), as carried on the wire: 32 bits of
/// seconds and 32 bits of fraction of a second.
///
/// The seconds count from the start of an NTP era, and the timestamp does
/// not say which. The crate places it as tshark does (RFC 4330 §3): with the
/// most significant bit set, in era 0 (1968 to 2036); clear, in era 1 (2036
/// to 2104). A timestamp that is all zero means "unknown"
/// ([`is_null`](Self::is_null)); its date is the Unix epoch.
///
/// The order is the order in time, eras included. `Display` writes the
/// date in RFC 3339, in UTC, to the nanosecond:
///
/// ```
/// use packet_parser::parse::application::protocols::ntp::NtpTimestamp;
///
/// let transmit = NtpTimestamp::from_be_bytes([0xcc, 0x2b, 0x0c, 0x4e, 0xfa, 0x8b, 0x00, 0xe5]);
/// assert_eq!(transmit.to_string(), "2008-07-18T12:34:22.978683524Z");
/// assert_eq!(transmit.unix_seconds(), 1_216_384_462);
///
/// // Era 1 follows era 0.
/// let era_1 = NtpTimestamp::new(0x0000_0025, 0);
/// assert_eq!(era_1.to_string(), "2036-02-07T06:28:53.000000000Z");
/// assert!(transmit < era_1);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct NtpTimestamp {
    /// Seconds since the start of the era.
    pub seconds: u32,
    /// Fraction of a second, in units of 2^-32 s.
    pub fraction: u32,
}

impl NtpTimestamp {
    /// A timestamp from its two fields.
    pub const fn new(seconds: u32, fraction: u32) -> Self {
        Self { seconds, fraction }
    }

    /// A timestamp from its 8 bytes, big-endian as on the wire.
    pub const fn from_be_bytes(bytes: [u8; 8]) -> Self {
        let [s0, s1, s2, s3, f0, f1, f2, f3] = bytes;
        Self::new(
            u32::from_be_bytes([s0, s1, s2, s3]),
            u32::from_be_bytes([f0, f1, f2, f3]),
        )
    }

    /// Whether the timestamp is all zero: "unknown" (RFC 5905 §6).
    pub const fn is_null(self) -> bool {
        self.seconds == 0 && self.fraction == 0
    }

    /// Whole seconds since the Unix epoch: negative before 1970, 0 for a
    /// null timestamp.
    pub const fn unix_seconds(self) -> i64 {
        let seconds = self.seconds as i64;
        if self.is_null() {
            0
        } else if self.seconds & 0x8000_0000 != 0 {
            seconds - NTP_TO_UNIX_EPOCH
        } else {
            seconds + (1_i64 << 32) - NTP_TO_UNIX_EPOCH
        }
    }

    /// The fraction of a second, in nanoseconds, rounded down.
    pub fn subsec_nanos(self) -> u32 {
        let nanos = (u64::from(self.fraction) * 1_000_000_000) >> 32;
        // Toujours sous 10^9 : la fraction est sous 2^32.
        u32::try_from(nanos).unwrap_or(999_999_999)
    }

    /// The timestamp as a [`SystemTime`], to the nanosecond, rounded down.
    /// `None` only where the platform cannot represent the date.
    pub fn to_system_time(self) -> Option<SystemTime> {
        let seconds = self.unix_seconds();
        let whole = Duration::from_secs(seconds.unsigned_abs());
        let since_epoch = if seconds >= 0 {
            SystemTime::UNIX_EPOCH.checked_add(whole)?
        } else {
            SystemTime::UNIX_EPOCH.checked_sub(whole)?
        };
        since_epoch.checked_add(Duration::from_nanos(u64::from(self.subsec_nanos())))
    }
}

impl Ord for NtpTimestamp {
    /// The order in time. The raw seconds only break the tie between a null
    /// timestamp and the one that falls exactly on the Unix epoch.
    fn cmp(&self, other: &Self) -> Ordering {
        (self.unix_seconds(), self.fraction, self.seconds).cmp(&(
            other.unix_seconds(),
            other.fraction,
            other.seconds,
        ))
    }
}

impl PartialOrd for NtpTimestamp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// The proleptic Gregorian date of a day counted from 1970-01-01 (Howard
/// Hinnant, `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

impl fmt::Display for NtpTimestamp {
    /// RFC 3339, UTC, nine digits of fraction: `2008-07-18T12:34:22.978683524Z`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let seconds = self.unix_seconds();
        let (year, month, day) = civil_from_days(seconds.div_euclid(86_400));
        let time = seconds.rem_euclid(86_400);
        write!(
            f,
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:09}Z",
            time / 3_600,
            time % 3_600 / 60,
            time % 60,
            self.subsec_nanos()
        )
    }
}

/// NTP Reference ID (4 bytes, RFC 5905 section 7.3).
///
/// Clock sources (stratum 1) are 4 ASCII bytes, left-justified and
/// zero/space padded. At stratum 0 the field carries a kiss code in a
/// Kiss-o'-Death reply, but whatever an unsynchronised client leaves there
/// in its request (ntpd sends its local clock id, `127.0.0.1`). At stratum
/// 2 and above it is the IPv4 address of the upstream server or, for an
/// IPv6 upstream, the first four octets of the MD5 hash of its address,
/// which can look like any IPv4 address, multicast included. The bytes are
/// stored as the raw fixed `[u8; 4]` (no allocation); use [`Refid::code`]
/// or the `Display` implementation for a readable form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refid {
    Ipv4(Ipv4Addr),
    KissCode([u8; 4]),
    ClockSource([u8; 4]),
}

impl Refid {
    /// Returns the ASCII code of a kiss code or clock source, trimmed of its
    /// trailing NUL/space padding. Returns `None` for IPv4 reference ids or
    /// if the bytes are not printable ASCII.
    pub fn code(&self) -> Option<&str> {
        match self {
            Refid::Ipv4(_) => None,
            Refid::KissCode(bytes) | Refid::ClockSource(bytes) => reference_code_str(bytes),
        }
    }
}

impl fmt::Display for Refid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refid::Ipv4(ip) => write!(f, "{ip}"),
            Refid::KissCode(bytes) => match reference_code_str(bytes) {
                Some(code) if !code.is_empty() => write!(f, "{code}"),
                Some(_) => write!(f, "NULL"),
                None => write!(f, "{bytes:02X?}"),
            },
            Refid::ClockSource(bytes) => match reference_code_str(bytes) {
                Some(code) if !code.is_empty() => write!(f, "{code}"),
                _ => write!(f, "{bytes:02X?}"),
            },
        }
    }
}

impl TryFrom<&[u8]> for NtpPacket {
    type Error = NtpPacketParseError;

    fn try_from(payload: &[u8]) -> Result<Self, Self::Error> {
        // Check if payload has the minimum length required for an NTP packet
        validate_ntp_packet_length(payload)?;

        let flags = extract_flags(&payload[0])?;
        let stratum = extract_stratum(&payload[1])?;
        let poll = extract_poll(&payload[2])?;
        let precision = extract_precision(&payload[3])?;
        let root_delay = extract_root_delay(&payload[4..8])?;
        let root_dispersion = extract_root_dispersion(&payload[8..12])?;
        let reference_id = extract_reference_id(stratum, &payload[12..16])?;
        let reference_timestamp = extract_timestamp(&payload[16..24])?;
        let originate_timestamp = extract_timestamp(&payload[24..32])?;
        let receive_timestamp = extract_timestamp(&payload[32..40])?;
        let transmit_timestamp = extract_timestamp(&payload[40..48])?;

        // Receive et Transmit partagent une horloge (#161), mais leur ordre
        // n'est verifie que par la sonde aveugle : en mode entrelace (chrony
        // `xleave`), Transmit est l'emission de la reponse precedente.

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

impl NtpPacket {
    /// Le poll, en log2 secondes : un entier signe (RFC 5905 §7.3), que le
    /// champ [`NtpPacket::poll`] garde brut — -7 (1/128 s, chrony) y vaut
    /// 249.
    pub fn poll_exponent(&self) -> i8 {
        self.poll as i8
    }

    /// Sonde NTP aveugle, hors du port 123 (#164).
    ///
    /// Plus stricte que [`TryFrom::try_from`], que le port 123 garde
    /// tolerant : l'ancien decodeur laissait passer un datagramme aleatoire
    /// sur 250 environ, et 43 datagrammes QUIC, KCP, PFCP ou NetBIOS du
    /// corpus nDPI passaient pour du NTP. Le poll, la precision et le root
    /// delay doivent etre de ceux qu'une implementation emet, ce qui suit les
    /// 48 octets d'en-tete des champs d'extension et un MAC bien formes,
    /// Receive ne pas suivre Transmit, et au stratum 0 l'identifiant de
    /// reference etre nul, un code ASCII ou `127.0.0.1` — le decodeur y
    /// accepte tout octet (#165), et une requete DNS hors du port 53 passait
    /// alors.
    pub(crate) fn is_blind_udp_match(payload: &[u8]) -> bool {
        NtpPacket::try_from(payload).is_ok_and(|packet| {
            is_plausible_poll(packet.poll)
                && is_plausible_precision(packet.precision)
                && is_plausible_root_delay(packet.root_delay)
                && is_valid_trailer(packet.flags.1, &payload[MINIMUM_NTP_PACKET_LENGTH..])
                && validate_datetime_ordering(packet.receive_timestamp, packet.transmit_timestamp)
                    .is_ok()
                && (packet.stratum != 0 || is_plausible_stratum_0_reference(&packet.reference_id))
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::errors::application::ntp::NtpPacketParseError;
    use crate::parse::application::protocols::ntp::NtpPacket;
    use crate::parse::application::protocols::ntp::*;

    #[test]
    fn test_valid_ntp_packet() {
        let binding = hex::decode(
            "d9000afa000000000001029000000000000000000000000000000000000000000000000000000000c50204eceed33c52",
        );

        let result = NtpPacket::try_from(binding.expect("REASON").as_slice())
            .expect("Expected a valid NTP packet");

        assert_eq!(result.flags, (3, 3, 1));
        assert_eq!(result.stratum, 0x00);
        assert_eq!(result.poll, 10);
        assert_eq!(result.precision, -6);
        assert_eq!(result.root_delay, 0x00000000);
        assert_eq!(result.root_dispersion, 66192);
        assert_eq!(result.reference_id, Refid::KissCode([0, 0, 0, 0]));
        assert_eq!(result.reference_id.to_string(), "NULL");
    }

    /// iti_Sample_File_MMS_and_GOOSE.pcap trame 2 : reponse d'un serveur v4
    /// (stratum 6, horloge locale 127.127.1.0) a un client dont l'horloge est
    /// en avance de 2,2 ms — originate (T1, horloge du client) depasse receive
    /// (T2, horloge du serveur). La crate la rejetait (#161).
    const SERVER_REPLY_CLIENT_AHEAD: &str = concat!(
        "240600ec00000000000002e37f7f0100cc2b0c374b1a1279cc2b0c4efb1abd7d",
        "cc2b0c4efa8a1caccc2b0c4efa8b00e5"
    );

    /// Meme capture, trame 54 : reponse d'un serveur v1 avec un originate nul.
    const V1_SERVER_REPLY_NULL_ORIGINATE: &str = concat!(
        "0c0600ec00000000000002e67f7f0100cc2b0c374b1a12790000000000000000",
        "cc2b0c51beb3ebd3cc2b0c51beb4a3bc"
    );

    /// Meme capture, trame 53 : requete d'un client v1, tout a zero.
    const V1_CLIENT_REQUEST_ALL_NULL: &str = concat!(
        "0b00000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000"
    );

    #[test]
    fn test_real_server_replies_are_accepted_whatever_the_client_clock() {
        let reply = hex::decode(SERVER_REPLY_CLIENT_AHEAD).unwrap();
        let packet = NtpPacket::try_from(reply.as_slice()).expect("reponse reelle (#161)");
        assert_eq!(packet.flags, (0, 4, 4));
        assert_eq!((packet.stratum, packet.poll, packet.precision), (6, 0, -20));
        assert_eq!((packet.root_delay, packet.root_dispersion), (0, 739));
        assert_eq!(
            packet.reference_id,
            Refid::Ipv4(Ipv4Addr::new(127, 127, 1, 0))
        );
        assert!(packet.originate_timestamp > packet.receive_timestamp);
        assert!(packet.receive_timestamp <= packet.transmit_timestamp);
        assert!(packet.reference_timestamp < packet.receive_timestamp);
        assert_eq!(
            packet.transmit_timestamp.to_string(),
            "2008-07-18T12:34:22.978683524Z"
        );

        let v1_reply = hex::decode(V1_SERVER_REPLY_NULL_ORIGINATE).unwrap();
        let packet = NtpPacket::try_from(v1_reply.as_slice()).expect("reponse v1 reelle");
        assert_eq!(packet.flags, (0, 1, 4));
        assert!(is_null_timestamp(packet.originate_timestamp));
        assert!(!is_null_timestamp(packet.reference_timestamp));

        let v1_request = hex::decode(V1_CLIENT_REQUEST_ALL_NULL).unwrap();
        let packet = NtpPacket::try_from(v1_request.as_slice()).expect("requete v1 reelle");
        assert_eq!(packet.flags, (0, 1, 3));
        assert!(is_null_timestamp(packet.transmit_timestamp));
    }

    /// Receive et Transmit inverses : ce que fait une reponse en mode
    /// entrelace (chrony `xleave`, Transmit de la reponse precedente). Le
    /// decodeur l'accepte ; la sonde aveugle, non.
    #[test]
    fn test_receive_after_transmit_is_decoded_but_not_blind() {
        let mut swapped = hex::decode(SERVER_REPLY_CLIENT_AHEAD).unwrap();
        let (receive, transmit) = (swapped[32..40].to_vec(), swapped[40..48].to_vec());
        swapped[32..40].copy_from_slice(&transmit);
        swapped[40..48].copy_from_slice(&receive);
        let packet = NtpPacket::try_from(swapped.as_slice()).expect("reponse entrelacee");
        assert!(packet.receive_timestamp > packet.transmit_timestamp);
        assert!(!NtpPacket::is_blind_udp_match(&swapped));
        assert!(NtpPacket::is_blind_udp_match(
            &hex::decode(SERVER_REPLY_CLIENT_AHEAD).unwrap()
        ));
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
    fn test_truncated_ntp_packet_one_byte_short() {
        // 47 bytes: one byte less than the minimum NTP packet size.
        let truncated = vec![0u8; 47];
        let result = NtpPacket::try_from(truncated.as_slice());
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
        assert!(matches!(
            result,
            Err(NtpPacketParseError::InvalidVersion { .. })
        ));
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
        assert!(matches!(
            result,
            Err(NtpPacketParseError::InvalidMode { .. })
        ));
    }

    /// The-Ultimate-PCAP.pcapng trame 11787 : reponse d'un serveur au
    /// stratum 2, sur IPv6, dont l'identifiant de reference `e5 bf 89 3d`
    /// est le debut du hachage MD5 de l'adresse de son amont IPv6 — il se
    /// lit 229.191.137.61, une adresse multicast, et la crate le rejetait
    /// (#165).
    const IPV6_UPSTREAM_HASH: &str = concat!(
        "240203ec0000004200000c22e5bf893de0269d9260da4c52e026a5168d2b6f19",
        "e026a5168d49c5abe026a5168d87450b",
    );

    /// The-Ultimate-PCAP.pcapng trames 47657 et 24308 : requetes de client
    /// non synchronise (stratum 0), qui laissent `127.0.0.1` ou `USER` la
    /// ou un serveur mettrait un kiss code (#165).
    const STRATUM_0_LOCAL_CLOCK: &str = concat!(
        "e30006e800000000000000007f00000100000000000000000000000000000000",
        "0000000000000000eacf60baec1c9a56",
    );
    const STRATUM_0_USER: &str = concat!(
        "e30006e8000000000000006355534552e368ff3a994210a70000000000000000",
        "0000000000000000e36901249a97167d",
    );

    #[test]
    fn test_reference_id_of_an_ipv6_upstream_is_accepted() {
        let payload = hex::decode(IPV6_UPSTREAM_HASH).expect("valid hex");
        let packet = NtpPacket::try_from(payload.as_slice()).expect("stratum 2 reply");
        assert_eq!(packet.stratum, 2);
        assert_eq!(
            packet.reference_id,
            Refid::Ipv4(std::net::Ipv4Addr::new(229, 191, 137, 61))
        );
        assert!(NtpPacket::is_blind_udp_match(&payload));
    }

    #[test]
    fn test_stratum_0_request_reference_id_is_accepted() {
        let payload = hex::decode(STRATUM_0_LOCAL_CLOCK).expect("valid hex");
        let packet = NtpPacket::try_from(payload.as_slice()).expect("stratum 0 request");
        assert_eq!(packet.flags, (3, 4, 3));
        assert_eq!(packet.reference_id, Refid::KissCode([127, 0, 0, 1]));
        assert_eq!(packet.reference_id.code(), None);
        assert_eq!(packet.reference_id.to_string(), "[7F, 00, 00, 01]");
        assert!(NtpPacket::is_blind_udp_match(&payload));

        let payload = hex::decode(STRATUM_0_USER).expect("valid hex");
        let packet = NtpPacket::try_from(payload.as_slice()).expect("stratum 0 request");
        assert_eq!(packet.reference_id, Refid::KissCode(*b"USER"));
        assert_eq!(packet.reference_id.to_string(), "USER");
    }

    /// pcaps_exemple/protocols/ntp/ndpi_NTPv3.pcap trame 1 : reponse NTPv3
    /// de 48 octets, poll 4, precision -6.
    const NDPI_NTPV3_REPLY: &str = concat!(
        "1c0004fa00000000000000000000000000000000000000000000000000000000",
        "d94f4f1100000000d94f4f1100000000",
    );

    /// Faux positifs de l'ancienne sonde aveugle (#164) : `gnutella.pcap`
    /// du corpus nDPI (`ntop/nDPI` 5915c399, non versee), trame 1458 (poll
    /// 49, precision +2, 33 octets apres l'en-tete) ; dans
    /// pcaps_exemple/protocols/ntp/, ndpi_crynet.pcap trame 133 (en-tete
    /// nul, 85 octets apres) et ndpi_pfcp.pcapng trame 11 (PFCP sur 8805 :
    /// precision +41, 253 octets apres).
    const NDPI_GNUTELLA_1458: &str = concat!(
        "9b0c3102b701e86616c4455c2d8b4eb84400003a0000000547544b470000289d",
        "0a8d06deffc8263c33897c2c9179fd84ab61045d2fe235700901010000e35524",
        "a993f1cdde80df576b40b0cca40fde218c",
    );
    const NDPI_CRYNET_133: &str = concat!(
        "9100000000000000000000000000000000000000000000000000000000000000",
        "02caba3bdd1595c450afede4acfd53464c7277ca9f558d3fd24706ee764d6146",
        "f3584cd4bb2d079a2fb6e19c9d6ee8f4fe67e1b9a2b064f22d2e62ed6c4c9553",
        "74000000010c77a040f5e9627cc8d7e155523fa137cd5fac78c0c9aa9a8ff416",
        "694ebf4fb4",
    );
    const NDPI_PFCP_11: &str = concat!(
        "210201290000000000000000000004000093005b009c00040000001900160042",
        "3f306e3369317679626a6573386c303932613130386a34327367366678347262",
        "2d6a3967656173387233316d716d6569717370723273646e376f38327a32387a",
        "016500e600090146bc5e4f99a9ffff006c0004000000010062000c0004454416",
        "8705debb306f1d00f900010100a100010100fb0001070011002c00e700010100",
        "c4000400000000003e0001048007000b48f902cf5626a6d153f372800d000248",
        "f9005a00010b00af0063800800040de954fd001d0004ffffffff00b40041003f",
        "7367766a61706c676c6d626371666e73316a61636c64326b797266352d6c6673",
        "713663647935676a7835746a69676e2d79706866707064676e37646d39736280",
        "03000a48f9000000000000000b",
    );

    /// Synthetique : la reponse reelle ci-dessus, poll de chrony a -7.
    #[test]
    fn test_negative_poll_is_signed() {
        let mut payload = hex::decode(NDPI_NTPV3_REPLY).expect("valid hex");
        payload[2] = (-7i8) as u8;
        let packet = NtpPacket::try_from(payload.as_slice()).expect("poll de chrony");
        assert_eq!(packet.poll, 249);
        assert_eq!(packet.poll_exponent(), -7);
        assert!(NtpPacket::is_blind_udp_match(&payload));
        payload[2] = (-8i8) as u8;
        assert!(matches!(
            NtpPacket::try_from(payload.as_slice()),
            Err(NtpPacketParseError::InvalidPoll)
        ));
    }

    #[test]
    fn test_blind_probe_keeps_real_ntp() {
        let payload = hex::decode(NDPI_NTPV3_REPLY).expect("valid hex");
        assert!(NtpPacket::try_from(payload.as_slice()).is_ok());
        assert!(NtpPacket::is_blind_udp_match(&payload));
    }

    #[test]
    fn test_blind_probe_rejects_former_false_positives() {
        for hex_payload in [NDPI_GNUTELLA_1458, NDPI_CRYNET_133, NDPI_PFCP_11] {
            let payload = hex::decode(hex_payload).expect("valid hex");
            // Le decodeur tolerant du port 123 les accepte toujours...
            assert!(NtpPacket::try_from(payload.as_slice()).is_ok());
            // ... la sonde aveugle, non.
            assert!(!NtpPacket::is_blind_udp_match(&payload));
        }
    }

    #[test]
    fn test_refid_display() {
        use std::net::Ipv4Addr;

        assert_eq!(Refid::KissCode([0, 0, 0, 0]).to_string(), "NULL");
        assert_eq!(Refid::KissCode(*b"RATE").to_string(), "RATE");
        assert_eq!(
            Refid::KissCode([127, 0, 0, 1]).to_string(),
            "[7F, 00, 00, 01]"
        );
        assert_eq!(Refid::ClockSource(*b"GPS\0").to_string(), "GPS");
        assert_eq!(Refid::ClockSource(*b"GPS ").to_string(), "GPS");
        assert_eq!(
            Refid::Ipv4(Ipv4Addr::new(8, 8, 8, 8)).to_string(),
            "8.8.8.8"
        );
    }

    #[test]
    fn test_refid_code_accessor() {
        use std::net::Ipv4Addr;

        assert_eq!(Refid::KissCode(*b"RATE").code(), Some("RATE"));
        assert_eq!(Refid::ClockSource(*b"GPS ").code(), Some("GPS"));
        assert_eq!(Refid::KissCode([0, 0, 0, 0]).code(), Some(""));
        assert_eq!(Refid::Ipv4(Ipv4Addr::new(8, 8, 8, 8)).code(), None);
    }

    #[test]
    fn test_check_ntp_packet() {
        // Valid NTP packet
        let binding = hex::decode(
            "d9000afa000000000001029000000000000000000000000000000000000000000000000000000000c50204eceed33c52",
        );

        let result = NtpPacket::try_from(binding.expect("REASON").as_slice());

        assert!((result.is_ok()));

        // Invalid NTP packet (short length)
        let short_ntp_packet = vec![0x1B, 0x00, 0x04];
        let result = NtpPacket::try_from(short_ntp_packet.as_slice());
        assert!(matches!(
            result,
            Err(NtpPacketParseError::InvalidPacketLength)
        ));

        // Invalid NTP packet (invalid version)
        let invalid_version_packet = vec![
            0x7B, 0x00, 0x04, 0xFA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4E, 0x49,
            0x4E, 0x00, 0xDC, 0xC0, 0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0, 0x00, 0x00,
            0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0, 0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0,
            0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71,
        ];
        let result = NtpPacket::try_from(invalid_version_packet.as_slice());
        assert!(matches!(
            result,
            Err(NtpPacketParseError::InvalidVersion { version: _ })
        ));
    }
}
