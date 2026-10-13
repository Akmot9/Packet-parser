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
/// 7. The **Receive** and **Transmit** timestamps, both taken on the
///    sender's clock, must be in order.
///    If any of these conditions are not met, an `NtpPacketParseError` is returned.
///
/// [`crate::parse::PacketFlow`] applies this decoder to UDP port 123. On any
/// other port it labels a datagram NTP only if, in addition, its poll,
/// precision and root delay are values an implementation emits and the bytes
/// after the 48-byte header are well-formed extension fields and MAC: four
/// header fields alone let about one random datagram in 230 pass for NTP.
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
/// - **`InconsistentTimestamps`** → The receive timestamp is later than the
///   transmit timestamp, both taken on the sender's clock. The originate
///   timestamp is the client's clock and is never compared.
///
/// These errors help diagnose malformed or unexpected packets.
use std::fmt;
use std::net::Ipv4Addr;

use chrono::{DateTime, Utc};

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
    pub reference_timestamp: DateTime<Utc>,
    /// The time at which the request departed the client for the server.
    pub originate_timestamp: DateTime<Utc>,
    /// The time at which the request arrived at the server.
    pub receive_timestamp: DateTime<Utc>,
    /// The time at which the reply departed the server for the client.
    pub transmit_timestamp: DateTime<Utc>,
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

        // Seuls Receive et Transmit partagent une horloge (#161).
        validate_datetime_ordering(receive_timestamp, transmit_timestamp)?;

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
    /// Sonde NTP aveugle, hors du port 123 (#164).
    ///
    /// Plus stricte que [`TryFrom::try_from`], que le port 123 garde
    /// tolerant : sur des octets quelconques, l'en-tete ne contraint que la
    /// version, le mode, le stratum et l'ordre de deux horodatages, et un
    /// datagramme sur 230 environ passait pour du NTP — QUIC, KCP, PFCP,
    /// datagrammes NetBIOS du corpus nDPI. Le poll, la precision et le root
    /// delay doivent etre de ceux qu'une implementation emet, et ce qui suit
    /// les 48 octets d'en-tete, des champs d'extension et un MAC bien formes.
    pub(crate) fn is_blind_udp_match(payload: &[u8]) -> bool {
        NtpPacket::try_from(payload).is_ok_and(|packet| {
            is_plausible_poll(packet.poll)
                && is_plausible_precision(packet.precision)
                && is_plausible_root_delay(packet.root_delay)
                && is_valid_trailer(packet.flags.1, &payload[MINIMUM_NTP_PACKET_LENGTH..])
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::errors::application::ntp::NtpPacketParseError;
    use crate::parse::application::NtpPacket;
    use crate::parse::application::protocols::ntp::*;
    // use chrono::TimeZone;

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
            packet
                .transmit_timestamp
                .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
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

    /// Receive et Transmit sont pris sur la meme horloge : inverses, la
    /// reponse est bien incoherente.
    #[test]
    fn test_receive_after_transmit_is_still_rejected() {
        let mut swapped = hex::decode(SERVER_REPLY_CLIENT_AHEAD).unwrap();
        let (receive, transmit) = (swapped[32..40].to_vec(), swapped[40..48].to_vec());
        swapped[32..40].copy_from_slice(&transmit);
        swapped[40..48].copy_from_slice(&receive);
        assert!(matches!(
            NtpPacket::try_from(swapped.as_slice()),
            Err(NtpPacketParseError::InconsistentTimestamps)
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

    /// Faux positifs de l'ancienne sonde aveugle (#164), dans
    /// pcaps_exemple/protocols/ntp/ : ndpi_gnutella.pcap trame 1458 (poll
    /// 49, precision +2, 33 octets apres l'en-tete), ndpi_crynet.pcap trame
    /// 133 (en-tete nul, 85 octets apres) et ndpi_pfcp.pcapng trame 11
    /// (PFCP sur 8805 : precision +41, 253 octets apres).
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
