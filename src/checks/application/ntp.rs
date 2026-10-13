// Copyright (c) 2024 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use std::net::Ipv4Addr;

use chrono::{DateTime, TimeZone, Utc};

use crate::{
    errors::application::ntp::NtpPacketParseError, parse::application::protocols::ntp::Refid,
};

pub const MINIMUM_NTP_PACKET_LENGTH: usize = 48;

/// ## NTP Validation Process
///
/// 1. The NTP packet must be at least **48 bytes** long.
/// 2. The **Version Number (VN)** in the first byte must be between `1` and `4`.
/// 3. The **Mode field** (first byte) must be in `[1, 2, 3, 4, 5]` (Client, Server, Broadcast, etc.).
/// 4. The **Stratum field** must be between `0` and `15` for valid servers.
/// 5. The **Poll field**, signed, must be at least `-7` (chrony, #165).
/// 6. At stratum 1, the **Reference ID** must be a printable ASCII code
///    (#162); at stratum 0 and from 2 to 15, any four bytes (#165).
///
/// Off port 123, the blind probe also checks the poll, the precision, the
/// root delay, the bytes after the header, the order of the Receive and
/// Transmit timestamps (both on the sender's clock; Originate is the
/// client's and never compared, #161) and the stratum 0 reference id:
/// [`is_plausible_poll`], [`is_plausible_precision`],
/// [`is_plausible_root_delay`], [`is_valid_trailer`],
/// [`validate_datetime_ordering`], [`is_plausible_stratum_0_reference`]
/// (#164).
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

/// Plus petit poll (log2 s, signe) qu'une implementation emette : chrony,
/// `MIN_POLL` -7 depuis sa version 4.3 (commit `685d8f72`), ecrit son poll
/// dans ses requetes et son serveur renvoie celui du client.
const MIN_POLL: i8 = -7;

/// Le poll est signe (RFC 5905 §7.3) : de -7 (1/128 s, chrony) a 127.
pub fn extract_poll(poll: &u8) -> Result<u8, NtpPacketParseError> {
    if (*poll as i8) < MIN_POLL {
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

/// Extrait l'identifiant de reference (RFC 5905 §7.3) selon le stratum.
///
/// - Stratum 0 (« non specifie ou invalide ») : un kiss code dans le paquet
///   Kiss-o'-Death d'un serveur, mais ce que veut le client non synchronise
///   dans sa requete — ntpd y laisse l'identifiant de son horloge locale
///   (`127.0.0.1`) : les quatre octets sont gardes tels quels (#165).
/// - Stratum 1 : un code ASCII imprimable, justifie a gauche et complete de
///   zeros, dont la liste, tenue par l'IANA, depasse l'extrait de la RFC
///   (GOES, GPS, GAL, PPS...) : ntpd emet aussi SHM, NMEA, LOCL... Tout code
///   imprimable non vide est accepte (#162).
/// - Stratum 2 a 15 : l'adresse IPv4 du serveur amont ou, pour un amont
///   IPv6, les quatre premiers octets du hachage MD5 de son adresse, qui
///   tombent n'importe ou, multicast et `0.0.0.0` compris (#165).
pub fn extract_reference_id(stratum: u8, payload: &[u8]) -> Result<Refid, NtpPacketParseError> {
    if payload.len() < 4 {
        return Err(NtpPacketParseError::InvalidReferenceIdForHigherStratum);
    }

    let ref_id_bytes = [payload[0], payload[1], payload[2], payload[3]];

    match stratum {
        0 => Ok(Refid::KissCode(ref_id_bytes)),
        1 => match reference_code_str(&ref_id_bytes) {
            Some(code) if !code.is_empty() => Ok(Refid::ClockSource(ref_id_bytes)),
            _ => Err(NtpPacketParseError::InvalidReferenceIdForStratum1),
        },
        2..=15 => Ok(Refid::Ipv4(Ipv4Addr::from(ref_id_bytes))),
        _ => Err(NtpPacketParseError::InvalidReferenceIdForHigherStratum),
    }
}

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

/// Poll (log2 s, signe) que la sonde aveugle admet (#164) : chrony va de -7
/// a 24 (`MIN_POLL`, `MAX_POLL`) ; ntpd de 3 a 17 ; un client SNTP envoie 0.
/// Les faux positifs du corpus nDPI portaient 46 a 118.
const BLIND_POLL: std::ops::RangeInclusive<i8> = MIN_POLL..=24;

/// Precision (log2 s, signee) que la sonde aveugle admet (#164) : de
/// 2^-32 s, la resolution d'un horodatage NTP, a 1 s (0, celle d'un client
/// SNTP qui ne la renseigne pas). Les faux positifs du corpus nDPI portaient
/// +2 a +124, ou -65 et -103.
const BLIND_PRECISION: std::ops::RangeInclusive<i8> = -32..=0;

/// Precision des requetes de client de chrony, qui la fixe a 32 (2^32 s,
/// une ere NTP entiere) depuis 2015 (commit `8225bf01`) — 33 requetes NTS et
/// NTPv4 de The-Ultimate-PCAP.pcapng, trames 11789, 11798 et 19532 a 19654.
const UNDISCLOSED_PRECISION: i8 = 32;

/// Root delay (format court, 16.16 s) au-dela duquel la sonde aveugle
/// refuse un paquet (#164) : 16 s, `MAXDISP` de la RFC 5905 — une source
/// dont la distance a la racine depasse `MAXDIST` (1 s ; 1,5 s chez ntpd)
/// est deja inutilisable. Le plus grand root delay reel des corpus vaut 1 s
/// (requetes a la ntpdate : precision -6, root delay et dispersion de 1 s) ;
/// un en-tete QUIC v1 en porte au moins 256 s, un segment KCP plus de
/// 20 000.
/// La root dispersion, elle, n'est pas bornee : un serveur ntpd de stratum 1
/// en annonce 107,8 s (`iec104/iti_JavaRMI_and_IEC_Misc.pcap`, trame 2).
const MAX_ROOT_DELAY: u32 = 16 << 16;

/// Plus long MAC avant NTPv4 : l'Extended Authenticator de Microsoft
/// ([MS-SNTP] §2.2.3 et §2.2.4), identifiant de cle, quatre octets de drapeaux et
/// condensat de 64 octets — W32Time, trames 40777 et 40778 de
/// The-Ultimate-PCAP.pcapng.
const MAX_LEGACY_MAC_LENGTH: usize = 72;

/// Plus long MAC d'un paquet NTPv4 qui suit des champs d'extension :
/// identifiant de cle et condensat SHA-1 (RFC 5905 §7.5.1.3, ajoute par
/// RFC 7822 §3). Au-dela, les octets qui suivent l'en-tete sont un champ
/// d'extension.
const MAX_V4_MAC_LENGTH: usize = 24;

/// Un crypto-NAK : l'identifiant de cle nul, seul, que ntpd renvoie quand
/// l'authentification d'une requete echoue — dans la version de la
/// requete (`authencrypt(0)`, quatre octets nuls).
const CRYPTO_NAK: [u8; 4] = [0; 4];

/// MAC seuls a condensat SHA-256, SHA-384 et SHA-512 (identifiant de cle et
/// 32, 48 ou 64 octets), que ntpd envoie en NTPv4 sans les tronquer.
const LONG_V4_MAC_LENGTHS: [usize; 3] = [36, 52, 68];

/// Plus court champ d'extension NTPv4 (RFC 7822 §3) : type, longueur et
/// douze octets de valeur.
const MIN_EXTENSION_FIELD_LENGTH: usize = 16;

/// Le poll d'un vrai paquet NTP, pour la sonde aveugle (#164).
pub fn is_plausible_poll(poll: u8) -> bool {
    BLIND_POLL.contains(&(poll as i8))
}

/// La precision d'un vrai paquet NTP, pour la sonde aveugle (#164).
pub fn is_plausible_precision(precision: i8) -> bool {
    BLIND_PRECISION.contains(&precision) || precision == UNDISCLOSED_PRECISION
}

/// Le root delay d'un vrai paquet NTP, pour la sonde aveugle (#164).
pub fn is_plausible_root_delay(root_delay: u32) -> bool {
    root_delay < MAX_ROOT_DELAY
}

/// L'identifiant de reference d'un vrai paquet de stratum 0, pour la sonde
/// aveugle : nul (requete de client), un kiss code ou un autre code ASCII,
/// ou `127.0.0.1`, que ntpd non synchronise laisse dans ses requetes. Le
/// decodeur accepte tout octet (#165) ; sans cette garde, une requete DNS
/// de 48 octets avec EDNS hors du port 53 — identifiant de poids faible nul,
/// drapeaux RD et AD lus comme un poll de 1 et la precision 32 de chrony —
/// sortait NTP, son premier label tenant lieu d'identifiant.
pub fn is_plausible_stratum_0_reference(reference_id: &Refid) -> bool {
    match reference_id {
        Refid::KissCode(bytes) => *bytes == [127, 0, 0, 1] || reference_code_str(bytes).is_some(),
        _ => false,
    }
}

/// Ce qui suit l'en-tete de 48 octets a la forme que fixe la RFC (#164) :
/// rien ; ou en NTPv4 des champs d'extension (longueur d'au moins seize
/// octets, multiple de quatre) suivis d'un MAC eventuel : quatre octets nuls
/// (crypto-NAK), 20 (MD5, AES-CMAC) ou 24 octets (SHA-1) — un reste de plus
/// de 24 octets est un champ d'extension, si bien que le dernier champ d'un
/// paquet sans MAC fait au moins 28 octets (RFC 5905 §7.5.1.4, ajoute par
/// RFC 7822 §3) —, ou un MAC seul a condensat SHA-256, SHA-384 ou SHA-512 ;
/// avant NTPv4, un crypto-NAK, ou un MAC : identifiant de cle et condensat
/// DES, MD5, SHA-1 ou plus long, jusqu'aux 72 octets de l'Extended
/// Authenticator de Microsoft.
pub fn is_valid_trailer(version: u8, trailer: &[u8]) -> bool {
    if trailer.is_empty() {
        return true;
    }
    if !trailer.len().is_multiple_of(4) {
        return false;
    }
    if version < 4 {
        return trailer == CRYPTO_NAK || (12..=MAX_LEGACY_MAC_LENGTH).contains(&trailer.len());
    }
    // Un MAC seul dont le condensat est un SHA-256, SHA-384 ou SHA-512 :
    // ntpd ne le tronque pas (#16640 du tracker Wireshark).
    if LONG_V4_MAC_LENGTHS.contains(&trailer.len()) {
        return true;
    }
    let mut rest = trailer;
    while rest.len() > MAX_V4_MAC_LENGTH {
        let length = usize::from(u16::from_be_bytes([rest[2], rest[3]]));
        if length < MIN_EXTENSION_FIELD_LENGTH || !length.is_multiple_of(4) || length > rest.len() {
            return false;
        }
        rest = &rest[length..];
    }
    rest.is_empty() || rest == CRYPTO_NAK || matches!(rest.len(), 20 | MAX_V4_MAC_LENGTH)
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

    /// #165 : au stratum 0, un client non synchronise met ce qu'il veut la
    /// ou un serveur mettrait un kiss code.
    #[test]
    fn test_stratum_0_keeps_any_reference_id() {
        for bytes in [[0xC3, 0xA9, 0xFF, 0xFE], [127, 0, 0, 1], *b"USER"] {
            assert_eq!(extract_reference_id(0, &bytes), Ok(Refid::KissCode(bytes)));
        }
        assert_eq!(
            extract_reference_id(0, &[127, 0, 0, 1]).unwrap().code(),
            None
        );
    }

    #[test]
    fn test_stratum_2_valid_ipv4() {
        let stratum = 2;
        let payload = [8, 8, 8, 8]; // Adresse IPv4 valide (Google DNS)
        let result = extract_reference_id(stratum, &payload);
        assert_eq!(result, Ok(Refid::Ipv4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    /// #165 : pour un amont IPv6, l'identifiant est le debut du hachage MD5
    /// de son adresse — `e5 bf 89 3d` dans The-Ultimate-PCAP.pcapng, qui se
    /// lit comme une adresse multicast.
    #[test]
    fn test_stratum_2_accepts_an_ipv6_upstream_hash() {
        for bytes in [[0xE5, 0xBF, 0x89, 0x3D], [224, 0, 0, 1], [0, 0, 0, 0]] {
            assert_eq!(
                extract_reference_id(2, &bytes),
                Ok(Refid::Ipv4(Ipv4Addr::from(bytes)))
            );
        }
        assert_eq!(
            extract_reference_id(15, &[192, 168, 1, 1]),
            Ok(Refid::Ipv4(Ipv4Addr::new(192, 168, 1, 1)))
        );
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

    /// Le poll est signe : chrony descend a -7 (1/128 s).
    #[test]
    fn test_extract_poll_accepts_chrony_negative_polls() {
        for poll in [0u8, 6, 17, 127, (-1i8) as u8, (-7i8) as u8] {
            assert_eq!(extract_poll(&poll), Ok(poll));
        }
        for poll in [(-8i8) as u8, 0x80] {
            assert_eq!(extract_poll(&poll), Err(NtpPacketParseError::InvalidPoll));
        }
    }

    #[test]
    fn test_plausible_root_delay_bounds() {
        // Nul (client), 1 s (requete a la ntpdate), juste sous 16 s.
        for root_delay in [0u32, 0x0000_0450, 0x0001_0000, 0x000f_ffff] {
            assert!(is_plausible_root_delay(root_delay), "{root_delay:#010x}");
        }
        // 16 s, un segment KCP (ndpi_kcp.pcap trame 24 : 20 992 s), un
        // en-tete QUIC v1 (au moins 256 s).
        for root_delay in [0x0010_0000u32, 0x5200_8000, 0x0100_0000, u32::MAX] {
            assert!(!is_plausible_root_delay(root_delay), "{root_delay:#010x}");
        }
    }

    #[test]
    fn test_plausible_poll_bounds() {
        // SNTP 0, ntpd 3 a 17, chrony -7 a 24.
        for poll in [0u8, 3, 6, 10, 17, 24, (-7i8) as u8, (-1i8) as u8] {
            assert!(is_plausible_poll(poll), "poll {}", poll as i8);
        }
        // Faux positifs du corpus nDPI (#164) : 46, 49, 73, 118.
        for poll in [25u8, 46, 49, 73, 118, 127, (-8i8) as u8, 0x80] {
            assert!(!is_plausible_poll(poll), "poll {}", poll as i8);
        }
    }

    #[test]
    fn test_plausible_precision_bounds() {
        // Et +32, la precision des requetes de client de chrony.
        for precision in [0i8, -6, -20, -25, -32, 32] {
            assert!(is_plausible_precision(precision), "precision {precision}");
        }
        // Faux positifs du corpus nDPI (#164) : +2, +10, +41, -65, -103.
        for precision in [1i8, 2, 10, 31, 33, 41, 127, -33, -65, -103, -128] {
            assert!(!is_plausible_precision(precision), "precision {precision}");
        }
    }

    /// Synthetique : formes de fin de paquet admises par la RFC 7822.
    #[test]
    fn test_trailer_structure() {
        // Rien apres l'en-tete, en toute version.
        for version in 1..=4 {
            assert!(is_valid_trailer(version, &[]));
        }
        // NTPv4 : MAC seul (crypto-NAK, MD5, SHA-1).
        assert!(is_valid_trailer(4, &[0; 4]));
        for length in [20, 24] {
            assert!(is_valid_trailer(4, &vec![0xAB; length]));
        }
        // NTPv4 : le plus court champ d'extension sans MAC (28 octets,
        // RFC 5905 §7.5.1.4), un champ de 24 octets suivi d'un crypto-NAK.
        let mut trailer = vec![0x01, 0x04, 0x00, 0x1c];
        trailer.extend_from_slice(&[0; 24]);
        assert!(is_valid_trailer(4, &trailer));
        let mut trailer = vec![0x01, 0x04, 0x00, 0x18];
        trailer.extend_from_slice(&[0; 20]);
        trailer.extend_from_slice(&[0; 4]);
        assert!(is_valid_trailer(4, &trailer));
        // NTPv4 : un champ d'extension de 16 octets puis un MAC de 20.
        let mut trailer = vec![0x01, 0x04, 0x00, 0x10];
        trailer.extend_from_slice(&[0; 12]);
        trailer.extend_from_slice(&[0xCD; 20]);
        assert!(is_valid_trailer(4, &trailer));
        // NTPv4 : deux champs (36 et 104 octets, comme NTS), sans MAC.
        let mut trailer = vec![0x01, 0x04, 0x00, 0x24];
        trailer.extend_from_slice(&[0; 32]);
        trailer.extend_from_slice(&[0x02, 0x04, 0x00, 0x68]);
        trailer.extend_from_slice(&[0; 100]);
        assert!(is_valid_trailer(4, &trailer));
        // NTPv4 : MAC seul a condensat SHA-256, SHA-384, SHA-512.
        for length in [36, 52, 68] {
            assert!(is_valid_trailer(4, &vec![0x0c; length]));
        }
        // Avant NTPv4 : crypto-NAK, identifiant de cle et condensat DES, MD5,
        // SHA-1, et l'Extended Authenticator de [MS-SNTP].
        for length in [4, 12, 20, 24, 68, 72] {
            assert!(is_valid_trailer(3, &vec![0; length]));
        }
    }

    /// Synthetique : formes rejetees.
    #[test]
    fn test_trailer_rejects_unstructured_bytes() {
        // Longueur non multiple de quatre (33 octets : gnutella.pcap du
        // corpus nDPI, non versee, trame 1458).
        assert!(!is_valid_trailer(3, &[0; 33]));
        assert!(!is_valid_trailer(4, &[0; 85]));
        // NTPv4 : MAC de 8, 12 ou 16 octets.
        for length in [8, 12, 16] {
            assert!(!is_valid_trailer(4, &vec![0; length]));
        }
        // NTPv4 : champ d'extension trop court ou qui deborde.
        for declared in [0u16, 12, 200] {
            let mut trailer = vec![0x01, 0x04];
            trailer.extend_from_slice(&declared.to_be_bytes());
            trailer.extend_from_slice(&[0; 28]);
            assert!(!is_valid_trailer(4, &trailer), "longueur {declared}");
        }
        // NTPv4 : deux champs de 30 octets, qui pavent la fin mais ne sont
        // pas alignes sur quatre.
        let mut field = vec![0x01, 0x04, 0x00, 0x1e];
        field.extend_from_slice(&[0; 26]);
        let trailer = [field.clone(), field].concat();
        assert_eq!(trailer.len(), 60);
        assert!(!is_valid_trailer(4, &trailer));
        // Un crypto-NAK est un identifiant de cle nul : quatre autres octets
        // ne sont ni un NAK ni un MAC.
        for version in [3, 4] {
            assert!(!is_valid_trailer(version, &[0xAB; 4]));
        }
        // Avant NTPv4 : pas de champ d'extension, un MAC d'au plus 72 octets.
        for length in [8, 76, 1204] {
            assert!(!is_valid_trailer(3, &vec![0; length]));
        }
        // NTPv4 : un champ d'extension de 16 octets ne peut pas finir un
        // paquet sans MAC (RFC 5905 §7.5.1.4) ; 40 octets ne sont ni un MAC
        // ni un champ d'extension suivi d'un MAC.
        let mut trailer = vec![0x01, 0x04, 0x00, 0x10];
        trailer.extend_from_slice(&[0; 12]);
        assert!(!is_valid_trailer(4, &trailer));
        assert!(!is_valid_trailer(4, &[0x0c; 40]));
    }

    /// Au stratum 0, la sonde aveugle n'admet qu'un identifiant nul, ASCII
    /// ou `127.0.0.1` ; le premier label d'une requete DNS (`07 68 65 6c`)
    /// ou les octets d'un segment KCP (`01 00 00 00`) n'en sont pas.
    #[test]
    fn test_plausible_stratum_0_reference() {
        for bytes in [[0u8; 4], *b"RATE", *b"INIT", *b"USER", [127, 0, 0, 1]] {
            assert!(
                is_plausible_stratum_0_reference(&Refid::KissCode(bytes)),
                "{bytes:02x?}"
            );
        }
        for bytes in [
            [0x07, b'h', b'e', b'l'],
            [1, 0, 0, 0],
            [0xC3, 0xA9, 0xFF, 0xFE],
            [127, 0, 0, 2],
        ] {
            assert!(
                !is_plausible_stratum_0_reference(&Refid::KissCode(bytes)),
                "{bytes:02x?}"
            );
        }
        assert!(!is_plausible_stratum_0_reference(&Refid::Ipv4(
            Ipv4Addr::LOCALHOST
        )));
    }
}
