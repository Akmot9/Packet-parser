// Copyright (c) 2024 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use std::{
    fmt::{self, Write},
    fs::File,
    io,
    path::Path,
    time::{Duration, SystemTime},
};

/// # PacketConverter
/// Une crate pour convertir et afficher des paquets réseau en Rust.
///
/// ## Fonctionnalités :
/// - Conversion d'une chaîne hexadécimale en `Vec<u8>`
/// - Conversion d'un `Vec<u8>` en chaîne hexadécimale
/// - Affichage formaté des paquets réseau
///   Structure représentant un paquet réseau.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub data: Vec<u8>,
}

impl Packet {
    /// Ecrit ce paquet dans un fichier PCAP a `path` (cree ou ecrase),
    /// horodate a l'instant de l'appel.
    ///
    /// Le fichier est un pcap classique (pas un pcapng) : version 2.4,
    /// `LINKTYPE_ETHERNET`, horodatage a la microseconde, `snaplen` de 65 535,
    /// dans le boutisme de la machine.
    ///
    /// # Errors
    ///
    /// Un paquet de plus de 65 535 octets est refuse avant toute ecriture : un
    /// fichier deja present a `path` reste alors intact. Les autres erreurs
    /// sont celles de la creation et de l'ecriture du fichier, et celle d'une
    /// horloge reglee avant 1970 ou apres 2106.
    pub fn packet_to_pcap(&self, path: impl AsRef<Path>) -> Result<(), Box<dyn std::error::Error>> {
        let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
        let image = pcap_image(timestamp, &self.data)?;
        io::Write::write_all(&mut File::create(path)?, &image)?;
        Ok(())
    }
}

/// Image d'un fichier pcap classique qui porte un seul paquet : l'en-tete
/// global de 24 octets, puis un enregistrement de 16 octets et les donnees.
///
/// Ecrite a la main : `pcap-file` ne servait qu'ici, et imposait a tout
/// appelant de `parse` ses propres dependances (#271). Elle reste l'oracle
/// des tests, qui comparent les deux sorties octet pour octet.
fn pcap_image(timestamp: Duration, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    const MAGIC_MICROSECONDS: u32 = 0xA1B2_C3D4;
    const VERSION: (u16, u16) = (2, 4);
    // Plus grande taille de paquet que le fichier annonce pouvoir porter.
    const SNAPLEN: u32 = 65_535;
    const LINKTYPE_ETHERNET: u32 = 1;
    const HEADERS_LEN: usize = 24 + 16;

    let len = match u32::try_from(data.len()) {
        Ok(len) if len <= SNAPLEN => len,
        _ => {
            let refusal = format!(
                "paquet de {} octets : un fichier pcap de snaplen {SNAPLEN} n'en porte pas autant",
                data.len()
            );
            return Err(io::Error::new(io::ErrorKind::InvalidInput, refusal).into());
        }
    };
    // Le format compte les secondes sur 32 bits non signes.
    let seconds = u32::try_from(timestamp.as_secs())?;

    let mut image = Vec::with_capacity(HEADERS_LEN + data.len());
    image.extend_from_slice(&MAGIC_MICROSECONDS.to_ne_bytes());
    image.extend_from_slice(&VERSION.0.to_ne_bytes());
    image.extend_from_slice(&VERSION.1.to_ne_bytes());
    image.extend_from_slice(&0_i32.to_ne_bytes()); // thiszone : UTC
    image.extend_from_slice(&0_u32.to_ne_bytes()); // sigfigs
    image.extend_from_slice(&SNAPLEN.to_ne_bytes());
    image.extend_from_slice(&LINKTYPE_ETHERNET.to_ne_bytes());

    image.extend_from_slice(&seconds.to_ne_bytes());
    image.extend_from_slice(&timestamp.subsec_micros().to_ne_bytes());
    image.extend_from_slice(&len.to_ne_bytes()); // incl_len : rien n'est tronque
    image.extend_from_slice(&len.to_ne_bytes()); // orig_len
    image.extend_from_slice(data);
    Ok(image)
}

/// Implémentation du trait `From<&str>` pour convertir une chaîne hexadécimale en `Packet`.
///
/// # Panics
///
/// Panique sur une chaîne de longueur impaire ou non hexadécimale : `From`
/// est infaillible par contrat. Pour une entrée utilisateur, passer par
/// [`try_hex_stream_to_bytes`] et construire `Packet { data }`.
impl From<&str> for Packet {
    fn from(hex: &str) -> Self {
        Packet {
            data: hex_stream_or_panic(hex),
        }
    }
}

/// Implémentation du trait `Display` pour afficher un paquet de manière lisible.
impl fmt::Display for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", format_hex_array(&self.data))
    }
}

/// Erreurs de conversion d'un flux hexadécimal.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HexStreamError {
    #[error("La chaîne hexadécimale doit avoir une longueur paire (longueur: {0})")]
    OddLength(usize),
    #[error("Valeur hex invalide: {0:?}")]
    InvalidDigit(String),
}

/// Convertit un flux hexadécimal Wireshark en `Vec<u8>`, sans paniquer sur une
/// entrée invalide.
pub fn try_hex_stream_to_bytes(hex: &str) -> Result<Vec<u8>, HexStreamError> {
    if !hex.len().is_multiple_of(2) {
        return Err(HexStreamError::OddLength(hex.len()));
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte_str = hex.get(i..i + 2).ok_or_else(|| {
            HexStreamError::InvalidDigit(hex.get(i..).unwrap_or_default().to_string())
        })?;
        let byte = u8::from_str_radix(byte_str, 16)
            .map_err(|_| HexStreamError::InvalidDigit(byte_str.to_string()))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

#[expect(
    clippy::panic,
    reason = "variante infaillible interne de From<&str> for Packet, panic documente"
)]
fn hex_stream_or_panic(hex: &str) -> Vec<u8> {
    match try_hex_stream_to_bytes(hex) {
        Ok(bytes) => bytes,
        Err(HexStreamError::OddLength(_)) => {
            panic!("La chaîne hexadécimale doit avoir une longueur paire")
        }
        Err(HexStreamError::InvalidDigit(_)) => panic!("Valeur hex invalide"),
    }
}

/// Convertit un slice `&[u8]` en une chaîne hexadécimale.
#[expect(clippy::unwrap_used, reason = "fmt::Write sur String est infaillible")]
pub fn bytes_to_hex_string(bytes: &[u8]) -> String {
    let mut hex_string = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut hex_string, "{byte:02X}").unwrap();
    }
    hex_string
}

/// Retourne un tableau formaté de bytes sous forme de chaîne Rust.
#[expect(clippy::unwrap_used, reason = "fmt::Write sur String est infaillible")]
pub fn format_hex_array(bytes: &[u8]) -> String {
    const BYTES_PER_LINE: usize = 8;

    if bytes.is_empty() {
        return "[\n];".to_string();
    }

    let mut out = String::from("[\n");

    for chunk in bytes.chunks(BYTES_PER_LINE) {
        out.push_str("    ");

        for (i, byte) in chunk.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            write!(&mut out, "0x{:02X}", byte).unwrap();
        }

        out.push_str(",\n");
    }

    out.push_str("];");
    out
}

/// Affiche un paquet réseau de manière lisible.
pub fn display_packet(bytes: &[u8]) {
    println!("Packet: {}", format_hex_array(bytes));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_hex_stream_or_panic_valid_ascii() {
        let hex = "48656C6C6F"; // "Hello"
        let expected = vec![0x48, 0x65, 0x6C, 0x6C, 0x6F];
        assert_eq!(hex_stream_or_panic(hex), expected);
    }

    #[test]
    fn test_hex_stream_or_panic_empty() {
        let hex = "";
        let expected: Vec<u8> = vec![];
        assert_eq!(hex_stream_or_panic(hex), expected);
    }

    #[test]
    fn test_hex_stream_or_panic_lowercase() {
        let hex = "deadbeef";
        let expected = vec![0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(hex_stream_or_panic(hex), expected);
    }

    #[test]
    fn test_try_hex_stream_to_bytes_valid() {
        assert_eq!(
            try_hex_stream_to_bytes("deadbeef"),
            Ok(vec![0xDE, 0xAD, 0xBE, 0xEF])
        );
    }

    #[test]
    fn test_try_hex_stream_to_bytes_odd_length() {
        assert_eq!(
            try_hex_stream_to_bytes("ABC"),
            Err(HexStreamError::OddLength(3))
        );
    }

    #[test]
    fn test_try_hex_stream_to_bytes_invalid_digit() {
        assert_eq!(
            try_hex_stream_to_bytes("ZZ"),
            Err(HexStreamError::InvalidDigit("ZZ".to_string()))
        );
    }

    #[test]
    #[should_panic(expected = "La chaîne hexadécimale doit avoir une longueur paire")]
    fn test_hex_stream_or_panic_odd_length_should_panic() {
        let _ = hex_stream_or_panic("ABC");
    }

    #[test]
    #[should_panic(expected = "Valeur hex invalide")]
    fn test_hex_stream_or_panic_invalid_hex_should_panic() {
        let _ = hex_stream_or_panic("ZZ");
    }

    #[test]
    fn test_bytes_to_hex_string_ascii() {
        let bytes = vec![0x48, 0x65, 0x6C, 0x6C, 0x6F];
        let expected = "48656C6C6F";
        assert_eq!(bytes_to_hex_string(&bytes), expected);
    }

    #[test]
    fn test_bytes_to_hex_string_empty() {
        let bytes: Vec<u8> = vec![];
        let expected = "";
        assert_eq!(bytes_to_hex_string(&bytes), expected);
    }

    #[test]
    fn test_bytes_to_hex_string_uppercase_output() {
        let bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let expected = "DEADBEEF";
        assert_eq!(bytes_to_hex_string(&bytes), expected);
    }

    #[test]
    fn test_format_hex_array_empty() {
        let bytes: Vec<u8> = vec![];
        let expected = "[\n];";
        assert_eq!(format_hex_array(&bytes), expected);
    }

    #[test]
    fn test_format_hex_array_single_line() {
        let bytes = vec![0x00, 0x01, 0x02];
        let expected = "[\n    0x00, 0x01, 0x02,\n];";
        assert_eq!(format_hex_array(&bytes), expected);
    }

    #[test]
    fn test_format_hex_array_exactly_one_full_line() {
        let bytes = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let expected = "[\n    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,\n];";
        assert_eq!(format_hex_array(&bytes), expected);
    }

    #[test]
    fn test_format_hex_array_multiple_lines() {
        let bytes = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];
        let expected = concat!(
            "[\n",
            "    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,\n",
            "    0x08, 0x09,\n",
            "];"
        );
        assert_eq!(format_hex_array(&bytes), expected);
    }

    #[test]
    fn test_packet_from_str() {
        let packet = Packet::from("48656C6C6F");
        let expected = Packet {
            data: vec![0x48, 0x65, 0x6C, 0x6C, 0x6F],
        };
        assert_eq!(packet, expected);
    }

    #[test]
    fn test_packet_display() {
        let packet = Packet::from("48656C6C6F");
        let expected = "[\n    0x48, 0x65, 0x6C, 0x6C, 0x6F,\n];";
        assert_eq!(packet.to_string(), expected);
    }

    #[test]
    fn test_packet_clone_and_eq() {
        let packet1 = Packet::from("DEADBEEF");
        let packet2 = packet1.clone();
        assert_eq!(packet1, packet2);
    }

    /// Chemin de sortie propre a un test, dans le repertoire temporaire : le
    /// chemin est celui que l'appelant donne, pas le repertoire courant.
    fn temp_pcap(test: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("packet_parser_{test}_{}.pcap", std::process::id()));
        let _ = fs::remove_file(&path);
        path
    }

    /// Ce que `pcap-file` ecrit pour le meme paquet et le meme horodatage.
    fn pcap_file_image(timestamp: Duration, data: &[u8]) -> Vec<u8> {
        use pcap_file::pcap::{PcapPacket, PcapWriter};

        let mut writer = PcapWriter::new(Vec::new()).unwrap();
        let orig_len = u32::try_from(data.len()).unwrap();
        writer
            .write_packet(&PcapPacket::new(timestamp, orig_len, data))
            .unwrap();
        writer.into_writer()
    }

    #[test]
    fn test_pcap_image_matches_pcap_file_byte_for_byte() {
        let frame = hex_stream_or_panic(
            "feaa81e86d1efeaa818ec864080045500034000000003d06206b36e6700dac140a02",
        );
        let largest = vec![0xA5; 65_535];
        let cases: [(Duration, &[u8]); 5] = [
            (Duration::new(1_763_251_200, 123_456_789), &frame),
            (Duration::new(0, 0), &[]),
            (Duration::new(1, 999_999_999), &[0x00]),
            (Duration::new(u64::from(u32::MAX), 999_000), &frame),
            (Duration::new(1_763_251_200, 0), &largest),
        ];

        for (timestamp, data) in cases {
            assert_eq!(
                pcap_image(timestamp, data).unwrap(),
                pcap_file_image(timestamp, data),
                "paquet de {} octets a {timestamp:?}",
                data.len()
            );
        }
    }

    #[test]
    fn test_pcap_image_rejects_a_packet_over_the_snaplen() {
        let too_long = vec![0; 65_536];

        let error = pcap_image(Duration::new(1, 0), &too_long).unwrap_err();

        let error = error.downcast_ref::<io::Error>().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("65536"), "{error}");
    }

    #[test]
    fn test_pcap_image_rejects_a_timestamp_past_32_bits() {
        let past_2106 = Duration::new(u64::from(u32::MAX) + 1, 0);

        assert!(pcap_image(past_2106, &[0x00]).is_err());
    }

    #[test]
    fn test_packet_to_pcap_is_read_back_by_pcap_file() {
        use pcap_file::{DataLink, TsResolution, pcap::PcapReader};

        let pcap_path = temp_pcap("read_back");
        let packet = Packet::from("48656C6C6F");
        let before = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();

        packet.packet_to_pcap(&pcap_path).unwrap();

        let mut reader = PcapReader::new(fs::File::open(&pcap_path).unwrap()).unwrap();
        let header = reader.header();
        assert_eq!((header.version_major, header.version_minor), (2, 4));
        assert_eq!(header.datalink, DataLink::ETHERNET);
        assert_eq!(header.snaplen, 65_535);
        assert_eq!(header.ts_resolution, TsResolution::MicroSecond);

        let read = reader.next_packet().unwrap().unwrap();
        assert_eq!(&*read.data, packet.data.as_slice());
        assert_eq!(read.orig_len, 5);
        // A la microseconde pres : le fichier ne garde pas les nanosecondes.
        assert!(read.timestamp + Duration::from_micros(1) > before);
        assert!(read.timestamp < before + Duration::from_secs(60));
        assert!(reader.next_packet().is_none());

        fs::remove_file(&pcap_path).unwrap();
    }

    #[test]
    fn test_packet_to_pcap_leaves_an_existing_file_alone_when_it_refuses() {
        let pcap_path = temp_pcap("refused");
        fs::write(&pcap_path, b"deja la").unwrap();
        let packet = Packet {
            data: vec![0; 65_536],
        };

        assert!(packet.packet_to_pcap(&pcap_path).is_err());

        assert_eq!(fs::read(&pcap_path).unwrap(), b"deja la");
        fs::remove_file(&pcap_path).unwrap();
    }
}
