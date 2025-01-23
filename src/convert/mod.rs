
use std::{fmt, fs::File};
use pcap_file::pcap::{PcapPacket, PcapWriter};


/// # PacketConverter
/// Une crate pour convertir et afficher des paquets réseau en Rust.
///
/// ## Fonctionnalités :
/// - Conversion d'une chaîne hexadécimale en `Vec<u8>`
/// - Conversion d'un `Vec<u8>` en chaîne hexadécimale
/// - Affichage formaté des paquets réseau
///

/// Structure représentant un paquet réseau.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub data: Vec<u8>,
}

impl Packet {
    pub fn packet_to_pcap(&self) -> Result<(), Box<dyn std::error::Error>>  {
        let file = File::create("output.pcap")?;
    
    // Configurer le PacketWriter avec les paramètres par défaut
    let writer = PcapWriter::new(file);

    let orig_len = self.data.len() as u32;
    let timestamp: std::time::Duration = std::time::SystemTime::now().duration_since(std::time::SystemTime::UNIX_EPOCH)?.into();
    let paccket = PcapPacket::new(timestamp, orig_len, &self.data);
    
    // Ajouter les données du paquet
    writer?.write_packet(&paccket)?;
    
    Ok(())
    }
}

/// Implémentation du trait `From<&str>` pour convertir une chaîne hexadécimale en `Packet`.
impl From<&str> for Packet {
    fn from(hex: &str) -> Self {
        Packet {
            data: hex_stream_to_bytes(hex),
        }
    }
}

/// Implémentation du trait `Display` pour afficher un paquet de manière lisible.
impl fmt::Display for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", format_hex_array(&self.data))
    }
}

/// Convertit un flux hexadécimal Wireshark en `Vec<u8>`.
pub fn hex_stream_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    assert!(hex.len() % 2 == 0, "La chaîne hexadécimale doit avoir une longueur paire");
    for i in (0..hex.len()).step_by(2) {
        let byte_str = &hex[i..i + 2];
        let byte = u8::from_str_radix(byte_str, 16).expect("Valeur hex invalide");
        bytes.push(byte);
    }
    bytes
}

/// Convertit un slice `&[u8]` en une chaîne hexadécimale.
pub fn bytes_to_hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{:02X}", byte)).collect()
}

/// Retourne un tableau formaté de bytes sous forme de chaîne Rust.
pub fn format_hex_array(bytes: &[u8]) -> String {
    let mut formatted = String::from("[\n");
    for (i, byte) in bytes.iter().enumerate() {
        formatted.push_str(&format!("    0x{:02X},", byte));
        if (i + 1) % 8 == 0 {
            formatted.push('\n');
        } else {
            formatted.push(' ');
        }
    }
    formatted.push_str("\n];");
    formatted
}

/// Affiche un paquet réseau de manière lisible.
pub fn display_packet(bytes: &[u8]) {
    println!("Packet: {}", format_hex_array(bytes));
}
