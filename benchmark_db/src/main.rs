use packet_parser::parse::PacketFlow;

use std::{convert::TryFrom, fs, path::Path};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PacketCaptureError {
    #[error("Failed to receive packet: {0}")]
    PacketReceiveError(String),

    #[error("Failed to parse packet: {0}")]
    PacketParseError(String),

    #[error(transparent)]
    PcapOpenError {
        #[from]
        source: pcap::Error,
    },

    #[error(transparent)]
    IoError {
        #[from]
        source: std::io::Error,
    },
}

fn main() -> Result<(), PacketCaptureError> {
    // Dossier contenant les fichiers .pcap
    let pcap_dir = Path::new("/home/erdt-cyber/exemple_pcap/801q");

    // Itérer sur les fichiers du dossier
    for entry in fs::read_dir(pcap_dir)? {
        let entry = entry?;
        let path = entry.path();

        // Filtrer uniquement les .pcap / .pcapng selon ton besoin
        let is_pcap = path.extension().and_then(|s| s.to_str()) == Some("pcap");
        if !is_pcap {
            continue;
        }

        println!("===============================");
        println!("Opening PCAP: {}", path.display());
        let mut cap = match pcap::Capture::from_file(&path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("pcap open failed for {}: {}", path.display(), e);
                eprintln!("pcap open debug: {:?}", e);
                return Err(PacketCaptureError::PcapOpenError { source: e });
            }
        };

        // Ouvrir le fichier PCAP
        let mut cap = pcap::Capture::from_file(&path)?;
        let mut counter = 0;
        let mut erreur = 0;
        // Lire les paquets
        loop {
            let packet = match cap.next_packet() {
                Ok(packet) => packet,
                Err(pcap::Error::NoMorePackets) => break, // fin du fichier
                Err(e) => {
                    eprintln!("Failed to receive packet: {}", e);
                    continue;
                }
            };

            // println!("--------------");
            // // packet.data est un &[u8]
            // println!("Received packet bytes: {:2X?}", packet.data);
            println!("taille du paquet: {}", &packet.data.len());
            // Parser via l’impl TryFrom<&[u8]>
            match PacketFlow::try_from(packet.data) {
                
                Ok(parsed_packet) => {
                    // println!("pas encore {}", counter);
                    let start = std::time::Instant::now();
                    // Si tu as un modèle "owned", ok.
                    // Attention: `to_owned()` sur un type peut faire autre chose selon ton impl.
                    let owned_json = parsed_packet.to_owned();
                    println!("owned_json: {}", owned_json);
                    counter += 1;
                    let duration = start.elapsed();
                    println!("temps pour parser: {}", duration.as_nanos());
                }
                Err(e) => {
                    eprintln!("Error parsing packet: {}", e); 
                    counter += 1;
                    erreur += 1;
                    println!("{:?} pour le {}", packet.data, counter);
                    
                },
            }
        }
        println!("{} paquets parseés", counter);
        println!("{} paquets non parseés", erreur);
    }

    Ok(())
}
