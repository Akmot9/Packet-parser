use packet_parser::{LinkType, parse};
use pcap_file::pcap::PcapReader;
use std::fs::File;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pcap_file_path = Path::new(
        "/home/erdt-cyber/rust/icsmaster/pcap/opc/opc-ua-ap-method-wireshark-freeze.pcap",
    );
    println!("Reading pcap file: {}", pcap_file_path.display());
    let mut reader = PcapReader::new(File::open(pcap_file_path)?)?;
    // Un pcap classique n'a qu'un seul LINKTYPE, dans son en-tete de fichier.
    let link_type = LinkType::from(u32::from(reader.header().datalink));
    let mut id = 0;
    while let Some(packet) = reader.next_raw_packet() {
        let packet = match packet {
            Ok(p) => p,
            Err(e) => {
                // Le lecteur ne consomme pas les octets fautifs : reessayer
                // bouclerait sur la meme erreur.
                eprintln!("pcap read error: {e}");
                break;
            }
        };
        id += 1;
        match parse(link_type, &packet.data) {
            Ok(flow) => println!("Packet {id}: {}", flow.to_owned()),
            Err(e) => eprintln!("parse error: {e} for packet {id}"),
        }
    }

    Ok(())
}
