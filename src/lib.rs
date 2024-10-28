pub mod parsed_packet;

mod errors;
mod validations;

pub use parsed_packet::ParsedPacket;

// struct ParsedPacket {
//     DataLink: DataLink,
//     size: usize,
// }

// struct DataLink {
//     destination_mac: MacAddress,
//     source_mac: MacAddress,
//     ethertype: u16,
//     payload: Option<Network>,
// }

// struct Network {
//     destination_oui: String,
//     ip_source: String,
//     ip_destination: String,
//     payload: Transport,
// }

// struct Transport {
//     protocole: String,
//     port_source: u16,
//     port_destination: u16,
//     payload: Application,       
// }

// struct Application {
//     protocole: String,
//     payload: Vec<u8>,
// }




// pub fn parse_packet(packet: &[u8]) {
//     println!("Packet received: {:02X?}", packet);

//     // Vérification que le paquet est assez long pour contenir une en-tête Ethernet
//     if packet.len() >= 14 {
//         // Extraction des adresses MAC source et destination
//         let destination_mac = MacAddress::from_bytes(&packet[0..6]).unwrap();
//         let source_mac = MacAddress::from_bytes(&packet[6..12]).unwrap();
//         let ethertype = u16::from_be_bytes([packet[12], packet[13]]);

//         // Extraction des OUI
//         let destination_oui = get_oui(&destination_mac);
//         let source_oui = get_oui(&source_mac);

//         println!("Destination MAC: {}", destination_mac);
//         println!("Source MAC: {}", source_mac);
//         println!("Destination OUI: {}", destination_oui);
//         println!("Source OUI: {}", source_oui);
//         println!("EtherType: 0x{:04X} ({})", ethertype, get_protocol_name(ethertype));
//     } else {
//         println!("Packet too short to contain Ethernet header");
//     }
// }

// // Fonction pour extraire l'OUI d'une adresse MAC
// fn get_oui(mac: &MacAddress) -> String {
//     // Récupère les 3 premiers octets de l'adresse MAC pour l'OUI
//     let bytes = mac.to_bytes();
//     format!("{:02X}-{:02X}-{:02X}", bytes[0], bytes[1], bytes[2])
// }

// // Fonction qui retourne le nom du protocole correspondant à l'EtherType
// fn get_protocol_name(ethertype: u16) -> &'static str {
//     match ethertype {
//         0x0800 => "IPv4",
//         0x0806 => "ARP",
//         0x86DD => "IPv6",
//         0x8847 => "MPLS Unicast",
//         0x8848 => "MPLS Multicast",
//         0x8100 => "VLAN-tagged frame (IEEE 802.1Q)",
//         0x88CC => "LLDP (Link Layer Discovery Protocol)",
//         0x8809 => "Ethernet Slow Protocols (LACP, Marker Protocol)",
//         _ => "Unknown",
//     }
// }
