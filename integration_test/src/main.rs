use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use packet_parser::parsed_packet::ParsedPacket;
use std::convert::TryFrom;

fn main() {
    // Sélectionner l'interface réseau 'enp0s31f6'
    let interface_name = "enxfeaa81e86d1e"; //enxfeaa81e86d1e
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter()
        .find(|iface: &NetworkInterface| iface.name == interface_name)
        .expect(&format!("Interface {} not found", interface_name));
    
    // Créer un canal pour recevoir les paquets
    let (tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx), // Corrige l'expression pour inclure `tx`
        Ok(_) => panic!("packetdump: unhandled channel type"),
        Err(e) => panic!("packetdump: unable to create channel: {}", e),
    };

    loop {
        // Recevoir un paquet
        let packet = match rx.next() {
            Ok(packet) => packet,
            Err(e) => {
                eprintln!("Failed to receive packet: {}", e);
                continue;
            }
        };
        println!("Received packet: {:2X?}", packet);
        // Tenter de parser le paquet
        match ParsedPacket::try_from(packet) {
            Ok(parsed_packet) => println!("{}", parsed_packet),
            Err(e) => eprintln!("Error parsing packet: {:?}", e),
        }
    }
}
