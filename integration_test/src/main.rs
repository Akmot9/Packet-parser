use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use packet_parser::ParsedPacket;
use std::convert::TryFrom;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PacketCaptureError {
    #[error("Interface {0} not found")]
    InterfaceNotFound(String),

    #[error("Failed to create channel: {0}")]
    ChannelCreationError(String),

    #[error("Failed to receive packet: {0}")]
    PacketReceiveError(String),

    #[error("Failed to parse packet: {0:?}")]
    PacketParseError(String),
}

fn find_interface(interface_name: &str) -> Result<NetworkInterface, PacketCaptureError> {
    let interfaces = datalink::interfaces();
    interfaces
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .ok_or_else(|| PacketCaptureError::InterfaceNotFound(interface_name.to_string()))
}

fn create_channel(interface: &NetworkInterface) -> Result<(Box<dyn datalink::DataLinkSender>, Box<dyn datalink::DataLinkReceiver>), PacketCaptureError> {
    match datalink::channel(interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => Ok((tx, rx)),
        Ok(_) => Err(PacketCaptureError::ChannelCreationError("Unhandled channel type".to_string())),
        Err(e) => Err(PacketCaptureError::ChannelCreationError(e.to_string())),
    }
}

fn main() -> Result<(), PacketCaptureError> {
    // Sélectionner l'interface réseau
    let interface_name = "wlp6s0"; // Exemple d'interface réseau wlp6s0 wlp0s20f3

    let interface = find_interface(interface_name)?;

    // Créer un canal pour recevoir les paquets
    let (_tx, mut rx) = create_channel(&interface)?;

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
            Err(e) => eprintln!("Error parsing packet: {:?}", PacketCaptureError::PacketParseError(e.to_string())),
        }
    }
}
