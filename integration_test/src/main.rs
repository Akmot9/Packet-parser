use packet_parser::parse::PacketFlow;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
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

fn create_channel(
    interface: &NetworkInterface,
) -> Result<
    (
        Box<dyn datalink::DataLinkSender>,
        Box<dyn datalink::DataLinkReceiver>,
    ),
    PacketCaptureError,
> {
    match datalink::channel(interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => Ok((tx, rx)),
        Ok(_) => Err(PacketCaptureError::ChannelCreationError(
            "Unhandled channel type".to_string(),
        )),
        Err(e) => {
            eprintln!(
                "use sudo setcap cap_net_raw,cap_net_admin=eip target/debug/integration_test"
            );
            Err(PacketCaptureError::ChannelCreationError(e.to_string()))
        }
    }
}

fn main() -> Result<(), PacketCaptureError> {
    // Sélectionner l'interface réseau
    let interface_name = "wlp0s20f3"; // Exemple d'interface réseau maison : wlp6s0 wlp0s20f3 enxfeaa81e86d1e veth0

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
        println!("--------------");
        println!("Received packet: {:2X?}", packet);

        // Tenter de parser le paquet
        match PacketFlow::try_from(packet) {
            Ok(parsed_packet) => {
                println!("=== Version avec to_string() ===");
                println!("{}", parsed_packet);

                println!("\n=== Version avec to_owned() ===");
                let owned_json = parsed_packet.to_owned();
                println!("{}", owned_json);
            }
            Err(e) => eprintln!(
                "Error parsing packet: {}",
                PacketCaptureError::PacketParseError(e.to_string())
            ),
        }
    }
}
