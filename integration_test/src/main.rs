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

    #[error("Failed to parse packet: {0}")]
    PacketParseError(String),

    #[error("Failed to serialize packet to JSON: {0}")]
    JsonError(String),
}

fn find_interface(interface_name: &str) -> Result<NetworkInterface, PacketCaptureError> {
    datalink::interfaces()
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
                "Hint: sudo setcap cap_net_raw,cap_net_admin=eip target/debug/integration_test"
            );
            Err(PacketCaptureError::ChannelCreationError(e.to_string()))
        }
    }
}

fn main() -> Result<(), PacketCaptureError> {
    let interface_name = "en0";
    let interface = find_interface(interface_name)?;
    let (_tx, mut rx) = create_channel(&interface)?;

    loop {
        let packet = rx
            .next()
            .map_err(|e| PacketCaptureError::PacketReceiveError(e.to_string()))?;

        println!("--------------");
        println!("Received packet: {:02X?}", packet);

        match PacketFlow::try_from(packet) {
            Ok(parsed_packet) => {
                // 1) rendu humain (Display)
                println!("=== Parsed (Display) ===");
                println!("{parsed_packet}");

                // 2) version owned sérialisable
                let owned = parsed_packet.to_owned();

                // 3) JSON compact (recommandé pour fichier / IPC)
                let json = serde_json::to_string(&owned)
                    .map_err(|e| PacketCaptureError::JsonError(e.to_string()))?;
                println!("=== Owned (JSON) ===");
                println!("{json}");

                // Option debug lisible:
                // let json_pretty = serde_json::to_string_pretty(&owned)
                //     .map_err(|e| PacketCaptureError::JsonError(e.to_string()))?;
                // println!("{json_pretty}");
            }
            Err(e) => eprintln!("{}", PacketCaptureError::PacketParseError(e.to_string())),
        }
    }
}
