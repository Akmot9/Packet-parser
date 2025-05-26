use crate::parse::transport::{protocols::TransportProtocol, Transport};
use std::fmt;

impl<'a> fmt::Display for Transport<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let source_port = self
            .source_port
            .map(|p| p.to_string())
            .unwrap_or_else(|| "N/A".to_string());
        let dest_port = self
            .destination_port
            .map(|p| p.to_string())
            .unwrap_or_else(|| "N/A".to_string());
        let payload_len = self.payload.map(|p| p.len()).unwrap_or(0);

        write!(
            f,
            r#"
    protocol: {},
    source_port: {},
    destination_port: {},
    payload_length: {},
    "#,
            self.protocol, source_port, dest_port, payload_len,
        )
    }
}

impl fmt::Display for TransportProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let protocol_str = match self {
            TransportProtocol::Tcp => "TCP",
            TransportProtocol::Udp => "UDP",
            TransportProtocol::Icmp => "ICMP",
            TransportProtocol::None => "None",
            TransportProtocol::Unknown => "Unknown",
        };
        write!(f, "{}", protocol_str)
    }
}