use serde::Serialize;

pub mod tcp;
pub mod udp;

#[derive(Debug, Clone, Serialize)]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Icmp,
    Unknown,
    None,
}

impl TransportProtocol {
    pub fn from_u8(value: u8) -> Self {
        match value {
            6 => TransportProtocol::Tcp,
            17 => TransportProtocol::Udp,
            1 => TransportProtocol::Icmp,
            0 => TransportProtocol::None,
            _ => TransportProtocol::Unknown,
        }
    }
}
