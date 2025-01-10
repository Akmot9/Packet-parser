use crate::errors::network::protocol::NetworkProtocolError;

mod mrp;
mod profinet;
mod ipv4;

#[derive(Debug)]
pub enum Protocol {
    ProfinetPacket,
    Mrp,
    Unknown,
}

impl TryFrom<&[u8]> for Protocol {
    type Error = NetworkProtocolError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        match value {
            Ok(Protocol::ProfinetPacket),
            Ok(Protocol::Mrp),
            _ => Ok(Protocol::Unknown),
        }
    }
}
