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
        match &value[..2] {
            [0x88, 0x92] => Ok(Protocol::ProfinetPacket),
            [0x88, 0xAB] => Ok(Protocol::Mrp),
            _ => Ok(Protocol::Unknown),
        }
    }
}
