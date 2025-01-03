mod mrp;
mod profinet;
// use profinet::ProfinetPacket;

use crate::errors::data_link::DataLinkError;
#[derive(Debug)]
pub enum DataLinkProtocol {
    ProfinetPacket,
    Mrp,
    Unknown,
}

impl TryFrom<&[u8]> for DataLinkProtocol {
    type Error = DataLinkError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        match &value[..2] {
            [0x88, 0x92] => Ok(DataLinkProtocol::ProfinetPacket),
            [0x88, 0xAB] => Ok(DataLinkProtocol::Mrp),
            _ => Ok(DataLinkProtocol::Unknown),
        }
    }
}
