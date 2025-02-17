pub mod protocols;
// use protocols::NetworkProtocol;

// #[derive(Debug, Clone)]
// pub struct NetworkPacket {
//     pub ip_source: std::net::IpAddr,
//     pub ip_destination: std::net::IpAddr,
//     pub protocol: NetworkProtocol,
//     pub payload: Vec<u8>,
// }

// impl<'a> TryFrom<&'a [u8]> for NetworkPacket<'a> {
//     type Error = NetworkPacketParseError;

//     fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
//         let protocol = NetworkProtocol::try_from(value)?;
//         Ok(NetworkPacket {
//             ip_source: protocol.ip,
//             ip_destination: protocol.ip,
//             protocol,
//             payload: protocol.payload,
//         })
//     }
// }
