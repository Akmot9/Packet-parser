mod ipaddress;
use crate::errors::network::NetworkError;
use ipaddress::IpAddress;

#[derive(Debug)]
pub struct Network<'a> {
    ip_destination: IpAddress,
    ip_source: IpAddress,
    transport_type: &'a str,
    payload: &'a [u8],
}

impl<'a> TryFrom<&'a [u8]> for Network<'a> {
    type Error = NetworkError;

    fn try_from(packets: &'a [u8]) -> Result<Self, Self::Error> {
        Ok(Network {
            ip_destination: IpAddress,
            ip_source: IpAddress,
            transport_type: todo!(),
            payload: todo!(),
        })
    }
}
