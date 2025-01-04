pub mod ipaddress;
mod protocols;

use crate::errors::network::NetworkError;
use ipaddress::IpAddress;
use protocols::Protocol;
use std::convert::TryFrom;

#[derive(Debug)]
pub struct Network<'a> {
    /// Adresse IP de destination.
    ip_destination: IpAddress,

    /// Adresse IP source.
    ip_source: IpAddress,

    /// Type de transport (par exemple, "TCP" ou "UDP").
    transport_type: &'a str,

    /// Charge utile des données.
    payload: &'a [u8],

    /// Le protocole analysé.
    parced_packet: Protocol,
}

impl<'a> TryFrom<&'a [u8]> for Network<'a> {
    type Error = NetworkError;

    fn try_from(packets: &'a [u8]) -> Result<Self, Self::Error> {
        // Étape 1 : Décoder le protocole réseau à partir des paquets bruts.
        let network_protocol = Protocol::try_from(packets)?;

        // Étape 2 : Extraire les adresses IP source et destination.
        let ip_destination = IpAddress::try_from(network_protocol.destination)?;
        let ip_source = IpAddress::try_from(network_protocol.source)?;

        // Étape 3 : Déterminer le type de transport et le payload.
        let transport_type = network_protocol.transport_type;
        let payload = network_protocol.payload;

        Ok(Network {
            ip_destination,
            ip_source,
            transport_type,
            payload,
            parced_packet: network_protocol,
        })
    }
}
