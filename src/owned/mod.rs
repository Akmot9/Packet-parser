use std::{hash::Hasher, net::IpAddr};

use serde::Serialize;

use crate::{Application, PacketFlow};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PacketFlowOwned {
    #[serde(flatten)]
    pub data_link: DataLinkOwned,
    #[serde(flatten)]
    pub internet: Option<InternetOwned>,
    #[serde(flatten)]
    pub transport: Option<TransportOwned>,
    #[serde(flatten)]
    pub application: Option<Application>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Hash, Eq)]
pub struct DataLinkOwned {
    pub destination_mac: String,
    /// The source MAC address as a string.
    pub source_mac: String,
    /// The Ethertype of the packet, indicating the protocol in the payload.
    pub ethertype: String,
}



#[derive(Debug, Clone, Serialize, PartialEq, Hash, Eq)]
pub struct InternetOwned {
    pub source_ip: Option<IpAddr>,
    pub destination_ip: Option<IpAddr>,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Hash, Eq)]
pub struct TransportOwned {
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ApplicationOwned {
    pub protocol: String,
}

impl<'a> From<PacketFlow<'a>> for PacketFlowOwned {
    fn from(flow: PacketFlow<'a>) -> Self {
        Self {
            data_link: DataLinkOwned {
                destination_mac: flow.data_link.destination_mac,
                source_mac: flow.data_link.source_mac,
                ethertype: flow.data_link.ethertype,
            },
            internet: match flow.internet {
                Some(internet) => Some(InternetOwned {
                    source_ip: internet.source,
                    destination_ip: internet.destination,
                    protocol: internet.protocol_name,
                }),
                None => None,
            },
            transport: match flow.transport {
                Some(transport) => Some(TransportOwned {
                    source_port: transport.source_port,
                    destination_port: transport.destination_port,
                    protocol: transport.protocol.to_string(),
                }),
                None => None,
            },
            application: match flow.application {
                Some(application) => Some(Application {
                    application_protocol: application.application_protocol,
                }),
                None => None,
            },
        }
    }
}


use std::hash::Hash;
impl Hash for PacketFlowOwned {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.data_link.hash(state);
        self.internet.hash(state);
        self.transport.hash(state);
        self.application.hash(state);
    }
}
