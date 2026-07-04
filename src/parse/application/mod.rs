// Copyright (c) 2024 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

pub mod protocols;
use protocols::{
    bitcoin::BitcoinPacket, dns::DnsPacket, ethernet_ip::EtherNetIpPacket, s7comm::S7CommPacket,
    snmp::SnmpPacket, tls::TlsPacket,
};
use serde::Serialize;

use crate::{
    errors::application::ApplicationError,
    parse::application::protocols::{
        giop::GiopPacket, modbus_tcp::ModbusTcpPacket, ntp::NtpPacket, opcua::OpcuaPacket,
        postgresql::is_likely_postgresql_payload, quic::QuicPacket, srvloc::SrvlocPacket,
    },
};

/// The `Application` struct contains information about the layer 7 protocol and its parsed data.
#[derive(Debug, Clone, Serialize, Eq)]
pub struct Application {
    pub application_protocol: &'static str,
}

impl TryFrom<&[u8]> for Application {
    type Error = ApplicationError;

    fn try_from(packet: &[u8]) -> Result<Self, Self::Error> {
        if packet.is_empty() {
            return Err(ApplicationError::EmptyPacket);
        }

        if NtpPacket::try_from(packet).is_ok() {
            return Ok(Application {
                application_protocol: "NTP",
            });
        }

        if BitcoinPacket::try_from(packet).is_ok() {
            return Ok(Application {
                application_protocol: "Bitcoin",
            });
        }
        if OpcuaPacket::try_from(packet).is_ok() {
            return Ok(Application {
                application_protocol: "OPC UA",
            });
        }
        if EtherNetIpPacket::try_from(packet).is_ok() {
            return Ok(Application {
                application_protocol: "EtherNet/IP",
            });
        }
        if is_likely_postgresql_payload(packet) {
            return Ok(Application {
                application_protocol: "PostgreSQL",
            });
        }
        if DnsPacket::try_from(packet).is_ok() {
            return Ok(Application {
                application_protocol: "DNS",
            });
        }
        if SnmpPacket::try_from(packet).is_ok() {
            return Ok(Application {
                application_protocol: "SNMP",
            });
        }
        if TlsPacket::try_from(packet).is_ok() {
            return Ok(Application {
                application_protocol: "TLS",
            });
        }
        if S7CommPacket::try_from(packet).is_ok() {
            return Ok(Application {
                application_protocol: "S7Comm",
            });
        }
        if GiopPacket::try_from(packet).is_ok() {
            return Ok(Application {
                application_protocol: "GIOP",
            });
        }
        if SrvlocPacket::try_from(packet).is_ok() {
            return Ok(Application {
                application_protocol: "SRVLOCK",
            });
        }
        if ModbusTcpPacket::try_from(packet).is_ok() {
            return Ok(Application {
                application_protocol: "ModbusTCP",
            });
        }
        // if Dhcpv6Packet::try_from(packet).is_ok() {
        //     return Ok(Application {
        //         application_protocol: "DHCPv6",
        //     });
        // }
        // if AmsPacket::try_from(packet).is_ok() {
        //     return Ok(Application {
        //         application_protocol: "AMS",
        //     });
        // }

        // if CotpHeader::from_bytes(packet).is_ok() {
        //     return Ok(Application {
        //         application_protocol: "COTP",
        //     });
        // }
        if QuicPacket::try_from(packet).is_ok() {
            return Ok(Application {
                application_protocol: "QUIQ",
            });
        }
        // If no parser matches, return a "None" protocol
        Ok(Application {
            application_protocol: "Unknown",
        })
    }
}

impl PartialEq for Application {
    fn eq(&self, other: &Self) -> bool {
        self.application_protocol == other.application_protocol
    }
}

use std::hash::{Hash, Hasher};

impl Hash for Application {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.application_protocol.hash(state);
    }
}

#[cfg(test)]
mod tests {

    use crate::parse::application::Application;
    use std::convert::TryFrom;

    #[test]
    fn test_ntp_packet_parsing() {
        let ntp_payload = hex::decode("d9000afa000000000001029000000000000000000000000000000000000000000000000000000000c50204ecec42ee92").expect("Invalid hex string");

        match Application::try_from(ntp_payload.as_slice()) {
            Ok(parsed) => {
                println!("Parsed application protocol: {:?}", parsed);
                assert_eq!(parsed.application_protocol, "NTP");
            }
            Err(e) => {
                panic!("Failed to parse DNS packet: {:?}", e);
            }
        }
    }

    #[test]
    fn test_postgresql_packet_detection_from_payload() {
        let query = b"select 1\0";
        let mut payload = Vec::new();
        payload.push(b'Q');
        payload.extend_from_slice(&(4 + query.len() as u32).to_be_bytes());
        payload.extend_from_slice(query);

        let parsed = Application::try_from(payload.as_slice()).unwrap();

        assert_eq!(parsed.application_protocol, "PostgreSQL");
    }

    #[test]
    fn test_postgresql_weak_shape_is_not_detected_from_payload() {
        let payload = [b'S', 0x00, 0x00, 0x00, 0x04];

        let parsed = Application::try_from(payload.as_slice()).unwrap();

        assert_ne!(parsed.application_protocol, "PostgreSQL");
    }
}
