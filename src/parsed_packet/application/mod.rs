pub mod protocols;
use crate::parsed_packet::application::protocols::{
    bitcoin::{parse_bitcoin_packet, BitcoinPacket},
    dhcp::{parse_dhcp_packet, DhcpPacket},
    http::{parse_http_request, HttpRequest},
    modbus::{parse_modbus_packet, ModbusPacket},
    ntp::{parse_ntp_packet, NtpPacket},
    tls::{parse_tls_packet, TlsPacket},
    dns::DnsPacket,
};


/// `Layer7Info` represents the possible layer 7 information that can be parsed.
#[derive(Debug)]
pub enum ApplicationProtocol {
    DnsPacket(DnsPacket),
    TlsPacket(TlsPacket),
    DhcpPacket(DhcpPacket),
    HttpRequest(HttpRequest),
    ModbusPacket(ModbusPacket),
    NtpPacket(NtpPacket),
    BitcoinPacket(BitcoinPacket),
    None,
}

/// `Layer7Infos` contains information about the layer 7 protocol and its parsed data.
#[derive(Debug)]
pub struct Application {
    pub application_protocol: String,
    pub layer_7_protocol_infos: Option<ApplicationProtocol>,
}

impl TryFrom<&[u8]> for Application {
    type Error = ApplicationParseError;

    fn try_from(packet: &[u8]) -> Result<Self, Self::Error> {
        if packet.is_empty() {
            return Err(ApplicationParseError::EmptyPacket);
        }

        // Attempt to parse each protocol and return the result if successful
        if let Ok(parsed_packet) = DnsPacket::try_from(packet) {
            return Ok(Application {
                application_protocol: "DNS".to_string(),
                layer_7_protocol_infos: Some(ApplicationProtocol::DnsPacket(parsed_packet)),
            });
        }
        // if let Ok(parsed_packet) = TlsPacket::try_from(packet) {
        //     return Ok(Application {
        //         application_protocol: "TLS".to_string(),
        //         layer_7_protocol_infos: Some(ApplicationProtocol::TlsPacket(parsed_packet)),
        //     });
        // }
        // if let Ok(parsed_packet) = DhcpPacket::try_from(packet) {
        //     return Ok(Application {
        //         application_protocol: "DHCP".to_string(),
        //         layer_7_protocol_infos: Some(ApplicationProtocol::DhcpPacket(parsed_packet)),
        //     });
        // }
        // if let Ok(parsed_packet) = HttpRequest::try_from(packet) {
        //     return Ok(Application {
        //         application_protocol: "HTTP".to_string(),
        //         layer_7_protocol_infos: Some(ApplicationProtocol::HttpRequest(parsed_packet)),
        //     });
        // }
        // if let Ok(parsed_packet) = ModbusPacket::try_from(packet) {
        //     return Ok(Application {
        //         application_protocol: "Modbus".to_string(),
        //         layer_7_protocol_infos: Some(ApplicationProtocol::ModbusPacket(parsed_packet)),
        //     });
        // }
        // if let Ok(parsed_packet) = NtpPacket::try_from(packet) {
        //     return Ok(Application {
        //         application_protocol: "NTP".to_string(),
        //         layer_7_protocol_infos: Some(ApplicationProtocol::NtpPacket(parsed_packet)),
        //     });
        // }
        // if let Ok(parsed_packet) = BitcoinPacket::try_from(packet) {
        //     return Ok(Application {
        //         application_protocol: "Bitcoin".to_string(),
        //         layer_7_protocol_infos: Some(ApplicationProtocol::BitcoinPacket(parsed_packet)),
        //     });
        // }

        // If no parser matches, return a "None" protocol
        Ok(Application {
            application_protocol: "Unknown".to_string(),
            layer_7_protocol_infos: None,
        })
    }
}

/// Errors related to parsing an `Application`
#[derive(Debug, thiserror::Error)]
pub enum ApplicationParseError {
    #[error("Packet is empty")]
    EmptyPacket,

    #[error("Failed to parse DNS packet")]
    DnsParseError,

    #[error("Failed to parse TLS packet")]
    TlsParseError,

    #[error("Failed to parse DHCP packet")]
    DhcpParseError,

    #[error("Failed to parse HTTP request")]
    HttpParseError,

    #[error("Failed to parse Modbus packet")]
    ModbusParseError,

    #[error("Failed to parse NTP packet")]
    NtpParseError,

    #[error("Failed to parse Bitcoin packet")]
    BitcoinParseError,
}
