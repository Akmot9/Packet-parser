pub mod protocols;
use crate::{
    determine::application::protocols::{
        bitcoin::BitcoinPacket,
        dhcp::DhcpPacket,
        dns::DnsPacket,
        http::HttpRequest,
        
        ntp::NtpPacket,
        tls::TlsPacket,
    },
    errors::application::ApplicationParseError,
};

/// The `ApplicationProtocol` enum represents the possible layer 7 information that can be parsed.
#[derive(Debug)]
pub enum ApplicationProtocol<'a> {
    Dns(DnsPacket),
    Tls(TlsPacket),
    Dhcp(DhcpPacket),
    Http(HttpRequest),
    Ntp(NtpPacket),
    Bitcoin(BitcoinPacket),

    Raw(&'a [u8]),

    None,
}

/// The `Application` struct contains information about the layer 7 protocol and its parsed data.
#[derive(Debug)]
pub struct Application<'a> {
    pub application_protocol: String,
    pub layer_7_protocol_infos: Option<ApplicationProtocol<'a>>,
}

impl<'a> TryFrom< &'a [u8]> for Application<'a> {
    type Error = ApplicationParseError;

    fn try_from(packet: &'a [u8]) -> Result<Self, Self::Error> {
        if packet.is_empty() {
            return Err(ApplicationParseError::EmptyPacket);
        }

        let parsers: &[(
            &str,
            fn(&[u8]) -> Result<ApplicationProtocol, ApplicationParseError>,
        )] = &[
            ("DNS", |data| {
                DnsPacket::try_from(data)
                    .map(ApplicationProtocol::Dns)
                    .map_err(|_| ApplicationParseError::DnsParseError)
            }),
            ("TLS", |data| {
                TlsPacket::try_from(data)
                    .map(ApplicationProtocol::Tls)
                    .map_err(|_| ApplicationParseError::TlsParseError)
            }),
            ("DHCP", |data| {
                DhcpPacket::try_from(data)
                    .map(ApplicationProtocol::Dhcp)
                    .map_err(|_| ApplicationParseError::DhcpParseError)
            }),
            ("HTTP", |data| {
                HttpRequest::try_from(data)
                    .map(ApplicationProtocol::Http)
                    .map_err(|_| ApplicationParseError::HttpParseError)
            }),
            ("NTP", |data| {
                NtpPacket::try_from(data)
                    .map(ApplicationProtocol::Ntp)
                    .map_err(|_| ApplicationParseError::NtpParseError)
            }),
            ("Bitcoin", |data| {
                BitcoinPacket::try_from(data)
                    .map(ApplicationProtocol::Bitcoin)
                    .map_err(|_| ApplicationParseError::BitcoinParseError)
            }),
        ];

        for (protocol_name, parser) in parsers {
            if let Ok(parsed_protocol) = parser(packet) {
                return Ok(Application {
                    application_protocol: protocol_name.to_string(),
                    layer_7_protocol_infos: Some(parsed_protocol),
                });
            }
        }

        // If no parser matches, return a "None" protocol
        Ok(Application {
            application_protocol: "Unknown".to_string(),
            layer_7_protocol_infos: Some(ApplicationProtocol::Raw(packet)), // Utilisation correcte avec 'a
        })
    }
}
