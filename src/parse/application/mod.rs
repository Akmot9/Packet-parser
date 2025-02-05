pub mod protocols;
use crate::{
    errors::application::ApplicationParseError,
    parse::application::protocols::ntp::NtpPacket,
};

/// The `ApplicationProtocol` enum represents the possible layer 7 information that can be parsed.
#[derive(Debug)]
pub enum ApplicationProtocol<'a> {
    Ntp(NtpPacket),

    Raw(&'a [u8]),

    None,
}

/// The `Application` struct contains information about the layer 7 protocol and its parsed data.
#[derive(Debug)]
pub struct Application<'a> {
    pub application_protocol: String,
    pub layer_7_protocol_infos: Option<ApplicationProtocol<'a>>,
}

impl<'a> TryFrom<&'a [u8]> for Application<'a> {
    type Error = ApplicationParseError;

    fn try_from(packet: &'a [u8]) -> Result<Self, Self::Error> {
        if packet.is_empty() {
            return Err(ApplicationParseError::EmptyPacket);
        }

        let parsers: &[(
            &str,
            fn(&[u8]) -> Result<ApplicationProtocol, ApplicationParseError>,
        )] = &[
            
            ("NTP", |data| {
                NtpPacket::try_from(data)
                    .map(ApplicationProtocol::Ntp)
                    .map_err(|_| ApplicationParseError::NtpParseError)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::application::Application;
    use std::convert::TryFrom;

    #[test]
    fn test_dns_packet_parsing() {
        let dns_payload = hex::decode("3155810000010001000000001a546f72696b31362d5452312d38322d3132382d3139342d3130350573756f6d69036e65740000010001c00c000100010000271000045280c269").expect("Invalid hex string");

        match Application::try_from(dns_payload.as_slice()) {
            Ok(parsed) => {
                println!("Parsed application protocol: {:?}", parsed);
                assert_eq!(parsed.application_protocol, "DNS");
            }
            Err(e) => {
                panic!("Failed to parse DNS packet: {:?}", e);
            }
        }
    }
}
