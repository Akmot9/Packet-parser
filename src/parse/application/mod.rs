pub mod protocols;
use crate::{
    errors::application::ApplicationParseError, parse::application::protocols::ntp::NtpPacket,
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

        if let Ok(ntp_packet) = NtpPacket::try_from(packet) {
            return Ok(Application {
                application_protocol: "NTP".to_string(),
                layer_7_protocol_infos: Some(ApplicationProtocol::Ntp(ntp_packet)),
            });
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
}
