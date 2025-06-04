use crate::parse::application::{Application, protocols::ApplicationProtocol};
use std::fmt;

impl fmt::Display for Application {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ", self.application_protocol)
    }
}

impl<'a> fmt::Display for ApplicationProtocol<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApplicationProtocol::Ntp(_) => write!(f, "NTP"),
            ApplicationProtocol::Tls(_) => write!(f, "TLS"),
            ApplicationProtocol::Http(_) => write!(f, "HTTP"),
            ApplicationProtocol::Mqtt(_) => write!(f, "MQTT"),
            ApplicationProtocol::Dhcp(_) => write!(f, "DHCP"),
            ApplicationProtocol::Bitcoin(_) => write!(f, "Bitcoin"),
            ApplicationProtocol::Dns(_) => write!(f, "DNS"),
            ApplicationProtocol::S7Comm(_) => write!(f, "S7Comm"),
            ApplicationProtocol::Cotp(_) => write!(f, "COTP"),
            ApplicationProtocol::Raw(data) => {
                let preview_len = 16.min(data.len());
                let hex_preview: String = data[..preview_len]
                    .iter()
                    .map(|&b| format!("{:02X}", b))
                    .collect::<Vec<_>>()
                    .join(" ");

                if data.len() > preview_len {
                    write!(f, "Raw [{} bytes]: {}...", data.len(), hex_preview)
                } else {
                    write!(f, "Raw [{} bytes]: {}", data.len(), hex_preview)
                }
            }
            ApplicationProtocol::None => write!(f, "None"),
        }
    }
}
