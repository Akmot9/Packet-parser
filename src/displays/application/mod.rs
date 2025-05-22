use std::fmt;
use crate::parse::application::{Application, protocols::ApplicationProtocol};

impl<'a> fmt::Display for Application<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ", self.application_protocol)
    }
}

impl<'a> fmt::Display for ApplicationProtocol<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApplicationProtocol::Ntp(_ntp) => write!(f, "NTP"),
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
            },
            ApplicationProtocol::None => write!(f, "None"),
        }
    }
}
