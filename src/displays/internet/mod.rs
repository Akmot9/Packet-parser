use std::fmt;

use crate::parse::internet::{Internet, NetworkAddress};

impl<'a> fmt::Display for Internet<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Afficher au plus 16 octets pour éviter la saturation

        let payload = self.payload.unwrap_or(&[]); // Handle None case

        write!(
            f,
            "\n    Protocol: {}\n    Source IP: {}\n    Destination IP: {}\n    Payload ({} bytes)\n",
            self.protocol_name,
            self.source,
            self.destination,
            payload.len(),

        )
    }
}

impl<'a> fmt::Display for NetworkAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkAddress::Ip(ip) => write!(f, "{}", ip),
            NetworkAddress::Mac(mac) => write!(f, "{}", mac),
        }
    }
}
