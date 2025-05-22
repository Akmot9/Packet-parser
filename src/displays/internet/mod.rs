use std::fmt;

use crate::parse::internet::Internet;

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
