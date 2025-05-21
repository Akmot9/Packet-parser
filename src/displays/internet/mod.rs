use std::fmt;

use crate::parse::internet::InternetPacket;

impl<'a> fmt::Display for InternetPacket<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Afficher au plus 16 octets pour éviter la saturation
        let preview_len = 16;
        let hex_preview: String = self
            .payload
            .iter()
            .take(preview_len)
            .map(|b| format!("{:02X} ", b))
            .collect();

        let suffix = if self.payload.len() > preview_len {
            "..."
        } else {
            ""
        };

        write!(
            f,
            "\n    Protocol: {}\n    Source IP: {}\n    Destination IP: {}\n    Payload ({} bytes): [{}{}]\n",
            self.protocol_name,
            self.source,
            self.destination,
            self.payload.len(),
            hex_preview.trim_end(),
            suffix
        )
    }
}
