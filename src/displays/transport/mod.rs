use crate::parse::transport::Transport;
use std::fmt;

impl<'a> fmt::Display for Transport<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let source_port = self
            .source_port
            .map(|p| p.to_string())
            .unwrap_or_else(|| "N/A".to_string());
        let dest_port = self
            .destination_port
            .map(|p| p.to_string())
            .unwrap_or_else(|| "N/A".to_string());
        let payload_len = self.payload.map(|p| p.len()).unwrap_or(0);

        write!(
            f,
            r#"
    protocol: {},
    source_port: {},
    destination_port: {},
    payload_length: {},
    "#,
            self.protocol, source_port, dest_port, payload_len,
        )
    }
}
