use crate::errors::application::srvloc::SrvlocPacketParseError;

pub fn ensure_len(buf: &[u8], needed: usize) -> Result<(), SrvlocPacketParseError> {
    if buf.len() < needed {
        Err(SrvlocPacketParseError::Truncated {
            expected_at_least: needed,
            actual: buf.len(),
        })
    } else {
        Ok(())
    }
}
