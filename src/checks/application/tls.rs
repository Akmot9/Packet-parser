use crate::errors::application::tls::TlsError;

pub const TLS_RECORD_HEADER_LEN: usize = 5;

pub fn validate_tls_header_length(buf: &[u8]) -> Result<(), TlsError> {
    if buf.len() < TLS_RECORD_HEADER_LEN {
        return Err(TlsError::TooShort);
    }

    Ok(())
}

pub fn validate_tls_payload_length(length: u16, available: usize) -> Result<(), TlsError> {
    if available < length as usize {
        return Err(TlsError::InconsistentLength {
            declared: length,
            available,
        });
    }

    Ok(())
}
