use crate::errors::application::dhcp::DhcpParseError;

pub fn validate_packet_length(payload: &[u8]) -> Result<(), DhcpParseError> {
    if payload.len() < 236 {
        Err(DhcpParseError::ShortPacket)
    } else {
        Ok(())
    }
}

pub fn validate_op(payload: &[u8]) -> Result<u8, DhcpParseError> {
    let op = payload[0];
    if op == 1 || op == 2 {
        Ok(op)
    } else {
        Err(DhcpParseError::InvalidOp)
    }
}

pub fn validate_htype(payload: &[u8]) -> Result<u8, DhcpParseError> {
    let htype = payload[1];
    if htype == 1 {
        Ok(htype)
    } else {
        Err(DhcpParseError::InvalidHType)
    }
}

pub fn validate_hlen(payload: &[u8]) -> Result<u8, DhcpParseError> {
    let hlen = payload[2];
    if hlen == 6 {
        Ok(hlen)
    } else {
        Err(DhcpParseError::InvalidHLen)
    }
}

pub fn extract_xid(payload: &[u8]) -> Result<u32, DhcpParseError> {
    Ok(u32::from_be_bytes([
        payload[4], payload[5], payload[6], payload[7],
    ]))
}

pub fn extract_secs(payload: &[u8]) -> Result<u16, DhcpParseError> {
    Ok(u16::from_be_bytes([payload[8], payload[9]]))
}

pub fn extract_flags(payload: &[u8]) -> Result<u16, DhcpParseError> {
    Ok(u16::from_be_bytes([payload[10], payload[11]]))
}

pub fn extract_ciaddr(payload: &[u8]) -> Result<[u8; 4], DhcpParseError> {
    Ok([payload[12], payload[13], payload[14], payload[15]])
}

pub fn extract_yiaddr(payload: &[u8]) -> Result<[u8; 4], DhcpParseError> {
    Ok([payload[16], payload[17], payload[18], payload[19]])
}

pub fn extract_siaddr(payload: &[u8]) -> Result<[u8; 4], DhcpParseError> {
    Ok([payload[20], payload[21], payload[22], payload[23]])
}

pub fn extract_giaddr(payload: &[u8]) -> Result<[u8; 4], DhcpParseError> {
    Ok([payload[24], payload[25], payload[26], payload[27]])
}

pub fn extract_chaddr(payload: &[u8]) -> Result<[u8; 16], DhcpParseError> {
    let mut chaddr = [0u8; 16];
    chaddr.copy_from_slice(&payload[28..44]);
    Ok(chaddr)
}

pub fn extract_sname(payload: &[u8]) -> Result<[u8; 64], DhcpParseError> {
    let mut sname = [0u8; 64];
    sname.copy_from_slice(&payload[44..108]);
    Ok(sname)
}

pub fn extract_file(payload: &[u8]) -> Result<[u8; 128], DhcpParseError> {
    let mut file = [0u8; 128];
    file.copy_from_slice(&payload[108..236]);
    Ok(file)
}

pub fn extract_options(payload: &[u8]) -> Result<Vec<u8>, DhcpParseError> {
    Ok(payload[236..].to_vec())
}
