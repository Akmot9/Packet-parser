

const IPV4_LENGH : usize = 20;

pub fn validate_ipv4_length(packets: &[u8]) -> Result<(), ParsedPacketError> {
    if packets.len() < IPV4_LENGH {
        return(Err())
    }
    Ok(())
}
