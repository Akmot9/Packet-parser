use crate::parsed_packet::network::IpAddress;
struct Ipv4 {
    version: u8,
    header_length: u8,
    type_of_service: u8,
    total_length: u16,
    id: u16,
    flags: u8,
    fragment_offset: u8,
    time_to_live: u8,
    protocol: u8,
    checksum: u16,
    source_address: IpAddress,
    destination_address: IpAddress
}

impl TryFrom<&[u8]> for Ipv4 {
    type Error = Ipv4Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        validate_ipv4_length(value)?;
        
       Ok(Ipv4 { 
        version: todo!(), 
        header_length: todo!(), 
        type_of_service: todo!(), 
        total_length: todo!(), 
        id: todo!(), 
        flags: todo!(), 
        fragment_offset: todo!(), 
        time_to_live: todo!(), 
        protocol: todo!(), 
        checksum: todo!(), 
        source_address: todo!(), 
        destination_address: todo!() 
    }) 
    }
}