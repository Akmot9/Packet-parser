#[derive(Debug)]
pub struct Transport<'a> {
    port_destination: u16,
    port_source: u16,
    payload: &'a [u8],
}

