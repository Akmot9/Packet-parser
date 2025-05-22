pub mod arp;

#[derive(Debug)]
pub enum InternetProtocolType {
    Arp,
    Ipv4,
    Ipv6,
    Unknown(u8),
}
