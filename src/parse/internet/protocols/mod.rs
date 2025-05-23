pub mod arp;
pub mod ipv4;
pub mod ipv6;

#[derive(Debug)]
pub enum InternetProtocolType {
    Arp,
    Ipv4,
    Ipv6,
    Unknown(u8),
}
