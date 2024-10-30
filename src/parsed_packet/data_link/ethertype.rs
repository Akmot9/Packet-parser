// ethertype.rs
#[derive(Debug, PartialEq, Eq)]
pub struct Ethertype(pub u16);

impl Ethertype {
    pub fn from(code: u16) -> Self {
        Ethertype(code)
    }

    pub fn name(&self) -> &'static str {
        match self.0 {
            0x0800 => "IPv4",
            0x86DD => "IPv6",
            0x0806 => "ARP",
            0x8100 => "VLAN-tagged frame",
            0x88CC => "LLDP",
            _ => "Unknown",
        }
    }
}

impl std::fmt::Display for Ethertype {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:04X} ({})", self.0, self.name())
    }
}
