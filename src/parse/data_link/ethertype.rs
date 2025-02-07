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
            0x8892 => "Profinet",
            0x88E3 => "MRP",
            0x88F7 => "PTP",
            0x9100 => "Q-in-Q",
            0x88A8 => "PBridge",
            0x22F3 => "Trill",
            0x6003 => "DECnet",
            0x8035 => "Rarp",
            0x809B => "AppleTalk",
            0x80F3 => "Aarp",
            0x8137 => "Ipx",
            0x8204 => "Qnx",
            0x8847 => "MPLS Unicast",
            0x8848 => "MPLS Multicast",
            0x8863 => "Pppoe Discovery Stage",
            0x8864 => "Pppoe Session Stage",
            0x8819 => "CobraNet",
            0x8902 => "cfm",
            _ => "Unknown",
        }
    }
}

