use serde::Serialize;

pub mod tcp;
pub mod udp;

/// Represents various transport layer protocols with their IANA protocol numbers
#[derive(Debug, Clone, Serialize)]
pub enum TransportProtocol {
    // Core protocols
    Tcp,
    Udp,
    Icmp,
    IcmpV6,
    Igmp,
    Pim,
    PimV2,

    // Routing protocols
    Egp,
    Igrp,
    Ospf,
    Eigrp,

    // Tunneling protocols
    Gre,
    IpInIp,

    // Security protocols
    Ah,
    Esp,

    // Other common protocols
    Rdp,
    Dccp,
    Rsvp,
    Sctp,

    // Special cases
    None,
    Unknown,
}

impl TransportProtocol {
    /// Converts an IANA protocol number to a TransportProtocol
    pub fn from_u8(value: u8) -> Self {
        match value {
            // Core protocols
            0 => TransportProtocol::None,
            1 => TransportProtocol::Icmp,
            2 => TransportProtocol::Igmp,
            6 => TransportProtocol::Tcp,
            17 => TransportProtocol::Udp,
            58 => TransportProtocol::IcmpV6,
            103 => TransportProtocol::PimV2,

            // Routing protocols
            8 => TransportProtocol::Egp,
            9 => TransportProtocol::Igrp,
            89 => TransportProtocol::Ospf,
            88 => TransportProtocol::Eigrp,

            // Tunneling
            47 => TransportProtocol::Gre,
            4 => TransportProtocol::IpInIp,

            // Security
            50 => TransportProtocol::Esp,
            51 => TransportProtocol::Ah,

            // Other protocols
            27 => TransportProtocol::Rdp,
            33 => TransportProtocol::Dccp,
            46 => TransportProtocol::Rsvp,
            132 => TransportProtocol::Sctp,

            _ => TransportProtocol::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_conversion() {
        assert!(matches!(
            TransportProtocol::from_u8(6),
            TransportProtocol::Tcp
        ));
        assert!(matches!(
            TransportProtocol::from_u8(17),
            TransportProtocol::Udp
        ));
        assert!(matches!(
            TransportProtocol::from_u8(1),
            TransportProtocol::Icmp
        ));
        assert!(matches!(
            TransportProtocol::from_u8(58),
            TransportProtocol::IcmpV6
        ));
        assert!(matches!(
            TransportProtocol::from_u8(47),
            TransportProtocol::Gre
        ));
        assert!(matches!(
            TransportProtocol::from_u8(50),
            TransportProtocol::Esp
        ));
        assert!(matches!(
            TransportProtocol::from_u8(255),
            TransportProtocol::Unknown
        ));
    }
}
