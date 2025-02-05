use std::fmt;

impl fmt::Display for DhcpPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DHCP Packet: op={}, htype={}, hlen={}, hops={}, xid={:08X}, secs={}, flags={}, ciaddr={:?}, yiaddr={:?}, siaddr={:?}, giaddr={:?}, chaddr={:?}, sname={:?}, file={:?}, options={:02X?}",
            self.op, self.htype, self.hlen, self.hops, self.xid, self.secs, self.flags, self.ciaddr, self.yiaddr, self.siaddr, self.giaddr, self.chaddr, self.sname, self.file, self.options
        )
    }
}
