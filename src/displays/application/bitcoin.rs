use std::fmt;

impl fmt::Display for BitcoinPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Bitcoin Packet: magic={:02X?}, command={}, length={}, checksum={:02X?}, payload={:02X?}",
            self.magic, self.command, self.length, self.checksum, self.payload
        )
    }
}