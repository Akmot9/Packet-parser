use packet_parser::parse::application::protocols::{dns::DnsPacket, ntp::NtpPacket, dhcp::DhcpPacket};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ntp_payload: &[u8] = &[
        0x1B, 0x00, 0x04, 0xFA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4E, 0x49,
        0x4E, 0x00, 0xDC, 0xC0, 0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0, 0x00, 0x00,
        0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0, 0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0,
        0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71,
    ];
    
    let ntp = NtpPacket::try_from(ntp_payload)?;

    println!("{:?}", ntp);

    let dns_payload = hex::decode("3155810000010001000000001a546f72696b31362d5452312d38322d3132382d3139342d3130350573756f6d69036e65740000010001c00c000100010000271000045280c269").expect("Invalid hex string");

    let dns_packet = DnsPacket::try_from(dns_payload.as_slice());
    println!("{:?}", dns_packet);

    let invalid_op_payload = vec![
        0x03, 0x01, 0x06, 0x00, 0x39, 0x03, 0xF3, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x0C, 0x29, 0x36, 0x57, 0xD2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];

    let result = DhcpPacket::try_from(invalid_op_payload.as_slice());
    print!("dhcp : {:?}", result);
    Ok(())
}