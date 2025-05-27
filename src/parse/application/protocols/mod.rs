// Copyright (c) 2024 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use dns::DnsPacket;
use ntp::NtpPacket;
use tls::TlsPacket;
use http::HttpRequest;
use mqtt::MqttPacket;
use dhcp::DhcpPacket;
use bitcoin::BitcoinPacket;
pub mod ntp;
pub mod tls;
pub mod http;
pub mod mqtt;
pub mod dhcp;
pub mod bitcoin;
pub mod dns;

/// The `ApplicationProtocol` enum represents the possible layer 7 information that can be parsed.
#[derive(Debug)]
pub enum ApplicationProtocol<'a> {
    Ntp(NtpPacket),
    Tls(TlsPacket),
    Http(HttpRequest),
    Mqtt(MqttPacket),
    Dhcp(DhcpPacket),
    Bitcoin(BitcoinPacket),
    Dns(DnsPacket),
    Raw(&'a [u8]),
    None,
}
