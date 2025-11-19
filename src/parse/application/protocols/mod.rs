// Copyright (c) 2024 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use bitcoin::BitcoinPacket;
use copt::CotpHeader;
use dhcp::DhcpPacket;
use dns::DnsPacket;
use http::HttpRequest;
use mqtt::MqttPacket;
use ntp::NtpPacket;
use s7comm::S7CommPacket;
use tls::TlsPacket;

use crate::parse::application::protocols::{giop::GiopPacket, quic::QuicPacket};

pub mod bitcoin;
pub mod copt;
pub mod dhcp;
pub mod dns;
pub mod http;
pub mod mqtt;
pub mod ntp;
pub mod s7comm;
pub mod tls;
pub mod quic;
pub mod giop;

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
    S7Comm(S7CommPacket<'a>),
    Cotp(CotpHeader),
    Quic(QuicPacket),
    Giop(GiopPacket),
    Raw(&'a [u8]),
    None,
}
