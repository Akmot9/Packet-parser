// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use serde::Serialize;
use thiserror::Error;

pub mod ams;
pub mod bitcoin;
pub mod copt;
pub mod dhcp;
pub mod dhcpv6;
pub mod dns;
pub mod ethernet_ip;
pub mod ftp;
pub mod giop;
pub mod http;
pub mod modbus_tcp;
pub mod mqtt;
pub mod netbios;
pub mod nntp;
pub mod ntp;
pub mod opcua;
pub mod openvpn;
pub mod postgresql;
pub mod quic;
pub mod s7comm;
pub mod smtp;
pub mod snmp;
pub mod srvloc;
pub mod ssdp;
pub mod ssh;
pub mod tls;

/// Errors related to parsing an `Application`.
///
/// Application-layer probing never fails on an unrecognized payload — it
/// yields no label instead — so the only error is an empty payload. The
/// per-protocol decoders report their own error types, under
/// [`crate::errors::application`].
#[derive(Debug, Error, Clone, Serialize)]
#[non_exhaustive]
pub enum ApplicationError {
    #[error("Packet is empty")]
    EmptyPacket,
}
