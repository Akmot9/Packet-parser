// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Error types of the application-layer decoders, one module per protocol.
//!
//! Classifying a payload has no error of its own: a payload that is not
//! recognized is labelled `Unknown`, and an empty payload has no application
//! layer. `ApplicationError`, which only `Application::try_from` returned,
//! was removed with it in 12.0 (issue #219).

pub mod ams;
pub mod asterix;
pub mod bacnet;
pub mod bitcoin;
pub mod cotp;
pub mod dcerpc;
pub mod dhcp;
pub mod dhcpv6;
pub mod dis;
pub mod dnp3;
pub mod dns;
pub mod ethernet_ip;
pub mod ftp;
pub mod giop;
pub mod http;
pub mod iec104;
pub mod ike;
pub mod java_rmi;
pub mod ldap;
pub mod modbus_tcp;
pub mod mqtt;
pub mod netbios;
pub mod nmf;
pub mod nntp;
pub mod ntp;
pub mod opcua;
pub mod openvpn;
pub mod postgresql;
pub mod ptp;
pub mod quic;
pub mod radius;
pub mod rdp;
pub mod rtcp;
pub mod rtp;
pub mod rtps;
pub mod s7comm;
pub mod sip;
pub mod skinny;
pub mod smtp;
pub mod snmp;
pub mod srvloc;
pub mod ssdp;
pub mod ssh;
pub mod stanag5066;
pub mod syslog;
pub mod tls;
pub mod umas;
pub mod valmet_dna;
pub mod wireguard;
