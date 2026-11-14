// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Les types d'erreur des decodeurs applicatifs, un module par protocole.
//!
//! La classification applicative n'a pas d'erreur a elle : un payload non
//! reconnu sort `Unknown`, un payload vide n'a pas de couche application.
//! `ApplicationError`, que seul `Application::try_from` rendait, est parti
//! avec lui en 12.0 (#219).

pub mod ams;
pub mod asterix;
pub mod bacnet;
pub mod bitcoin;
pub mod copt;
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
pub mod modbus_tcp;
pub mod mqtt;
pub mod netbios;
pub mod nntp;
pub mod ntp;
pub mod opcua;
pub mod openvpn;
pub mod postgresql;
pub mod ptp;
pub mod quic;
pub mod radius;
pub mod rdp;
pub mod rtps;
pub mod s7comm;
pub mod smtp;
pub mod snmp;
pub mod srvloc;
pub mod ssdp;
pub mod ssh;
pub mod stanag5066;
pub mod tls;
pub mod umas;
pub mod valmet_dna;
pub mod wireguard;
