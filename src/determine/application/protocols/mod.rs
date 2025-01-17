//! # Packet Module
//!
//! This module contains submodules for different packet types, each providing functionality for parsing and representing the specific protocol's packets.
//!
//! ## Submodules
//!
//! - [`bitcoin`]: Contains functions and structures for parsing Bitcoin protocol packets.
//! - [`dhcp`]: Contains functions and structures for parsing DHCP protocol packets.
//! - [`http`]: Contains functions and structures for parsing HTTP protocol requests.
//! - [`modbus`]: Contains functions and structures for parsing Modbus protocol packets.
//! - [`ntp`]: Contains functions and structures for parsing NTP protocol packets.
//! - [`tls`]: Contains functions and structures for parsing TLS protocol packets.

pub mod bitcoin;
pub mod dhcp;
pub mod dns;
pub mod http;
pub mod modbus;
pub mod ntp;
pub mod tls;
