// Copyright (c) 2024 Cyprien Avico <avicocyprien@yahoo.com>
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! # Packet Parser
//!
//! **Packet Parser** is a modular Rust library designed to analyze and decode raw network packets.
//!
//! This crate allows processing different layers of a network packet, starting from the data link layer
//! (Ethernet II) and moving down through the network, transport, and application layers.
//!
//! ## Features
//! - **Multi-layer analysis**: Supports data link, network, transport, and application layers.
//! - **Error management**: Detailed error handling to facilitate debugging.
//! - **Packet validation**: Built-in verification mechanisms to ensure data integrity.
//! - **Modular architecture**: Easily extendable to support new protocols.
//!
//! ## Usage Example
//!
//! ```rust
//! use packet_parser::DataLink;
//! use hex::decode;
//!
//! let hex_dump_data = "feaa81e86d1efeaa818ec864080045500034000000003d06206b36e6700dac140a0201bbc1087d7f02aa4e2b998e80100081748300000101080a9373c9c207ef14e3";
//! let packet = decode(hex_dump_data).expect("Hexadecimal conversion failed");
//!
//! match DataLink::try_from(packet.as_slice()) {
//!     Ok(datalink) => println!("{:?}", datalink),
//!     Err(e) => eprintln!("Parsing error: {:?}", e),
//! }
//! ```

/// Module handling format and integrity checks for packets.
pub mod checks;

/// Module for converting packet formats.
pub mod convert;

/// Module for displaying parsed data (internal use).
mod displays;

/// Centralized error management for the crate.
mod errors;

/// Main module for packet analysis.
pub mod parse;

/// Exports data link layer parsing functionality.
pub use parse::data_link::DataLink;

/// Exports MAC address parsing functionality.
pub use parse::data_link::mac_addres::MacAddress;

/// Exports data link layer parsing functionality.
pub use parse::PacketFlux;
