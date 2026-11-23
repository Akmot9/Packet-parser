// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! A host: loads plugins, then counts the application labels of a capture.
//!
//! ```text
//! cargo run --example plugin_host -- capture.pcapng plugin.so [plugin2.so ...]
//! ```
//!
//! Everything stays on the machine: the capture is read, parsed and counted
//! locally, and only the counts are printed. With `--fields`, the fields of
//! the first flow of each added label are printed too.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::process::ExitCode;

use packet_parser::{ApplicationProtocol, LinkType, ParseConfig, parse_with};
use packet_parser_plugin::load_parser;
use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::{Block, PcapNgReader};

const PCAPNG_MAGIC: u32 = 0x0A0D_0D0A;
const UNKNOWN_INTERFACE: &str =
    "a packet block names an interface that the capture does not describe";

type Frames = Vec<(LinkType, Vec<u8>)>;

/// The frames of a pcap or pcapng file, with their link type.
fn frames(path: &str) -> Result<Frames, Box<dyn std::error::Error>> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    reader.seek(SeekFrom::Start(0))?;

    let mut frames = Vec::new();
    if u32::from_be_bytes(magic) == PCAPNG_MAGIC {
        let mut reader = PcapNgReader::new(reader)?;
        let mut link_types = Vec::new();
        while let Some(block) = reader.next_block() {
            match block? {
                Block::SectionHeader(_) => link_types.clear(),
                Block::InterfaceDescription(interface) => {
                    link_types.push(LinkType::from(u32::from(interface.linktype)));
                }
                // The three packet blocks of pcapng. A packet whose
                // interface is not described cannot be read: it is an error,
                // not a frame to skip.
                Block::EnhancedPacket(packet) => {
                    let interface = usize::try_from(packet.interface_id)?;
                    let link_type = link_types.get(interface).ok_or(UNKNOWN_INTERFACE)?;
                    frames.push((*link_type, packet.data.into_owned()));
                }
                Block::Packet(packet) => {
                    let interface = usize::from(packet.interface_id);
                    let link_type = link_types.get(interface).ok_or(UNKNOWN_INTERFACE)?;
                    frames.push((*link_type, packet.data.into_owned()));
                }
                // A Simple Packet Block has no interface id: it comes from
                // the first interface of its section.
                Block::SimplePacket(packet) => {
                    let link_type = link_types.first().ok_or(UNKNOWN_INTERFACE)?;
                    frames.push((*link_type, packet.data.into_owned()));
                }
                _ => {}
            }
        }
    } else {
        let mut reader = PcapReader::new(reader)?;
        let link_type = LinkType::from(u32::from(reader.header().datalink));
        while let Some(packet) = reader.next_raw_packet() {
            frames.push((link_type, packet?.data.into_owned()));
        }
    }
    Ok(frames)
}

fn run(arguments: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let show_fields = arguments.iter().any(|argument| argument == "--fields");
    let mut paths = arguments.iter().filter(|argument| *argument != "--fields");
    let (Some(capture), plugins) = (paths.next(), paths) else {
        return Err("usage : plugin_host [--fields] <capture> <plugin> [plugin...]".into());
    };

    let mut config = ParseConfig::new();
    for plugin in plugins {
        // SAFETY: the user names the libraries to load on the command line,
        // and runs this example on their own machine.
        let parser = unsafe { load_parser(plugin) }?;
        let label = parser.label();
        config.add_parser(parser)?;
        println!("plugin {plugin} : {label}");
    }

    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut shown = Vec::new();
    for (link_type, data) in frames(capture)? {
        let Ok(flow) = parse_with(link_type, &data, &config) else {
            *counts.entry("(erreur L2)").or_default() += 1;
            continue;
        };
        for level in flow.flatten() {
            let protocol = level
                .application
                .as_ref()
                .map(|application| application.protocol);
            *counts
                .entry(protocol.map_or("(sans application)", ApplicationProtocol::label))
                .or_default() += 1;
            if show_fields
                && let Some(ApplicationProtocol::Custom(label)) = protocol
                && !shown.contains(&label)
                && let Some(fields) = config.custom_fields(level)
            {
                shown.push(label);
                println!("premier flux {label} :");
                for (name, value) in fields {
                    println!("  {name} = {value}");
                }
            }
        }
    }
    for (label, count) in counts {
        println!("{count:>8}  {label}");
    }
    Ok(())
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match run(&arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
