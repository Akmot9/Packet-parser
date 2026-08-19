// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Lecture de captures partagee entre tests d'integration, via `pcap-file`
//! (Rust pur, aucune dependance systeme).
//!
//! Chaque binaire de test compile ce module independamment et n'en consomme
//! qu'une partie : le dead_code est structurel, pas un oubli.
#![allow(dead_code)]

use std::{
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom},
    path::Path,
};

use packet_parser::LinkType;
use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::{Block, PcapNgReader};

/// Lecture d'un fichier de capture via `pcap-file` (Rust pur, aucune
/// dependance systeme — c'est ce qui permet a ce test de tourner aussi sur
/// les runners Windows/macOS de la CI, la ou libpcap exigeait le SDK Npcap).
/// Meme logique que `examples/scan_pcaps.rs` : le LINKTYPE est resolu par
/// interface pour les pcapng, et une erreur de lecture en cours de fichier
/// est signalee au lieu de faire passer une lecture amputee pour complete.
pub enum FileRead {
    /// Format non reconnu par `pcap-file` (ex. NetXRay `.cap`).
    Unsupported,
    Frames {
        frames: Vec<(LinkType, Vec<u8>)>,
        /// Nombre de trames lues avant une erreur de lecture, le cas echeant.
        read_error_after: Option<usize>,
    },
}

pub const PCAPNG_SHB_MAGIC: u32 = 0x0A0D_0D0A;

pub fn read_capture(path: &Path) -> FileRead {
    let Ok(file) = File::open(path) else {
        return FileRead::Unsupported;
    };
    let mut reader = BufReader::new(file);
    let mut magic = [0u8; 4];
    if reader.read_exact(&mut magic).is_err() || reader.seek(SeekFrom::Start(0)).is_err() {
        return FileRead::Unsupported;
    }

    let mut frames = Vec::new();
    let mut read_error = false;
    if u32::from_be_bytes(magic) == PCAPNG_SHB_MAGIC {
        let Ok(mut reader) = PcapNgReader::new(reader) else {
            return FileRead::Unsupported;
        };
        // LINKTYPE par interface ; une nouvelle section remet la
        // numerotation a zero (RFC pcapng, section 4.2).
        let mut linktypes: Vec<LinkType> = Vec::new();
        while let Some(block) = reader.next_block() {
            let Ok(block) = block else {
                read_error = true;
                break;
            };
            match block {
                Block::SectionHeader(_) => linktypes.clear(),
                Block::InterfaceDescription(idb) => {
                    linktypes.push(LinkType::from(u32::from(idb.linktype)));
                }
                Block::EnhancedPacket(epb) => {
                    if let Some(&link_type) = linktypes.get(epb.interface_id as usize) {
                        frames.push((link_type, epb.data.into_owned()));
                    }
                }
                Block::Packet(pb) => {
                    if let Some(&link_type) = linktypes.get(pb.interface_id as usize) {
                        frames.push((link_type, pb.data.into_owned()));
                    }
                }
                Block::SimplePacket(spb) => {
                    if let [link_type] = linktypes[..] {
                        frames.push((link_type, spb.data.into_owned()));
                    }
                }
                _ => {}
            }
        }
    } else {
        let Ok(mut reader) = PcapReader::new(reader) else {
            return FileRead::Unsupported;
        };
        let link_type = LinkType::from(u32::from(reader.header().datalink));
        // `next_raw_packet` : `next_packet` rejette `orig_len > snap_len`,
        // pourtant legitime pour une trame tronquee a la capture.
        while let Some(packet) = reader.next_raw_packet() {
            match packet {
                Ok(packet) => frames.push((link_type, packet.data.into_owned())),
                Err(_) => {
                    read_error = true;
                    break;
                }
            }
        }
    }

    FileRead::Frames {
        read_error_after: read_error.then_some(frames.len()),
        frames,
    }
}

pub fn collect_capture_files(path: &Path, captures: &mut Vec<std::path::PathBuf>) {
    if path.is_dir() {
        if path.file_name().is_some_and(|name| name == "s7comm") {
            return;
        }

        let mut entries: Vec<_> = std::fs::read_dir(path)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
            .map(|entry| entry.expect("readable directory entry").path())
            .collect();
        entries.sort();
        for entry in entries {
            collect_capture_files(entry.as_path(), captures);
        }
        return;
    }

    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "pcap" | "pcapng" | "cap"
            )
        })
    {
        captures.push(path.to_path_buf());
    }
}
