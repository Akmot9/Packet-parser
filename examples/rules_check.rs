// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Met au point un fichier de regles TOML (#325) sur des captures, en local.
//!
//! Usage :
//!   cargo run --release --features rules --example rules_check -- \
//!       <regles.toml> <capture...> [--fields N]
//!
//! Le fichier est valide (chaque erreur avec sa ligne), puis chaque capture
//! est lue deux fois, sans puis avec les regles. Le bilan donne, par
//! etiquette de regle, le nombre de flux qu'elle nomme, et le nombre de
//! flux `Unknown` avant et apres. Avec `--fields N`, les champs des N
//! premiers flux de chaque etiquette sont affiches.
//!
//! Tout reste sur la machine : l'outil ne lit que les fichiers passes en
//! argument et n'ecrit que sur la sortie standard. Un fichier de regles
//! confidentiel se met au point ici sans quitter le poste.
//!
//! Une regle ne nomme qu'un flux que la crate laissait `Unknown` : si un
//! flux deja nomme changeait d'etiquette, l'outil le signale et sort en
//! erreur, ce serait un defaut de la crate.

use std::collections::BTreeMap;
use std::fs::File;
use std::path::Path;
use std::process::ExitCode;

use packet_parser::{
    ApplicationProtocol, LinkType, PacketFlow, ParseConfig, RuleSet, parse, parse_with,
};
use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::{Block, PcapNgReader};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(rules_path) = args.next() else {
        eprintln!("usage : rules_check <regles.toml> <capture...> [--fields N]");
        return ExitCode::from(2);
    };
    let mut captures = Vec::new();
    let mut shown_fields = 0_usize;
    while let Some(arg) = args.next() {
        if arg == "--fields" {
            match args.next().and_then(|n| n.parse().ok()) {
                Some(n) => shown_fields = n,
                None => {
                    eprintln!("--fields attend un nombre");
                    return ExitCode::from(2);
                }
            }
        } else {
            captures.push(arg);
        }
    }

    let text = match std::fs::read_to_string(&rules_path) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("{rules_path} : {error}");
            return ExitCode::from(2);
        }
    };
    let rules = match RuleSet::from_toml(&text) {
        Ok(rules) => rules,
        Err(error) => {
            eprintln!("{rules_path} : {error}");
            return ExitCode::from(2);
        }
    };
    let config = match ParseConfig::new().with_rules(&rules) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{rules_path} : {error}");
            return ExitCode::from(2);
        }
    };
    let labels: Vec<&str> = rules.labels().collect();
    println!(
        "{rules_path} : {} etiquette(s) : {}",
        labels.len(),
        labels.join(", ")
    );
    if captures.is_empty() {
        println!("fichier valide ; aucune capture a lire");
        return ExitCode::SUCCESS;
    }

    let mut named: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut shown: BTreeMap<&'static str, usize> = BTreeMap::new();
    let (mut frames, mut unknown_before, mut unknown_after, mut taken) = (0, 0, 0, 0);
    for capture in &captures {
        let Some(packets) = read(Path::new(capture)) else {
            eprintln!("{capture} : capture illisible");
            continue;
        };
        for (index, (link, data)) in packets.iter().enumerate() {
            frames += 1;
            let (Ok(before), Ok(after)) = (
                parse(LinkType(*link), data),
                parse_with(LinkType(*link), data, &config),
            ) else {
                continue;
            };
            for (level, (old, new)) in before
                .flatten()
                .into_iter()
                .zip(after.flatten())
                .enumerate()
            {
                let old_label = application(old);
                let new_label = application(new);
                unknown_before += usize::from(old_label == Some(ApplicationProtocol::Unknown));
                unknown_after += usize::from(new_label == Some(ApplicationProtocol::Unknown));
                let Some(ApplicationProtocol::Custom(label)) = new_label else {
                    continue;
                };
                if old_label != Some(ApplicationProtocol::Unknown) {
                    taken += 1;
                    eprintln!(
                        "{capture} trame {} : {old_label:?} renomme {label}, ce qui ne doit jamais arriver",
                        index + 1
                    );
                }
                *named.entry(label).or_default() += 1;
                let count = shown.entry(label).or_default();
                if *count < shown_fields {
                    *count += 1;
                    let fields = config
                        .custom_fields(new)
                        .unwrap_or_default()
                        .into_iter()
                        .map(|(name, value)| format!("{name}={value}"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    let place = if level == 0 {
                        String::new()
                    } else {
                        format!(" (niveau {level})")
                    };
                    println!("  {capture} trame {}{place} {label} : {fields}", index + 1);
                }
            }
        }
    }

    println!("{frames} trame(s) dans {} capture(s)", captures.len());
    for label in &labels {
        println!(
            "  {label} : {} flux",
            named.get(label).copied().unwrap_or(0)
        );
    }
    println!("  Unknown : {unknown_before} avant les regles, {unknown_after} apres");
    if taken > 0 {
        eprintln!("{taken} flux deja nommes ont change d'etiquette");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn application(flow: &PacketFlow<'_>) -> Option<ApplicationProtocol> {
    flow.application
        .as_ref()
        .map(|application| application.protocol)
}

/// Les trames d'un pcap ou d'un pcapng, avec le LINKTYPE de leur interface.
fn read(path: &Path) -> Option<Vec<(u32, Vec<u8>)>> {
    let mut packets = Vec::new();
    if let Ok(mut reader) = PcapReader::new(File::open(path).ok()?) {
        let link = u32::from(reader.header().datalink);
        while let Some(Ok(packet)) = reader.next_packet() {
            packets.push((link, packet.data.into_owned()));
        }
        return Some(packets);
    }
    let mut reader = PcapNgReader::new(File::open(path).ok()?).ok()?;
    let mut links: Vec<u32> = Vec::new();
    while let Some(Ok(block)) = reader.next_block() {
        match block {
            Block::InterfaceDescription(interface) => links.push(u32::from(interface.linktype)),
            Block::EnhancedPacket(packet) => {
                let link = usize::try_from(packet.interface_id)
                    .ok()
                    .and_then(|id| links.get(id));
                if let Some(link) = link {
                    packets.push((*link, packet.data.into_owned()));
                }
            }
            Block::SimplePacket(packet) => {
                if let Some(link) = links.first() {
                    packets.push((*link, packet.data.into_owned()));
                }
            }
            _ => {}
        }
    }
    Some(packets)
}
