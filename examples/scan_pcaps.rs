// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Balaye des fichiers pcap/pcapng et compte les protocoles applicatifs
//! détectés par `PacketFlow`, fichier par fichier.
//!
//! Usage :
//!   cargo run --example scan_pcaps -- <pcap|dossier>... [--focus PROTO]
//!
//! Avec `--focus`, chaque trame détectée comme PROTO est détaillée
//! (n° de trame, ports, premiers octets du payload) pour auditer les
//! faux positifs.
//!
//! ## Pourquoi ne pas passer par libpcap
//!
//! Un pcapng peut décrire **plusieurs interfaces**, chacune avec son propre
//! LINKTYPE, et chaque paquet référence la sienne par `interface_id`. Lire un
//! tel fichier avec un unique `get_datalink()` en début de fichier revient à
//! appliquer le LINKTYPE de la première interface à tous les paquets ; la
//! lecture s'interrompt au premier changement, et le fichier compte alors zéro
//! trame sans que rien ne le signale (issue #74).
//!
//! `pcap-file` donne accès aux blocs de description d'interface, donc au
//! LINKTYPE réel de chaque paquet. `packet_parser::parse` prend justement le
//! `LinkType` en paramètre : c'est l'itération qui était en cause, pas la
//! crate.

use packet_parser::{LinkType, parse};
use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::{Block, PcapNgReader};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Premier mot d'un Section Header Block, qui identifie un pcapng.
const PCAPNG_SHB_MAGIC: u32 = 0x0A0D_0D0A;

fn collect_pcaps(path: &Path, out: &mut Vec<PathBuf>) {
    if path.is_dir() {
        let mut entries: Vec<_> = match std::fs::read_dir(path) {
            Ok(rd) => rd.flatten().map(|e| e.path()).collect(),
            Err(_) => return,
        };
        entries.sort();
        for entry in entries {
            collect_pcaps(&entry, out);
        }
    } else if matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("pcap") | Some("pcapng") | Some("cap")
    ) {
        out.push(path.to_path_buf());
    }
}

/// Issue de la lecture d'un fichier.
///
/// `truncated_by` est le point clé : une lecture qui s'arrête sur une erreur
/// n'est pas une lecture complète, et l'ancienne boucle `while let Ok(..)`
/// confondait les deux. Un fichier partiellement lu doit le dire.
#[derive(Default)]
struct ReadOutcome {
    frames: usize,
    truncated_by: Option<String>,
}

/// Applique `on_packet` à chaque paquet du fichier, avec le `LinkType` de
/// l'interface dont il provient.
fn for_each_packet(
    path: &Path,
    on_packet: &mut impl FnMut(LinkType, &[u8]),
) -> std::io::Result<ReadOutcome> {
    let mut file = BufReader::new(File::open(path)?);

    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)?;
    file.seek(SeekFrom::Start(0))?;

    // Le SHB est le seul bloc dont le type est fixe et connu d'avance ; tout
    // le reste (pcap classique, quel que soit son boutisme ou sa resolution
    // temporelle) est delegue a PcapReader, qui lit son propre en-tete.
    if u32::from_be_bytes(magic) == PCAPNG_SHB_MAGIC {
        Ok(read_pcapng(file, on_packet))
    } else {
        Ok(read_pcap(file, on_packet))
    }
}

fn read_pcapng(
    reader: BufReader<File>,
    on_packet: &mut impl FnMut(LinkType, &[u8]),
) -> ReadOutcome {
    let mut outcome = ReadOutcome::default();

    let mut reader = match PcapNgReader::new(reader) {
        Ok(r) => r,
        Err(e) => {
            outcome.truncated_by = Some(format!("en-tete pcapng illisible ({e})"));
            return outcome;
        }
    };

    // LINKTYPE par interface, indexe par `interface_id`. Une nouvelle section
    // remet la numerotation a zero (RFC pcapng §4.2).
    let mut linktypes: Vec<LinkType> = Vec::new();

    // `next_block` rend `None` en fin de fichier et `Some(Err)` sur erreur de
    // lecture : ce sont deux choses differentes. Sur erreur, on s'arrete — le
    // parseur sous-jacent ne consomme pas les octets fautifs, donc reessayer
    // bouclerait — mais on le signale au lieu de faire passer une lecture
    // amputee pour une lecture complete.
    while let Some(block) = reader.next_block() {
        let block = match block {
            Ok(block) => block,
            Err(e) => {
                outcome.truncated_by = Some(format!(
                    "bloc illisible apres {} trames ({e})",
                    outcome.frames
                ));
                break;
            }
        };

        match block {
            Block::SectionHeader(_) => linktypes.clear(),
            Block::InterfaceDescription(idb) => {
                linktypes.push(LinkType::from(u32::from(idb.linktype)));
            }
            Block::EnhancedPacket(epb) => {
                if let Some(&link_type) = linktypes.get(epb.interface_id as usize) {
                    outcome.frames += 1;
                    on_packet(link_type, &epb.data);
                }
            }
            // Bloc obsolete (pcapng pre-1.0), conserve par certains outils.
            Block::Packet(pb) => {
                if let Some(&link_type) = linktypes.get(pb.interface_id as usize) {
                    outcome.frames += 1;
                    on_packet(link_type, &pb.data);
                }
            }
            // Le Simple Packet Block ne porte pas d'`interface_id` : il n'est
            // valide que si la section decrit une seule interface.
            Block::SimplePacket(spb) => {
                if let [link_type] = linktypes[..] {
                    outcome.frames += 1;
                    on_packet(link_type, &spb.data);
                }
            }
            _ => {}
        }
    }

    outcome
}

fn read_pcap(reader: BufReader<File>, on_packet: &mut impl FnMut(LinkType, &[u8])) -> ReadOutcome {
    let mut outcome = ReadOutcome::default();

    let mut reader = match PcapReader::new(reader) {
        Ok(r) => r,
        Err(e) => {
            outcome.truncated_by = Some(format!("en-tete pcap illisible ({e})"));
            return outcome;
        }
    };

    // Un pcap classique n'a qu'un seul LINKTYPE, dans son en-tete de fichier.
    let link_type = LinkType::from(u32::from(reader.header().datalink));

    // `next_raw_packet` plutot que `next_packet` : ce dernier rejette
    // `orig_len > snap_len` comme invalide, ce qui est trop strict. Une trame
    // tronquee a la capture a legitimement une longueur de fil superieure au
    // snaplen declare, et libpcap l'accepte. Sur le corpus, cette validation
    // faisait tomber une capture de 3 584 trames a 4. On ne lit de toute
    // facon que `data`.
    while let Some(packet) = reader.next_raw_packet() {
        match packet {
            Ok(packet) => {
                outcome.frames += 1;
                on_packet(link_type, &packet.data);
            }
            Err(e) => {
                outcome.truncated_by = Some(format!(
                    "paquet illisible apres {} trames ({e})",
                    outcome.frames
                ));
                break;
            }
        }
    }

    outcome
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let focus = args
        .iter()
        .position(|a| a == "--focus")
        .map(|i| args.remove(i + 1))
        .inspect(|_| {
            args.retain(|a| a != "--focus");
        });

    if args.is_empty() {
        eprintln!("usage: scan_pcaps <pcap|dossier>... [--focus PROTO]");
        std::process::exit(2);
    }

    let mut files = Vec::new();
    for arg in &args {
        collect_pcaps(Path::new(arg), &mut files);
    }

    let mut grand_total: BTreeMap<String, usize> = BTreeMap::new();
    let mut incomplets = Vec::new();

    for file in &files {
        let mut tally: BTreeMap<String, usize> = BTreeMap::new();
        let mut frame_no = 0usize;

        let mut on_packet = |link_type: LinkType, data: &[u8]| {
            frame_no += 1;
            // L'erreur porte son LINKTYPE : sur une capture multi-interfaces,
            // un total d'erreurs anonyme ne dit pas s'il manque un decodeur de
            // liaison ou si les trames sont reellement corrompues.
            let Ok(flow) = parse(link_type, data) else {
                *tally
                    .entry(format!("<erreur L2 lt={link_type}>"))
                    .or_default() += 1;
                return;
            };

            // La détection applicative pertinente est celle du flux le plus
            // interne (après dé-tunnellisation éventuelle).
            let flows = flow.flatten();
            let innermost = flows.last().expect("flatten n'est jamais vide");
            let label = match &innermost.application {
                Some(app) => app.application_protocol.to_string(),
                None => "<pas de L7>".to_string(),
            };

            if let Some(focus_proto) = &focus
                && label.eq_ignore_ascii_case(focus_proto)
            {
                let fmt_port = |p: Option<u16>| p.map_or("?".into(), |p| p.to_string());
                let (sport, dport, head) = match &innermost.transport {
                    Some(t) => (
                        fmt_port(t.source_port),
                        fmt_port(t.destination_port),
                        t.payload
                            .map(|p| {
                                p.iter()
                                    .take(16)
                                    .map(|b| format!("{b:02X}"))
                                    .collect::<Vec<_>>()
                                    .join(" ")
                            })
                            .unwrap_or_default(),
                    ),
                    None => ("?".into(), "?".into(), String::new()),
                };
                println!(
                    "{}: trame {frame_no} {sport}->{dport} [{head}]",
                    file.display()
                );
            }

            *tally.entry(label).or_default() += 1;
        };

        let outcome = match for_each_packet(file, &mut on_packet) {
            Ok(outcome) => outcome,
            Err(e) => {
                eprintln!("{}: illisible ({e})", file.display());
                continue;
            }
        };

        println!("\n== {} ({} trames)", file.display(), outcome.frames);
        if let Some(raison) = &outcome.truncated_by {
            println!("   ⚠ lecture incomplete : {raison}");
            incomplets.push(file.display().to_string());
        }
        for (proto, count) in &tally {
            println!("   {proto:<12} {count}");
            *grand_total.entry(proto.clone()).or_default() += count;
        }
    }

    println!("\n== TOTAL ({} fichiers)", files.len());
    for (proto, count) in &grand_total {
        println!("   {proto:<12} {count}");
    }

    // Un total de corpus construit sur des lectures amputees est trompeur :
    // c'est exactement ce que faisait l'ancienne boucle, en silence.
    if !incomplets.is_empty() {
        println!(
            "\n⚠ {} fichier(s) lus incompletement, les totaux ci-dessus sont partiels :",
            incomplets.len()
        );
        for file in &incomplets {
            println!("   {file}");
        }
    }

    Ok(())
}
