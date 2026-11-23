// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Les trames mesurees : celles des captures versionnees que les trois
//! crates decodent de la meme facon.

use std::path::Path;

use packet_parser::LinkType;

use crate::{Key, ep, pn, pp};

#[path = "../../../tests/common/mod.rs"]
mod common;
use common::{FileRead, read_capture};

/// Captures de `pcaps_exemple/`, toutes versionnees et de source connue
/// (`pcaps_exemple/SOURCE.md`). Deux captures de terrain, longues et
/// melangees, et le sous-ensemble de `benches/` (#214).
pub const CORPORA: [(&str, &[&str]); 3] = [
    ("4sics", &["4SICS-GeekLounge-151020.pcap"]),
    ("ultimate", &["The-Ultimate-PCAP.pcapng"]),
    (
        "subset",
        &[
            "ftp.pcap",
            "protocols/tcp/tcp_handshake.pcapng",
            "protocols/dns/dns.pcap",
            "protocols/tls/tls12-dsb.pcapng",
            "protocols/modbus/Modbus.pcap",
            "protocols/dnp3/dnp3.pcap",
            "protocols/s7comm/s7comm_downloading_block_db1.pcap",
            "protocols/iec104/wireshark_iec104.pcap",
            "protocols/profinet/miguelob_pn.pcapng",
            "protocols/mqtt/mqtt_packets.pcapng",
            "protocols/asterix/cat_034_048.pcap",
            "tunnels/vxlan/vxlan_ping.pcapng",
        ],
    ),
];

/// Ce que chaque fonction mesuree a lu d'une trame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Readings {
    pub packet_parser: Option<Key>,
    pub etherparse_slice: Option<Key>,
    pub etherparse_full: Option<Key>,
    pub etherparse_headers: Option<Key>,
    pub pnet_slice: Option<Key>,
    pub pnet_full: Option<Key>,
}

impl Readings {
    pub fn of(frame: &[u8]) -> Self {
        Self {
            packet_parser: pp::full(frame).as_ref().and_then(pp::key),
            etherparse_slice: ep::slice(frame).as_ref().and_then(ep::slice_key),
            etherparse_full: ep::full(frame).as_ref().and_then(ep::full_key),
            etherparse_headers: ep::full_from_slices(frame)
                .as_ref()
                .and_then(ep::headers_key),
            pnet_slice: pn::slice(frame).as_ref().map(pn::slice_key),
            pnet_full: pn::full(frame).as_ref().map(pn::full_key),
        }
    }

    fn all(&self) -> [Option<Key>; 6] {
        [
            self.packet_parser,
            self.etherparse_slice,
            self.etherparse_full,
            self.etherparse_headers,
            self.pnet_slice,
            self.pnet_full,
        ]
    }

    /// La cle commune, si les six lectures la rendent.
    pub fn agreed(&self) -> Option<Key> {
        let all = self.all();
        all.iter().all(|key| *key == all[0]).then_some(all[0])?
    }

    /// Aucune crate ne lit de couche 4 : ARP, LLDP, Profinet, fragment...
    pub fn out_of_scope(&self) -> bool {
        self.all().iter().all(Option::is_none)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Counts {
    /// Trames lues dans les captures.
    pub read: usize,
    /// Trames d'une interface qui n'est pas Ethernet.
    pub not_ethernet: usize,
    /// Trames sans couche 4 pour les trois crates.
    pub out_of_scope: usize,
    /// Trames ou les crates ne rendent pas la meme lecture.
    pub disagreed: usize,
}

pub struct Corpus {
    pub name: &'static str,
    /// Les trames gardees : les six lectures y sont egales.
    pub frames: Vec<Vec<u8>>,
    pub bytes: u64,
    pub counts: Counts,
    /// Les premieres trames ecartees pour desaccord, pour les expliquer.
    pub disagreements: Vec<(String, usize, Readings)>,
}

pub fn load(name: &'static str, captures: &[&str]) -> Corpus {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../pcaps_exemple");
    let mut corpus = Corpus {
        name,
        frames: Vec::new(),
        bytes: 0,
        counts: Counts::default(),
        disagreements: Vec::new(),
    };
    for capture in captures {
        let FileRead::Frames {
            frames,
            read_error_after: None,
        } = read_capture(&root.join(capture))
        else {
            panic!("capture illisible : {capture}");
        };
        assert!(!frames.is_empty(), "capture vide : {capture}");
        for (number, (link_type, frame)) in frames.into_iter().enumerate() {
            corpus.counts.read += 1;
            if link_type != LinkType::ETHERNET {
                corpus.counts.not_ethernet += 1;
                continue;
            }
            let readings = Readings::of(&frame);
            if readings.out_of_scope() {
                corpus.counts.out_of_scope += 1;
            } else if readings.agreed().is_some() {
                corpus.bytes += frame.len() as u64;
                corpus.frames.push(frame);
            } else {
                corpus.counts.disagreed += 1;
                if corpus.disagreements.len() < 10_000 {
                    corpus
                        .disagreements
                        .push(((*capture).to_string(), number + 1, readings));
                }
            }
        }
    }
    assert!(!corpus.frames.is_empty(), "corpus vide : {name}");
    corpus
}

pub fn load_all() -> Vec<Corpus> {
    CORPORA
        .iter()
        .map(|(name, captures)| load(name, captures))
        .collect()
}
