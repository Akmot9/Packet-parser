// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Etat des lieux PROFINET (issue #133) sur `pcaps_exemple/protocols/profinet/`.
//!
//! Chaque trame EtherType 0x8892 (VLAN compris) passe par le validateur DCP de
//! la couche internet. Le test fige ce que la crate en fait aujourd'hui : 103
//! trames `internet = Profinet`, 129 `corrupted`, par variante d'erreur. La
//! plupart des 129 sont des trames saines (trafic cyclique RT_CLASS_1, PTCP,
//! alarmes, fragments ; DCP Set et Identify Response dont le premier bloc
//! n'est pas un NameOfStation). Le correctif de #133 doit faire baisser ces
//! comptes et mettre a jour l'attendu dans le meme commit, avec sa
//! justification, comme `golden_pcaps`.

use std::collections::BTreeMap;
use std::path::Path;

use packet_parser::{CorruptedLayerKind, NetworkProtocol, parse};

mod common;
use common::{FileRead, collect_capture_files, read_capture};

/// Trames PN-RT par capture, comptees par `tshark -Y pn_rt` (4.6.6) : la crate
/// doit les retrouver toutes par leur EtherType, derriere un tag VLAN ou non.
const PN_RT_FRAMES: &[(&str, usize)] = &[
    ("cisagov_profinet_io_cm.pcap", 10),
    ("cisagov_profinet_io_cm_mixed_1.pcap", 164),
    ("iti_ChangeIPUsingDCP.pcap", 4),
    ("iti_PROFINET-RT.pcap", 14),
    ("iti_profinet-wireshark-bug.pcap", 4),
    ("miguelob_pn.pcapng", 18),
    ("miguelob_pn_dcp.pcapng", 18),
];

/// Variante de `ProfinetPacketError` derriere le texte de `CorruptedLayer`.
fn error_variant(error: &str) -> &'static str {
    if error.contains("Unknown Frame ID") {
        "UnknownFrameId"
    } else if error.contains("Invalid DCP block length") {
        "InvalidDcpBlockLength"
    } else if error.contains("Invalid name of station") {
        "InvalidNameOfStation"
    } else if error.contains("Packet too short") {
        "PacketTooShort"
    } else {
        panic!("erreur PROFINET inattendue : {error}")
    }
}

#[test]
fn profinet_frames_are_all_found_and_their_outcome_is_frozen() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("pcaps_exemple")
        .join("protocols")
        .join("profinet");
    let mut captures = Vec::new();
    collect_capture_files(dir.as_path(), &mut captures);
    captures.sort();

    let mut per_file: BTreeMap<String, usize> = BTreeMap::new();
    let mut outcomes: BTreeMap<&'static str, usize> = BTreeMap::new();
    for path in &captures {
        let name = path
            .file_name()
            .expect("nom de fichier")
            .to_string_lossy()
            .into_owned();
        let FileRead::Frames {
            frames,
            read_error_after,
        } = read_capture(path)
        else {
            panic!("{name}: format de capture non lu");
        };
        assert_eq!(read_error_after, None, "{name}: lecture interrompue");
        for (link_type, data) in &frames {
            let flow = parse(*link_type, data).unwrap_or_else(|error| panic!("{name}: {error}"));
            if flow.data_link.network_protocol() != NetworkProtocol::Profinet {
                continue;
            }
            *per_file.entry(name.clone()).or_default() += 1;
            // Rien n'est parse au-dessus d'une trame PROFINET, valide ou non.
            assert!(
                flow.transport.is_none(),
                "{name}: transport sur une trame PROFINET"
            );
            assert!(
                flow.application.is_none(),
                "{name}: application sur une trame PROFINET"
            );
            let outcome = match (&flow.internet, &flow.corrupted) {
                (Some(internet), None) => {
                    assert_eq!(internet.protocol_name, "Profinet");
                    assert!(internet.source.is_none() && internet.payload.is_empty());
                    "Profinet"
                }
                (None, Some(corrupted)) => {
                    assert_eq!(corrupted.layer, CorruptedLayerKind::Internet);
                    error_variant(&corrupted.error)
                }
                (internet, corrupted) => {
                    panic!("{name}: internet={internet:?} corrupted={corrupted:?}")
                }
            };
            *outcomes.entry(outcome).or_default() += 1;
        }
    }

    let expected_per_file: BTreeMap<String, usize> = PN_RT_FRAMES
        .iter()
        .map(|(file, count)| ((*file).to_string(), *count))
        .collect();
    assert_eq!(
        per_file, expected_per_file,
        "trames PN-RT trouvees par capture (oracle : tshark -Y pn_rt)"
    );

    // 232 trames PN-RT. Les 129 `corrupted` sont, a une exception pres, des
    // trames saines que le validateur DCP ne sait pas lire (issue #133) :
    // - UnknownFrameId : 10 RT_CLASS_1 (0x8000/0x8010), 41 PTCP (0xFF40),
    //   6 alarmes (0xFE01), 10 fragments (0xFF85-0xFF8D) ;
    // - InvalidDcpBlockLength : 56 des 102 cycliques 0xC000/0xC002 de
    //   mixed_1, lues comme du DCP (les 46 autres passent, champs DCP = bruit) ;
    // - InvalidNameOfStation : 5 DCP sains dont le premier bloc n'est pas un
    //   NameOfStation (bloc IP d'un Set request, DeviceOptions d'une Identify
    //   response) ;
    // - PacketTooShort : une Identify request de 32 octets, capturee en
    //   sortie sans bourrage, dont DCPDataLength annonce des blocs absents.
    let expected: BTreeMap<&str, usize> = [
        ("Profinet", 103),
        ("UnknownFrameId", 67),
        ("InvalidDcpBlockLength", 56),
        ("InvalidNameOfStation", 5),
        ("PacketTooShort", 1),
    ]
    .into_iter()
    .collect();
    assert_eq!(
        outcomes, expected,
        "\nissue du validateur DCP par trame PN-RT (a figer si le changement est voulu) :\n{outcomes:#?}\n"
    );
}
