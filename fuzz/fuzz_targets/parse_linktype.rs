// Fuzz du point d'entrée multi-linktype : le premier octet choisit le
// LinkType (Ethernet, RAW, LINUX_SLL, valeurs non supportées…), le reste
// est la trame. Aucun couple (link type, octets) ne doit provoquer de
// panic, seulement Ok(_) ou Err(_).
#![no_main]

use libfuzzer_sys::fuzz_target;
use packet_parser::{LinkType, parse};

fuzz_target!(|data: &[u8]| {
    let Some((&selector, frame)) = data.split_first() else {
        return;
    };
    // Alterne entre les link types du catalogue (supportés ou non) et une
    // valeur arbitraire, pour couvrir le dispatch et le refus propre.
    let link_type = match selector % 6 {
        0 => LinkType::ETHERNET,
        1 => LinkType::RAW,
        2 => LinkType::LINUX_SLL,
        3 => LinkType::LINUX_SLL2,
        4 => LinkType(u32::MAX),
        _ => LinkType(selector as u32),
    };
    if let Ok(flow) = parse(link_type, frame) {
        let _ = flow.to_owned();
        let _ = flow.flatten();
    }
});
