// Fuzz du point d'entrée multi-linktype : le premier octet choisit le
// LinkType (supportés ou non), le reste est la trame. Aucun couple (link
// type, octets) ne doit provoquer de panic, seulement Ok(_) ou Err(_).
#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use packet_parser::{LinkType, is_supported, parse};

// Le catalogue vient de la bibliotheque elle-meme : tout decodeur que
// `is_supported` annonce est fuzze d'office. La liste ecrite a la main qui
// le precedait avait oublie LINKTYPE_NULL (#95), IPV4 et IPV6.
static SUPPORTED: LazyLock<Vec<LinkType>> = LazyLock::new(|| {
    (0..=u32::from(u16::MAX))
        .map(LinkType)
        .filter(|&link_type| is_supported(link_type))
        .collect()
});

fuzz_target!(|data: &[u8]| {
    let Some((&selector, frame)) = data.split_first() else {
        return;
    };
    // Les link types du catalogue, plus deux valeurs pour le refus propre :
    // u32::MAX, et le selecteur lui-meme pris comme LINKTYPE arbitraire.
    let index = usize::from(selector) % (SUPPORTED.len() + 2);
    let link_type = match SUPPORTED.get(index) {
        Some(&link_type) => link_type,
        None if index == SUPPORTED.len() => LinkType(u32::MAX),
        None => LinkType(u32::from(selector)),
    };
    if let Ok(flow) = parse(link_type, frame) {
        // `to_owned_flow`, pas `to_owned` : depuis a488065, ce dernier n'est
        // plus que le `Clone` de `ToOwned`.
        let _ = flow.to_owned_flow();
        let _ = flow.flatten();
    }
});
