// Aides des cibles dediees a un seul decodeur applicatif (issue #272),
// incluses par `#[path]` : appartenance d'un emprunt a l'entree, et rejeu des
// graines reelles sous mutation XOR.
#![allow(dead_code)] // chaque inclusion n'utilise qu'une partie du module

/// Vrai si `field` est vide ou tient tout entier dans `input` : un champ
/// emprunte pointe dans l'entree, jamais dans une copie ni au-dela.
pub fn inside(input: &[u8], field: &[u8]) -> bool {
    let (outer, inner) = (input.as_ptr_range(), field.as_ptr_range());
    field.is_empty() || (outer.start <= inner.start && inner.end <= outer.end)
}

/// Rejoue `exercise` sur chaque graine mutee : deux octets de fuzz
/// choisissent une position et un masque XOR. Types, longueurs et chaines
/// d'une trame reelle sont atteints des le depart, sans attendre que le
/// fuzzer reconstruise un en-tete valide.
pub fn replay_mutated(seeds: &[&[u8]], data: &[u8], exercise: impl Fn(&[u8])) {
    for seed in seeds {
        let mut seeded = seed.to_vec();
        for [offset, mask] in data.as_chunks::<2>().0 {
            let offset = usize::from(*offset) % seeded.len();
            seeded[offset] ^= mask;
        }
        exercise(&seeded);
    }
}
