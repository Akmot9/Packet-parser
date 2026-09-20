// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Les types publics que seule la crate construit sont `#[non_exhaustive]`
//! (issue #21, epic #76).
//!
//! Six des quatorze ruptures de la 11.0.0 etaient « ajouter un champ ou une
//! variante a un type exhaustif » : sans l'attribut, completer un decodeur ou
//! nommer une nouvelle erreur est une rupture SemVer, et des correctifs d'une
//! demi-journee devenaient des majeures. Ces tests lisent les sources pour
//! qu'un nouveau protocole ne puisse pas l'oublier.
//!
//! La regle :
//! - tout enum d'erreur de `src/errors` ;
//! - tout enum public de `src/parse` dont les valeurs suivent une spec ou un
//!   registre evolutif, et toute struct a champs nommes que le parseur
//!   construit ;
//! - **sauf** les types listes dans `CONSTRUCTIBLE`, que les consommateurs
//!   construisent eux-memes (Sonar batit `CorruptedLayer` et `VlanTag` en
//!   litteral), et les enums fermes par construction.

use std::{fs, path::Path};

/// Types volontairement exhaustifs, avec la raison.
const CONSTRUCTIBLE: [(&str, &str); 10] = [
    ("VlanTag", "type valeur construit par les consommateurs"),
    ("TlsVersion", "type valeur { major, minor }"),
    ("BridgeId", "type valeur"),
    (
        "CorruptedLayer",
        "construit en litteral par les consommateurs",
    ),
    ("ParseConfig", "champs prives, construit par builder"),
    ("GiopMessages", "iterateur a champs prives"),
    ("VlanStack", "vue a champs prives"),
    ("HttpHeaders", "vue a champs prives"),
    ("Ecn", "deux bits : quatre valeurs, toutes nommees"),
    (
        "QuicPacketType",
        "deux bits : quatre valeurs, toutes nommees",
    ),
];

struct Scan {
    checked: usize,
    offenders: Vec<String>,
}

/// Parcourt `dir` et releve les declarations `pub enum` (et `pub struct` a
/// accolades si `structs`) sans `#[non_exhaustive]`.
fn scan(dir: &Path, structs: bool, scan_result: &mut Scan) {
    for entry in fs::read_dir(dir).expect("repertoire lisible") {
        let path = entry.expect("entree lisible").path();
        if path.is_dir() {
            scan(&path, structs, scan_result);
            continue;
        }
        if path.extension().is_none_or(|ext| ext != "rs") {
            continue;
        }
        let source = fs::read_to_string(&path).expect("source lisible");
        let lines: Vec<&str> = source.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            let declaration = line.trim_start();
            let rest = match declaration.strip_prefix("pub enum ") {
                Some(rest) => rest,
                None if structs => match declaration.strip_prefix("pub struct ") {
                    // Les structs tuple et unit sont des types valeur.
                    Some(rest) if rest.trim_end().ends_with('{') => rest,
                    _ => continue,
                },
                None => continue,
            };
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if CONSTRUCTIBLE.iter().any(|(allowed, _)| *allowed == name) {
                continue;
            }
            scan_result.checked += 1;
            // Attributs et doc-comments contigus au-dessus de la declaration.
            let marked = lines[..index]
                .iter()
                .rev()
                .take_while(|above| {
                    let above = above.trim_start();
                    above.starts_with("#[") || above.starts_with("///") || above.starts_with(')')
                })
                .any(|above| above.contains("non_exhaustive"));
            if !marked {
                scan_result
                    .offenders
                    .push(format!("{} : {name}", path.display()));
            }
        }
    }
}

#[test]
fn every_public_error_enum_is_non_exhaustive() {
    let mut result = Scan {
        checked: 0,
        offenders: Vec::new(),
    };
    scan(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src/errors"),
        false,
        &mut result,
    );

    assert!(
        result.checked >= 46,
        "enums d'erreur trouves : {}",
        result.checked
    );
    assert!(
        result.offenders.is_empty(),
        "enums d'erreur sans #[non_exhaustive] :\n{}",
        result.offenders.join("\n")
    );
}

#[test]
fn every_parser_built_type_is_non_exhaustive() {
    let mut result = Scan {
        checked: 0,
        offenders: Vec::new(),
    };
    scan(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src/parse"),
        true,
        &mut result,
    );

    assert!(result.checked >= 140, "types trouves : {}", result.checked);
    assert!(
        result.offenders.is_empty(),
        "types publics sans #[non_exhaustive] (les marquer, ou les ajouter a \
         CONSTRUCTIBLE avec une raison) :\n{}",
        result.offenders.join("\n")
    );
}
