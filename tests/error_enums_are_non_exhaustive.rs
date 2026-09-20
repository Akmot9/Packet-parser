// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Tout enum d'erreur public est `#[non_exhaustive]` (issue #21, epic #76).
//!
//! Sans l'attribut, ajouter une variante d'erreur a un parseur est une
//! rupture SemVer : c'est ce qui avait transforme des correctifs d'une
//! demi-journee en majeures. Le test lit les sources de `src/errors` pour
//! qu'un nouveau protocole ne puisse pas l'oublier.

use std::{fs, path::Path};

fn visit(dir: &Path, offenders: &mut Vec<String>, enums: &mut usize) {
    for entry in fs::read_dir(dir).expect("src/errors lisible") {
        let path = entry.expect("entree lisible").path();
        if path.is_dir() {
            visit(&path, offenders, enums);
            continue;
        }
        if path.extension().is_none_or(|ext| ext != "rs") {
            continue;
        }
        let source = fs::read_to_string(&path).expect("source lisible");
        let lines: Vec<&str> = source.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            let Some(name) = line.trim_start().strip_prefix("pub enum ") else {
                continue;
            };
            *enums += 1;
            // Attributs et doc-comments contigus au-dessus de la declaration.
            let attributes = lines[..index]
                .iter()
                .rev()
                .take_while(|above| {
                    let above = above.trim_start();
                    above.starts_with("#[") || above.starts_with("///") || above.starts_with(')')
                })
                .any(|above| above.contains("non_exhaustive"));
            if !attributes {
                offenders.push(format!(
                    "{} : {}",
                    path.display(),
                    name.trim_end_matches(" {")
                ));
            }
        }
    }
}

#[test]
fn every_public_error_enum_is_non_exhaustive() {
    let errors = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/errors");
    let mut offenders = Vec::new();
    let mut enums = 0;
    visit(&errors, &mut offenders, &mut enums);

    assert!(
        enums >= 46,
        "le parcours a bien trouve les enums d'erreur : {enums}"
    );
    assert!(
        offenders.is_empty(),
        "enums d'erreur sans #[non_exhaustive] :\n{}",
        offenders.join("\n")
    );
}
