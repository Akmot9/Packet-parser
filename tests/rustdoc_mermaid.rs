//! Les schemas ```mermaid packet-beta de la rustdoc sont dessines par
//! mermaid 11 (`docs/rustdoc/mermaid.html`, #215). mermaid refuse un schema
//! dont les champs ne se suivent pas a partir du bit 0 : le bloc reste alors
//! du code, sans erreur ni avertissement de `cargo doc`. La CI ne lance pas
//! de navigateur ; ce test garde la regle que mermaid applique.

use std::fs;
use std::path::{Path, PathBuf};

fn rust_sources(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("src/ lisible") {
        let path = entry.expect("entree lisible").path();
        if path.is_dir() {
            rust_sources(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}

/// Le texte d'un commentaire de doc (`///` ou `//!`), sans le marqueur.
fn doc_text(line: &str) -> Option<&str> {
    let line = line.trim_start();
    let text = line
        .strip_prefix("///")
        .or_else(|| line.strip_prefix("//!"))?;
    Some(text.strip_prefix(' ').unwrap_or(text))
}

/// Les schemas mermaid d'un fichier : (ligne du bloc, lignes du schema).
fn mermaid_blocks(source: &str) -> Vec<(usize, Vec<String>)> {
    let mut blocks = Vec::new();
    let mut current: Option<(usize, Vec<String>)> = None;
    for (index, line) in source.lines().enumerate() {
        let Some(text) = doc_text(line) else {
            assert!(current.is_none(), "bloc mermaid non ferme ligne {index}");
            continue;
        };
        match current.as_mut() {
            None if text.trim_end() == "```mermaid" => current = Some((index + 1, Vec::new())),
            None => {}
            Some(_) if text.trim_end() == "```" => blocks.extend(current.take()),
            Some((_, lines)) => lines.push(text.to_string()),
        }
    }
    blocks
}

/// Verifie un schema packet-beta comme mermaid 11 : chaque champ commence
/// juste apres le precedent, le premier au bit 0, et finit apres son debut.
fn check_packet(lines: &[String]) -> Result<(), String> {
    let mut lines = lines.iter().map(|line| line.trim());
    // L'en-tete YAML facultatif (`---`, `title: ...`, `---`).
    let mut first = lines.next();
    if first == Some("---") {
        for line in lines.by_ref() {
            if line == "---" {
                break;
            }
        }
        first = lines.next();
    }
    if first != Some("packet-beta") {
        return Err(format!("premiere ligne {first:?}, attendu packet-beta"));
    }
    let mut next_bit = 0u32;
    // `%%` ouvre un commentaire mermaid.
    for line in lines.filter(|line| !line.is_empty() && !line.starts_with("%%")) {
        let (range, label) = line
            .split_once(':')
            .ok_or_else(|| format!("champ sans ':' : {line}"))?;
        let label = label.trim();
        if label.len() < 2 || !label.starts_with('"') || !label.ends_with('"') {
            return Err(format!("libelle sans guillemets : {line}"));
        }
        let range = range.trim();
        let (start, end) = if let Some(bits) = range.strip_prefix('+') {
            let bits: u32 = bits.parse().map_err(|_| format!("taille : {line}"))?;
            if bits == 0 {
                return Err(format!("champ de 0 bit : {line}"));
            }
            (next_bit, next_bit + bits - 1)
        } else {
            let (start, end) = range.split_once('-').unwrap_or((range, range));
            let start: u32 = start.parse().map_err(|_| format!("debut : {line}"))?;
            let end: u32 = end.parse().map_err(|_| format!("fin : {line}"))?;
            (start, end)
        };
        if start != next_bit {
            return Err(format!("{line} : attendu un debut au bit {next_bit}"));
        }
        if end < start {
            return Err(format!("{line} : fin avant le debut"));
        }
        next_bit = end + 1;
    }
    Ok(())
}

#[test]
fn rustdoc_packet_diagrams_are_drawable_by_mermaid() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_sources(&src, &mut files);
    files.sort();

    let mut diagrams = 0;
    let mut failures = Vec::new();
    for file in &files {
        let source = fs::read_to_string(file).expect("source lisible");
        for (line, lines) in mermaid_blocks(&source) {
            diagrams += 1;
            if let Err(reason) = check_packet(&lines) {
                let file = file.strip_prefix(&src).unwrap_or(file).display();
                failures.push(format!("src/{file}:{line} : {reason}"));
            }
        }
    }
    // Garde contre un test vide : 74 schemas a l'ecriture du test.
    assert!(diagrams >= 70, "{diagrams} schemas mermaid trouves");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn the_check_rejects_what_mermaid_rejects() {
    let lines = |text: &str| text.lines().map(str::to_string).collect::<Vec<_>>();
    assert!(check_packet(&lines("packet-beta\n0-15: \"A\"\n+16: \"B\"\n32: \"C\"")).is_ok());
    assert!(
        check_packet(&lines(
            "---\ntitle: T\n---\npacket-beta\n%% note\n0-7: \"A\""
        ))
        .is_ok()
    );
    // Le schema Valmet DNA de la 11.8.0 commencait au bit 96.
    assert!(check_packet(&lines("packet-beta\n96-287: \"A\"")).is_err());
    assert!(check_packet(&lines("packet-beta\n0-7: \"A\"\n9-15: \"B\"")).is_err());
    assert!(check_packet(&lines("packet-beta\n0-7: \"A\"\n8-15: B")).is_err());
    assert!(check_packet(&lines("flowchart\nA --> B")).is_err());
}
