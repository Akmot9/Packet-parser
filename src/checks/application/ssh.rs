// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Controles pour la chaine d'identification SSH (RFC 4253 §4.2).
//!
//! Format : `SSH-protoversion-softwareversion [SP comments] CR LF`.
//!
//! Deux ecarts a la RFC sont tolerees ici parce que le corpus reel les
//! contient (`pcaps_exemple/The-Ultimate-PCAP.pcapng`) :
//!
//! - le CR est optionnel — `SSH-2.0-Cisco-1.25\n` et
//!   `SSH-2.0-OpenSSH_7.4p1 Raspbian-10+deb9u3\n` terminent par un LF nu ;
//! - `softwareversion` peut contenir un tiret, que la RFC interdit pourtant
//!   explicitement — `SSH-2.0-Cisco-1.25` en est un cas.
//!
//! En revanche `protoversion` reste strictement contraint a `2.0` ou `1.99` :
//! c'est ce qui rend la signature assez forte pour le probing a l'aveugle.

use crate::{
    checks::application::http::{HIGH_BITS, LOW_BITS},
    errors::application::ssh::SshError,
};

/// Prefixe litteral de toute chaine d'identification SSH.
pub const SSH_PREFIX: &[u8] = b"SSH-";

/// `SSH-` (4) + `2.0` (3) + `-` (1) + un octet de logiciel (1) + LF (1).
pub const SSH_MIN_LENGTH: usize = 10;

/// RFC 4253 §4.2 : la chaine ne doit pas depasser 255 octets, CR et LF inclus.
pub const SSH_MAX_IDENTIFICATION_LENGTH: usize = 255;

/// Borne des lignes qu'un serveur envoie avant sa chaine d'identification
/// (RFC 4253 §4.2, « The server MAY send other lines of data before sending
/// the version string »), en octets, fins de ligne incluses (#307). Elle est
/// du meme ordre que la borne de la chaine elle-meme : au-dela, le segment
/// n'est plus lu comme du SSH.
pub const SSH_MAX_PRELUDE_LENGTH: usize = 1024;

/// Les deux seules valeurs de `protoversion` definies.
const SUPPORTED_PROTOCOL_VERSIONS: [&str; 2] = ["2.0", "1.99"];

/// Verifie qu'il reste de quoi porter une identification minimale.
pub fn validate_ssh_min_length(payload: &[u8]) -> Result<(), SshError> {
    if payload.len() < SSH_MIN_LENGTH {
        return Err(SshError::InvalidLength {
            expected: SSH_MIN_LENGTH,
            actual: payload.len(),
        });
    }
    Ok(())
}

/// Verifie le prefixe litteral `SSH-`.
pub fn validate_ssh_prefix(payload: &[u8]) -> Result<(), SshError> {
    if !payload.starts_with(SSH_PREFIX) {
        return Err(SshError::MissingPrefix);
    }
    Ok(())
}

/// Renvoie le segment a partir de sa chaine d'identification, apres les
/// lignes que le serveur a pu envoyer avant elle (#307).
///
/// Chacune de ces lignes est terminee par CRLF, ne commence pas par `SSH-`
/// (RFC 4253 §4.2 : « Such lines MUST NOT begin with "SSH-" »), est de
/// l'UTF-8 sans octet de controle ASCII autre que TAB, et toutes tiennent
/// dans [`SSH_MAX_PRELUDE_LENGTH`] octets. Sinon, et quand aucune ligne ne
/// commence par `SSH-`, le segment est refuse ([`SshError::MissingPrefix`]) :
/// la regle SSH est aveugle sur TCP, et seule une chaine en tete de ligne
/// apres du texte borne y reste une signature forte. Une charge binaire est
/// refusee des son premier octet de controle.
pub fn locate_ssh_identification(payload: &[u8]) -> Result<&[u8], SshError> {
    find_ssh_identification(payload).ok_or(SshError::MissingPrefix)
}

/// [`locate_ssh_identification`] sans son erreur, pour la sonde du dispatch :
/// tentee sur tout segment TCP non reconnu qui s'ouvre par un octet de
/// texte, elle n'a que faire du motif du refus.
pub fn find_ssh_identification(payload: &[u8]) -> Option<&[u8]> {
    if payload.starts_with(SSH_PREFIX) {
        return Some(payload);
    }
    // Les premiers octets de la premiere ligne refusent presque tout segment
    // qui n'est pas du SSH : ils sont lus ici, sans appel ni cadre de pile ;
    // la suite est rare.
    let first_line = prelude_text_start(payload)?;
    find_ssh_identification_after(payload, first_line)
}

/// La suite de [`find_ssh_identification`] quand le segment s'ouvre par une
/// ligne de preambule : de `first_line` octets, que suit son CRLF, ou qui
/// reste a lire au-dela de ses premiers octets (`None`).
#[inline(never)]
fn find_ssh_identification_after(payload: &[u8], first_line: Option<usize>) -> Option<&[u8]> {
    let mut text = match first_line {
        Some(text) => text,
        None => prelude_text_length_by_words(payload)?,
    };
    let mut rest = payload;
    let mut start = 0;
    loop {
        core::str::from_utf8(rest.get(..text)?).ok()?;
        start += text + 2;
        if start > SSH_MAX_PRELUDE_LENGTH {
            return None;
        }
        rest = payload.get(start..)?;
        if rest.starts_with(SSH_PREFIX) {
            return Some(rest);
        }
        text = prelude_text_length(rest)?;
    }
}

/// Vrai, a l'indice d'un octet, pour un octet de controle ASCII autre que
/// TAB : il termine le texte d'une ligne de preambule. En table : un seul
/// test par octet lu, la ou la comparaison en cascade en coutait le double.
static ENDS_PRELUDE_TEXT: [bool; 256] = {
    let mut table = [false; 256];
    let mut byte = 0;
    while byte < table.len() {
        table[byte] = (byte < 0x20 && byte != 0x09) || byte == 0x7f;
        byte += 1;
    }
    table
};

/// La longueur du texte de la ligne de preambule qui ouvre `rest`, CRLF
/// exclu : jusqu'au premier octet de controle autre que TAB, parmi les
/// [`SSH_MAX_PRELUDE_LENGTH`] premiers, qui doit etre un CR devant un LF.
/// Le texte reste a valider en UTF-8.
fn prelude_text_length(rest: &[u8]) -> Option<usize> {
    match prelude_text_start(rest)? {
        Some(text) => Some(text),
        None => prelude_text_length_by_words(rest),
    }
}

/// Les octets que [`prelude_text_start`] lit un a un, avant la lecture par
/// mots : une charge binaire, un octet de controle sur huit, s'y arrete
/// vingt-quatre fois sur vingt-cinq, et l'entree de la lecture par mots
/// coute plus que les quelques octets qu'elle lui epargnerait.
const PRELUDE_FIRST_BYTES: usize = 24;

/// Le debut de [`prelude_text_length`], sur les [`PRELUDE_FIRST_BYTES`]
/// premiers octets de `rest` : la longueur du texte quand la ligne y finit,
/// `Some(None)` quand ils sont tous du texte et que d'autres octets suivent,
/// `None` quand la ligne est refusee.
#[inline(always)]
fn prelude_text_start(rest: &[u8]) -> Option<Option<usize>> {
    let first = rest.get(..PRELUDE_FIRST_BYTES).unwrap_or(rest);
    match first
        .iter()
        .position(|byte| ENDS_PRELUDE_TEXT[usize::from(*byte)])
    {
        Some(index) => prelude_text_end(rest, index).map(Some),
        None if first.len() < rest.len() => Some(None),
        None => None,
    }
}

/// `index` quand l'octet de controle qui s'y trouve est le CR d'un CRLF.
fn prelude_text_end(rest: &[u8], index: usize) -> Option<usize> {
    match rest.get(index..index + 2) {
        Some(b"\r\n") => Some(index),
        _ => None,
    }
}

/// La suite de [`prelude_text_length`] quand les [`PRELUDE_FIRST_BYTES`]
/// premiers octets sont du texte : la ligne se lit par mots de huit octets,
/// une instruction et demie par octet au lieu de six. Du texte sans fin de
/// ligne (JSON, base64, le corps d'une reponse HTTP) est lu jusqu'a la
/// borne.
///
/// `(x - n) & !x` leve le bit fort de chaque octet sous `n` : sous 0x20 dans
/// le mot, sous 1 dans le mot croise avec 0x7f, donc sur chaque DEL. Une
/// retenue peut le lever a tort, mais seulement au-dessus d'un octet qui le
/// leve a raison : le bit leve le plus bas designe le premier octet de
/// controle, et lui seul est lu.
#[inline(never)]
fn prelude_text_length_by_words(rest: &[u8]) -> Option<usize> {
    let scanned = rest.get(..SSH_MAX_PRELUDE_LENGTH).unwrap_or(rest);
    let mut index = PRELUDE_FIRST_BYTES;
    while let Some(word) = scanned.get(index..).and_then(<[u8]>::first_chunk::<8>) {
        let word = u64::from_le_bytes(*word);
        let below_space = word.wrapping_sub(LOW_BITS * 0x20) & !word;
        let delete = word ^ (LOW_BITS * 0x7f);
        let delete = delete.wrapping_sub(LOW_BITS) & !delete;
        let controls = (below_space | delete) & HIGH_BITS;
        if controls == 0 {
            index += 8;
            continue;
        }
        index += (controls.trailing_zeros() / 8) as usize;
        if scanned.get(index) != Some(&b'\t') {
            return prelude_text_end(rest, index);
        }
        // TAB est du texte : la lecture reprend apres lui.
        index += 1;
    }
    // Moins d'un mot avant la borne ou la fin du segment.
    let position = scanned
        .get(index..)?
        .iter()
        .position(|byte| ENDS_PRELUDE_TEXT[usize::from(*byte)])?;
    prelude_text_end(rest, index + position)
}

/// Renvoie la ligne d'identification, terminateur exclu.
///
/// Le LF est obligatoire, le CR qui le precede est optionnel : deux serveurs
/// du corpus emettent un LF nu.
pub fn extract_ssh_identification_line(payload: &[u8]) -> Result<&[u8], SshError> {
    let line_feed = payload
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or(SshError::MissingLineTerminator)?;

    if line_feed + 1 > SSH_MAX_IDENTIFICATION_LENGTH {
        return Err(SshError::IdentificationTooLong {
            max: SSH_MAX_IDENTIFICATION_LENGTH,
            actual: line_feed + 1,
        });
    }

    let end = if line_feed > 0 && payload[line_feed - 1] == b'\r' {
        line_feed - 1
    } else {
        line_feed
    };

    Ok(&payload[..end])
}

/// Verifie que la ligne ne contient que de l'ASCII imprimable.
///
/// La RFC autorise l'espace uniquement comme separateur des commentaires ;
/// on l'accepte partout dans la ligne, mais aucun octet de controle.
pub fn validate_ssh_printable(line: &[u8]) -> Result<(), SshError> {
    for (offset, byte) in line.iter().enumerate() {
        if !(0x20..=0x7e).contains(byte) {
            return Err(SshError::NonPrintableByte { offset });
        }
    }
    Ok(())
}

/// Extrait `protoversion` et renvoie le reste de la ligne, separateur exclu.
///
/// C'est le controle qui porte toute la force de la signature : sans lui,
/// n'importe quel texte commencant par `SSH-` passerait pour du SSH.
pub fn extract_ssh_protocol_version(line: &[u8]) -> Result<(&str, &[u8]), SshError> {
    let after_prefix = &line[SSH_PREFIX.len()..];
    let separator = after_prefix
        .iter()
        .position(|byte| *byte == b'-')
        .ok_or(SshError::MissingVersionSeparator)?;

    let version = core::str::from_utf8(&after_prefix[..separator])
        .map_err(|_| SshError::UnsupportedProtocolVersion)?;

    if !SUPPORTED_PROTOCOL_VERSIONS.contains(&version) {
        return Err(SshError::UnsupportedProtocolVersion);
    }

    Ok((version, &after_prefix[separator + 1..]))
}

/// Scinde le reste de la ligne en `softwareversion` et commentaires.
///
/// Le premier espace separe les deux ; `softwareversion` conserve ses tirets
/// eventuels, contrairement a ce que prescrit la RFC.
pub fn extract_ssh_software_and_comments(rest: &[u8]) -> Result<(&str, Option<&str>), SshError> {
    let (software, comments) = match rest.iter().position(|byte| *byte == b' ') {
        Some(space) => (&rest[..space], Some(&rest[space + 1..])),
        None => (rest, None),
    };

    if software.is_empty() {
        return Err(SshError::EmptySoftwareVersion);
    }

    let software = core::str::from_utf8(software).map_err(|_| SshError::NonPrintableByte {
        offset: SSH_PREFIX.len(),
    })?;
    let comments = match comments {
        Some(bytes) => {
            Some(
                core::str::from_utf8(bytes).map_err(|_| SshError::NonPrintableByte {
                    offset: SSH_PREFIX.len(),
                })?,
            )
        }
        None => None,
    };

    Ok((software, comments))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// La lecture d'origine des lignes de preambule (#307), octet par octet
    /// et en cascade : la reference de `find_ssh_identification`.
    fn reference_locate(payload: &[u8]) -> Result<&[u8], SshError> {
        fn line_length(rest: &[u8]) -> Result<usize, SshError> {
            for (index, byte) in rest.iter().enumerate().take(SSH_MAX_PRELUDE_LENGTH) {
                match *byte {
                    b'\r' if rest.get(index + 1) == Some(&b'\n') => {
                        let line = rest.get(..index).ok_or(SshError::MissingPrefix)?;
                        core::str::from_utf8(line).map_err(|_| SshError::MissingPrefix)?;
                        return Ok(index + 2);
                    }
                    b'\t' => {}
                    byte if byte < 0x20 || byte == 0x7f => return Err(SshError::MissingPrefix),
                    _ => {}
                }
            }
            Err(SshError::MissingPrefix)
        }
        let mut start = 0;
        loop {
            let rest = payload.get(start..).ok_or(SshError::MissingPrefix)?;
            if rest.starts_with(SSH_PREFIX) {
                return Ok(rest);
            }
            start += line_length(rest)?;
            if start > SSH_MAX_PRELUDE_LENGTH {
                return Err(SshError::MissingPrefix);
            }
        }
    }

    /// Meme decision, et meme segment rendu, que la reference ; rend vrai
    /// quand une chaine d'identification est trouvee.
    fn agrees(payload: &[u8]) -> bool {
        let expected = reference_locate(payload);
        assert_eq!(locate_ssh_identification(payload), expected, "{payload:?}");
        let expected = expected.ok();
        assert_eq!(find_ssh_identification(payload), expected, "{payload:?}");
        expected.is_some()
    }

    /// La table est la comparaison qu'elle remplace.
    #[test]
    fn prelude_table_is_the_ascii_controls_but_tab() {
        for byte in 0..=u8::MAX {
            assert_eq!(
                ENDS_PRELUDE_TEXT[usize::from(byte)],
                byte != b'\t' && (byte < 0x20 || byte == 0x7f),
                "{byte:#04x}"
            );
        }
    }

    /// Des preambules d'une a trois lignes, puis chaque troncature et chaque
    /// valeur de chaque octet : la recherche rend ce que rendait la lecture
    /// d'origine.
    #[test]
    fn prelude_search_agrees_with_the_reference_on_every_byte_value() {
        let seeds: [&[u8]; 9] = [
            b"SSH-2.0-OpenSSH_9.6\r\n",
            b"Welcome\r\nSSH-2.0-OpenSSH_9.6\r\n",
            b"Hello\r\n\tcaf\xc3\xa9\r\n\r\nSSH-1.99-Server\n",
            b"\r\n\r\nSSH-2.0-x\n",
            b"a\tb\r\nSSH-",
            b"Welcome\r\nnothing else here\r\n",
            b"Welcome\nSSH-2.0-OpenSSH_9.6\r\n",
            b"\xe2\x82\xac uro\r\nSSH-2.0-OpenSSH_9.6\r\n",
            b"GET / HTTP/1.1\r\nHost: a\r\n\r\nSSH-2.0-quoted\r\n",
        ];
        let (mut found, mut refused) = (0, 0);
        let mut check = |payload: &[u8]| {
            if agrees(payload) {
                found += 1;
            } else {
                refused += 1;
            }
        };
        check(b"");
        for seed in seeds {
            check(seed);
            let mut mutated = seed.to_vec();
            for position in 0..seed.len() {
                check(&seed[..position]);
                for value in 0..=u8::MAX {
                    mutated[position] = value;
                    check(&mutated);
                }
                mutated[position] = seed[position];
            }
        }
        assert!(found > 20_000, "{found} recherches abouties");
        assert!(refused > 10_000, "{refused} recherches refusees");
    }

    /// La lecture par mots de huit octets : toutes les suites de cinq octets
    /// pris parmi le texte, TAB, les controles et leurs voisins qu'une
    /// retenue pourrait confondre (espace, `~`), a chaque decalage dans le
    /// mot au-dela des octets lus un a un et a cheval sur leur frontiere,
    /// devant une fin de ligne et une banniere.
    #[test]
    fn prelude_search_agrees_with_the_reference_on_every_word_pattern() {
        const ALPHABET: [u8; 9] = [b'a', b'\t', b' ', b'~', 0x7f, 0x1f, b'\r', b'\n', 0x80];
        let (mut found, mut refused) = (0, 0);
        let mut digits = [0_usize; 5];
        loop {
            let pattern = digits.map(|digit| ALPHABET[digit]);
            for offset in PRELUDE_FIRST_BYTES - 3..PRELUDE_FIRST_BYTES + 8 {
                let mut payload = vec![b'x'; offset];
                payload.extend_from_slice(&pattern);
                payload.extend_from_slice(b"xy\r\nSSH-2.0-OpenSSH_9.6\r\n");
                if agrees(&payload) {
                    found += 1;
                } else {
                    refused += 1;
                }
            }
            let Some(position) = digits.iter().position(|digit| digit + 1 < ALPHABET.len()) else {
                break;
            };
            digits[position] += 1;
            digits[..position].fill(0);
        }
        assert!(found > 12_000, "{found} recherches abouties");
        assert!(refused > 600_000, "{refused} recherches refusees");
    }

    /// Autour de la borne des lignes de preambule : une ligne, puis deux,
    /// dont le dernier CRLF tombe avant, sur et apres
    /// [`SSH_MAX_PRELUDE_LENGTH`], chaque troncature proche de la borne, et
    /// un octet de controle a chaque position de la fenetre lue.
    #[test]
    fn prelude_search_agrees_with_the_reference_around_the_bound() {
        let banner = b"SSH-2.0-OpenSSH_9.6\r\n";
        let mut found = 0;
        for prelude in SSH_MAX_PRELUDE_LENGTH - 4..=SSH_MAX_PRELUDE_LENGTH + 4 {
            for first in [prelude, prelude / 2, 2, 3] {
                let mut payload = vec![b'a'; first - 2];
                payload.extend_from_slice(b"\r\n");
                if first < prelude {
                    payload.resize(prelude - 2, b'b');
                    payload.extend_from_slice(b"\r\n");
                }
                payload.extend_from_slice(banner);
                found += usize::from(agrees(&payload));
                for cut in prelude - 3..prelude + 3 {
                    agrees(&payload[..cut]);
                }
            }
        }
        assert!(found > 15, "{found} recherches abouties");

        let mut payload = vec![b'a'; SSH_MAX_PRELUDE_LENGTH + 8];
        payload.extend_from_slice(b"\r\n");
        payload.extend_from_slice(banner);
        for position in 0..payload.len() {
            let original = payload[position];
            for value in [0x00, b'\t', b'\n', b'\r', 0x1f, 0x7f, 0x80, 0xff] {
                payload[position] = value;
                agrees(&payload);
            }
            payload[position] = original;
        }
    }
}
