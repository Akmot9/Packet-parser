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

use crate::errors::application::ssh::SshError;

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
    let mut start = 0;
    loop {
        let rest = payload.get(start..).ok_or(SshError::MissingPrefix)?;
        if rest.starts_with(SSH_PREFIX) {
            return Ok(rest);
        }
        start += prelude_line_length(rest)?;
        if start > SSH_MAX_PRELUDE_LENGTH {
            return Err(SshError::MissingPrefix);
        }
    }
}

/// La longueur, CRLF compris, de la ligne de preambule qui ouvre `rest`.
fn prelude_line_length(rest: &[u8]) -> Result<usize, SshError> {
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
