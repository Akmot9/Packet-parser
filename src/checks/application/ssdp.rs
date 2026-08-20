// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Controles pour les messages SSDP (HTTPU, UPnP Device Architecture 1.1 §1).
//!
//! SSDP reutilise la syntaxe HTTP/1.1 sur UDP. Ce qui le distingue d'une
//! requete HTTP ordinaire est verrouille ici : le Request-URI est exactement
//! `*` et les seules methodes sont `M-SEARCH` et `NOTIFY` ; la seule ligne de
//! statut emise est `HTTP/1.1 200 OK` (reponse a un M-SEARCH). Un M-SEARCH
//! doit en plus porter `MAN: "ssdp:discover"` (UDA 1.1 §1.3.2).

use crate::{
    errors::application::ssdp::SsdpError, parse::application::protocols::ssdp::SsdpMessageType,
};

/// Ligne de statut, seule reponse definie : `HTTP/1.1 200 OK`.
pub const SSDP_RESPONSE_START_LINE: &str = "HTTP/1.1 200 OK";

/// Version HTTP imposee dans les lignes de requete.
pub const SSDP_HTTP_VERSION: &str = "HTTP/1.1";

/// Valeur imposee de l'en-tete MAN d'un M-SEARCH, guillemets compris.
pub const SSDP_DISCOVER_MAN: &str = "\"ssdp:discover\"";

/// Separateur entre le bloc d'en-tetes et la fin du message.
const HEAD_TERMINATOR: &str = "\r\n\r\n";

/// Plus court message possible : la ligne de statut nue `HTTP/1.1 200 OK`
/// suivie de CRLF et de la ligne vide finale.
pub const SSDP_MIN_LENGTH: usize = SSDP_RESPONSE_START_LINE.len() + HEAD_TERMINATOR.len();

/// Verifie qu'il reste de quoi porter un message SSDP minimal.
pub fn validate_ssdp_min_length(payload: &[u8]) -> Result<(), SsdpError> {
    if payload.len() < SSDP_MIN_LENGTH {
        return Err(SsdpError::InvalidLength {
            expected: SSDP_MIN_LENGTH,
            actual: payload.len(),
        });
    }
    Ok(())
}

/// Verifie que le message est de l'UTF-8 et le renvoie emprunte.
///
/// Un payload binaire echoue ici : SSDP est purement textuel.
pub fn extract_ssdp_text(payload: &[u8]) -> Result<&str, SsdpError> {
    core::str::from_utf8(payload).map_err(|_| SsdpError::InvalidUtf8)
}

/// Renvoie le bloc start-line + en-tetes, ligne vide finale exclue.
///
/// La ligne vide est obligatoire : un datagramme UDP porte le message en
/// entier, un bloc non termine n'est donc pas un SSDP tronque mais un autre
/// protocole. Les octets apres la ligne vide sont ignores — la trame 38194 du
/// corpus (`pcaps_exemple/The-Ultimate-PCAP.pcapng`) emet un CRLF surnumeraire
/// apres la fin du message.
pub fn extract_ssdp_head(text: &str) -> Result<&str, SsdpError> {
    match text.find(HEAD_TERMINATOR) {
        Some(index) => Ok(&text[..index]),
        None => Err(SsdpError::MissingHeaderTerminator),
    }
}

/// Classe la premiere ligne et renvoie le type de message.
///
/// Trois formes exactes sont acceptees : `M-SEARCH * HTTP/1.1`,
/// `NOTIFY * HTTP/1.1` et `HTTP/1.1 200 OK`. C'est le controle qui porte la
/// distinction avec HTTP : une requete HTTP ordinaire n'utilise jamais ces
/// methodes ni le Request-URI `*` avec elles.
pub fn extract_ssdp_message_type(line: &str) -> Result<SsdpMessageType, SsdpError> {
    // Ligne de statut : seule la reponse 200 OK existe en SSDP.
    if let Some(status) = line.strip_prefix("HTTP/1.1") {
        if status != " 200 OK" {
            return Err(SsdpError::InvalidStatusLine);
        }
        return Ok(SsdpMessageType::Response);
    }

    let mut parts = line.splitn(3, ' ');
    let message_type = match parts.next().unwrap_or_default() {
        "M-SEARCH" => SsdpMessageType::MSearch,
        "NOTIFY" => SsdpMessageType::Notify,
        _ => return Err(SsdpError::UnknownMethod),
    };

    if parts.next() != Some("*") {
        return Err(SsdpError::InvalidRequestUri);
    }

    if parts.next() != Some(SSDP_HTTP_VERSION) {
        return Err(SsdpError::UnsupportedHttpVersion);
    }

    Ok(message_type)
}

/// Verifie qu'une ligne d'en-tete a la forme `Nom: valeur` et renvoie la
/// paire empruntee, espaces peripheriques exclus.
///
/// L'espace apres `:` est optionnel : la trame 38194 du corpus emet
/// `ST:upnp:rootdevice` sans espace.
pub fn extract_ssdp_header_line(line: &str) -> Result<(&str, &str), SsdpError> {
    let (name, value) = line.split_once(':').ok_or(SsdpError::InvalidHeader)?;
    let name = name.trim();
    if name.is_empty() {
        return Err(SsdpError::InvalidHeader);
    }
    Ok((name, value.trim()))
}

/// Verifie qu'un M-SEARCH porte `MAN: "ssdp:discover"` (UDA 1.1 §1.3.2).
///
/// Les autres types de message ne sont pas contraints : NOTIFY et la reponse
/// n'emploient pas MAN.
pub fn validate_ssdp_man(
    message_type: SsdpMessageType,
    man: Option<&str>,
) -> Result<(), SsdpError> {
    if message_type == SsdpMessageType::MSearch && man != Some(SSDP_DISCOVER_MAN) {
        return Err(SsdpError::MissingDiscoverMan);
    }
    Ok(())
}
