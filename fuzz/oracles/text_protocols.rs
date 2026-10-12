// Oracle de la politique hors port des protocoles texte FTP, SMTP et NNTP
// (issue #66), partage par la cible de fuzz `policy_dispatch` et le test de
// parite `tests/fuzz_policy_parity.rs` (issue #108), inclus par `#[path]`.
//
// Les listes recopient celles de `src/parse/dispatch.rs` a dessein plutot que
// de les importer : un oracle qui lirait celles du parseur ne pourrait pas
// les prendre en defaut. Le test de parite confronte les deux copies a
// chaque PR, verbe par verbe et port par port ; le fuzz nocturne, les
// comportements qu'elles induisent sur des octets hostiles. Toute
// modification de l'une se reporte dans l'autre.
#![allow(dead_code)] // chaque inclusion n'utilise qu'une partie du module

use packet_parser::parse::application::protocols::{
    ftp::FtpMessage, nntp::NntpMessage, smtp::SmtpMessage,
};

/// Miroir de `FTP_ONLY_VERBS` (src/parse/dispatch.rs) : verbes que seul FTP
/// definit (RFC 959/2428).
pub const FTP_ONLY_VERBS: [&str; 11] = [
    "RETR", "STOR", "PASV", "APPE", "RNFR", "RNTO", "MKD", "CDUP", "EPSV", "EPRT", "NLST",
];

/// Miroir de `SMTP_ONLY_VERBS`.
pub const SMTP_ONLY_VERBS: [&str; 4] = ["EHLO", "HELO", "MAIL", "RCPT"];

/// Miroir de `NNTP_ONLY_VERBS` (POST en est exclu : HTTP).
pub const NNTP_ONLY_VERBS: [&str; 7] = [
    "ARTICLE",
    "XOVER",
    "XHDR",
    "IHAVE",
    "LISTGROUP",
    "NEWGROUPS",
    "NEWNEWS",
];

/// Miroir de `is_text_protocol_port` : ports standards de la famille texte,
/// ou un verbe distinctif est du contenu en transit (corps DATA, article),
/// jamais une commande d'un autre protocole.
pub const TEXT_PROTOCOL_PORTS: [u16; 4] = [21, 25, 587, 119];

/// Port de chaque etiquette texte, pour les regles a port de la table.
pub const FTP_PORTS: [u16; 1] = [21];
pub const SMTP_PORTS: [u16; 2] = [25, 587];
pub const NNTP_PORTS: [u16; 1] = [119];

/// Miroir de `PROBE_CAP` : la sonde ne lit que ce prefixe du payload,
/// l'oracle juge donc les memes octets qu'elle.
pub const PROBE_CAP: usize = 18 * 1024;

pub fn is_text_protocol_port(port: Option<u16>) -> bool {
    port.is_some_and(|port| TEXT_PROTOCOL_PORTS.contains(&port))
}

fn probed(payload: &[u8]) -> &[u8] {
    &payload[..payload.len().min(PROBE_CAP)]
}

/// Une commande complete (ligne CRLF, UTF-8, arite, aucun octet de controle
/// hors TAB — #109) dont le verbe n'existe qu'en FTP.
pub fn is_ftp_only_command(payload: &[u8]) -> bool {
    matches!(
        FtpMessage::try_from(probed(payload)),
        Ok(FtpMessage::Command { verb, .. })
            if FTP_ONLY_VERBS.iter().any(|only| only.eq_ignore_ascii_case(verb))
    )
}

pub fn is_smtp_only_command(payload: &[u8]) -> bool {
    matches!(
        SmtpMessage::try_from(probed(payload)),
        Ok(SmtpMessage::Command { verb, .. })
            if SMTP_ONLY_VERBS.iter().any(|only| only.eq_ignore_ascii_case(verb))
    )
}

pub fn is_nntp_only_command(payload: &[u8]) -> bool {
    matches!(
        NntpMessage::try_from(probed(payload)),
        Ok(NntpMessage::Command { verb, .. })
            if NNTP_ONLY_VERBS.iter().any(|only| only.eq_ignore_ascii_case(verb))
    )
}

/// Etiquette que la politique hors port attribue a un segment TCP dont aucun
/// port n'est standard : au plus une, les trois listes etant disjointes.
pub fn expected_off_port_label(payload: &[u8]) -> Option<&'static str> {
    if is_ftp_only_command(payload) {
        Some("FTP")
    } else if is_smtp_only_command(payload) {
        Some("SMTP")
    } else if is_nntp_only_command(payload) {
        Some("NNTP")
    } else {
        None
    }
}

/// Le port standard de `label` figure-t-il parmi les deux ports du segment ?
pub fn on_own_port(label: &str, ports: [Option<u16>; 2]) -> bool {
    let own: &[u16] = match label {
        "FTP" => &FTP_PORTS,
        "SMTP" => &SMTP_PORTS,
        "NNTP" => &NNTP_PORTS,
        _ => &[],
    };
    ports.iter().flatten().any(|port| own.contains(port))
}
