// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Parite entre l'oracle de politique du fuzz (`fuzz/oracles/text_protocols.rs`,
//! cible `policy_dispatch`) et la table de dispatch (issue #108).
//!
//! L'oracle recopie les listes de verbes, les ports et `PROBE_CAP` de
//! `src/parse/dispatch.rs` au lieu de les importer : un oracle qui lirait
//! ceux du parseur ne pourrait pas le prendre en defaut. Le prix etait une
//! derive silencieuse — #66 a elargi la detection FTP hors port, l'oracle
//! est reste a TCP/21, et le fuzz nocturne a echoue quatre nuits (#107). Ce
//! test confronte les deux copies a chaque PR : tout verbe des trois
//! protocoles, sous plusieurs formes, sur chaque port de la famille et hors
//! port, TCP et UDP, par le point d'entree public.

#[path = "../fuzz/oracles/frames.rs"]
mod frames;
#[path = "../fuzz/oracles/text_protocols.rs"]
mod text_protocols;

use frames::{EPHEMERAL_PORT, ethernet_ipv4_payload};
use packet_parser::{PacketFlow, parse::transport::protocols::TransportProtocol};
use text_protocols::{
    FTP_ONLY_VERBS, NNTP_ONLY_VERBS, SMTP_ONLY_VERBS, TEXT_PROTOCOL_PORTS, expected_off_port_label,
    is_text_protocol_port, on_own_port,
};

/// Tous les verbes que les trois parseurs connaissent (`FTP_COMMANDS`,
/// `SMTP_COMMANDS`, `NNTP_COMMANDS` dans `src/checks/application/`), plus
/// trois intrus. Un verbe ajoute a une liste `*_ONLY_VERBS` de la table sans
/// son miroir dans l'oracle — ou l'inverse — fait echouer ce test.
const VERBS: &[&str] = &[
    // FTP (RFC 959 et extensions)
    "USER",
    "PASS",
    "ACCT",
    "CWD",
    "CDUP",
    "SMNT",
    "QUIT",
    "REIN",
    "PORT",
    "PASV",
    "TYPE",
    "STRU",
    "MODE",
    "RETR",
    "STOR",
    "STOU",
    "APPE",
    "ALLO",
    "REST",
    "RNFR",
    "RNTO",
    "ABOR",
    "DELE",
    "RMD",
    "MKD",
    "PWD",
    "LIST",
    "NLST",
    "SITE",
    "SYST",
    "STAT",
    "HELP",
    "NOOP",
    "FEAT",
    "CLNT",
    "OPTS",
    "EPSV",
    "EPRT",
    "SIZE",
    "MDTM",
    "MLST",
    "MLSD",
    "AUTH",
    "PBSZ",
    "PROT",
    "LPRT",
    // SMTP (RFC 5321 et extensions)
    "HELO",
    "EHLO",
    "MAIL",
    "RCPT",
    "DATA",
    "RSET",
    "VRFY",
    "EXPN",
    "STARTTLS",
    "BDAT",
    // NNTP (RFC 3977 et extensions)
    "CAPABILITIES",
    "ARTICLE",
    "BODY",
    "HEAD",
    "GROUP",
    "LISTGROUP",
    "IHAVE",
    "LAST",
    "NEWGROUPS",
    "NEWNEWS",
    "NEXT",
    "POST",
    "SLAVE",
    "XGTITLE",
    "XHDR",
    "XOVER",
    "OVER",
    "HDR",
    "XPAT",
    "AUTHINFO",
    "DATE",
    // Intrus
    "BONJOUR",
    "GET",
    "PUT",
];

/// Formes d'argument qui satisfont l'arite ou la syntaxe d'au moins un verbe
/// de chaque protocole (PORT, EPRT, PBSZ, PROT, MAIL/RCPT, HDR, AUTHINFO...).
const ARGUMENTS: &[&str] = &[
    "",
    " fichier.bin",
    " a b",
    " a b c",
    " FROM:<a@b.example>",
    " TO:<a@b.example>",
    " 127,0,0,1,8,1",
    " |2|::1|2121|",
    " 0",
    " P",
    " 12345",
    " 1-5",
    " READER",
    " USER alice",
    " Subject 12-20",
    " alt.test 20060101 000000",
    " <id@example> x y z",
    // Separateur tabulation : admis par NNTP seulement (RFC 3977 §3.1) ; la
    // garde du dispatch le laissait passer pour l'espace seul (#108).
    "\t12345",
    "\tSubject\t12-20",
];

fn label_of(frame: &[u8]) -> Option<&'static str> {
    PacketFlow::try_from(frame)
        .expect("trame synthetique analysable")
        .application
        .map(|application| application.application_protocol)
}

fn text_label(label: Option<&'static str>) -> Option<&'static str> {
    label.filter(|label| matches!(*label, "FTP" | "SMTP" | "NNTP"))
}

#[test]
fn off_port_policy_matches_the_fuzz_oracle_for_every_verb() {
    let mut labelled = 0usize;
    for verb in VERBS {
        for argument in ARGUMENTS {
            for line in [
                format!("{verb}{argument}\r\n"),
                format!("{}{argument}\r\n", verb.to_ascii_lowercase()),
            ] {
                let payload = line.as_bytes();
                let expected = expected_off_port_label(payload);

                // Hors port, dans les deux sens : l'etiquette texte est
                // exactement celle de l'oracle.
                for (source, destination) in [(EPHEMERAL_PORT, 5_000), (5_000, EPHEMERAL_PORT)] {
                    let frame =
                        ethernet_ipv4_payload(TransportProtocol::Tcp, source, destination, payload);
                    assert_eq!(
                        text_label(label_of(&frame)),
                        expected,
                        "{} sur TCP {source} -> {destination}",
                        payload.escape_ascii()
                    );
                }
                labelled += usize::from(expected.is_some());

                // Sur un port de la famille : jamais reclasse par contenu
                // vers un autre protocole texte, dans les deux sens.
                for port in TEXT_PROTOCOL_PORTS {
                    assert!(is_text_protocol_port(Some(port)));
                    for (source, destination) in [(EPHEMERAL_PORT, port), (port, EPHEMERAL_PORT)] {
                        let frame = ethernet_ipv4_payload(
                            TransportProtocol::Tcp,
                            source,
                            destination,
                            payload,
                        );
                        if let Some(label) = text_label(label_of(&frame)) {
                            assert!(
                                on_own_port(label, [Some(source), Some(destination)]),
                                "{} sur TCP {source} -> {destination} : {label} reclasse",
                                payload.escape_ascii()
                            );
                        }
                    }
                }

                // Jamais sur UDP.
                let frame =
                    ethernet_ipv4_payload(TransportProtocol::Udp, EPHEMERAL_PORT, 5_000, payload);
                assert_eq!(
                    text_label(label_of(&frame)),
                    None,
                    "{} sur UDP",
                    payload.escape_ascii()
                );
            }
        }
    }
    // Le test ne vaut que si l'oracle etiquette effectivement quelque chose.
    assert!(
        labelled >= 3 * ARGUMENTS.len(),
        "oracle muet : {labelled} etiquettes"
    );
}

/// Chaque verbe des listes de l'oracle est reconnu hors port sous au moins
/// une forme : une liste de l'oracle qui citerait un verbe que la table
/// ignore (ou que le parseur ne connait pas) echoue ici.
#[test]
fn every_oracle_verb_is_detected_off_port_in_some_form() {
    for (verbs, label) in [
        (&FTP_ONLY_VERBS[..], "FTP"),
        (&SMTP_ONLY_VERBS[..], "SMTP"),
        (&NNTP_ONLY_VERBS[..], "NNTP"),
    ] {
        for verb in verbs {
            let detected = ARGUMENTS.iter().any(|argument| {
                let line = format!("{verb}{argument}\r\n");
                let frame = ethernet_ipv4_payload(
                    TransportProtocol::Tcp,
                    EPHEMERAL_PORT,
                    5_000,
                    line.as_bytes(),
                );
                label_of(&frame) == Some(label)
            });
            assert!(detected, "{verb} n'est jamais etiquete {label} hors port");
        }
    }
}
