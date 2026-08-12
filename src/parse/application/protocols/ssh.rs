// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Parseur de la chaine d'identification SSH (RFC 4253 §4.2).
//!
//! Seule cette chaine est lisible sans etat : tout ce qui suit l'echange de
//! versions est chiffre. Elle suffit pourtant a identifier le protocole et,
//! en analyse securite, a exposer la version du serveur.

use std::convert::TryFrom;

use crate::{
    checks::application::ssh::{
        extract_ssh_identification_line, extract_ssh_protocol_version,
        extract_ssh_software_and_comments, validate_ssh_min_length, validate_ssh_prefix,
        validate_ssh_printable,
    },
    errors::application::ssh::SshError,
};

#[cfg_attr(all(doc, feature = "doc-diagrams"), aquamarine::aquamarine)]
/// Chaine d'identification SSH (RFC 4253 §4.2).
///
/// Contrairement aux autres parseurs de la crate, le format est textuel et de
/// longueur variable ; le schema donne la disposition logique des champs.
///
/// ```mermaid
/// ---
/// title: SshPacket
/// ---
/// packet-beta
/// 0-31: "Prefixe litteral SSH-"
/// 32-55: "protoversion (2.0 ou 1.99)"
/// 56-63: "Separateur -"
/// 64-127: "softwareversion"
/// 128-159: "SP + comments (optionnel)"
/// 160-175: "CR LF (CR optionnel)"
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshPacket<'a> {
    /// `2.0` ou `1.99`, seules valeurs definies.
    pub protocol_version: &'a str,
    /// Implementation annoncee, par exemple `OpenSSH_8.9p1`.
    pub software_version: &'a str,
    /// Commentaires libres apres le premier espace, souvent la distribution.
    pub comments: Option<&'a str>,
}

impl<'a> TryFrom<&'a [u8]> for SshPacket<'a> {
    type Error = SshError;

    fn try_from(payload: &'a [u8]) -> Result<Self, SshError> {
        validate_ssh_min_length(payload)?;
        validate_ssh_prefix(payload)?;

        let line = extract_ssh_identification_line(payload)?;
        validate_ssh_printable(line)?;

        let (protocol_version, rest) = extract_ssh_protocol_version(line)?;
        let (software_version, comments) = extract_ssh_software_and_comments(rest)?;

        Ok(SshPacket {
            protocol_version,
            software_version,
            comments,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trame 5211 : client OpenSSH sur Ubuntu, terminaison CRLF et
    /// commentaires (pcaps_exemple/The-Ultimate-PCAP.pcapng).
    const OPENSSH_UBUNTU: &[u8] = b"SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.1\r\n";

    /// Trame 5213 : serveur Cisco. Deux ecarts a la RFC dans une seule
    /// bannniere — LF nu sans CR, et un tiret dans softwareversion.
    const CISCO: &[u8] = b"SSH-2.0-Cisco-1.25\n";

    /// Trame 11589 : PuTTY, sans commentaires.
    const PUTTY: &[u8] = b"SSH-2.0-PuTTY_Release_0.63\r\n";

    /// Trame 20780 : OpenSSH sur Raspbian, LF nu mais avec commentaires.
    const OPENSSH_RASPBIAN: &[u8] = b"SSH-2.0-OpenSSH_7.4p1 Raspbian-10+deb9u3\n";

    #[test]
    fn parses_openssh_banner_with_comments() {
        let packet = SshPacket::try_from(OPENSSH_UBUNTU).expect("captured banner parses");

        assert_eq!(packet.protocol_version, "2.0");
        assert_eq!(packet.software_version, "OpenSSH_7.2p2");
        assert_eq!(packet.comments, Some("Ubuntu-4ubuntu2.1"));
    }

    #[test]
    fn parses_banner_without_comments() {
        let packet = SshPacket::try_from(PUTTY).expect("captured banner parses");

        assert_eq!(packet.software_version, "PuTTY_Release_0.63");
        assert_eq!(packet.comments, None);
    }

    /// Le CR est optionnel dans la vraie vie, et softwareversion peut porter
    /// un tiret : deux points sur lesquels la RFC est plus stricte que le
    /// corpus. Sans ce test, un parseur ecrit d'apres la seule RFC rejetterait
    /// cette bannniere.
    #[test]
    fn parses_cisco_banner_with_bare_line_feed_and_dashed_software_version() {
        let packet = SshPacket::try_from(CISCO).expect("captured Cisco banner parses");

        assert_eq!(packet.protocol_version, "2.0");
        assert_eq!(packet.software_version, "Cisco-1.25");
        assert_eq!(packet.comments, None);
    }

    #[test]
    fn parses_banner_with_bare_line_feed_and_comments() {
        let packet = SshPacket::try_from(OPENSSH_RASPBIAN).expect("captured banner parses");

        assert_eq!(packet.software_version, "OpenSSH_7.4p1");
        assert_eq!(packet.comments, Some("Raspbian-10+deb9u3"));
    }

    /// Synthetique : c'est ce controle qui empeche le probing a l'aveugle de
    /// capturer n'importe quel texte commencant par `SSH-`.
    #[test]
    fn rejects_unknown_protocol_version() {
        let result = SshPacket::try_from(&b"SSH-3.0-OpenSSH_9.0\r\n"[..]);

        assert_eq!(result.unwrap_err(), SshError::UnsupportedProtocolVersion);
    }

    /// Synthetique : le protocole SSH-1 historique n'est pas couvert.
    #[test]
    fn rejects_legacy_ssh_1_banner() {
        let result = SshPacket::try_from(&b"SSH-1.5-OpenSSH_3.9\r\n"[..]);

        assert_eq!(result.unwrap_err(), SshError::UnsupportedProtocolVersion);
    }

    /// Synthetique : sans terminateur, la bannniere est incomplete — un
    /// segment TCP a pu la couper.
    #[test]
    fn rejects_identification_without_line_feed() {
        let result = SshPacket::try_from(&b"SSH-2.0-OpenSSH_8.9p1"[..]);

        assert_eq!(result.unwrap_err(), SshError::MissingLineTerminator);
    }

    /// Synthetique : la banniere la plus courte possible fait 10 octets
    /// (`SSH-` + `2.0` + `-` + un octet de logiciel + LF). A neuf, le
    /// pre-check de longueur doit deja trancher, sans laisser un controle
    /// plus tardif rendre un diagnostic moins precis.
    #[test]
    fn rejects_identification_one_byte_below_the_minimum() {
        let result = SshPacket::try_from(&b"SSH-2.0-\n"[..]);

        assert_eq!(
            result.unwrap_err(),
            SshError::InvalidLength {
                expected: 10,
                actual: 9
            }
        );
    }

    /// Synthetique : du texte quelconque ne doit pas etre pris pour du SSH.
    #[test]
    fn rejects_payload_without_prefix() {
        let result = SshPacket::try_from(&b"GET /index.html HTTP/1.1\r\n"[..]);

        assert_eq!(result.unwrap_err(), SshError::MissingPrefix);
    }

    /// Synthetique : octet de controle au milieu de la ligne.
    #[test]
    fn rejects_non_printable_byte_in_identification() {
        let result = SshPacket::try_from(&b"SSH-2.0-Open\x01SSH\r\n"[..]);

        assert_eq!(
            result.unwrap_err(),
            SshError::NonPrintableByte { offset: 12 }
        );
    }
}
