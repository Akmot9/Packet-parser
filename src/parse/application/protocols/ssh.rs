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
        extract_ssh_software_and_comments, find_ssh_identification, locate_ssh_identification,
        validate_ssh_min_length, validate_ssh_prefix, validate_ssh_printable,
    },
    errors::application::ssh::SshError,
};

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
#[non_exhaustive]
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
        let identification = locate_ssh_identification(payload)?;
        Self::from_identification(identification)
    }
}

impl<'a> SshPacket<'a> {
    /// La chaine d'identification qui ouvre `identification`, une fois les
    /// lignes de preambule passees.
    fn from_identification(identification: &'a [u8]) -> Result<Self, SshError> {
        validate_ssh_min_length(identification)?;
        validate_ssh_prefix(identification)?;

        let line = extract_ssh_identification_line(identification)?;
        validate_ssh_printable(line)?;

        let (protocol_version, rest) = extract_ssh_protocol_version(line)?;
        let (software_version, comments) = extract_ssh_software_and_comments(rest)?;

        Ok(SshPacket {
            protocol_version,
            software_version,
            comments,
        })
    }

    /// La sonde du dispatch : la decision de [`TryFrom::try_from`], par les
    /// memes controles, sans construire l'erreur d'un segment qui n'est pas
    /// du SSH. Tout segment TCP non reconnu qui s'ouvre par un octet de
    /// texte la paie.
    pub(crate) fn is_tcp_match(payload: &[u8]) -> bool {
        validate_ssh_min_length(payload).is_ok()
            && find_ssh_identification(payload).is_some_and(Self::opens)
    }

    /// Vrai si `identification` s'ouvre par une chaine d'identification
    /// valide. Hors ligne : le refus de la sonde, de loin son issue la plus
    /// frequente, ne paie pas le cadre de pile du decodeur.
    #[inline(never)]
    fn opens(identification: &[u8]) -> bool {
        SshPacket::from_identification(identification).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::application::ssh::SSH_MAX_PRELUDE_LENGTH;

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

    /// RFC 4253 §4.2 : « The server MAY send other lines of data before
    /// sending the version string » (#307).
    #[test]
    fn lines_before_the_identification_are_skipped() {
        let packet = SshPacket::try_from(&b"Welcome\r\nSSH-2.0-OpenSSH_9.6\r\n"[..])
            .expect("ligne avant la banniere");
        assert_eq!(packet.protocol_version, "2.0");
        assert_eq!(packet.software_version, "OpenSSH_9.6");

        let packet = SshPacket::try_from(&b"Hello\r\n\tcaf\xc3\xa9\r\n\r\nSSH-1.99-Server\n"[..])
            .expect("plusieurs lignes, TAB, UTF-8, ligne vide");
        assert_eq!(packet.protocol_version, "1.99");

        // La premiere ligne en SSH- est la banniere, et elle est validee.
        assert_eq!(
            SshPacket::try_from(&b"Welcome\r\nSSH-3.0-Bad\r\nSSH-2.0-Good\r\n"[..]),
            Err(SshError::UnsupportedProtocolVersion)
        );
    }

    /// Les lignes qui precedent la banniere restent du texte borne : la regle
    /// SSH est aveugle sur TCP.
    #[test]
    fn lines_before_the_identification_stay_bounded_text() {
        for payload in [
            // Pas de ligne SSH-.
            &b"Welcome\r\nnothing else here\r\n"[..],
            // Une ligne sans fin de ligne avant SSH-.
            b"Welcome SSH-2.0-OpenSSH_9.6\r\n",
            // Un LF nu termine la ligne qui precede.
            b"Welcome\nSSH-2.0-OpenSSH_9.6\r\n",
            // Un octet de controle, ou du binaire, dans la ligne qui precede.
            b"Wel\x01come\r\nSSH-2.0-OpenSSH_9.6\r\n",
            b"\xff\xfe\r\nSSH-2.0-OpenSSH_9.6\r\n",
        ] {
            assert_eq!(
                SshPacket::try_from(payload),
                Err(SshError::MissingPrefix),
                "{payload:?}"
            );
        }

        let banner = b"SSH-2.0-OpenSSH_9.6\r\n";
        let within = |prelude: usize| {
            let mut payload = vec![b'a'; prelude - 2];
            payload.extend_from_slice(b"\r\n");
            payload.extend_from_slice(banner);
            payload
        };
        assert!(SshPacket::try_from(within(SSH_MAX_PRELUDE_LENGTH).as_slice()).is_ok());
        assert_eq!(
            SshPacket::try_from(within(SSH_MAX_PRELUDE_LENGTH + 1).as_slice()),
            Err(SshError::MissingPrefix)
        );
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

    /// La sonde du dispatch (`is_tcp_match`) rend, pour tout segment, la
    /// decision de `try_from` : sur les bannieres du corpus, des bannieres
    /// precedees de lignes, des refus, leurs troncatures et chaque valeur de
    /// chacun de leurs octets.
    #[test]
    fn test_probe_agrees_with_the_decoder() {
        let seeds: [&[u8]; 12] = [
            OPENSSH_UBUNTU,
            CISCO,
            PUTTY,
            OPENSSH_RASPBIAN,
            b"SSH-1.99-Server\n",
            b"Welcome\r\nSSH-2.0-OpenSSH_9.6\r\n",
            b"Hello\r\n\tcaf\xc3\xa9\r\n\r\nSSH-1.99-Server\n",
            b"Welcome\r\nSSH-3.0-Bad\r\nSSH-2.0-Good\r\n",
            b"SSH-2.0-OpenSSH_8.9p1",
            b"SSH-2.0-\n",
            b"Welcome\r\nSSH-2.0-\n",
            b"GET /index.html HTTP/1.1\r\n",
        ];
        let (mut accepted, mut refused) = (0, 0);
        let mut check = |payload: &[u8]| {
            let decoded = SshPacket::try_from(payload).is_ok();
            assert_eq!(SshPacket::is_tcp_match(payload), decoded, "{payload:?}");
            if decoded {
                accepted += 1;
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
            // Ce qui suit la banniere ne change rien, binaire compris.
            mutated.extend_from_slice(b"\x00\x01\xff suite\r\n");
            check(&mutated);
        }
        // Une identification sans fin de ligne, puis au-dela de sa borne.
        let mut long = b"motd\r\nSSH-2.0-".to_vec();
        long.resize(300, b'x');
        check(&long);
        long.push(b'\n');
        check(&long);

        assert!(accepted > 10_000, "{accepted} segments acceptes");
        assert!(refused > 20_000, "{refused} segments refuses");
    }
}
