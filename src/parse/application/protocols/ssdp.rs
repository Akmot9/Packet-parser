// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Parseur des messages SSDP (Simple Service Discovery Protocol).
//!
//! SSDP est le protocole de decouverte d'UPnP (draft-cai-ssdp, repris par
//! UPnP Device Architecture 1.1 §1). Il transporte de l'HTTP sur UDP (HTTPU),
//! normalement vers 239.255.255.250:1900 : recherches `M-SEARCH`, annonces
//! `NOTIFY` et reponses unicast `HTTP/1.1 200 OK`.
//!
//! Recouvrement avec HTTP : la syntaxe est celle de HTTP/1.1, mais la
//! distinction est nette — les methodes `M-SEARCH` et `NOTIFY` n'existent pas
//! en HTTP ordinaire, et le Request-URI est exactement `*`. Le parseur HTTP de
//! la crate rejette d'ailleurs ces methodes (liste RFC 9110), les deux
//! parseurs sont donc disjoints sur les requetes ; seule la reponse
//! `HTTP/1.1 200 OK` est ambigue sans le contexte UDP 1900.

use std::convert::TryFrom;

use crate::{
    checks::application::ssdp::{
        extract_ssdp_head, extract_ssdp_header_line, extract_ssdp_message_type, extract_ssdp_text,
        validate_ssdp_man, validate_ssdp_min_length,
    },
    errors::application::ssdp::SsdpError,
};

/// Type d'un message SSDP, donne par sa premiere ligne.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsdpMessageType {
    /// Recherche multicast `M-SEARCH * HTTP/1.1`.
    MSearch,
    /// Annonce `NOTIFY * HTTP/1.1` (ssdp:alive, ssdp:byebye, ssdp:update).
    Notify,
    /// Reponse unicast `HTTP/1.1 200 OK` a un M-SEARCH.
    Response,
}

/// Message SSDP (UPnP Device Architecture 1.1 §1).
///
/// Le format est textuel et de longueur variable ; le schema donne la
/// disposition logique des champs. Tous les champs empruntes pointent dans le
/// payload original : aucun octet n'est copie.
///
/// ```mermaid
/// ---
/// title: SsdpPacket
/// ---
/// packet-beta
/// 0-63: "Start line (M-SEARCH * HTTP/1.1 | NOTIFY * HTTP/1.1 | HTTP/1.1 200 OK) CRLF"
/// 64-127: "Headers variable (Nom: valeur CRLF)"
/// 128-143: "CRLF final (ligne vide)"
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsdpPacket<'a> {
    /// Type de message donne par la premiere ligne.
    pub message_type: SsdpMessageType,
    /// `MAN`, guillemets compris — toujours `"ssdp:discover"` sur un M-SEARCH.
    pub man: Option<&'a str>,
    /// `MX` : attente maximale de reponse d'un M-SEARCH, en secondes.
    pub mx: Option<&'a str>,
    /// `ST` (search target) d'un M-SEARCH ou d'une reponse.
    pub st: Option<&'a str>,
    /// `NT` (notification type) d'un NOTIFY.
    pub nt: Option<&'a str>,
    /// `NTS` : sous-type de NOTIFY (ssdp:alive, ssdp:byebye, ssdp:update).
    pub nts: Option<&'a str>,
    /// `USN` : identifiant unique du service annonce.
    pub usn: Option<&'a str>,
    /// `LOCATION` : URL de la description du device.
    pub location: Option<&'a str>,
    /// `SERVER` : implementation annoncee (NOTIFY et reponse).
    pub server: Option<&'a str>,
}

impl<'a> TryFrom<&'a [u8]> for SsdpPacket<'a> {
    type Error = SsdpError;

    fn try_from(payload: &'a [u8]) -> Result<Self, SsdpError> {
        validate_ssdp_min_length(payload)?;
        let text = extract_ssdp_text(payload)?;
        let head = extract_ssdp_head(text)?;

        let mut lines = head.split("\r\n");
        // `split` produit toujours au moins un element : la premiere ligne
        // existe structurellement, et une ligne vide echoue en UnknownMethod.
        let message_type = extract_ssdp_message_type(lines.next().unwrap_or_default())?;

        let mut man = None;
        let mut mx = None;
        let mut st = None;
        let mut nt = None;
        let mut nts = None;
        let mut usn = None;
        let mut location = None;
        let mut server = None;

        // Le bloc s'arrete a la ligne vide deja consommee par
        // extract_ssdp_head : toute ligne restante doit etre un en-tete.
        for line in lines {
            let (name, value) = extract_ssdp_header_line(line)?;
            // Noms insensibles a la casse (syntaxe HTTP) ; la premiere
            // occurrence gagne.
            let slot = match () {
                _ if name.eq_ignore_ascii_case("MAN") => &mut man,
                _ if name.eq_ignore_ascii_case("MX") => &mut mx,
                _ if name.eq_ignore_ascii_case("ST") => &mut st,
                _ if name.eq_ignore_ascii_case("NT") => &mut nt,
                _ if name.eq_ignore_ascii_case("NTS") => &mut nts,
                _ if name.eq_ignore_ascii_case("USN") => &mut usn,
                _ if name.eq_ignore_ascii_case("LOCATION") => &mut location,
                _ if name.eq_ignore_ascii_case("SERVER") => &mut server,
                // Autres en-tetes (HOST, CACHE-CONTROL...) : valides mais
                // non exposes.
                _ => continue,
            };
            if slot.is_none() {
                *slot = Some(value);
            }
        }

        validate_ssdp_man(message_type, man)?;

        Ok(SsdpPacket {
            message_type,
            man,
            mx,
            st,
            nt,
            nts,
            usn,
            location,
            server,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trame 8156 : M-SEARCH d'une box AVM vers 239.255.255.250:1900
    /// (pcaps_exemple/The-Ultimate-PCAP.pcapng).
    const MSEARCH_AVM: &[u8] = b"M-SEARCH * HTTP/1.1\r\n\
        HOST: 239.255.255.250:1900\r\n\
        MAN: \"ssdp:discover\"\r\n\
        MX: 5\r\n\
        ST: urn:schemas-upnp-org:device:avm-aha:1\r\n\
        \r\n";

    /// Trame 8199 : NOTIFY ssdp:alive d'un media renderer
    /// (pcaps_exemple/The-Ultimate-PCAP.pcapng).
    const NOTIFY_ALIVE: &[u8] = b"NOTIFY * HTTP/1.1\r\n\
        HOST: 239.255.255.250:1900\r\n\
        CACHE-CONTROL: max-age=1800\r\n\
        LOCATION: http://192.168.7.12:8080/MediaRenderer/desc.xml\r\n\
        NT: upnp:rootdevice\r\n\
        NTS: ssdp:alive\r\n\
        SERVER: KnOS/3.2 UPnP/1.0 DMP/3.5\r\n\
        USN: uuid:5f9ec1b3-ed59-1900-4530-00a0dede5413::upnp:rootdevice\r\n\
        \r\n";

    /// Synthetique : le corpus ne contient aucune reponse 200 OK ; la forme
    /// suit UDA 1.1 §1.3.3.
    const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\n\
        CACHE-CONTROL: max-age=1800\r\n\
        EXT:\r\n\
        LOCATION: http://192.168.7.12:8080/MediaRenderer/desc.xml\r\n\
        SERVER: KnOS/3.2 UPnP/1.0 DMP/3.5\r\n\
        ST: upnp:rootdevice\r\n\
        USN: uuid:5f9ec1b3-ed59-1900-4530-00a0dede5413::upnp:rootdevice\r\n\
        \r\n";

    #[test]
    fn parses_msearch() {
        let packet = SsdpPacket::try_from(MSEARCH_AVM).expect("captured M-SEARCH parses");

        assert_eq!(packet.message_type, SsdpMessageType::MSearch);
        assert_eq!(packet.man, Some("\"ssdp:discover\""));
        assert_eq!(packet.mx, Some("5"));
        assert_eq!(packet.st, Some("urn:schemas-upnp-org:device:avm-aha:1"));
        assert_eq!(packet.nt, None);
        assert_eq!(packet.usn, None);
    }

    #[test]
    fn parses_notify_alive() {
        let packet = SsdpPacket::try_from(NOTIFY_ALIVE).expect("captured NOTIFY parses");

        assert_eq!(packet.message_type, SsdpMessageType::Notify);
        assert_eq!(packet.nt, Some("upnp:rootdevice"));
        assert_eq!(packet.nts, Some("ssdp:alive"));
        assert_eq!(
            packet.location,
            Some("http://192.168.7.12:8080/MediaRenderer/desc.xml")
        );
        assert_eq!(packet.server, Some("KnOS/3.2 UPnP/1.0 DMP/3.5"));
        assert_eq!(
            packet.usn,
            Some("uuid:5f9ec1b3-ed59-1900-4530-00a0dede5413::upnp:rootdevice")
        );
        assert_eq!(packet.man, None);
        assert_eq!(packet.st, None);
    }

    #[test]
    fn parses_response() {
        let packet = SsdpPacket::try_from(RESPONSE).expect("valid response parses");

        assert_eq!(packet.message_type, SsdpMessageType::Response);
        assert_eq!(packet.st, Some("upnp:rootdevice"));
        assert_eq!(packet.server, Some("KnOS/3.2 UPnP/1.0 DMP/3.5"));
    }

    #[test]
    fn is_zero_copy() {
        let packet = SsdpPacket::try_from(NOTIFY_ALIVE).expect("captured NOTIFY parses");

        // Chaque champ emprunte doit pointer dans le payload original.
        let range = NOTIFY_ALIVE.as_ptr_range();
        for field in [
            packet.nt,
            packet.nts,
            packet.usn,
            packet.location,
            packet.server,
        ] {
            let ptr = field.expect("field is set").as_ptr();
            assert!(range.contains(&ptr), "field does not borrow from payload");
        }
    }

    /// Synthetique : une methode HTTP ordinaire ne doit pas passer pour du
    /// SSDP — c'est la moitie de la disjonction avec le parseur HTTP.
    #[test]
    fn rejects_unknown_method() {
        let result = SsdpPacket::try_from(&b"GET * HTTP/1.1\r\nHOST: a\r\n\r\n"[..]);

        assert_eq!(result.unwrap_err(), SsdpError::UnknownMethod);
    }

    /// Synthetique : un NOTIFY avec un URI concret n'est pas du SSDP (c'est
    /// la forme GENA sur TCP, hors perimetre).
    #[test]
    fn rejects_non_star_request_uri() {
        let result = SsdpPacket::try_from(&b"NOTIFY /callback HTTP/1.1\r\nHOST: a\r\n\r\n"[..]);

        assert_eq!(result.unwrap_err(), SsdpError::InvalidRequestUri);
    }

    /// Synthetique : seule la version 1.1 est definie pour SSDP.
    #[test]
    fn rejects_non_1_1_version() {
        let result = SsdpPacket::try_from(&b"M-SEARCH * HTTP/1.0\r\nHOST: a\r\n\r\n"[..]);

        assert_eq!(result.unwrap_err(), SsdpError::UnsupportedHttpVersion);
    }

    /// Synthetique : seule la reponse 200 OK existe en SSDP.
    #[test]
    fn rejects_non_200_status_line() {
        let result = SsdpPacket::try_from(&b"HTTP/1.1 404 Not Found\r\n\r\n"[..]);

        assert_eq!(result.unwrap_err(), SsdpError::InvalidStatusLine);
    }

    /// Synthetique : ligne d'en-tete sans separateur `:`.
    #[test]
    fn rejects_header_without_colon() {
        let result = SsdpPacket::try_from(&b"NOTIFY * HTTP/1.1\r\nNotAHeader\r\n\r\n"[..]);

        assert_eq!(result.unwrap_err(), SsdpError::InvalidHeader);
    }

    /// Synthetique : un payload binaire n'est pas de l'UTF-8.
    #[test]
    fn rejects_binary_payload() {
        let payload = [
            0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01, 0xff, 0xfe,
            0x00, 0x13, 0x00, 0x00, 0x00,
        ];
        let result = SsdpPacket::try_from(&payload[..]);

        assert_eq!(result.unwrap_err(), SsdpError::InvalidUtf8);
    }

    /// Synthetique : un M-SEARCH sans MAN: "ssdp:discover" est invalide
    /// (UDA 1.1 §1.3.2).
    #[test]
    fn rejects_msearch_without_discover_man() {
        let result = SsdpPacket::try_from(
            &b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMX: 3\r\n\r\n"[..],
        );

        assert_eq!(result.unwrap_err(), SsdpError::MissingDiscoverMan);
    }

    /// Synthetique : sans ligne vide finale, le message n'est pas complet —
    /// un datagramme UDP porte toujours le message en entier.
    #[test]
    fn rejects_head_without_empty_line() {
        let result = SsdpPacket::try_from(&b"M-SEARCH * HTTP/1.1\r\nHOST: a\r\n"[..]);

        assert_eq!(result.unwrap_err(), SsdpError::MissingHeaderTerminator);
    }

    /// Synthetique : en dessous du plus court message possible, le pre-check
    /// de longueur tranche avant tout autre diagnostic.
    #[test]
    fn rejects_payload_below_minimum_length() {
        let result = SsdpPacket::try_from(&b"HTTP/1.1 200 OK\r\n\r"[..]);

        assert_eq!(
            result.unwrap_err(),
            SsdpError::InvalidLength {
                expected: 19,
                actual: 18
            }
        );
    }
}
