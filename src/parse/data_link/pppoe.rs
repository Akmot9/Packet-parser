// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! PPPoE Session (RFC 2516 §5) : la liaison d'un abonne fibre ou xDSL a son
//! fournisseur. Apres l'EtherType `0x8864`, six octets d'en-tete PPPoE
//! (version et type 1, code 0, identifiant de session, longueur), puis le
//! protocole PPP sur deux octets (RFC 1661 §2) et son paquet. Comme les tags
//! VLAN, la couche liaison pele la session pour atteindre la vraie couche 3
//! quand PPP porte IPv4 ou IPv6 (#172).

use serde::Serialize;

/// EtherType d'une session PPPoE (RFC 2516 §5).
pub const PPPOE_SESSION_ETHERTYPE: u16 = 0x8864;

/// Version (1) et type (1) d'une session PPPoE, sur un octet.
const PPPOE_VERSION_TYPE: u8 = 0x11;

/// Code d'une trame de donnees de session (RFC 2516 §5).
const PPPOE_SESSION_DATA: u8 = 0x00;

/// En-tete PPPoE : version et type, code, session, longueur.
const PPPOE_HEADER_LEN: usize = 6;

/// Champ protocole PPP, non compresse.
const PPP_PROTOCOL_LEN: usize = 2;

/// Champ protocole PPP compresse (PFC, RFC 1661 §6.5) : un octet.
const PPP_COMPRESSED_PROTOCOL_LEN: usize = 1;

/// Protocoles PPP qui portent un paquet IP (RFC 1332, RFC 5072).
const PPP_IPV4: u16 = 0x0021;
const PPP_IPV6: u16 = 0x0057;

/// Une session PPPoE et le protocole PPP qu'elle porte.
///
/// ```mermaid
/// ---
/// title: PppoeSession
/// ---
/// packet-beta
/// 0-3: "Version = 1"
/// 4-7: "Type = 1"
/// 8-15: "Code = 0x00"
/// 16-31: "Session ID u16"
/// 32-47: "Length u16"
/// 48-63: "PPP protocol u16"
/// 64-95: "PPP payload (variable)"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
pub struct PppoeSession {
    /// L'identifiant de session, choisi par le concentrateur d'acces.
    pub session_id: u16,
    /// Longueur declaree de la charge PPPoE, protocole PPP compris.
    pub length: u16,
    /// Protocole PPP (RFC 1661 §2) : `0x0021` IPv4, `0x0057` IPv6, `0xC021`
    /// LCP, `0x8021` IPCP, `0x8057` IPv6CP... Un champ compresse sur un
    /// octet (PFC, RFC 1661 §6.5) est rendu sur seize bits : `0x21` vaut
    /// `0x0021`.
    pub ppp_protocol: u16,
}

impl PppoeSession {
    /// Le nom du protocole PPP, quand il est connu.
    pub fn ppp_protocol_name(&self) -> Option<&'static str> {
        Some(match self.ppp_protocol {
            PPP_IPV4 => "IPv4",
            PPP_IPV6 => "IPv6",
            0xC021 => "LCP",
            0xC023 => "PAP",
            0xC223 => "CHAP",
            0x8021 => "IPCP",
            0x8057 => "IPv6CP",
            0xC025 => "LQR",
            0x80FD => "CCP",
            _ => return None,
        })
    }

    /// L'EtherType du paquet porte, quand PPP porte IPv4 ou IPv6.
    pub(crate) fn inner_ethertype(&self) -> Option<u16> {
        match self.ppp_protocol {
            PPP_IPV4 => Some(0x0800),
            PPP_IPV6 => Some(0x86DD),
            _ => None,
        }
    }
}

/// Lit une session PPPoE apres son EtherType : l'en-tete, le protocole PPP,
/// et le paquet PPP, borne comme le fait tshark par la longueur declaree —
/// le bourrage d'une trame Ethernet courte est ainsi ecarte — puis par la
/// fin de la trame, quand la longueur deborde (capture tronquee). Une
/// longueur plus courte que le paquet IP qu'elle porte le tronque, comme
/// chez tshark et dans le noyau Linux (`pppoe_rcv`) : la couche internet le
/// signale alors corrompu. `None` si ce n'est pas une trame de donnees de
/// session bien formee.
pub(crate) fn peel_session(payload: &[u8]) -> Option<(PppoeSession, &[u8])> {
    let header = payload.get(..PPPOE_HEADER_LEN)?;
    if header[0] != PPPOE_VERSION_TYPE || header[1] != PPPOE_SESSION_DATA {
        return None;
    }
    // L'octet de poids faible d'un protocole PPP est impair, celui de poids
    // fort pair (RFC 1661 §2) : un premier octet impair est un champ
    // compresse (PFC), que RFC 2516 §7 deconseille sans l'interdire.
    let (ppp_protocol, protocol_len) = match *payload.get(PPPOE_HEADER_LEN..)? {
        [low, ..] if low & 1 == 1 => (u16::from(low), PPP_COMPRESSED_PROTOCOL_LEN),
        [high, low, ..] => (u16::from_be_bytes([high, low]), PPP_PROTOCOL_LEN),
        _ => return None,
    };
    let length = u16::from_be_bytes([header[4], header[5]]);
    let declared = usize::from(length);
    if declared < protocol_len {
        return None;
    }
    let end = payload.len().min(PPPOE_HEADER_LEN + declared);
    Some((
        PppoeSession {
            session_id: u16::from_be_bytes([header[2], header[3]]),
            length,
            ppp_protocol,
        },
        &payload[PPPOE_HEADER_LEN + protocol_len..end],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetique : session 0x001e, IPv4, un paquet de quatre octets, puis
    /// le bourrage d'une trame Ethernet courte.
    #[test]
    fn test_peel_ipv4_session() {
        let payload = [
            0x11, 0x00, 0x00, 0x1e, 0x00, 0x06, 0x00, 0x21, 1, 2, 3, 4, 0, 0,
        ];
        let (session, inner) = peel_session(&payload).expect("session");
        assert_eq!(session.session_id, 0x001e);
        assert_eq!(session.length, 6);
        assert_eq!(session.ppp_protocol_name(), Some("IPv4"));
        assert_eq!(session.inner_ethertype(), Some(0x0800));
        assert_eq!(inner, &[1, 2, 3, 4]);
    }

    #[test]
    fn test_control_protocol_has_no_inner_ethertype() {
        let payload = [0x11, 0x00, 0x00, 0x1e, 0x00, 0x04, 0xc0, 0x21, 0x09, 0x01];
        let (session, inner) = peel_session(&payload).expect("session LCP");
        assert_eq!(session.ppp_protocol_name(), Some("LCP"));
        assert_eq!(session.inner_ethertype(), None);
        assert_eq!(inner, &[0x09, 0x01]);
    }

    /// Comme tshark : une longueur qui deborde de la trame (capture tronquee)
    /// est bornee aux octets presents, une longueur plus courte que le
    /// paquet le tronque.
    #[test]
    fn test_declared_length_is_bounded_by_the_frame() {
        let payload = [0x11, 0x00, 0x00, 0x1e, 0x00, 0x09, 0x00, 0x21, 1, 2];
        let (session, inner) = peel_session(&payload).expect("session tronquee");
        assert_eq!(session.length, 9);
        assert_eq!(inner, &[1, 2]);
        let payload = [0x11, 0x00, 0x00, 0x1e, 0x00, 0x03, 0x00, 0x21, 1, 2];
        let (session, inner) = peel_session(&payload).expect("longueur courte");
        assert_eq!(session.length, 3);
        assert_eq!(inner, &[1]);
    }

    /// Champ protocole compresse (PFC) : `0x21` sur un octet est IPv4, comme
    /// le lit tshark ; un premier octet pair annonce un champ sur deux
    /// octets.
    #[test]
    fn test_compressed_protocol_field() {
        let payload = [0x11, 0x00, 0x00, 0x1e, 0x00, 0x05, 0x21, 1, 2, 3, 4, 0];
        let (session, inner) = peel_session(&payload).expect("PFC");
        assert_eq!(session.ppp_protocol, 0x0021);
        assert_eq!(session.inner_ethertype(), Some(0x0800));
        assert_eq!(inner, &[1, 2, 3, 4]);
        let payload = [0x11, 0x00, 0x00, 0x1e, 0x00, 0x01, 0x57];
        let (session, inner) = peel_session(&payload).expect("PFC, IPv6 vide");
        assert_eq!(session.ppp_protocol_name(), Some("IPv6"));
        assert!(inner.is_empty());
    }

    #[test]
    fn test_malformed_sessions() {
        // Version ou type autre que 1, code de decouverte, longueur qui ne
        // couvre pas le protocole PPP.
        for payload in [
            [0x12, 0x00, 0, 1, 0, 2, 0x00, 0x21],
            [0x11, 0x65, 0, 1, 0, 2, 0x00, 0x21],
            [0x11, 0x00, 0, 1, 0, 1, 0x00, 0x21],
        ] {
            assert!(peel_session(&payload).is_none(), "{payload:02x?}");
        }
        // En-tete PPPoE ou champ protocole incomplet.
        assert!(peel_session(&[0x11, 0x00, 0, 1, 0, 2, 0x00]).is_none());
        assert!(peel_session(&[0x11, 0x00, 0, 1, 0, 2]).is_none());
        assert!(peel_session(&[0x11, 0x00, 0, 1, 0]).is_none());
    }
}
