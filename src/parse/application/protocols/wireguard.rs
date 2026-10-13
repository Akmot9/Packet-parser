// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! WireGuard (livre blanc de J. A. Donenfeld, `drivers/net/wireguard/messages.h`
//! de Linux) : un tunnel VPN sur UDP dont chaque datagramme porte un seul
//! message — l'initiation et la reponse du handshake Noise IK, le cookie
//! qu'un repondeur sous charge renvoie, et les donnees chiffrees du tunnel.
//!
//! Le decodeur lit le type, les trois octets reserves, les index de session,
//! le compteur des donnees et les champs de taille fixe (cles ephemeres,
//! champs chiffres, mac1 et mac2), empruntes au datagramme. Rien n'est
//! dechiffre : sans les cles, le paquet transporte reste opaque.
//!
//! WireGuard n'a pas de port IANA ; 51820 est celui de `wg-quick`, et l'on en
//! voit bien d'autres (Tailscale 41641, ProtonVPN 443, Mullvad 5060). Sur
//! 51820 ou un port declare par Decode As, la forme suffit ; ailleurs, la
//! sonde aveugle exige en plus des octets reserves nuls (Linux lit
//! l'en-tete comme un entier de quatre octets) et, pour les donnees, un
//! compteur sous `REKEY_AFTER_MESSAGES` et un paquet clair complete a seize
//! octets ou arrete a la MTU : sans ces deux gardes, un datagramme Zoom ou
//! TeamViewer qui commence par `04 00 00 00` passait pour du WireGuard, comme
//! il passe pour tshark.

use std::convert::TryFrom;

use crate::{
    checks::application::wireguard::{
        AUTHENTICATION_TAG_LENGTH, COOKIE_REPLY_LENGTH, HANDSHAKE_INITIATION_LENGTH,
        HANDSHAKE_RESPONSE_LENGTH, MESSAGE_HEADER_LENGTH, TRANSPORT_HEADER_LENGTH, ensure_len,
        is_padded_transport_length, is_plausible_counter, validate_message_length,
    },
    errors::application::wireguard::WireGuardParseError,
};

/// Handshake Initiation (type 1) : l'initiateur ouvre une session.
///
/// ```mermaid
/// ---
/// title: HandshakeInitiation
/// ---
/// packet-beta
/// 0-7: "Type = 1"
/// 8-31: "Reserved"
/// 32-63: "Sender index u32 LE"
/// 64-319: "Unencrypted ephemeral (32 bytes)"
/// 320-703: "Encrypted static (48 bytes)"
/// 704-927: "Encrypted timestamp (28 bytes)"
/// 928-1055: "mac1 (16 bytes)"
/// 1056-1183: "mac2 (16 bytes)"
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HandshakeInitiation<'a> {
    /// Index que l'initiateur choisit pour la session.
    pub sender_index: u32,
    /// Cle publique ephemere Curve25519.
    pub unencrypted_ephemeral: &'a [u8; 32],
    /// Cle publique statique de l'initiateur, chiffree.
    pub encrypted_static: &'a [u8; 48],
    /// Horodatage TAI64N, chiffre (anti-rejeu).
    pub encrypted_timestamp: &'a [u8; 28],
    pub mac1: &'a [u8; 16],
    /// Nul sauf apres un Cookie Reply.
    pub mac2: &'a [u8; 16],
}

/// Handshake Response (type 2) : le repondeur accepte la session.
///
/// ```mermaid
/// ---
/// title: HandshakeResponse
/// ---
/// packet-beta
/// 0-7: "Type = 2"
/// 8-31: "Reserved"
/// 32-63: "Sender index u32 LE"
/// 64-95: "Receiver index u32 LE"
/// 96-351: "Unencrypted ephemeral (32 bytes)"
/// 352-479: "Encrypted nothing (16 bytes)"
/// 480-607: "mac1 (16 bytes)"
/// 608-735: "mac2 (16 bytes)"
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HandshakeResponse<'a> {
    /// Index que le repondeur choisit pour la session.
    pub sender_index: u32,
    /// L'index de l'initiation a laquelle il repond.
    pub receiver_index: u32,
    pub unencrypted_ephemeral: &'a [u8; 32],
    /// Un tag Poly1305 sur un texte clair vide.
    pub encrypted_nothing: &'a [u8; 16],
    pub mac1: &'a [u8; 16],
    pub mac2: &'a [u8; 16],
}

/// Cookie Reply (type 3) : un repondeur sous charge demande a l'initiateur
/// de prouver son adresse avant tout calcul de handshake.
///
/// ```mermaid
/// ---
/// title: CookieReply
/// ---
/// packet-beta
/// 0-7: "Type = 3"
/// 8-31: "Reserved"
/// 32-63: "Receiver index u32 LE"
/// 64-255: "Nonce (24 bytes)"
/// 256-511: "Encrypted cookie (32 bytes)"
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CookieReply<'a> {
    pub receiver_index: u32,
    /// Nonce XChaCha20-Poly1305.
    pub nonce: &'a [u8; 24],
    pub encrypted_cookie: &'a [u8; 32],
}

/// Transport Data (type 4) : un paquet du tunnel, chiffre.
///
/// ```mermaid
/// ---
/// title: TransportData
/// ---
/// packet-beta
/// 0-7: "Type = 4"
/// 8-31: "Reserved"
/// 32-63: "Receiver index u32 LE"
/// 64-127: "Counter u64 LE"
/// 128-255: "Encrypted packet and Poly1305 tag (variable)"
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TransportData<'a> {
    /// L'index de session du destinataire.
    pub receiver_index: u32,
    /// Compteur du message, aussi nonce de ChaCha20-Poly1305.
    pub counter: u64,
    /// Le paquet chiffre, tag de seize octets compris.
    pub encrypted_packet: &'a [u8],
}

impl TransportData<'_> {
    /// Un keepalive : un paquet chiffre vide, rien que le tag.
    pub fn is_keepalive(&self) -> bool {
        self.encrypted_packet.len() == AUTHENTICATION_TAG_LENGTH
    }
}

/// Le message porte par le datagramme.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WireGuardMessage<'a> {
    HandshakeInitiation(HandshakeInitiation<'a>),
    HandshakeResponse(HandshakeResponse<'a>),
    CookieReply(CookieReply<'a>),
    TransportData(TransportData<'a>),
}

/// Un message WireGuard : un datagramme UDP entier.
///
/// ```mermaid
/// ---
/// title: WireGuardPacket
/// ---
/// packet-beta
/// 0-7: "Message type u8"
/// 8-31: "Reserved (3 bytes)"
/// 32-63: "Message (variable)"
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct WireGuardPacket<'a> {
    /// 1 a 4.
    pub message_type: u8,
    /// Nuls chez Linux et wireguard-go ; Cloudflare WARP s'en sert.
    pub reserved: [u8; 3],
    pub message: WireGuardMessage<'a>,
}

impl WireGuardPacket<'_> {
    /// Sonde WireGuard aveugle, hors du port 51820 et des ports declares.
    ///
    /// Plus stricte que [`TryFrom::try_from`] : le type n'est qu'un octet,
    /// et un Transport Data n'a que `04 00 00 00` et sa taille minimale pour
    /// lui. Les octets reserves doivent etre nuls, et un Transport Data
    /// porter un compteur sous 2^60 et un paquet clair complete a seize
    /// octets — ou arrete a une MTU d'au moins 576 octets. Sur le corpus de
    /// tests de nDPI, 59 datagrammes Zoom, TeamViewer et League of Legends
    /// que tshark prend pour du WireGuard echouent ainsi, et aucun des 128
    /// vrais messages du corpus de `pcaps_exemple/protocols/wireguard/`.
    pub(crate) fn is_blind_udp_match(payload: &[u8]) -> bool {
        WireGuardPacket::try_from(payload).is_ok_and(|packet| {
            packet.reserved == [0; 3]
                && match packet.message {
                    WireGuardMessage::TransportData(data) => {
                        is_plausible_counter(data.counter)
                            && is_padded_transport_length(payload.len())
                    }
                    _ => true,
                }
        })
    }
}

/// Le champ de `N` octets a l'offset `at`, emprunte au message.
fn field<const N: usize>(payload: &[u8], at: usize) -> Result<&[u8; N], WireGuardParseError> {
    payload
        .get(at..)
        .and_then(<[u8]>::first_chunk::<N>)
        .ok_or(WireGuardParseError::Truncated {
            expected: at + N,
            actual: payload.len(),
        })
}

/// Un index de session : petit-boutiste, comme tout entier WireGuard.
fn index(payload: &[u8], at: usize) -> Result<u32, WireGuardParseError> {
    field::<4>(payload, at).map(|bytes| u32::from_le_bytes(*bytes))
}

impl<'a> TryFrom<&'a [u8]> for WireGuardPacket<'a> {
    type Error = WireGuardParseError;

    fn try_from(payload: &'a [u8]) -> Result<Self, Self::Error> {
        ensure_len(payload, MESSAGE_HEADER_LENGTH)?;
        let message_type = payload[0];
        validate_message_length(message_type, payload.len())?;
        let reserved = [payload[1], payload[2], payload[3]];
        let message = match message_type {
            1 => WireGuardMessage::HandshakeInitiation(HandshakeInitiation {
                sender_index: index(payload, 4)?,
                unencrypted_ephemeral: field(payload, 8)?,
                encrypted_static: field(payload, 40)?,
                encrypted_timestamp: field(payload, 88)?,
                mac1: field(payload, 116)?,
                mac2: field(payload, 132)?,
            }),
            2 => WireGuardMessage::HandshakeResponse(HandshakeResponse {
                sender_index: index(payload, 4)?,
                receiver_index: index(payload, 8)?,
                unencrypted_ephemeral: field(payload, 12)?,
                encrypted_nothing: field(payload, 44)?,
                mac1: field(payload, 60)?,
                mac2: field(payload, 76)?,
            }),
            3 => WireGuardMessage::CookieReply(CookieReply {
                receiver_index: index(payload, 4)?,
                nonce: field(payload, 8)?,
                encrypted_cookie: field(payload, 32)?,
            }),
            _ => WireGuardMessage::TransportData(TransportData {
                receiver_index: index(payload, 4)?,
                counter: u64::from_le_bytes(*field::<8>(payload, 8)?),
                encrypted_packet: &payload[TRANSPORT_HEADER_LENGTH..],
            }),
        };
        Ok(WireGuardPacket {
            message_type,
            reserved,
            message,
        })
    }
}

// Les tailles fixes du livre blanc, verifiees a la compilation : le dernier
// champ de chaque message finit exactement avec lui.
const _: () = {
    assert!(132 + 16 == HANDSHAKE_INITIATION_LENGTH);
    assert!(76 + 16 == HANDSHAKE_RESPONSE_LENGTH);
    assert!(32 + 32 == COOKIE_REPLY_LENGTH);
};

#[cfg(test)]
mod tests {
    use super::*;

    /// `wireshark_wireguard-ping-tcp.pcap` (pcaps_exemple/protocols/wireguard/),
    /// trame 1 : initiation de 10.9.0.1:43462 vers 10.9.0.2:51820, index
    /// 0x30d037d8, mac2 nul — WireGuard de Linux entre deux espaces de noms.
    const PING_INITIATION: &str = concat!(
        "01000000d837d0305fcec7c8e5c8e2e3f7989eef60c228d82329d602b6b1e2bb",
        "9d068f89cf9d4d4532780f6d27264f7b98701fdc27a4ec00aeb6becdbef2332f",
        "1b4084cadb93823935c012ae255e7b25eff13940c321fa6bd66a2a87b061db14",
        "30173e937f569349de2856dc5f2616763eeeafc0533b01dd965e7ec76976e28f",
        "683d671200000000000000000000000000000000",
    );

    /// Trame 2 : la reponse, index 0xab7df406 pour 0x30d037d8.
    const PING_RESPONSE: &str = concat!(
        "0200000006f47dabd837d030b18d5550bd4042a37a46823ac08db1ec66839bc0",
        "ca2d64bc15cd80232b66232faec24af8918de1060ff5c98e865d5f35f272214c",
        "5260110dc4c61e32cdd8542100000000000000000000000000000000",
    );

    /// Trame 9 : un keepalive, compteur 3.
    const PING_KEEPALIVE: &str = "0400000006f47dab03000000000000001956e2b6651dd4f59cb23092a0d09671";

    /// Trame 3 : un paquet du tunnel (ICMP echo chiffre), compteur 0.
    const PING_DATA: &str = concat!(
        "0400000006f47dab0000000000000000a4ebc12ee3f990da18033a0789c04e27",
        "00f6f5c271d42ac4b4d6262e666549b445a7436e829bffb6ac65f05648bc0c39",
        "1fe7c5884874376127164940188f03dba67af8388eaab76c593628bf9dc7be03",
        "346d912e916dad862545454701364f2d2486d7ced4c8642ce547ddb26ef6a46b",
    );

    fn decode(hex_payload: &str) -> Vec<u8> {
        hex::decode(hex_payload).expect("valid hex")
    }

    #[test]
    fn test_handshake_initiation() {
        let payload = decode(PING_INITIATION);
        assert_eq!(payload.len(), 148);
        let packet = WireGuardPacket::try_from(payload.as_slice()).expect("initiation");
        assert_eq!(packet.message_type, 1);
        assert_eq!(packet.reserved, [0; 3]);
        let WireGuardMessage::HandshakeInitiation(initiation) = &packet.message else {
            panic!("initiation attendue");
        };
        assert_eq!(initiation.sender_index, 0x30d0_37d8);
        assert_eq!(initiation.unencrypted_ephemeral.as_slice(), &payload[8..40]);
        assert_eq!(initiation.mac1.as_slice(), &payload[116..132]);
        assert_eq!(initiation.mac2, &[0; 16]);
        assert!(WireGuardPacket::is_blind_udp_match(&payload));
    }

    #[test]
    fn test_handshake_response() {
        let payload = decode(PING_RESPONSE);
        let packet = WireGuardPacket::try_from(payload.as_slice()).expect("reponse");
        let WireGuardMessage::HandshakeResponse(response) = &packet.message else {
            panic!("reponse attendue");
        };
        assert_eq!(response.sender_index, 0xab7d_f406);
        assert_eq!(response.receiver_index, 0x30d0_37d8);
        assert_eq!(response.encrypted_nothing.as_slice(), &payload[44..60]);
        assert!(WireGuardPacket::is_blind_udp_match(&payload));
    }

    #[test]
    fn test_transport_data_and_keepalive() {
        let payload = decode(PING_DATA);
        let packet = WireGuardPacket::try_from(payload.as_slice()).expect("donnees");
        let WireGuardMessage::TransportData(data) = &packet.message else {
            panic!("donnees attendues");
        };
        assert_eq!((data.receiver_index, data.counter), (0xab7d_f406, 0));
        assert_eq!(data.encrypted_packet.len(), 112);
        assert!(!data.is_keepalive());

        let payload = decode(PING_KEEPALIVE);
        let packet = WireGuardPacket::try_from(payload.as_slice()).expect("keepalive");
        let WireGuardMessage::TransportData(data) = &packet.message else {
            panic!("donnees attendues");
        };
        assert_eq!(data.counter, 3);
        assert!(data.is_keepalive());
        assert!(WireGuardPacket::is_blind_udp_match(&payload));
    }

    /// Synthetique : un Cookie Reply (aucune capture reelle n'en porte),
    /// index, nonce et cookie aux offsets du livre blanc.
    #[test]
    fn test_cookie_reply() {
        let mut payload = vec![3, 0, 0, 0];
        payload.extend_from_slice(&0x1122_3344u32.to_le_bytes());
        payload.extend((0..24).map(|i| i as u8));
        payload.extend((100..132).map(|i| i as u8));
        let packet = WireGuardPacket::try_from(payload.as_slice()).expect("cookie");
        let WireGuardMessage::CookieReply(cookie) = &packet.message else {
            panic!("cookie attendu");
        };
        assert_eq!(cookie.receiver_index, 0x1122_3344);
        assert_eq!(cookie.nonce[0], 0);
        assert_eq!(cookie.encrypted_cookie[31], 131);
        assert!(WireGuardPacket::is_blind_udp_match(&payload));
    }

    #[test]
    fn test_invalid_messages() {
        assert_eq!(
            WireGuardPacket::try_from(&[1u8, 0, 0][..]),
            Err(WireGuardParseError::Truncated {
                expected: 4,
                actual: 3
            })
        );
        let mut payload = decode(PING_INITIATION);
        payload[0] = 5;
        assert_eq!(
            WireGuardPacket::try_from(payload.as_slice()),
            Err(WireGuardParseError::UnknownMessageType(5))
        );
        // Une initiation d'un octet de trop, ou amputee.
        let mut payload = decode(PING_INITIATION);
        payload.push(0);
        assert!(matches!(
            WireGuardPacket::try_from(payload.as_slice()),
            Err(WireGuardParseError::InvalidLength {
                message_type: 1,
                ..
            })
        ));
        assert!(WireGuardPacket::try_from(&decode(PING_RESPONSE)[..91]).is_err());
        assert!(WireGuardPacket::try_from(&decode(PING_KEEPALIVE)[..31]).is_err());
    }

    /// Synthetique : des octets reserves non nuls (Cloudflare WARP) se
    /// decodent, mais ne passent pas la sonde aveugle.
    #[test]
    fn test_reserved_bytes_are_kept_but_refused_blind() {
        let mut payload = decode(PING_KEEPALIVE);
        payload[1..4].copy_from_slice(&[0x02, 0x78, 0x00]);
        let packet = WireGuardPacket::try_from(payload.as_slice()).expect("keepalive");
        assert_eq!(packet.reserved, [0x02, 0x78, 0x00]);
        assert!(!WireGuardPacket::is_blind_udp_match(&payload));
    }

    /// Synthetique : un compteur au-dela de 2^60, ou un paquet clair ni
    /// complete a seize octets ni arrete a une MTU, ne sont pas du WireGuard
    /// pour la sonde aveugle.
    #[test]
    fn test_blind_probe_refuses_implausible_transport_data() {
        let mut payload = decode(PING_DATA);
        payload[15] = 0x10;
        assert!(WireGuardPacket::try_from(payload.as_slice()).is_ok());
        assert!(!WireGuardPacket::is_blind_udp_match(&payload));

        let mut payload = decode(PING_DATA);
        payload.push(0);
        assert!(WireGuardPacket::try_from(payload.as_slice()).is_ok());
        assert!(!WireGuardPacket::is_blind_udp_match(&payload));
    }
}
