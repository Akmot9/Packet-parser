// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Parseur du protocole de transport OpenVPN (issue #5).
//!
//! OpenVPN encapsule son canal de controle (session TLS) et son canal de
//! donnees dans un protocole maison. Sur UDP le datagramme commence
//! directement par l'octet opcode/key id ; sur TCP chaque message est prefixe
//! de sa longueur sur u16 big-endian, plusieurs messages pouvant etre
//! coalises dans un meme segment.
//!
//! Tout ce qui suit la session id d'un message de controle reste opaque : en
//! `tls-auth`/`tls-crypt` un HMAC de taille negociee hors bande s'y
//! intercale, et rien dans le paquet ne l'annonce. Le parseur expose donc
//! l'opcode, le key id, la session id (canal de controle), le peer id
//! (`P_DATA_V2`) et le reste emprunte, sans copie.

use std::convert::TryFrom;

use crate::{
    checks::application::openvpn::{
        extract_openvpn_opcode_and_key_id, extract_openvpn_peer_id, extract_openvpn_session_id,
        read_openvpn_tcp_record, validate_openvpn_hard_reset_key_id, validate_openvpn_length,
    },
    errors::application::openvpn::OpenVpnError,
};

/// Les onze opcodes definis par le protocole (ssl_pkt.h d'OpenVPN).
///
/// La valeur est celle des 5 bits hauts du premier octet, avant decalage.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenVpnOpcode {
    /// `P_CONTROL_HARD_RESET_CLIENT_V1` : ouverture de session, methode de
    /// clef 1 (historique).
    ControlHardResetClientV1 = 1,
    /// `P_CONTROL_HARD_RESET_SERVER_V1`.
    ControlHardResetServerV1 = 2,
    /// `P_CONTROL_SOFT_RESET_V1` : renegociation de clef dans une session
    /// etablie.
    ControlSoftResetV1 = 3,
    /// `P_CONTROL_V1` : fragment du flux TLS du canal de controle.
    ControlV1 = 4,
    /// `P_ACK_V1` : acquittement pur (pas de payload TLS).
    AckV1 = 5,
    /// `P_DATA_V1` : datagramme chiffre du tunnel.
    DataV1 = 6,
    /// `P_CONTROL_HARD_RESET_CLIENT_V2` : ouverture de session, methode de
    /// clef 2 (la forme courante).
    ControlHardResetClientV2 = 7,
    /// `P_CONTROL_HARD_RESET_SERVER_V2`.
    ControlHardResetServerV2 = 8,
    /// `P_DATA_V2` : datagramme chiffre precede d'un peer id de 3 octets.
    DataV2 = 9,
    /// `P_CONTROL_HARD_RESET_CLIENT_V3` : ouverture `tls-crypt-v2`, embarque
    /// la clef client enveloppee (WKc).
    ControlHardResetClientV3 = 10,
    /// `P_CONTROL_WKC_V1` (OpenVPN 2.6) : fragment de controle portant la
    /// clef client enveloppee quand elle ne tient pas dans le hard reset v3.
    ControlWkcV1 = 11,
}

impl OpenVpnOpcode {
    /// Mappe la valeur 5 bits du fil vers l'opcode, `None` hors de 1..=10.
    pub fn from_wire(wire: u8) -> Option<Self> {
        Some(match wire {
            1 => Self::ControlHardResetClientV1,
            2 => Self::ControlHardResetServerV1,
            3 => Self::ControlSoftResetV1,
            4 => Self::ControlV1,
            5 => Self::AckV1,
            6 => Self::DataV1,
            7 => Self::ControlHardResetClientV2,
            8 => Self::ControlHardResetServerV2,
            9 => Self::DataV2,
            10 => Self::ControlHardResetClientV3,
            11 => Self::ControlWkcV1,
            _ => return None,
        })
    }

    /// Vrai pour le canal de donnees (`P_DATA_V1`/`P_DATA_V2`) : pas de
    /// session id, charge entierement chiffree.
    pub const fn is_data(self) -> bool {
        matches!(self, Self::DataV1 | Self::DataV2)
    }

    /// Vrai pour les seuls hard resets : ils ouvrent une session, donc leur
    /// key id est toujours 0 — un soft reset (renegociation) peut porter un
    /// key id non nul.
    pub const fn is_hard_reset(self) -> bool {
        matches!(
            self,
            Self::ControlHardResetClientV1
                | Self::ControlHardResetServerV1
                | Self::ControlHardResetClientV2
                | Self::ControlHardResetServerV2
                | Self::ControlHardResetClientV3
        )
    }

    /// Vrai pour les hard/soft resets, qui ne transportent pas de payload TLS
    /// libre et sont donc bornes en taille.
    pub const fn is_reset(self) -> bool {
        matches!(
            self,
            Self::ControlHardResetClientV1
                | Self::ControlHardResetServerV1
                | Self::ControlSoftResetV1
                | Self::ControlHardResetClientV2
                | Self::ControlHardResetServerV2
                | Self::ControlHardResetClientV3
        )
    }
}

/// Un message OpenVPN, tel que pose sur UDP (sur TCP, voir
/// [`OpenVpnPacket::from_tcp_stream`]).
///
/// ```mermaid
/// ---
/// title: OpenVpnPacket (canal de controle)
/// ---
/// packet-beta
/// 0-4: "Opcode"
/// 5-7: "Key ID"
/// 8-71: "Session ID"
/// 72-95: "[tls-auth : HMAC + replay packet-id + net-time]"
/// 96-103: "Ack array length"
/// 104-135: "Acks + remote session id (si acks)"
/// 136-167: "Message packet-id"
/// 168-191: "Payload TLS"
/// ```
///
/// Les champs entre crochets ne sont presents qu'en `tls-auth`/`tls-crypt`
/// et rien dans le paquet ne les annonce : tout ce qui suit la session id est
/// donc expose brut dans [`OpenVpnPacket::payload`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenVpnPacket<'a> {
    /// Opcode des 5 bits hauts du premier octet.
    pub opcode: OpenVpnOpcode,
    /// Key id des 3 bits bas (0..=7), change a chaque renegociation.
    pub key_id: u8,
    /// Session id locale de l'emetteur — canal de controle uniquement.
    pub session_id: Option<u64>,
    /// Peer id 24 bits — `P_DATA_V2` uniquement.
    pub peer_id: Option<u32>,
    /// Reste du message, emprunte sans copie : HMAC/acks/TLS pour le canal
    /// de controle, charge chiffree pour le canal de donnees.
    pub payload: &'a [u8],
}

impl<'a> TryFrom<&'a [u8]> for OpenVpnPacket<'a> {
    type Error = OpenVpnError;

    fn try_from(packet: &'a [u8]) -> Result<Self, OpenVpnError> {
        let (opcode, key_id) = extract_openvpn_opcode_and_key_id(packet)?;
        validate_openvpn_hard_reset_key_id(opcode, key_id)?;
        validate_openvpn_length(opcode, packet.len())?;
        let after_opcode = &packet[1..];

        let (session_id, peer_id, payload) = match opcode {
            OpenVpnOpcode::DataV1 => (None, None, after_opcode),
            OpenVpnOpcode::DataV2 => {
                let (peer_id, rest) = extract_openvpn_peer_id(after_opcode)?;
                (None, Some(peer_id), rest)
            }
            _ => {
                let (session_id, rest) = extract_openvpn_session_id(after_opcode)?;
                (Some(session_id), None, rest)
            }
        };

        Ok(OpenVpnPacket {
            opcode,
            key_id,
            session_id,
            peer_id,
            payload,
        })
    }
}

impl<'a> OpenVpnPacket<'a> {
    /// Parse le premier enregistrement d'un flux TCP OpenVPN (prefixe de
    /// longueur u16 big-endian) et rend les octets qui le suivent —
    /// eventuellement d'autres enregistrements coalises dans le segment.
    pub fn from_tcp_stream(stream: &'a [u8]) -> Result<(Self, &'a [u8]), OpenVpnError> {
        let (record, rest) = read_openvpn_tcp_record(stream)?;
        Ok((Self::try_from(record)?, rest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Payload UDP de la trame 1 de
    /// `pcaps_exemple/protocols/openvpn/OpenVPN_UDP_tls-auth.pcapng` :
    /// P_CONTROL_HARD_RESET_CLIENT_V2, key id 0, session id
    /// 0x813814621d67462d, HMAC SHA-1 tls-auth puis replay packet-id 1.
    const HARD_RESET_CLIENT_V2: &[u8] = &[
        0x38, 0x81, 0x38, 0x14, 0x62, 0x1d, 0x67, 0x46, 0x2d, 0xde, 0x86, 0x73, 0x4d, 0x2c, 0xbf,
        0xf1, 0x51, 0xb2, 0xb1, 0x23, 0x1b, 0x61, 0xe4, 0x23, 0x08, 0xa2, 0x72, 0x81, 0x8e, 0x00,
        0x00, 0x00, 0x01, 0x50, 0xff, 0x26, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    /// Payload UDP de la trame 365 du meme fichier : P_DATA_V1, key id 0,
    /// 52 octets de charge chiffree.
    const DATA_V1: &[u8] = &[
        0x30, 0xd7, 0xb2, 0x33, 0xd3, 0x22, 0x03, 0xd9, 0xb4, 0xf2, 0x7c, 0xe4, 0xa9, 0x43, 0xde,
        0xd9, 0xb8, 0xd5, 0x1b, 0x86, 0x7e, 0x5c, 0x40, 0xf6, 0x5b, 0x26, 0xe5, 0x45, 0x7c, 0x52,
        0x1c, 0xca, 0x59, 0xe8, 0x63, 0x87, 0x8d, 0x46, 0xb0, 0xf4, 0x82, 0xdd, 0x06, 0x1f, 0x96,
        0x8f, 0x5d, 0x62, 0xd8, 0x17, 0x9b, 0xbb, 0xa6,
    ];

    /// Payload TCP de la trame 4 de
    /// `pcaps_exemple/protocols/openvpn/OpenVPN_TCP_tls-auth.pcapng` :
    /// prefixe de longueur 0x002a (42) puis le meme type de hard reset
    /// client v2, session id 0x28e1328a7185e6ca.
    const TCP_HARD_RESET_CLIENT_V2: &[u8] = &[
        0x00, 0x2a, 0x38, 0x28, 0xe1, 0x32, 0x8a, 0x71, 0x85, 0xe6, 0xca, 0x77, 0x9c, 0xda, 0x2d,
        0x22, 0x30, 0xe4, 0x75, 0x50, 0x40, 0xa7, 0x8d, 0xf9, 0x56, 0xf0, 0x26, 0x8c, 0x51, 0xfb,
        0x71, 0x00, 0x00, 0x00, 0x01, 0x50, 0xff, 0x20, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn parses_a_captured_hard_reset_client_v2() {
        let packet = OpenVpnPacket::try_from(HARD_RESET_CLIENT_V2).expect("captured hard reset");

        assert_eq!(packet.opcode, OpenVpnOpcode::ControlHardResetClientV2);
        assert_eq!(packet.key_id, 0);
        assert_eq!(packet.session_id, Some(0x8138_1462_1d67_462d));
        assert_eq!(packet.peer_id, None);
        // Tout ce qui suit la session id : HMAC (20) + replay packet-id (4) +
        // net-time (4) + ack array length (1) + message packet-id (4).
        assert_eq!(packet.payload.len(), 33);
        assert_eq!(packet.payload, &HARD_RESET_CLIENT_V2[9..]);
    }

    #[test]
    fn parses_a_captured_data_v1() {
        let packet = OpenVpnPacket::try_from(DATA_V1).expect("captured data packet");

        assert_eq!(packet.opcode, OpenVpnOpcode::DataV1);
        assert_eq!(packet.key_id, 0);
        assert_eq!(packet.session_id, None);
        assert_eq!(packet.peer_id, None);
        assert_eq!(packet.payload, &DATA_V1[1..]);
        assert_eq!(packet.payload.len(), 52);
    }

    #[test]
    fn parses_a_captured_tcp_record() {
        let (packet, rest) =
            OpenVpnPacket::from_tcp_stream(TCP_HARD_RESET_CLIENT_V2).expect("captured TCP record");

        assert_eq!(packet.opcode, OpenVpnOpcode::ControlHardResetClientV2);
        assert_eq!(packet.session_id, Some(0x28e1_328a_7185_e6ca));
        assert!(rest.is_empty());
    }

    /// Synthetique : un P_DATA_V2 minimal — le corpus tls-auth de 2013 ne
    /// contient que du P_DATA_V1, l'extraction du peer id est donc verrouillee
    /// sur des octets construits.
    #[test]
    fn parses_a_data_v2_peer_id() {
        let mut bytes = vec![0x48, 0x00, 0x00, 0x2a];
        bytes.extend_from_slice(&[0xde; 15]);
        let packet = OpenVpnPacket::try_from(bytes.as_slice()).expect("data v2");

        assert_eq!(packet.opcode, OpenVpnOpcode::DataV2);
        assert_eq!(packet.peer_id, Some(42));
        assert_eq!(packet.session_id, None);
        assert_eq!(packet.payload, &[0xde; 15]);

        // Sous le minimum plausible d'un datagramme chiffre : refus — c'est
        // la garde anti-faux-positifs du canal de donnees.
        assert!(OpenVpnPacket::try_from(&[0x48, 0x00, 0x00, 0x2a, 0xde, 0xad][..]).is_err());
    }

    /// Synthetique : opcodes hors de 1..=10 — c'est le rejet qui rend le
    /// module utilisable derriere le garde-fou de port sans etiqueter
    /// n'importe quel datagramme.
    #[test]
    fn rejects_unknown_opcodes() {
        for byte in [0x00u8, 0x07, 0x60, 0xf8, 0xff] {
            let mut packet = vec![byte];
            packet.extend_from_slice(&[0u8; 24]);
            assert_eq!(
                OpenVpnPacket::try_from(packet.as_slice()).unwrap_err(),
                OpenVpnError::UnknownOpcode { opcode: byte >> 3 },
                "byte {byte:#04x} must not map to an opcode"
            );
        }
    }

    #[test]
    fn rejects_an_empty_packet() {
        assert_eq!(
            OpenVpnPacket::try_from(&[][..]).unwrap_err(),
            OpenVpnError::EmptyPacket
        );
    }

    /// Synthetique : troncatures sous le minimum de chaque famille d'opcodes.
    #[test]
    fn rejects_truncated_packets() {
        // Hard reset client v2 reduit a l'opcode + 8 octets : sous les 14
        // requis pour un message de controle.
        assert_eq!(
            OpenVpnPacket::try_from(&HARD_RESET_CLIENT_V2[..9]).unwrap_err(),
            OpenVpnError::TooShort {
                expected: 14,
                actual: 9
            }
        );
        // ACK sans son premier packet-id acquitte.
        let mut ack = vec![0x28];
        ack.extend_from_slice(&[0u8; 13]);
        assert_eq!(
            OpenVpnPacket::try_from(ack.as_slice()).unwrap_err(),
            OpenVpnError::TooShort {
                expected: 22,
                actual: 14
            }
        );
        // P_DATA_V1 sous le minimum plausible d'un datagramme chiffre.
        assert_eq!(
            OpenVpnPacket::try_from(&[0x30][..]).unwrap_err(),
            OpenVpnError::TooShort {
                expected: 16,
                actual: 1
            }
        );
        // P_DATA_V2 avec un peer id incomplet.
        assert_eq!(
            OpenVpnPacket::try_from(&[0x48, 0x00, 0x00][..]).unwrap_err(),
            OpenVpnError::TooShort {
                expected: 19,
                actual: 3
            }
        );
    }

    /// Synthetique : les record types TLS 0x14 a 0x17 (ChangeCipherSpec,
    /// Alert, Handshake, Application Data) miment l'opcode 2 avec un key id
    /// 4 a 7 — un hard reset ouvre une session et porte toujours le key id 0,
    /// le controle rejette donc toute cette famille de collisions.
    #[test]
    fn rejects_tls_records_masquerading_as_hard_resets() {
        for first in [0x14u8, 0x15, 0x16, 0x17] {
            let mut packet = vec![first, 0x03, 0x03];
            packet.extend_from_slice(&[0u8; 200]);
            assert_eq!(
                OpenVpnPacket::try_from(packet.as_slice()).unwrap_err(),
                OpenVpnError::HardResetWithNonZeroKeyId {
                    key_id: first & 0b111
                },
                "TLS record type {first:#04x} must not parse as a hard reset"
            );
        }
    }

    /// Synthetique : un pseudo hard reset de 2 Ko — un vrai reset ne
    /// transporte pas de payload TLS libre, la borne rejette donc les gros
    /// paquets quelconques dont le premier octet mime un reset.
    #[test]
    fn rejects_an_oversized_reset() {
        let mut packet = vec![0x38];
        packet.extend_from_slice(&[0u8; 2048]);
        assert_eq!(
            OpenVpnPacket::try_from(packet.as_slice()).unwrap_err(),
            OpenVpnError::ResetTooLong {
                max: 1280,
                actual: 2049
            }
        );
    }

    #[test]
    fn rejects_truncated_tcp_records() {
        // Prefixe incomplet.
        assert_eq!(
            OpenVpnPacket::from_tcp_stream(&[0x00][..]).unwrap_err(),
            OpenVpnError::TcpLengthMissing { actual: 1 }
        );
        // Prefixe annoncant 42 octets, segment coupe apres 3.
        assert_eq!(
            OpenVpnPacket::from_tcp_stream(&TCP_HARD_RESET_CLIENT_V2[..5]).unwrap_err(),
            OpenVpnError::TcpRecordTruncated {
                declared: 42,
                available: 3
            }
        );
    }
}
