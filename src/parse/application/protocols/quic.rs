// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use crate::{
    checks::application::quic::{
        QUIC_RETRY_INTEGRITY_TAG_LEN, QUIC_V1, QUIC_VERSION_NEGOTIATION, QuicCursor,
        extract_first_byte, extract_version, is_invariant_long_header, read_cid,
        read_length_and_payload, read_v1_cid, split_retry_token_and_tag,
        validate_supported_versions, varint_to_len,
    },
    errors::application::quic::QuicError,
};

/// QUIC Long Header Packet
///
/// ```mermaid
/// ---
/// title: QuicPacket
/// ---
/// packet-beta
/// 0-0: "Header Form u1"
/// 1-1: "Fixed Bit u1"
/// 2-3: "Long Packet Type u2"
/// 4-5: "Reserved u2 (protégé)"
/// 6-7: "Packet Number Length u2 (protégé)"
/// 8-39: "Version u32"
/// 40-47: "DCID Length u8"
/// 48-207: "Destination Connection ID variable"
/// 208-215: "SCID Length u8"
/// 216-375: "Source Connection ID variable"
/// 376-439: "Token / Length / Packet Number / Payload variable"
/// ```
///
/// Modélisation minimale d'un paquet QUIC v1 (RFC 9000/9001) avec Long Header:
/// couvre `Initial` et `Handshake`, ainsi que quelques frames fréquentes.
///
/// Le parsing est zero-copy : `token`, les Connection IDs et le payload sont
/// des slices empruntées (`&'a [u8]`) au paquet original.
///
/// Remarques :
/// - Un paquet `Initial` peut contenir un Token.
/// - Un paquet `Handshake` n'a pas de Token.
/// - Le champ `length` du Long Header inclut PN + payload chiffré (frames).
/// - La protection d'en-tête (RFC 9001 §5.4) masque le numéro de paquet et
///   les quatre bits bas de l'octet 0, dont sa longueur. Sans les clés, ni
///   l'un ni l'autre ne se lit : `packet_number` vaut `None`, `pn_length`
///   garde les deux bits tels quels, et la charge commence au numéro de
///   paquet (#293).
/// - La charge n'est pas déchiffrée : `QuicPayload::EncryptedPayload(&'a [u8])`.
/// - Un Version Negotiation (version 0, RFC 9000 §17.2.1) se lit aussi : il
///   appartient a la v1, et sa forme est celle des invariants (RFC 8999 §6).
///   Les autres versions sont refusees (`UnsupportedVersion`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum QuicPacket<'a> {
    /// Paquet QUIC avec Long Header de type Initial (Packet Type = 0x00)
    Initial {
        /// Entête Long Header commun.
        header: QuicLongHeader<'a>,
        /// Jeton fourni/retourné par le serveur (anti-DoS, address validation).
        token: &'a [u8],
        /// Les `length_field` octets qui suivent le champ Length : numéro de
        /// paquet protégé, puis charge chiffrée.
        payload: QuicPayload<'a>,
    },
    /// Paquet QUIC avec Long Header de type Handshake (Packet Type = 0x02)
    Handshake {
        /// Entête Long Header commun.
        header: QuicLongHeader<'a>,
        /// Les `length_field` octets qui suivent le champ Length : numéro de
        /// paquet protégé, puis charge chiffrée.
        payload: QuicPayload<'a>,
    },
    /// Autres Long Headers (0-RTT, Retry).
    ///
    /// Pour un 0-RTT, `payload` porte, comme pour Initial et Handshake, le
    /// numéro de paquet protégé puis la charge chiffrée.
    ///
    /// Pour un Retry (RFC 9000 §17.2.5), `payload` porte les octets bruts
    /// apres l'en-tete : Retry Token puis Retry Integrity Tag (16 octets,
    /// RFC 9001 §5.8). Le parseur garantit la presence du tag ;
    /// [`QuicPacket::retry_token`] et [`QuicPacket::retry_integrity_tag`]
    /// exposent les deux champs separes sans copie.
    OtherLong {
        header: QuicLongHeader<'a>,
        payload: QuicPayload<'a>,
    },
    /// Version Negotiation (RFC 9000 §17.2.1, RFC 8999 §6) : un en-tete long
    /// de version 0, que le serveur envoie quand il ne parle pas la version
    /// du client. Il n'a ni type, ni longueur, ni protection (#299).
    VersionNegotiation {
        /// Les sept bits bas de l'octet 0, libres (« Unused ») : le serveur
        /// les tire au hasard, le Fixed Bit compris.
        unused: u8,
        /// Destination Connection ID : le SCID du client. Les invariants en
        /// permettent 255 octets, et non 20 comme la v1.
        dcid: ConnectionId<'a>,
        /// Source Connection ID : le DCID du client.
        scid: ConnectionId<'a>,
        /// Les versions proposees, brutes : des blocs de 4 octets
        /// big-endian, jusqu'a la fin du datagramme. Voir
        /// [`QuicPacket::supported_versions`].
        versions: &'a [u8],
    },
}

impl<'a> QuicPacket<'a> {
    /// La version de l'en-tete long : 1, ou 0 pour un Version Negotiation.
    pub fn version(&self) -> u32 {
        match self {
            QuicPacket::Initial { header, .. }
            | QuicPacket::Handshake { header, .. }
            | QuicPacket::OtherLong { header, .. } => header.version,
            QuicPacket::VersionNegotiation { .. } => QUIC_VERSION_NEGOTIATION,
        }
    }

    /// Les versions d'un Version Negotiation, dans l'ordre du paquet. `None`
    /// si le paquet n'en est pas un.
    pub fn supported_versions(&self) -> Option<impl Iterator<Item = u32> + 'a> {
        match self {
            QuicPacket::VersionNegotiation { versions, .. } => {
                let versions: &'a [u8] = versions;
                let (chunks, _) = versions.as_chunks::<4>();
                Some(chunks.iter().map(|chunk| u32::from_be_bytes(*chunk)))
            }
            _ => None,
        }
    }

    /// Sonde de port, UDP 443 (#299) : la v1 et le Version Negotiation
    /// doivent se lire en entier. Les autres versions n'ont que leurs
    /// invariants (RFC 8999 §5.1), un en-tete long et deux Connection IDs
    /// dans le datagramme : une version reservee 0x?a?a?a?a (RFC 9000 §15),
    /// une version de brouillon ou a venir.
    pub(crate) fn is_port_match(payload: &[u8]) -> bool {
        let version = payload
            .get(1..5)
            .map(|bytes| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
        match version {
            Some(QUIC_V1 | QUIC_VERSION_NEGOTIATION) => QuicPacket::try_from(payload).is_ok(),
            Some(_) => is_invariant_long_header(payload),
            None => false,
        }
    }

    /// Sonde aveugle : la v1 seule. Hors port, les invariants et le Version
    /// Negotiation, quelques octets de forme libre, ne prouvent rien.
    pub(crate) fn is_blind_udp_match(payload: &[u8]) -> bool {
        QuicPacket::try_from(payload).is_ok_and(|packet| packet.version() == QUIC_V1)
    }

    /// Lit un Version Negotiation, `cur` place apres l'octet 0.
    fn version_negotiation(b0: u8, mut cur: QuicCursor<'a>) -> Result<Self, QuicError> {
        cur.take(4)?; // version 0
        let dcid = read_cid(&mut cur)?;
        let scid = read_cid(&mut cur)?;
        let versions = cur.take_rest();
        validate_supported_versions(versions)?;
        Ok(QuicPacket::VersionNegotiation {
            unused: b0 & 0b0111_1111,
            dcid,
            scid,
            versions,
        })
    }

    /// Token et tag d'un paquet Retry, separes sans copie.
    ///
    /// `None` si le paquet n'est pas un Retry, ou si un `OtherLong` construit
    /// a la main ne porte pas les 16 octets du tag (un paquet issu de
    /// `try_from` les porte toujours).
    fn retry_parts(&self) -> Option<(&'a [u8], &'a [u8; QUIC_RETRY_INTEGRITY_TAG_LEN])> {
        match self {
            QuicPacket::OtherLong {
                header,
                payload: QuicPayload::EncryptedPayload(raw),
            } if header.packet_type == QuicPacketType::Retry => split_retry_token_and_tag(raw).ok(),
            _ => None,
        }
    }

    /// Retry Token (RFC 9000 §17.2.5) : tout ce qui suit l'en-tete long,
    /// moins les 16 octets du tag. Peut etre vide (structure acceptee, voir
    /// `split_retry_token_and_tag`). `None` si le paquet n'est pas un Retry.
    pub fn retry_token(&self) -> Option<&'a [u8]> {
        self.retry_parts().map(|(token, _)| token)
    }

    /// Retry Integrity Tag (RFC 9001 §5.8) : les 16 derniers octets du
    /// paquet. `None` si le paquet n'est pas un Retry.
    pub fn retry_integrity_tag(&self) -> Option<&'a [u8; QUIC_RETRY_INTEGRITY_TAG_LEN]> {
        self.retry_parts().map(|(_, tag)| tag)
    }
}

/// Entête commun aux paquets QUIC à Long Header.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct QuicLongHeader<'a> {
    /// Doit valoir 1 pour Long Header.
    pub header_form_long: bool,
    /// Bit fixé à 1 par la spec.
    pub fixed_bit: bool,
    /// Type de paquet (Initial, 0-RTT, Handshake, Retry).
    pub packet_type: QuicPacketType,
    /// Version QUIC (ex: 0x00000001 pour QUIC v1).
    pub version: u32,
    /// Destination Connection ID (DCID).
    pub dcid: ConnectionId<'a>,
    /// Source Connection ID (SCID).
    pub scid: ConnectionId<'a>,
    /// Deux bits bas de l'octet 0, plus un (1..=4) : la longueur du numéro de
    /// paquet, une fois la protection d'en-tête retirée. Dans un Initial, un
    /// 0-RTT ou un Handshake reçu, ces bits sont **protégés** (RFC 9001
    /// §5.4.1) : lus tels quels, ils ne disent rien de la longueur réelle.
    /// Sans objet pour un Retry.
    pub pn_length: u8,
    /// Longueur (varint) annoncée pour le numéro de paquet et la charge,
    /// protégés ensemble ; au moins 20 octets (RFC 9001 §5.4.2).
    pub length_field: u64,
    /// Numéro de paquet. Toujours `None` : il est protégé (RFC 9001 §5.4),
    /// et le lire demande de retirer la protection d'en-tête, donc les clés.
    pub packet_number: Option<u64>,
}

/// Type de paquet Long Header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicPacketType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
}

/// Connection ID : au plus 20 octets en v1 (RFC 9000 §17.2), 255 dans un
/// Version Negotiation (RFC 8999 §5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ConnectionId<'a> {
    /// Longueur du CID.
    pub len: u8,
    /// Octets du CID (slice empruntée au paquet).
    pub bytes: &'a [u8],
}

/// Charge utile d’un paquet QUIC une fois l’entête parsé.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum QuicPayload<'a> {
    /// Ensemble de frames décodées (après déchiffrement).
    Frames(Vec<QuicFrame<'a>>),
    /// Payload encore chiffré ou non interprété (slice empruntée au paquet).
    EncryptedPayload(&'a [u8]),
}

/// Ensemble minimal de frames QUIC utiles au handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum QuicFrame<'a> {
    /// Frame ACK (RFC 9000 §19.3)
    Ack(AckFrame),
    /// Frame CRYPTO (RFC 9001 §4) — transporte les enregistrements TLS 1.3.
    Crypto(CryptoFrame<'a>),
    /// PADDING (0x00)
    Padding { length: u64 },
    /// PING (0x01)
    Ping,
    /// Autre type de frame non gérée ici.
    Unknown { frame_type: u64, raw: &'a [u8] },
}

/// Frame ACK (schéma simplifié : first range + ranges supplémentaires).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AckFrame {
    /// Plus grand numéro de paquet accusé de réception.
    pub largest_acknowledged: u64,
    /// Délai d’ACK en microsecondes (valeur QUIC encodée en exponentiel; ici post-décodée).
    pub ack_delay_us: u64,
    /// Nombre de ranges additionnels (peut être 0).
    pub ack_range_count: u64,
    /// Premier intervalle (taille du range commençant à `largest_acknowledged`).
    pub first_ack_range: u64,
    /// Ranges additionnels : (gap, ack_range_len)
    pub additional_ranges: Vec<AckRange>,
}

/// Un intervalle d’ACK supplémentaire (gap + longueur du range).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AckRange {
    /// Ecart (paquets non accusés) avant le prochain range.
    pub gap: u64,
    /// Taille du range suivant.
    pub ack_range_len: u64,
}

/// Frame CRYPTO : transporte des fragments TLS 1.3 (ClientHello, ServerHello, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CryptoFrame<'a> {
    /// Offset dans le flux CRYPTO (peut arriver en fragments).
    pub offset: u64,
    /// Taille des données (facultatif si `data.len()` suffit).
    pub length: u64,
    /// Données TLS (potentiellement fragmentées) — slice empruntée au paquet.
    pub data: &'a [u8],
}

impl<'a> TryFrom<&'a [u8]> for QuicPacket<'a> {
    type Error = QuicError;

    fn try_from(buf: &'a [u8]) -> Result<Self, Self::Error> {
        // Pas de pré-check de longueur global : QuicCursor borne déjà chaque
        // lecture (aucun indexage non vérifié) et un pré-check changerait les
        // payloads des erreurs Truncated { needed, remaining } existantes.
        let mut cur = QuicCursor::new(buf);

        // 1) Octet 0 : Long Header bits (NotLongHeader prime sur FixedBitNotSet)
        let b0 = cur.take_u8()?;
        // Version Negotiation : version 0, sans Fixed Bit ni type (RFC 8999
        // §6). Les autres paquets gardent l'ordre de leurs erreurs.
        let mut ahead = cur;
        if b0 & 0b1000_0000 != 0
            && ahead.take(4).ok() == Some(&QUIC_VERSION_NEGOTIATION.to_be_bytes()[..])
        {
            return Self::version_negotiation(b0, cur);
        }
        let (packet_type, pn_length) = extract_first_byte(b0)?;

        // 2) Version
        let version = extract_version(&mut cur)?;

        // 3) DCID / SCID, 20 octets au plus chacun en v1 (#299)
        let dcid = read_v1_cid(&mut cur)?;
        let scid = read_v1_cid(&mut cur)?;

        // 4) En-tête commun assemblé (length_field complété par
        //    read_length_and_payload après ses validations)
        let mut header = QuicLongHeader {
            // extract_first_byte a validé que ces deux bits valent 1.
            header_form_long: true,
            fixed_bit: true,
            packet_type,
            version,
            dcid,
            scid,
            pn_length,
            length_field: 0, // placeholder, on remplit après
            // Protégé (RFC 9001 §5.4) : jamais lu sans les clés (#293).
            packet_number: None,
        };

        // 5) Champs spécifiques selon type
        match packet_type {
            QuicPacketType::Initial => {
                // Token Length (varint) + Token
                let token_len = varint_to_len(cur.read_varint()?);
                let token = cur.take(token_len)?;

                let payload = read_length_and_payload(&mut cur, &mut header)?;

                Ok(QuicPacket::Initial {
                    header,
                    token,
                    payload: QuicPayload::EncryptedPayload(payload),
                })
            }

            QuicPacketType::Handshake => {
                // Pas de Token, directement Length (varint)
                let payload = read_length_and_payload(&mut cur, &mut header)?;

                Ok(QuicPacket::Handshake {
                    header,
                    payload: QuicPayload::EncryptedPayload(payload),
                })
            }

            QuicPacketType::ZeroRtt => {
                // Length (varint), PN, payload (non déchiffré ici)
                let payload = read_length_and_payload(&mut cur, &mut header)?;

                Ok(QuicPacket::OtherLong {
                    header,
                    payload: QuicPayload::EncryptedPayload(payload),
                })
            }

            QuicPacketType::Retry => {
                // Retry (RFC 9000 §17.2.5) : pas de Length ni PN. Le reste
                // du paquet est Token (longueur libre) + Integrity Tag
                // (16 octets, RFC 9001 §5.8). On valide la presence du tag
                // puis on garde les octets bruts ; retry_token() et
                // retry_integrity_tag() exposent la separation.
                let rest = cur.take_rest();
                split_retry_token_and_tag(rest)?;
                Ok(QuicPacket::OtherLong {
                    header,
                    payload: QuicPayload::EncryptedPayload(rest),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Un Version Negotiation : octet 0, version 0, DCID, SCID, versions.
    fn version_negotiation(b0: u8, dcid: &[u8], scid: &[u8], versions: &[u8]) -> Vec<u8> {
        let mut buf = vec![b0, 0, 0, 0, 0];
        buf.push(u8::try_from(dcid.len()).expect("CID court"));
        buf.extend_from_slice(dcid);
        buf.push(u8::try_from(scid.len()).expect("CID court"));
        buf.extend_from_slice(scid);
        buf.extend_from_slice(versions);
        buf
    }

    /// Un Initial v1 dont le DCID fait `dcid_len` octets, sans SCID ni
    /// token, et 21 octets proteges : l'exemple de #299.
    fn initial_with_dcid(version: u32, dcid_len: u8) -> Vec<u8> {
        let mut buf = vec![0xC0];
        buf.extend_from_slice(&version.to_be_bytes());
        buf.push(dcid_len);
        buf.extend(std::iter::repeat_n(0xAB, usize::from(dcid_len)));
        buf.extend_from_slice(&[0x00, 0x00, 0x15]); // SCID vide, token vide, Length 21
        buf.extend_from_slice(&[0x5A; 21]);
        buf
    }

    #[test]
    fn a_version_negotiation_lists_its_versions() {
        // Les sept bits bas sont libres : le Fixed Bit est ici a 0.
        let buf = version_negotiation(0x95, &[0x11; 8], &[], &[0, 0, 0, 1, 0x6B, 0x33, 0x43, 0xCF]);
        let packet = QuicPacket::try_from(buf.as_slice()).expect("Version Negotiation");
        assert_eq!(packet.version(), 0);
        let QuicPacket::VersionNegotiation {
            unused, dcid, scid, ..
        } = &packet
        else {
            panic!("attendu un Version Negotiation : {packet:?}");
        };
        assert_eq!(*unused, 0x15);
        assert_eq!(dcid.bytes, &[0x11; 8]);
        assert!(scid.bytes.is_empty());
        assert_eq!(
            packet.supported_versions().map(Iterator::collect::<Vec<_>>),
            Some(vec![1, 0x6B33_43CF])
        );

        let empty = version_negotiation(0x80, &[], &[], &[]);
        let packet = QuicPacket::try_from(empty.as_slice()).expect("liste vide");
        assert_eq!(packet.supported_versions().map(Iterator::count), Some(0));
    }

    #[test]
    fn a_version_negotiation_refuses_a_partial_version() {
        let buf = version_negotiation(0xC0, &[0x11; 8], &[0x22; 8], &[0, 0, 0, 1, 0xFF]);
        assert_eq!(
            QuicPacket::try_from(buf.as_slice()),
            Err(QuicError::Truncated {
                needed: 4,
                remaining: 1
            })
        );
    }

    #[test]
    fn a_version_negotiation_may_echo_long_connection_ids() {
        // Le client d'une autre version peut avoir choisi 255 octets : le
        // serveur les renvoie (RFC 8999 §6).
        let buf = version_negotiation(0xC0, &[0x11; 255], &[0x22; 21], &[0, 0, 0, 1]);
        let packet = QuicPacket::try_from(buf.as_slice()).expect("CID des invariants");
        assert!(matches!(
            packet,
            QuicPacket::VersionNegotiation { ref dcid, .. } if dcid.len == 255
        ));
    }

    #[test]
    fn a_v1_connection_id_over_twenty_bytes_is_refused() {
        assert!(QuicPacket::try_from(initial_with_dcid(1, 20).as_slice()).is_ok());
        assert_eq!(
            QuicPacket::try_from(initial_with_dcid(1, 21).as_slice()),
            Err(QuicError::ConnectionIdTooLong {
                length: 21,
                max: 20
            })
        );
        let mut long_scid = vec![0xC0, 0, 0, 0, 1, 0, 21];
        long_scid.extend([0xCD; 21]);
        assert_eq!(
            QuicPacket::try_from(long_scid.as_slice()),
            Err(QuicError::ConnectionIdTooLong {
                length: 21,
                max: 20
            })
        );
    }

    #[test]
    fn the_port_probe_reads_other_versions_by_their_invariants() {
        // v1 : lue en entier, au plus 20 octets de CID.
        assert!(QuicPacket::is_port_match(&initial_with_dcid(1, 20)));
        assert!(!QuicPacket::is_port_match(&initial_with_dcid(1, 21)));
        // Version reservee, Fixed Bit a 0 : seuls les invariants comptent,
        // et un CID de 30 octets y est permis.
        let mut reserved = initial_with_dcid(0x1A2A_3A4A, 30);
        reserved[0] = 0x80;
        assert!(QuicPacket::is_port_match(&reserved));
        assert_eq!(
            QuicPacket::try_from(reserved.as_slice()),
            Err(QuicError::FixedBitNotSet)
        );
        // Un SCID qui deborde du datagramme n'est pas un en-tete long.
        assert!(!QuicPacket::is_port_match(&[
            0xC0, 0x0A, 0x0A, 0x0A, 0x0A, 0, 4, 1
        ]));
        // Un Version Negotiation se lit en entier.
        let negotiation = version_negotiation(0xC0, &[0x11; 8], &[], &[0, 0, 0, 1]);
        assert!(QuicPacket::is_port_match(&negotiation));
        assert!(!QuicPacket::is_port_match(
            &negotiation[..negotiation.len() - 1]
        ));
        // Un en-tete court n'est pas pour cette sonde.
        assert!(!QuicPacket::is_port_match(&[0x40; 32]));
    }

    #[test]
    fn the_blind_probe_takes_version_1_only() {
        assert!(QuicPacket::is_blind_udp_match(&initial_with_dcid(1, 8)));
        assert!(!QuicPacket::is_blind_udp_match(&initial_with_dcid(1, 21)));
        let negotiation = version_negotiation(0xC0, &[0x11; 8], &[], &[0, 0, 0, 1]);
        assert!(!QuicPacket::is_blind_udp_match(&negotiation));
        assert!(!QuicPacket::is_blind_udp_match(&initial_with_dcid(
            0x0A0A_0A0A,
            8
        )));
    }

    // -------- Tests --------

    #[test]
    fn test_valid_quic_initial_minimal() {
        // construit un QUIC Initial minimal (comme tes autres tests),
        // pas besoin ETH/IPv6/UDP pour l’instant.
        let mut buf = Vec::new();
        buf.push(0xC0); // Long=1, Fixed=1, Initial, PN len=1
        buf.extend_from_slice(&0x00000001u32.to_be_bytes());
        buf.push(0); // dcid len
        buf.push(0); // scid len
        buf.push(0x00); // token len = 0
        buf.push(0x14); // length = 20, le minimum (RFC 9001 §5.4.2)
        buf.extend_from_slice(&[0u8; 20]); // PN protégé et charge

        let pkt = QuicPacket::try_from(buf.as_slice()).expect("must parse");
        match pkt {
            QuicPacket::Initial {
                header,
                token,
                payload,
            } => {
                assert_eq!(header.version, 1);
                assert!(token.is_empty());
                assert!(matches!(payload, QuicPayload::EncryptedPayload(v) if v.len() == 20));
            }
            _ => panic!("expected Initial"),
        }
    }

    #[test]
    fn test_error_short_buffer() {
        let buf = [0xC0u8]; // beaucoup trop court
        let res = QuicPacket::try_from(&buf[..]);
        assert!(matches!(res, Err(QuicError::Truncated { .. })));
    }

    #[test]
    fn test_error_not_long_header() {
        // MSB = 0 → Short Header → notre parseur Long Header doit refuser
        // 0x40 = 0100_0000 (fixed bit = 1, mais header_form_long = 0)
        let mut buf = Vec::new();
        buf.push(0x40);
        buf.extend_from_slice(&0x00000001u32.to_be_bytes()); // version (ne sera pas lu)
        buf.push(0); // dcid len
        buf.push(0); // scid len
        let res = QuicPacket::try_from(buf.as_slice());
        assert!(matches!(res, Err(QuicError::NotLongHeader)));
    }

    #[test]
    fn test_error_fixed_bit_zero() {
        // Long Header (MSB=1) mais fixed bit = 0 → doit échouer
        // 1000_0000 = 0x80 : header_form_long=1, fixed=0, type=00, pnlen=00
        let mut buf = Vec::new();
        buf.push(0x80);
        buf.extend_from_slice(&0x00000001u32.to_be_bytes()); // version
        buf.push(0); // dcid len
        buf.push(0); // scid len
        // Pour Initial: token_len=0 varint (0x00)
        buf.push(0x00);
        // length varint: 1 (PN seul)
        buf.push(0x01);
        // PN sur 1 octet (pn_length=1 via b0=0x80 -> pn_len_code=0 -> 1)
        buf.push(0x00);
        let res = QuicPacket::try_from(buf.as_slice());
        assert!(matches!(res, Err(QuicError::FixedBitNotSet)));
    }

    #[test]
    fn test_error_truncated_payload_length() {
        // Construire un Initial valide en apparence mais avec length trop grand
        // b0: 1100_0000 = 0xC0 (Long=1, Fixed=1, Type=Initial(00), PN len code=00 -> 1 octet)
        let mut buf = Vec::new();
        buf.push(0xC0);
        // version v1
        buf.extend_from_slice(&0x00000001u32.to_be_bytes());
        // dcid/scid vides
        buf.push(0); // dcid len
        buf.push(0); // scid len
        // token_len = 0 (varint 1o)
        buf.push(0x00);
        // length = 30 (varint 1o) : PN protégé et charge
        buf.push(0x1E);
        // MAIS on ne met que 22 octets au lieu de 30 → doit échouer
        buf.extend_from_slice(&[0xAA; 22]);

        let res = QuicPacket::try_from(buf.as_slice());
        assert!(matches!(
            res,
            Err(QuicError::PayloadTooShort {
                expected: 30,
                available: 22
            })
        ));
    }

    /// Un Initial v1 sans identifiants de connexion, jusqu'au champ Token
    /// Length exclu.
    fn initial_prefix() -> Vec<u8> {
        let mut buf = vec![0xC0]; // Long=1, Fixed=1, Initial, PN len=1
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&[0, 0]); // dcid len, scid len
        buf
    }

    /// Varint de huit octets (RFC 9000 §16) valant 2^32 + 2.
    const WIDE_VARINT: [u8; 8] = [0xC0, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02];

    /// #273 : un Token Length de 2^32 + 2 suivi de deux octets de token.
    /// Tronquee a 32 bits, la longueur vaudrait 2 et le paquet passerait.
    #[test]
    fn test_wide_token_length_is_not_truncated() {
        let mut buf = initial_prefix();
        buf.extend_from_slice(&WIDE_VARINT); // token len
        buf.extend_from_slice(&[0xAA, 0xBB]); // les deux octets qu'une troncature lirait
        buf.extend_from_slice(&[0x01, 0x00]); // length = 1, PN

        assert!(matches!(
            QuicPacket::try_from(buf.as_slice()),
            Err(QuicError::Truncated { .. })
        ));
    }

    /// #273 : un champ Length de 2^32 + 2 suivi de deux octets. Tronquee a
    /// 32 bits, la longueur vaudrait 2.
    #[test]
    fn test_wide_length_field_is_not_truncated() {
        let mut buf = initial_prefix();
        buf.push(0x00); // token len = 0
        buf.extend_from_slice(&WIDE_VARINT); // length
        buf.extend_from_slice(&[0x00, 0xAA]); // les deux octets qu'une troncature lirait

        assert!(matches!(
            QuicPacket::try_from(buf.as_slice()),
            Err(QuicError::PayloadTooShort { available: 2, .. })
        ));
    }

    #[test]
    fn test_initial_pkn_1_ack() {
        let bytes = hex::decode(
            "c4000000010008f409517248c4ab52004016dae7c01a42788f5049396532534a03ae8ebd63bf94e4",
        )
        .expect("Invalid hex string");

        let parsed = QuicPacket::try_from(bytes.as_slice()).expect("must parse");

        match parsed {
            QuicPacket::Initial {
                header,
                token,
                payload,
            } => {
                // Header bits
                assert!(header.header_form_long);
                assert!(header.fixed_bit);

                // Type / version
                assert!(matches!(header.packet_type, QuicPacketType::Initial));
                assert_eq!(header.version, 1);

                // DCID / SCID
                assert_eq!(header.dcid.len, 0);
                assert!(header.dcid.bytes.is_empty());

                assert_eq!(header.scid.len, 8);
                assert_eq!(
                    header.scid.bytes,
                    hex::decode("f409517248c4ab52").unwrap().as_slice()
                );

                // Token
                assert!(token.is_empty());

                // Length field (PN + payload chiffré)
                assert_eq!(header.length_field, 22);
                // Bits protégés de l'octet 0, tels quels (#293).
                assert_eq!(header.pn_length, 1);
                // Le numéro de paquet est protégé : il n'est pas lu.
                assert_eq!(header.packet_number, None);

                // Les 22 octets qui suivent Length, numéro de paquet compris.
                match payload {
                    QuicPayload::EncryptedPayload(v) => {
                        assert_eq!(
                            v,
                            hex::decode("dae7c01a42788f5049396532534a03ae8ebd63bf94e4")
                                .unwrap()
                                .as_slice()
                        );
                    }
                    _ => panic!("expected EncryptedPayload"),
                }
            }
            _ => panic!("expected Initial"),
        }
    }
}

#[cfg(test)]
mod extra_tests {
    use super::*;

    /// En-tête long commun : version 1, DCID de 2 octets, SCID vide.
    fn long_header(first_byte: u8) -> Vec<u8> {
        let mut buf = vec![first_byte];
        buf.extend_from_slice(&1u32.to_be_bytes()); // version 1
        buf.push(2); // dcid len
        buf.extend_from_slice(&[0xAA, 0xBB]);
        buf.push(0); // scid len
        buf
    }

    /// Les 20 octets du minimum (RFC 9001 §5.4.2), numéro de paquet protégé
    /// et charge, précédés de leur champ Length.
    fn protected_part(bytes: &mut Vec<u8>) -> Vec<u8> {
        let part: Vec<u8> = (0x80..0x94).collect();
        bytes.push(part.len() as u8);
        bytes.extend_from_slice(&part);
        part
    }

    #[test]
    fn parses_initial_with_token_and_payload() {
        let mut buf = long_header(0xC1); // Initial, bits de PN len à 1
        buf.push(3); // token len
        buf.extend_from_slice(&[1, 2, 3]);
        let part = protected_part(&mut buf);

        let packet = QuicPacket::try_from(buf.as_slice()).expect("Initial valide");
        match packet {
            QuicPacket::Initial {
                header,
                token,
                payload,
            } => {
                assert_eq!(header.version, 1);
                assert_eq!(header.dcid.bytes, &[0xAA, 0xBB]);
                assert_eq!(header.pn_length, 2);
                assert_eq!(header.packet_number, None);
                assert_eq!(header.length_field, 20);
                assert_eq!(token, &[1, 2, 3]);
                assert!(matches!(
                    payload,
                    QuicPayload::EncryptedPayload(b) if b == part.as_slice()
                ));
            }
            other => panic!("attendu Initial, obtenu {other:?}"),
        }
    }

    #[test]
    fn parses_handshake_packet() {
        let mut buf = long_header(0xE0); // Handshake
        let part = protected_part(&mut buf);

        let packet = QuicPacket::try_from(buf.as_slice()).expect("Handshake valide");
        match packet {
            QuicPacket::Handshake { header, payload } => {
                assert_eq!(header.packet_number, None);
                assert!(matches!(
                    payload,
                    QuicPayload::EncryptedPayload(b) if b == part.as_slice()
                ));
            }
            other => panic!("attendu Handshake, obtenu {other:?}"),
        }
    }

    #[test]
    fn parses_zero_rtt_packet() {
        let mut buf = long_header(0xD0); // 0-RTT
        protected_part(&mut buf);

        let packet = QuicPacket::try_from(buf.as_slice()).expect("0-RTT valide");
        assert!(matches!(packet, QuicPacket::OtherLong { .. }));
    }

    #[test]
    fn parses_retry_packet() {
        // Octets synthetiques : token de 3 octets puis tag de 16 octets.
        let mut buf = long_header(0xF0); // Retry
        buf.extend_from_slice(&[0x11, 0x22, 0x33]); // token
        let tag = [0x5Au8; 16];
        buf.extend_from_slice(&tag); // integrity tag

        let packet = QuicPacket::try_from(buf.as_slice()).expect("Retry valide");
        match &packet {
            QuicPacket::OtherLong { header, payload } => {
                assert!(matches!(header.packet_type, QuicPacketType::Retry));
                // Le payload brut reste token + tag (compat inchangee).
                assert!(matches!(
                    payload,
                    QuicPayload::EncryptedPayload(b) if b.len() == 19
                ));
            }
            other => panic!("attendu OtherLong, obtenu {other:?}"),
        }
        // Token et tag separes aux bons offsets.
        assert_eq!(packet.retry_token(), Some(&[0x11, 0x22, 0x33][..]));
        assert_eq!(packet.retry_integrity_tag(), Some(&tag));
    }

    #[test]
    fn parses_retry_packet_with_empty_token() {
        // Octets synthetiques : tag seul (16 octets), token vide.
        // Choix documente : le rejet d'un token vide (RFC 9000 §17.2.5) est
        // une obligation du client, pas du parseur stateless — la structure
        // est acceptee.
        let mut buf = long_header(0xF0); // Retry
        let tag = [0xA5u8; 16];
        buf.extend_from_slice(&tag);

        let packet = QuicPacket::try_from(buf.as_slice()).expect("token vide accepte");
        assert_eq!(packet.retry_token(), Some(&[][..]));
        assert_eq!(packet.retry_integrity_tag(), Some(&tag));
    }

    #[test]
    fn rejects_retry_packet_too_short_for_tag() {
        // Octets synthetiques : 15 octets apres l'en-tete, le tag de 16
        // octets ne tient pas — erreur nommee, pas de panique.
        let mut buf = long_header(0xF0); // Retry
        buf.extend_from_slice(&[0x00u8; 15]);

        assert!(matches!(
            QuicPacket::try_from(buf.as_slice()),
            Err(QuicError::Truncated {
                needed: 16,
                remaining: 15
            })
        ));
    }

    #[test]
    fn retry_accessors_return_none_for_non_retry() {
        // Les accesseurs Retry ne repondent pas pour un Handshake.
        let mut buf = long_header(0xE0); // Handshake
        protected_part(&mut buf);

        let packet = QuicPacket::try_from(buf.as_slice()).expect("Handshake valide");
        assert_eq!(packet.retry_token(), None);
        assert_eq!(packet.retry_integrity_tag(), None);
    }

    #[test]
    fn retry_token_and_tag_are_zero_copy() {
        // Les slices retournees doivent pointer dans le buffer d'entree.
        let mut buf = long_header(0xF0); // Retry
        buf.extend_from_slice(&[0xDE, 0xAD]); // token
        buf.extend_from_slice(&[0x77u8; 16]); // tag

        let packet = QuicPacket::try_from(buf.as_slice()).expect("Retry valide");
        let token = packet.retry_token().expect("token present");
        let tag = packet.retry_integrity_tag().expect("tag present");
        let input_range = buf.as_ptr() as usize..buf.as_ptr() as usize + buf.len();
        assert!(input_range.contains(&(token.as_ptr() as usize)));
        assert!(input_range.contains(&(tag.as_ptr() as usize)));
    }

    #[test]
    fn parses_two_byte_varint_token_length() {
        let mut buf = long_header(0xC0); // Initial, PN len 1
        buf.extend_from_slice(&[0x40, 0x02]); // token len = 2 en varint 2 octets
        buf.extend_from_slice(&[0xCA, 0xFE]);
        protected_part(&mut buf);

        let packet = QuicPacket::try_from(buf.as_slice()).expect("varint 2 octets valide");
        match packet {
            QuicPacket::Initial { token, .. } => assert_eq!(token, &[0xCA, 0xFE]),
            other => panic!("attendu Initial, obtenu {other:?}"),
        }
    }

    #[test]
    fn zero_copy_payload_points_into_input() {
        // Le payload retourné doit être une sous-slice du buffer d'entrée,
        // pas une copie.
        let mut buf = long_header(0xE0); // Handshake
        protected_part(&mut buf);

        let packet = QuicPacket::try_from(buf.as_slice()).expect("Handshake valide");
        let QuicPacket::Handshake {
            payload: QuicPayload::EncryptedPayload(p),
            ..
        } = packet
        else {
            panic!("attendu Handshake");
        };
        let input_range = buf.as_ptr() as usize..buf.as_ptr() as usize + buf.len();
        assert!(input_range.contains(&(p.as_ptr() as usize)));
    }

    #[test]
    fn rejects_invalid_packets() {
        // buffer vide
        assert!(QuicPacket::try_from(&[][..]).is_err());
        // header court (short header)
        assert!(QuicPacket::try_from(&[0x40u8, 0, 0, 0, 1][..]).is_err());
        // fixed bit absent
        assert!(QuicPacket::try_from(&[0x80u8, 0, 0, 0, 1][..]).is_err());
        // version inconnue
        let mut buf = vec![0xC0];
        buf.extend_from_slice(&2u32.to_be_bytes());
        buf.extend_from_slice(&[0, 0]);
        assert!(matches!(
            QuicPacket::try_from(buf.as_slice()),
            Err(QuicError::UnsupportedVersion(2))
        ));
        // tronqué au milieu du DCID
        let mut buf = vec![0xC0];
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.push(8); // dcid len 8 mais rien derrière
        assert!(matches!(
            QuicPacket::try_from(buf.as_slice()),
            Err(QuicError::Truncated {
                needed: 8,
                remaining: 0
            })
        ));
    }

    #[test]
    fn rejects_truncated_long_header() {
        // Version coupée en plein milieu (2 octets sur 4).
        let buf = [0xC0u8, 0x00, 0x00];
        assert!(matches!(
            QuicPacket::try_from(&buf[..]),
            Err(QuicError::Truncated {
                needed: 4,
                remaining: 2
            })
        ));
    }

    #[test]
    fn rejects_token_length_beyond_buffer() {
        let mut buf = long_header(0xC0); // Initial, PN len 1
        buf.push(0x20); // token len = 32 mais seulement 2 octets derrière
        buf.extend_from_slice(&[0x01, 0x02]);
        assert!(matches!(
            QuicPacket::try_from(buf.as_slice()),
            Err(QuicError::Truncated {
                needed: 32,
                remaining: 2
            })
        ));
    }

    #[test]
    fn rejects_truncated_varint_token_length() {
        let mut buf = long_header(0xC0); // Initial, PN len 1
        buf.push(0x80); // varint 4 octets annoncé, mais buffer fini
        assert!(matches!(
            QuicPacket::try_from(buf.as_slice()),
            Err(QuicError::TruncatedVarint {
                needed: 3,
                remaining: 0
            })
        ));
    }

    /// RFC 9001 §5.4.2 : un paquet trop court pour l'échantillon de la
    /// protection d'en-tête (4 + 16 octets après Length) est rejeté. Les
    /// bits de PN len n'y changent rien : ils sont protégés.
    #[test]
    fn rejects_length_field_below_the_header_protection_sample() {
        for first_byte in [0xC0, 0xC3, 0xD0, 0xE1] {
            let mut buf = long_header(first_byte);
            if first_byte & 0x30 == 0 {
                buf.push(0); // token len 0 (Initial)
            }
            buf.push(19); // length 19 < 20
            buf.extend_from_slice(&[0x55; 19]);
            assert!(
                matches!(
                    QuicPacket::try_from(buf.as_slice()),
                    Err(QuicError::LengthFieldTooSmall {
                        length_field: 19,
                        min: 20
                    })
                ),
                "{first_byte:#04x}"
            );
        }
    }

    #[test]
    fn rejects_payload_shorter_than_length_field() {
        let mut buf = long_header(0xE0);
        buf.push(30); // length = 30 mais un seul octet dispo
        buf.push(0x00);
        assert!(matches!(
            QuicPacket::try_from(buf.as_slice()),
            Err(QuicError::PayloadTooShort {
                expected: 30,
                available: 1
            })
        ));
    }
}
