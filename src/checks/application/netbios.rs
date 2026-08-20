// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Controles NetBIOS (RFC 1001/1002) : Name Service (NBNS, UDP 137) et
//! Session Service (NBSS, TCP 139).
//!
//! NBNS reutilise le format d'en-tete DNS (12 octets) mais encode les noms
//! avec le "first-level encoding" (RFC 1001 §14.1) : chaque demi-octet du nom
//! NetBIOS de 16 octets est additionne a 'A', ce qui donne un label unique de
//! 32 octets dont chaque caractere est dans 'A'..='P'. Le seizieme octet
//! decode est le suffixe de service (0x00 workstation, 0x20 file server...).
//!
//! Toutes les fonctions travaillent sur des slices bornees : aucune
//! indexation sans verification prealable, aucune allocation.

use crate::{
    errors::application::netbios::{NbnsError, NbssError},
    parse::application::protocols::netbios::{
        NbnsFlags, NbnsQuestion, NbnsRecordType, NbnsResourceRecord, NbssMessageType, NetbiosName,
    },
};

/// En-tete NBNS : meme gabarit que DNS, 12 octets.
pub const NBNS_HEADER_LENGTH: usize = 12;

/// Label "first-level" : 32 octets, chaque demi-octet du nom + 'A'.
pub const NETBIOS_ENCODED_LABEL_LENGTH: usize = 32;

/// Nom NetBIOS decode : 15 caracteres + 1 octet de suffixe.
pub const NETBIOS_NAME_LENGTH: usize = 16;

/// RFC 1002 : un nom encode complet (labels + terminateur) tient en 255 octets.
/// Le premier label consomme 33 octets (longueur + 32), le terminateur 1 :
/// il reste au plus 221 octets pour le scope.
pub const NETBIOS_MAX_SCOPE_LENGTH: usize = 221;

/// Taille minimale d'une question : nom en pointeur (2) + type (2) + classe (2).
pub const NBNS_QUESTION_MIN_LENGTH: usize = 6;

/// Taille minimale d'un enregistrement : nom en pointeur (2) + type (2) +
/// classe (2) + TTL (4) + longueur de RDATA (2).
pub const NBNS_RECORD_MIN_LENGTH: usize = 12;

/// En-tete NBSS : type (1) + flags (1) + longueur (2).
pub const NBSS_HEADER_LENGTH: usize = 4;

/// Session request NBSS : nom appele (34 min) + nom appelant (34 min).
pub const NBSS_SESSION_REQUEST_MIN_LENGTH: u32 = 68;

/// Seule classe definie pour NBNS (IN).
const NBNS_CLASS_IN: u16 = 0x0001;

/// Opcodes NBNS valides (RFC 1002 §4.2.1.1). 0x0 query, 0x5 registration,
/// 0x6 release, 0x7 WACK, 0x8 refresh ; 0xf est la registration multi-domicile,
/// extension Microsoft courante sur les reseaux Windows.
const NBNS_VALID_OPCODES: [u8; 6] = [0x0, 0x5, 0x6, 0x7, 0x8, 0xf];

/// Rcodes NBNS valides : 0x3 (NAM_ERR DNS) n'est pas defini pour NBNS.
const NBNS_VALID_RCODES: [u8; 7] = [0x0, 0x1, 0x2, 0x4, 0x5, 0x6, 0x7];

/// Bits reserves de NM_FLAGS (entre RA et B) : doivent rester a zero.
const NBNS_RESERVED_FLAGS_MASK: u16 = 0x0060;

// ---------------------------------------------------------------------------
// NBNS
// ---------------------------------------------------------------------------

/// Verifie qu'au moins l'en-tete de 12 octets est present.
pub fn validate_nbns_min_length(packet: &[u8]) -> Result<(), NbnsError> {
    if packet.len() < NBNS_HEADER_LENGTH {
        return Err(NbnsError::InvalidLength {
            expected: NBNS_HEADER_LENGTH,
            actual: packet.len(),
        });
    }
    Ok(())
}

/// Decompose et valide le mot de flags NBNS.
///
/// C'est le controle qui separe NBNS d'un paquet DNS : NBNS accepte les
/// opcodes registration/release/WACK/refresh et le bit B (broadcast) que le
/// validateur DNS strict rejette.
pub fn extract_nbns_flags(raw: u16) -> Result<NbnsFlags, NbnsError> {
    let opcode = ((raw >> 11) & 0xF) as u8;
    if !NBNS_VALID_OPCODES.contains(&opcode) {
        return Err(NbnsError::InvalidOpcode(opcode));
    }

    if raw & NBNS_RESERVED_FLAGS_MASK != 0 {
        return Err(NbnsError::NonZeroReservedFlags(raw));
    }

    let rcode = (raw & 0xF) as u8;
    if !NBNS_VALID_RCODES.contains(&rcode) {
        return Err(NbnsError::InvalidRcode(rcode));
    }

    Ok(NbnsFlags {
        response: raw & 0x8000 != 0,
        opcode,
        authoritative_answer: raw & 0x0400 != 0,
        truncated: raw & 0x0200 != 0,
        recursion_desired: raw & 0x0100 != 0,
        recursion_available: raw & 0x0080 != 0,
        broadcast: raw & 0x0010 != 0,
        rcode,
    })
}

/// Lit les quatre compteurs de sections et refuse un message vide.
///
/// Contrairement au DNS unicast, une reponse NBNS legitime peut n'avoir
/// aucune question (registration response : QD=0, AN=1) : seul le message
/// sans aucune entree est rejete.
pub fn extract_nbns_counts(packet: &[u8]) -> Result<[u16; 4], NbnsError> {
    validate_nbns_min_length(packet)?;

    let counts = [
        u16::from_be_bytes([packet[4], packet[5]]),
        u16::from_be_bytes([packet[6], packet[7]]),
        u16::from_be_bytes([packet[8], packet[9]]),
        u16::from_be_bytes([packet[10], packet[11]]),
    ];

    if counts.iter().all(|count| *count == 0) {
        return Err(NbnsError::EmptyMessage);
    }

    Ok(counts)
}

/// Lit un `u16` reseau avec verification de bornes.
pub fn extract_nbns_u16(packet: &[u8], offset: usize) -> Result<u16, NbnsError> {
    if offset + 2 > packet.len() {
        return Err(NbnsError::TruncatedRecord { offset });
    }
    Ok(u16::from_be_bytes([packet[offset], packet[offset + 1]]))
}

/// Lit un `u32` reseau avec verification de bornes.
pub fn extract_nbns_u32(packet: &[u8], offset: usize) -> Result<u32, NbnsError> {
    if offset + 4 > packet.len() {
        return Err(NbnsError::TruncatedRecord { offset });
    }
    Ok(u32::from_be_bytes([
        packet[offset],
        packet[offset + 1],
        packet[offset + 2],
        packet[offset + 3],
    ]))
}

/// Decode le label "first-level" de 32 octets a `offset`.
///
/// Retourne le nom decode (15 caracteres + suffixe) et l'offset du premier
/// octet apres le label.
pub fn extract_netbios_encoded_name(
    packet: &[u8],
    offset: usize,
) -> Result<(NetbiosName, usize), NbnsError> {
    if offset >= packet.len() {
        return Err(NbnsError::TruncatedName { offset });
    }

    let label_length = packet[offset];
    if label_length as usize != NETBIOS_ENCODED_LABEL_LENGTH {
        return Err(NbnsError::InvalidNameLength {
            offset,
            length: label_length,
        });
    }

    let label_start = offset + 1;
    let label_end = label_start + NETBIOS_ENCODED_LABEL_LENGTH;
    if label_end > packet.len() {
        return Err(NbnsError::TruncatedName { offset });
    }

    let mut decoded = [0u8; NETBIOS_NAME_LENGTH];
    for (index, slot) in decoded.iter_mut().enumerate() {
        let position = label_start + 2 * index;
        let high = packet[position];
        let low = packet[position + 1];
        if !(b'A'..=b'P').contains(&high) || !(b'A'..=b'P').contains(&low) {
            return Err(NbnsError::InvalidNameEncoding { offset: position });
        }
        *slot = ((high - b'A') << 4) | (low - b'A');
    }

    let mut name = [0u8; NETBIOS_NAME_LENGTH - 1];
    name.copy_from_slice(&decoded[..NETBIOS_NAME_LENGTH - 1]);

    Ok((
        NetbiosName {
            name,
            suffix: decoded[NETBIOS_NAME_LENGTH - 1],
        },
        label_end,
    ))
}

/// Parcourt les labels de scope jusqu'au terminateur nul.
///
/// Retourne la zone brute des labels de scope (vide si absent) et l'offset
/// du premier octet apres le terminateur. La longueur totale est bornee par
/// la limite RFC de 255 octets pour un nom encode.
pub fn extract_netbios_scope(packet: &[u8], offset: usize) -> Result<(&[u8], usize), NbnsError> {
    let start = offset;
    let mut position = offset;

    loop {
        if position >= packet.len() {
            return Err(NbnsError::TruncatedName { offset: position });
        }
        let label_length = packet[position];
        if label_length == 0 {
            return Ok((&packet[start..position], position + 1));
        }
        // Un pointeur de compression au milieu d'un scope n'existe pas dans
        // les piles reelles : refuse plutot que suivi.
        if label_length & 0xC0 == 0xC0 {
            return Err(NbnsError::InvalidPointer { offset: position });
        }
        if label_length > 63 {
            return Err(NbnsError::InvalidScopeLabel { offset: position });
        }
        position += 1 + label_length as usize;
        if position - start > NETBIOS_MAX_SCOPE_LENGTH {
            return Err(NbnsError::NameTooLong { offset: position });
        }
    }
}

/// Extrait un champ nom complet : soit un nom encode inline, soit un pointeur
/// de compression DNS (deux octets, bits hauts a 11) vers un nom inline situe
/// plus tot dans le paquet.
///
/// Un seul saut de pointeur est autorise et la cible doit etre strictement
/// avant le pointeur : aucune boucle possible sur entree hostile.
pub fn extract_nbns_name_field(
    packet: &[u8],
    offset: usize,
) -> Result<(NetbiosName, &[u8], usize), NbnsError> {
    if offset >= packet.len() {
        return Err(NbnsError::TruncatedName { offset });
    }

    if packet[offset] & 0xC0 == 0xC0 {
        if offset + 2 > packet.len() {
            return Err(NbnsError::TruncatedName { offset });
        }
        let target = (u16::from_be_bytes([packet[offset], packet[offset + 1]]) & 0x3FFF) as usize;
        if target >= offset {
            return Err(NbnsError::InvalidPointer { offset });
        }
        // La cible doit etre un nom inline : un pointeur vers un pointeur est
        // refuse par le controle de longueur de label (0xC0 != 32).
        let (name, after_label) = extract_netbios_encoded_name(packet, target)?;
        let (scope, _) = extract_netbios_scope(packet, after_label)?;
        return Ok((name, scope, offset + 2));
    }

    let (name, after_label) = extract_netbios_encoded_name(packet, offset)?;
    let (scope, next) = extract_netbios_scope(packet, after_label)?;
    Ok((name, scope, next))
}

/// Type de question : seuls NB (0x0020) et NBSTAT (0x0021) sont definis.
pub fn extract_nbns_question_type(raw: u16) -> Result<NbnsRecordType, NbnsError> {
    match raw {
        0x0020 => Ok(NbnsRecordType::NetBios),
        0x0021 => Ok(NbnsRecordType::NodeStatus),
        other => Err(NbnsError::InvalidQuestionType(other)),
    }
}

/// Type d'enregistrement (RFC 1002 §4.2.1.2).
pub fn extract_nbns_record_type(raw: u16) -> Result<NbnsRecordType, NbnsError> {
    match raw {
        0x0001 => Ok(NbnsRecordType::Address),
        0x0002 => Ok(NbnsRecordType::NameServer),
        0x000A => Ok(NbnsRecordType::Null),
        0x0020 => Ok(NbnsRecordType::NetBios),
        0x0021 => Ok(NbnsRecordType::NodeStatus),
        other => Err(NbnsError::InvalidRecordType(other)),
    }
}

/// Seule la classe IN est definie pour NBNS.
pub fn validate_nbns_class(raw: u16) -> Result<(), NbnsError> {
    if raw != NBNS_CLASS_IN {
        return Err(NbnsError::InvalidClass(raw));
    }
    Ok(())
}

/// Extrait une question complete a `offset` et retourne l'offset suivant.
pub fn extract_nbns_question(
    packet: &[u8],
    offset: usize,
) -> Result<(NbnsQuestion<'_>, usize), NbnsError> {
    let (name, scope, after_name) = extract_nbns_name_field(packet, offset)?;
    let question_type = extract_nbns_question_type(extract_nbns_u16(packet, after_name)?)?;
    validate_nbns_class(extract_nbns_u16(packet, after_name + 2)?)?;

    Ok((
        NbnsQuestion {
            name,
            scope,
            question_type,
        },
        after_name + 4,
    ))
}

/// Extrait un enregistrement complet a `offset` et retourne l'offset suivant.
///
/// Le RDATA est garde brut : sa structure depend du type et le borner suffit
/// a la detection.
pub fn extract_nbns_record(
    packet: &[u8],
    offset: usize,
) -> Result<(NbnsResourceRecord<'_>, usize), NbnsError> {
    let (name, scope, after_name) = extract_nbns_name_field(packet, offset)?;
    let record_type = extract_nbns_record_type(extract_nbns_u16(packet, after_name)?)?;
    validate_nbns_class(extract_nbns_u16(packet, after_name + 2)?)?;
    let ttl = extract_nbns_u32(packet, after_name + 4)?;
    let rdata_length = extract_nbns_u16(packet, after_name + 8)? as usize;

    let rdata_start = after_name + 10;
    let rdata_end = rdata_start + rdata_length;
    if rdata_end > packet.len() {
        return Err(NbnsError::TruncatedRecord {
            offset: rdata_start,
        });
    }

    Ok((
        NbnsResourceRecord {
            name,
            scope,
            record_type,
            ttl,
            rdata: &packet[rdata_start..rdata_end],
        },
        rdata_end,
    ))
}

// ---------------------------------------------------------------------------
// NBSS
// ---------------------------------------------------------------------------

/// Verifie qu'au moins l'en-tete de 4 octets est present.
pub fn validate_nbss_min_length(packet: &[u8]) -> Result<(), NbssError> {
    if packet.len() < NBSS_HEADER_LENGTH {
        return Err(NbssError::InvalidLength {
            expected: NBSS_HEADER_LENGTH,
            actual: packet.len(),
        });
    }
    Ok(())
}

/// Type de message NBSS (RFC 1002 §4.3.1).
pub fn extract_nbss_message_type(raw: u8) -> Result<NbssMessageType, NbssError> {
    match raw {
        0x00 => Ok(NbssMessageType::SessionMessage),
        0x81 => Ok(NbssMessageType::SessionRequest),
        0x82 => Ok(NbssMessageType::PositiveSessionResponse),
        0x83 => Ok(NbssMessageType::NegativeSessionResponse),
        0x84 => Ok(NbssMessageType::RetargetSessionResponse),
        0x85 => Ok(NbssMessageType::SessionKeepAlive),
        other => Err(NbssError::UnknownMessageType(other)),
    }
}

/// Longueur annoncee : 16 bits plus le bit d'extension du champ flags,
/// soit 17 bits utiles. Les 7 bits hauts du champ flags sont reserves.
pub fn extract_nbss_length(packet: &[u8]) -> Result<u32, NbssError> {
    validate_nbss_min_length(packet)?;

    let flags = packet[1];
    if flags & 0xFE != 0 {
        return Err(NbssError::NonZeroReservedFlags(flags));
    }

    let base = u16::from_be_bytes([packet[2], packet[3]]) as u32;
    Ok(base + ((flags & 0x01) as u32) * 0x1_0000)
}

/// Le payload annonce doit tenir dans les octets disponibles.
pub fn validate_nbss_payload_available(packet_len: usize, length: u32) -> Result<(), NbssError> {
    let announced = length as usize;
    let available = packet_len - NBSS_HEADER_LENGTH;
    if announced > available {
        return Err(NbssError::TruncatedPayload {
            announced,
            available,
        });
    }
    Ok(())
}

/// Coherence longueur / type (RFC 1002 §4.3.2 a §4.3.7) : les reponses de
/// session ont des tailles fixes, la session request porte au moins deux noms
/// encodes de 34 octets.
pub fn validate_nbss_length_for_type(
    message_type: NbssMessageType,
    length: u32,
) -> Result<(), NbssError> {
    let valid = match message_type {
        NbssMessageType::SessionMessage => true,
        NbssMessageType::SessionRequest => length >= NBSS_SESSION_REQUEST_MIN_LENGTH,
        NbssMessageType::PositiveSessionResponse | NbssMessageType::SessionKeepAlive => length == 0,
        NbssMessageType::NegativeSessionResponse => length == 1,
        NbssMessageType::RetargetSessionResponse => length == 6,
    };

    if !valid {
        return Err(NbssError::InvalidPayloadLength {
            message_type: message_type.code(),
            length,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Nom encode de la trame 38229 (pcaps_exemple/The-Ultimate-PCAP.pcapng) :
    /// WEBERLAB, suffixe 0x1b (domain master browser).
    const WEBERLAB_ENCODED: &[u8] = b"\x20FHEFECEFFCEMEBECCACACACACACACABL\x00";

    #[test]
    fn decodes_a_captured_first_level_name() {
        let (name, next) = extract_netbios_encoded_name(WEBERLAB_ENCODED, 0).expect("valid name");

        assert_eq!(name.trimmed(), b"WEBERLAB");
        assert_eq!(name.suffix, 0x1b);
        assert_eq!(next, 33);
    }

    /// Synthetique : un octet hors 'A'..='P' dans le label.
    #[test]
    fn rejects_a_byte_outside_the_half_octet_alphabet() {
        let mut encoded = [0u8; 33];
        encoded[0] = 32;
        encoded[1..33].fill(b'A');
        encoded[5] = b'z';

        let result = extract_netbios_encoded_name(&encoded, 0);

        assert_eq!(result, Err(NbnsError::InvalidNameEncoding { offset: 5 }));
    }

    /// Synthetique : le premier label doit faire exactement 32 octets.
    #[test]
    fn rejects_a_first_label_that_is_not_32_bytes() {
        let packet = [4u8, b'A', b'B', b'C', b'D', 0];

        let result = extract_netbios_encoded_name(&packet, 0);

        assert_eq!(
            result,
            Err(NbnsError::InvalidNameLength {
                offset: 0,
                length: 4
            })
        );
    }

    /// Synthetique : label annonce mais octets absents.
    #[test]
    fn rejects_a_truncated_label() {
        let mut packet = [b'A'; 20];
        packet[0] = 32;

        let result = extract_netbios_encoded_name(&packet, 0);

        assert_eq!(result, Err(NbnsError::TruncatedName { offset: 0 }));
    }

    /// Synthetique : scope sans terminateur nul.
    #[test]
    fn rejects_a_scope_without_terminator() {
        let packet = [3u8, b'l', b'a', b'b'];

        let result = extract_netbios_scope(&packet, 0);

        assert_eq!(result, Err(NbnsError::TruncatedName { offset: 4 }));
    }

    /// Synthetique : une chaine de labels qui depasse la limite RFC de 255
    /// octets doit etre coupee sans boucle infinie.
    #[test]
    fn bounds_a_hostile_scope_chain() {
        let mut packet = Vec::new();
        for _ in 0..8 {
            packet.push(63u8);
            packet.extend_from_slice(&[b'a'; 63]);
        }
        packet.push(0);

        let result = extract_netbios_scope(&packet, 0);

        assert!(matches!(result, Err(NbnsError::NameTooLong { .. })));
    }

    /// Synthetique : un pointeur doit viser strictement avant lui-meme.
    #[test]
    fn rejects_a_forward_or_self_pointer() {
        // Pointeur en offset 0 vers offset 0 : boucle immediate.
        let packet = [0xC0u8, 0x00, 0x00, 0x20, 0x00, 0x01];

        let result = extract_nbns_name_field(&packet, 0);

        assert_eq!(result, Err(NbnsError::InvalidPointer { offset: 0 }));
    }

    #[test]
    fn nbns_flags_accept_a_broadcast_registration() {
        // Trame 38172 : opcode registration, RD, bit B.
        let flags = extract_nbns_flags(0x2910).expect("captured flags are valid");

        assert!(!flags.response);
        assert_eq!(flags.opcode, 0x5);
        assert!(flags.recursion_desired);
        assert!(flags.broadcast);
        assert_eq!(flags.rcode, 0);
    }

    /// Synthetique : opcode DNS (status, 0x2) inconnu de NBNS.
    #[test]
    fn nbns_flags_reject_a_dns_only_opcode() {
        assert_eq!(
            extract_nbns_flags(0x1000),
            Err(NbnsError::InvalidOpcode(0x2))
        );
    }

    /// Synthetique : bits reserves de NM_FLAGS non nuls.
    #[test]
    fn nbns_flags_reject_reserved_bits() {
        assert_eq!(
            extract_nbns_flags(0x0060),
            Err(NbnsError::NonZeroReservedFlags(0x0060))
        );
    }

    /// Synthetique : rcode 0x3 est une erreur DNS, pas NBNS.
    #[test]
    fn nbns_flags_reject_the_dns_name_error_rcode() {
        assert_eq!(
            extract_nbns_flags(0x8003),
            Err(NbnsError::InvalidRcode(0x3))
        );
    }

    #[test]
    fn nbss_message_types_cover_the_rfc_1002_set() {
        assert_eq!(
            extract_nbss_message_type(0x00),
            Ok(NbssMessageType::SessionMessage)
        );
        assert_eq!(
            extract_nbss_message_type(0x81),
            Ok(NbssMessageType::SessionRequest)
        );
        assert_eq!(
            extract_nbss_message_type(0x82),
            Ok(NbssMessageType::PositiveSessionResponse)
        );
        assert_eq!(
            extract_nbss_message_type(0x83),
            Ok(NbssMessageType::NegativeSessionResponse)
        );
        assert_eq!(
            extract_nbss_message_type(0x84),
            Ok(NbssMessageType::RetargetSessionResponse)
        );
        assert_eq!(
            extract_nbss_message_type(0x85),
            Ok(NbssMessageType::SessionKeepAlive)
        );
    }

    /// Synthetique : type hors table.
    #[test]
    fn nbss_rejects_an_unknown_message_type() {
        assert_eq!(
            extract_nbss_message_type(0x02),
            Err(NbssError::UnknownMessageType(0x02))
        );
        assert_eq!(
            extract_nbss_message_type(0xff),
            Err(NbssError::UnknownMessageType(0xff))
        );
    }

    /// Synthetique : le bit d'extension ajoute 65536 a la longueur.
    #[test]
    fn nbss_length_combines_the_extension_bit() {
        let packet = [0x00u8, 0x01, 0x00, 0x2a];

        assert_eq!(extract_nbss_length(&packet), Ok(0x1_002a));
    }

    /// Synthetique : les 7 bits hauts du champ flags sont reserves.
    #[test]
    fn nbss_length_rejects_reserved_flag_bits() {
        let packet = [0x00u8, 0x80, 0x00, 0x10];

        assert_eq!(
            extract_nbss_length(&packet),
            Err(NbssError::NonZeroReservedFlags(0x80))
        );
    }
}
