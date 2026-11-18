// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use crate::errors::application::dns::{
    DnsFlagsError, DnsHeaderError, DnsPacketError, DnsQueryParseError,
};

pub const DNS_MINIMUM_SIZE: usize = 12;

pub fn check_dns_minimum_size(bytes: &[u8]) -> Result<(), DnsPacketError> {
    if bytes.len() < DNS_MINIMUM_SIZE {
        return Err(DnsPacketError::InsufficientData {
            expected: DNS_MINIMUM_SIZE,
            actual: bytes.len(),
        });
    }

    Ok(())
}

pub fn check_packet_length(bytes: &[u8]) -> Result<(), DnsHeaderError> {
    if bytes.len() < DNS_MINIMUM_SIZE {
        return Err(DnsHeaderError::PacketTooShort);
    }

    Ok(())
}

fn parse_counts(bytes: &[u8]) -> Result<[u16; 4], DnsHeaderError> {
    if bytes.len() < 8 {
        return Err(DnsHeaderError::PacketTooShort);
    }

    let questions_count = u16::from_be_bytes([bytes[0], bytes[1]]);
    let answers_count = u16::from_be_bytes([bytes[2], bytes[3]]);
    let authorities_count = u16::from_be_bytes([bytes[4], bytes[5]]);
    let additionals_count = u16::from_be_bytes([bytes[6], bytes[7]]);
    Ok([
        questions_count,
        answers_count,
        authorities_count,
        additionals_count,
    ])
}

pub fn validate_and_parse_count(bytes: &[u8]) -> Result<[u16; 4], DnsHeaderError> {
    let counts = parse_counts(bytes)?;

    if counts[0] == 0 && (counts[1] > 0 || counts[2] > 0 || counts[3] > 0) {
        return Err(DnsHeaderError::InvalidCounts);
    }

    Ok(counts)
}

/// Same as [`validate_and_parse_count`], but tolerates an empty question
/// section even when records are present.
///
/// Legitimate for mDNS (RFC 6762 §6): responders send unsolicited
/// announcements that never echo a question, unlike classic unicast DNS
/// where an answer without its matching question is a red flag.
pub(crate) fn parse_count_allow_empty_question(bytes: &[u8]) -> Result<[u16; 4], DnsHeaderError> {
    parse_counts(bytes)
}

pub fn check_dns_query_size(
    bytes: &[u8],
    offset: usize,
    required_size: usize,
) -> Result<(), DnsQueryParseError> {
    if offset + required_size > bytes.len() {
        return Err(DnsQueryParseError::InsufficientData {
            required: required_size,
            offset,
            available: bytes.len() - offset,
        });
    }

    Ok(())
}

pub fn check_dns_name_offset(bytes: &[u8], offset: usize) -> Result<(), DnsQueryParseError> {
    if offset >= bytes.len() {
        return Err(DnsQueryParseError::OutOfBoundParse);
    }

    Ok(())
}

pub fn check_dns_label_bounds(
    bytes: &[u8],
    offset: usize,
    label_len: usize,
) -> Result<(), DnsQueryParseError> {
    if offset + label_len > bytes.len() {
        return Err(DnsQueryParseError::OutOfBoundParse);
    }

    Ok(())
}

/// Longueur maximale d'un nom de domaine sur le fil, octets de longueur des
/// labels et label racine compris (RFC 1035 §2.3.4 et §3.1).
pub const DNS_MAX_NAME_LENGTH: usize = 255;

/// Verifie la longueur sur le fil d'un nom en cours de lecture, labels
/// atteints par les pointeurs de compression compris. Au-dela de
/// [`DNS_MAX_NAME_LENGTH`], le nom est invalide — tshark l'affiche
/// « <Name too long> ».
///
/// C'est aussi la borne du travail par nom : sans elle, des noms qui
/// pointent tous vers un QNAME de milliers de labels le faisaient relire en
/// entier, en temps quadratique dans la taille du message (#184).
pub fn check_dns_name_length(wire_length: usize) -> Result<(), DnsQueryParseError> {
    if wire_length > DNS_MAX_NAME_LENGTH {
        return Err(DnsQueryParseError::OutOfBoundParse);
    }

    Ok(())
}

pub fn verify_dns_flags(flags: u16) -> Result<u16, DnsFlagsError> {
    let (qr, opcode, aa, tc, _rd, ra, z, rcode) = extract_dns_flags(flags);

    verify_z_field(z)?;
    verify_opcode(opcode)?;
    verify_rcode(rcode)?;
    verify_ra_in_query(qr, ra)?;

    if qr == 1 {
        verify_response_flags(opcode, aa, tc, rcode)?;
    }

    Ok(flags)
}

/// Validate the DNS header flags accepted on reception by mDNS.
///
/// RFC 6762 sections 18.3 and 18.11 require receivers to ignore messages with
/// non-zero OPCODE or RCODE. Its other header bits are explicitly ignored on
/// reception, so applying the stricter unicast-DNS validator here would reject
/// otherwise receivable mDNS traffic.
pub(crate) fn verify_mdns_flags(flags: u16) -> Result<u16, DnsFlagsError> {
    let (_, opcode, _, _, _, _, _, rcode) = extract_dns_flags(flags);

    if opcode != 0 {
        return Err(DnsFlagsError::InvalidOpcode(opcode));
    }
    if rcode != 0 {
        return Err(DnsFlagsError::InvalidRCode(rcode));
    }

    Ok(flags)
}

/// Validate the DNS-format header flags with the LLMNR layout (RFC 4795
/// section 2.1.1).
///
/// La disposition differe de DNS : le bit 10 est C (conflict), le bit 8 est
/// T (tentative), et Z couvre 4 bits (7-4) — la position RA de DNS fait
/// partie de Z. Regles appliquees, celles du recepteur :
/// - seul l'opcode 0 (requete standard) est defini ; un autre opcode « MUST
///   be silently discarded » ;
/// - les 4 bits Z sont ignores : l'emetteur doit les mettre a zero, mais le
///   recepteur « MUST ignore them » (#288) ;
/// - le RCODE d'une requete est ignore (« the responder ignores the RCODE
///   and assumes it to be zero ») ; celui d'une reponse reste borne aux
///   rcodes DNS classiques (0..=5) ;
/// - les bits C et T sont libres dans les deux sens.
///
/// Les flags sont rendus tels que lus sur le fil, bits ignores compris.
/// Seul le port UDP 5355, reserve a LLMNR, separe donc une reponse DNS
/// recursive (RA dans Z) d'une reponse LLMNR.
pub(crate) fn verify_llmnr_flags(flags: u16) -> Result<u16, DnsFlagsError> {
    let (qr, opcode, rcode) = extract_llmnr_flags(flags);

    if opcode != 0 {
        return Err(DnsFlagsError::InvalidOpcode(opcode));
    }
    if qr == 1 && rcode > 5 {
        return Err(DnsFlagsError::InvalidRCode(rcode));
    }

    Ok(flags)
}

/// Parse et valide les compteurs d'un en-tete LLMNR (RFC 4795 section 2.1.1) :
/// QDCOUNT vaut exactement 1 dans les deux sens (requetes et reponses non
/// conformes sont ecartees en silence par la RFC), et une requete ne
/// transporte ni answer ni authority. ARCOUNT n'est pas contraint.
pub(crate) fn parse_and_validate_llmnr_counts(
    bytes: &[u8],
    is_query: bool,
) -> Result<[u16; 4], DnsHeaderError> {
    let counts = parse_counts(bytes)?;

    if counts[0] != 1 {
        return Err(DnsHeaderError::InvalidCounts);
    }
    if is_query && (counts[1] != 0 || counts[2] != 0) {
        return Err(DnsHeaderError::InvalidCounts);
    }

    Ok(counts)
}

fn extract_dns_flags(flags: u16) -> (u16, u16, u16, u16, u16, u16, u16, u16) {
    let qr = (flags >> 15) & 0b1;
    let opcode = (flags >> 11) & 0b1111;
    let aa = (flags >> 10) & 0b1;
    let tc = (flags >> 9) & 0b1;
    let rd = (flags >> 8) & 0b1;
    let ra = (flags >> 7) & 0b1;
    // Seul le bit 6 est encore reserve (Z) : les bits 5 et 4 sont AD
    // (authentic data) et CD (checking disabled) depuis DNSSEC (RFC 4035
    // §3.1.6, §3.2.2). Les traiter comme Z rejetait toute requete DNSSEC
    // reelle (trame 11830 de The-Ultimate-PCAP, CD=1 dans un tunnel 6in4).
    let z = (flags >> 6) & 0b1;
    let rcode = flags & 0b1111;
    (qr, opcode, aa, tc, rd, ra, z, rcode)
}

/// Decoupe les flags selon la disposition LLMNR : (qr, opcode, rcode).
/// C (bit 10), T (bit 8) et Z (bits 7-4) ne sont pas retournes car aucune
/// regle de validation ne les contraint.
fn extract_llmnr_flags(flags: u16) -> (u16, u16, u16) {
    let qr = (flags >> 15) & 0b1;
    let opcode = (flags >> 11) & 0b1111;
    let rcode = flags & 0b1111;
    (qr, opcode, rcode)
}

fn verify_z_field(z: u16) -> Result<(), DnsFlagsError> {
    if z != 0 {
        return Err(DnsFlagsError::InvalidZField(z));
    }
    Ok(())
}

fn verify_opcode(opcode: u16) -> Result<(), DnsFlagsError> {
    if opcode > 5 {
        return Err(DnsFlagsError::InvalidOpcode(opcode));
    }
    Ok(())
}

fn verify_rcode(rcode: u16) -> Result<(), DnsFlagsError> {
    if rcode > 5 {
        return Err(DnsFlagsError::InvalidRCode(rcode));
    }
    Ok(())
}

fn verify_ra_in_query(qr: u16, ra: u16) -> Result<(), DnsFlagsError> {
    if qr == 0 && ra != 0 {
        return Err(DnsFlagsError::RaInQuery(ra));
    }
    Ok(())
}

fn verify_response_flags(opcode: u16, aa: u16, tc: u16, rcode: u16) -> Result<(), DnsFlagsError> {
    if opcode == 2 && (aa != 0 || tc != 0) {
        return Err(DnsFlagsError::AaTcInStatusResponse(aa, tc));
    }

    if rcode == 2 && aa != 0 {
        return Err(DnsFlagsError::AaInServerFailure(aa));
    }

    // Pas de regle sur rcode 3 (NXDOMAIN) : un serveur autoritaire repond
    // aa=1, mais un resolveur recursif relaie le NXDOMAIN avec aa=0 — les
    // deux sont legaux (RFC 1035 ne lie pas AA au rcode). L'ancienne
    // exigence aa=1 rejetait des reponses reelles du corpus
    // (dns_query_nonexistent.pcapng trame 2, dns_lab.pcapng trame 18).

    if rcode == 5 && aa != 0 {
        return Err(DnsFlagsError::AaInRefused(aa));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_z_field() {
        assert_eq!(verify_z_field(0), Ok(()));
        assert_eq!(verify_z_field(1), Err(DnsFlagsError::InvalidZField(1)));
    }

    #[test]
    fn test_verify_opcode() {
        assert_eq!(verify_opcode(0), Ok(()));
        assert_eq!(verify_opcode(5), Ok(()));
        assert_eq!(verify_opcode(6), Err(DnsFlagsError::InvalidOpcode(6)));
    }

    #[test]
    fn test_verify_rcode() {
        assert_eq!(verify_rcode(0), Ok(()));
        assert_eq!(verify_rcode(5), Ok(()));
        assert_eq!(verify_rcode(6), Err(DnsFlagsError::InvalidRCode(6)));
    }

    #[test]
    fn count_parsers_reject_short_slices_without_panicking() {
        let short_counts = [0_u8; 7];

        assert!(matches!(
            validate_and_parse_count(&short_counts),
            Err(DnsHeaderError::PacketTooShort)
        ));
        assert!(matches!(
            parse_count_allow_empty_question(&short_counts),
            Err(DnsHeaderError::PacketTooShort)
        ));
    }

    // Valeurs de flags synthetiques : elles ciblent chaque regle de
    // validation LLMNR, le corpus ne contenant que des requetes a flags nuls.
    #[test]
    fn llmnr_flags_accept_conflict_and_tentative_bits() {
        // Requete standard, tous bits a zero.
        assert_eq!(verify_llmnr_flags(0x0000), Ok(0x0000));
        // Reponse avec C=1 (conflit) : bit 10.
        assert_eq!(verify_llmnr_flags(0x8400), Ok(0x8400));
        // Reponse avec T=1 (tentative) : bit 8 — position RD en DNS.
        assert_eq!(verify_llmnr_flags(0x8100), Ok(0x8100));
        // Reponse tronquee TC=1 avec rcode 3 (NXDOMAIN).
        assert_eq!(verify_llmnr_flags(0x8203), Ok(0x8203));
    }

    #[test]
    fn llmnr_flags_reject_nonzero_opcode() {
        // Opcode 1 (IQUERY) : seul l'opcode 0 est defini en LLMNR.
        assert_eq!(
            verify_llmnr_flags(0x0800),
            Err(DnsFlagsError::InvalidOpcode(1))
        );
        // Opcode 5 (UPDATE), legal en DNS classique, refuse ici.
        assert_eq!(
            verify_llmnr_flags(0x2800),
            Err(DnsFlagsError::InvalidOpcode(5))
        );
    }

    #[test]
    fn llmnr_flags_ignore_z_bits() {
        // RFC 4795 §2.1.1 : « implementations of this specification MUST
        // ignore them ». Bit 7 (position RA en DNS), bit 4 (dernier bit de
        // Z), puis les quatre, en requete et en reponse.
        for flags in [0x0080, 0x0010, 0x00F0, 0x80F0] {
            assert_eq!(verify_llmnr_flags(flags), Ok(flags), "{flags:#06x}");
        }
    }

    #[test]
    fn llmnr_flags_ignore_query_rcode_and_bound_response_rcode() {
        // Requete : « the responder ignores the RCODE and assumes it to be
        // zero », quelle que soit sa valeur.
        assert_eq!(verify_llmnr_flags(0x0003), Ok(0x0003));
        assert_eq!(verify_llmnr_flags(0x000F), Ok(0x000F));
        // Reponse : RCODE hors des rcodes DNS classiques.
        assert_eq!(
            verify_llmnr_flags(0x8006),
            Err(DnsFlagsError::InvalidRCode(6))
        );
    }

    #[test]
    fn llmnr_counts_require_exactly_one_question() {
        // Requete conforme : [1, 0, 0, 0].
        let query = [0, 1, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            parse_and_validate_llmnr_counts(&query, true).unwrap(),
            [1, 0, 0, 0]
        );

        // Zero question : ecarte dans les deux sens.
        let zero_questions = [0, 0, 0, 1, 0, 0, 0, 0];
        assert!(matches!(
            parse_and_validate_llmnr_counts(&zero_questions, true),
            Err(DnsHeaderError::InvalidCounts)
        ));
        assert!(matches!(
            parse_and_validate_llmnr_counts(&zero_questions, false),
            Err(DnsHeaderError::InvalidCounts)
        ));

        // Deux questions : ecarte aussi.
        let two_questions = [0, 2, 0, 0, 0, 0, 0, 0];
        assert!(matches!(
            parse_and_validate_llmnr_counts(&two_questions, true),
            Err(DnsHeaderError::InvalidCounts)
        ));
    }

    #[test]
    fn llmnr_counts_reject_records_in_query_but_allow_them_in_response() {
        // Une requete ne transporte ni answer ni authority.
        let query_with_answer = [0, 1, 0, 1, 0, 0, 0, 0];
        assert!(matches!(
            parse_and_validate_llmnr_counts(&query_with_answer, true),
            Err(DnsHeaderError::InvalidCounts)
        ));
        let query_with_authority = [0, 1, 0, 0, 0, 1, 0, 0];
        assert!(matches!(
            parse_and_validate_llmnr_counts(&query_with_authority, true),
            Err(DnsHeaderError::InvalidCounts)
        ));

        // Une reponse porte ses answers.
        let response_with_answer = [0, 1, 0, 1, 0, 0, 0, 0];
        assert_eq!(
            parse_and_validate_llmnr_counts(&response_with_answer, false).unwrap(),
            [1, 1, 0, 0]
        );
    }

    #[test]
    fn llmnr_counts_reject_short_slices_without_panicking() {
        let short_counts = [0_u8; 7];
        assert!(matches!(
            parse_and_validate_llmnr_counts(&short_counts, true),
            Err(DnsHeaderError::PacketTooShort)
        ));
    }

    #[test]
    fn mdns_flags_require_zero_opcode_and_rcode() {
        assert_eq!(verify_mdns_flags(0x8400), Ok(0x8400));
        // AA/TC/RD/RA/Z/AD/CD are ignored on reception (RFC 6762
        // sections 18.4-18.10), including an unset AA bit in a response.
        assert_eq!(verify_mdns_flags(0x07f0), Ok(0x07f0));
        assert_eq!(verify_mdns_flags(0x8000), Ok(0x8000));
        assert_eq!(
            verify_mdns_flags(0x8800),
            Err(DnsFlagsError::InvalidOpcode(1))
        );
        assert_eq!(
            verify_mdns_flags(0x8001),
            Err(DnsFlagsError::InvalidRCode(1))
        );
    }
}
