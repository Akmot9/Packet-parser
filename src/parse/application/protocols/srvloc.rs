// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use core::convert::TryFrom;

use crate::{checks::application::srvloc::*, errors::application::srvloc::SrvlocPacketParseError};

/// Service Location Protocol Packet
///
/// ```mermaid
/// ---
/// title: SrvlocPacket
/// ---
/// packet-beta
/// 0-7: "Version u8"
/// 8-15: "Function u8"
/// 16-39: "Packet Length u16/u24"
/// 40-55: "Flags / Dialect"
/// 56-79: "Extension Offset / Language"
/// 80-95: "Transaction ID u16"
/// 96-111: "Language Tag Length u16"
/// 112-175: "Language Tag / Payload variable"
/// ```
///
/// Zero-copy: all variable-length fields borrow from the original packet.
#[derive(Debug)]
pub struct SrvlocPacket<'a> {
    pub header: SrvlocHeader<'a>,
    pub payload: SrvlocMessage<'a>,
}

#[derive(Debug)]
pub enum SrvlocHeader<'a> {
    V1(SrvlocHeaderV1<'a>),
    V2(SrvlocHeaderV2<'a>),
}

#[derive(Debug)]
pub struct SrvlocHeaderV2<'a> {
    pub version: u8,
    pub function: u8,

    // 3 octets sur le fil -> on le stocke dans un u32
    pub packet_length: u32,

    // 2 octets sur le fil
    pub flags: u16,

    // 3 octets sur le fil -> u32
    pub next_extension_offset: u32,

    // 2 octets sur le fil -> u16
    pub xid: u16,

    // 2 octets sur le fil -> u16
    pub lang_tag_len: u16,

    // chaîne UTF-8 empruntée au paquet ("en", "fr", etc.)
    pub lang_tag: &'a str,
}

#[derive(Debug)]
pub struct SrvlocHeaderV1<'a> {
    pub version: u8,
    pub function: u8,
    pub packet_length: u16, // 2 octets
    pub flags: u8,
    pub dialect: u8,
    pub language: &'a str, // 2 bytes ASCII -> "en"

    pub encoding: u8,
    pub transaction_id: u16,
    pub error_code: u16,

    pub url_length: u16,
    pub url: &'a str,

    pub scope_list_length: u16,
    pub scope_list: &'a str,
}

/// Body brut du message, tel que porte par [`SrvlocPacket::payload`].
///
/// Cette enum publique est exhaustive : lui ajouter des variantes casserait
/// les `match` (et patterns irrefutables) des utilisateurs, rupture reservee
/// a la prochaine majeure (epic #76). Le decodage typed du body passe donc
/// par [`SrvlocPacket::body`], qui retourne [`SrvlocBody`].
#[derive(Debug)]
pub enum SrvlocMessage<'a> {
    Raw(&'a [u8]),
}

/// Body d'un message SRVLOC decode selon la version et le code fonction,
/// obtenu via [`SrvlocPacket::body`].
///
/// `#[non_exhaustive]` des sa creation : les fonctions restantes (AttrRqst,
/// DAAdvert v2, etc.) pourront etre ajoutees sans rupture.
#[non_exhaustive]
#[derive(Debug)]
pub enum SrvlocBody<'a> {
    /// SLPv2 Service Request (function 1, RFC 2608 section 8.1).
    SrvRqstV2(SrvRqstV2<'a>),
    /// SLPv2 Service Reply (function 2, RFC 2608 section 8.2).
    SrvRplyV2(SrvRplyV2<'a>),
    /// Codes fonction non implementes : octets bruts du body.
    Raw(&'a [u8]),
}

/// SLPv2 Service Request body (RFC 2608 section 8.1).
///
/// Cinq chaines prefixees chacune par leur longueur `u16` big-endian.
///
/// ```mermaid
/// ---
/// title: SrvRqstV2
/// ---
/// packet-beta
/// 0-15: "PRList Length u16"
/// 16-31: "PRList variable"
/// 32-47: "Service Type Length u16"
/// 48-63: "Service Type variable"
/// 64-79: "Scope List Length u16"
/// 80-95: "Scope List variable"
/// 96-111: "Predicate Length u16"
/// 112-127: "Predicate variable"
/// 128-143: "SLP SPI Length u16"
/// 144-159: "SLP SPI variable"
/// ```
///
/// Zero-copy : chaque `&str` emprunte au paquet d'origine.
#[non_exhaustive]
#[derive(Debug)]
pub struct SrvRqstV2<'a> {
    /// Previous Responder List : adresses ayant deja repondu.
    pub pr_list: &'a str,
    /// Type de service demande (par exemple "service:printer").
    pub service_type: &'a str,
    /// Liste de scopes ou chercher.
    pub scope_list: &'a str,
    /// Predicat LDAPv3 de filtrage des attributs.
    pub predicate: &'a str,
    /// SLP Security Parameter Index.
    pub slp_spi: &'a str,
}

/// SLPv2 Service Reply body (RFC 2608 section 8.2).
///
/// ```mermaid
/// ---
/// title: SrvRplyV2
/// ---
/// packet-beta
/// 0-15: "Error Code u16"
/// 16-31: "URL Entry Count u16"
/// 32-63: "URL Entries variable"
/// ```
#[non_exhaustive]
#[derive(Debug)]
pub struct SrvRplyV2<'a> {
    /// Code d'erreur SLP (0 = succes).
    pub error_code: u16,
    /// Nombre d'URL entries declare par l'emetteur.
    pub url_entry_count: u16,
    /// URL entries decodees ; leur nombre egale `url_entry_count`.
    pub url_entries: Vec<UrlEntryV2<'a>>,
}

/// SLPv2 URL Entry (RFC 2608 section 4.3).
///
/// ```mermaid
/// ---
/// title: UrlEntryV2
/// ---
/// packet-beta
/// 0-7: "Reserved u8"
/// 8-23: "Lifetime u16"
/// 24-39: "URL Length u16"
/// 40-55: "URL variable"
/// 56-63: "Num Auths u8"
/// 64-95: "Auth Blocks variable"
/// ```
///
/// Zero-copy : `url` et `auth_blocks` empruntent au paquet d'origine.
#[non_exhaustive]
#[derive(Debug)]
pub struct UrlEntryV2<'a> {
    /// Octet reserve (doit etre 0 sur le fil, non contraint ici).
    pub reserved: u8,
    /// Duree de vie de l'enregistrement, en secondes.
    pub lifetime: u16,
    /// Longueur declaree de l'URL.
    pub url_length: u16,
    /// URL du service, UTF-8 valide.
    pub url: &'a str,
    /// Nombre d'authentication blocks.
    pub num_auths: u8,
    /// Authentication blocks bruts (bornes validees, contenu non decode).
    pub auth_blocks: &'a [u8],
}

impl<'a> TryFrom<&'a [u8]> for SrvlocPacket<'a> {
    type Error = SrvlocPacketParseError;

    fn try_from(payload: &'a [u8]) -> Result<Self, Self::Error> {
        // Dispatch conserve dans TryFrom : SLPv1 et SLPv2 sont deux formats
        // wire distincts, chaque branche deroule la sequence lineaire
        // canonique (pre-check de longueur, extract_* champ par champ,
        // validations croisees, construction).
        let version = extract_version(payload)?;

        match version {
            1 => parse_v1_packet(payload),
            2 => parse_v2_packet(payload),
            other => Err(SrvlocPacketParseError::UnsupportedVersion(other)),
        }
    }
}

impl<'a> SrvlocPacket<'a> {
    /// Decode le body du message selon la version et le code fonction.
    ///
    /// Chemin additif (epic #76) : `SrvlocMessage` est une enum exhaustive
    /// figee jusqu'a la prochaine majeure, le body typed est donc expose par
    /// cette methode plutot que par de nouvelles variantes de `payload`.
    ///
    /// - SLPv2 SrvRqst / SrvRply : body decode ; deja valide par `try_from`,
    ///   le re-decodage est zero-copy et ne peut pas echouer sur un paquet
    ///   construit par `try_from`.
    /// - SLPv1 DAAdvert : les champs decodes sont deja dans le header V1.
    /// - Autres codes fonction : [`SrvlocBody::Raw`].
    pub fn body(&self) -> Result<SrvlocBody<'a>, SrvlocPacketParseError> {
        let SrvlocMessage::Raw(raw) = &self.payload;
        match &self.header {
            SrvlocHeader::V1(_) => Ok(SrvlocBody::Raw(raw)),
            SrvlocHeader::V2(header) => parse_v2_body(header.function, raw),
        }
    }
}

/// Longueur minimale d'une URL entry v2 sur le fil : reserved u8 +
/// lifetime u16 + longueur d'URL u16 + num auths u8, avec une URL vide.
const URL_ENTRY_V2_MIN_LENGTH: usize = 6;

/// Dispatch du body SLPv2 par code fonction (issue #53) : SrvRqst et SrvRply
/// sont decodes, les autres codes restent bruts.
fn parse_v2_body(function: u8, body: &[u8]) -> Result<SrvlocBody<'_>, SrvlocPacketParseError> {
    match function {
        SRVLOC_FUNCTION_SRV_RQST => Ok(SrvlocBody::SrvRqstV2(parse_srv_rqst_v2(body)?)),
        SRVLOC_FUNCTION_SRV_RPLY => Ok(SrvlocBody::SrvRplyV2(parse_srv_rply_v2(body)?)),
        _ => Ok(SrvlocBody::Raw(body)),
    }
}

/// Decode un body SrvRqst v2 (RFC 2608 section 8.1) : cinq chaines prefixees
/// par leur longueur u16, chacune bornee et validee UTF-8.
fn parse_srv_rqst_v2(body: &[u8]) -> Result<SrvRqstV2<'_>, SrvlocPacketParseError> {
    let mut offset = 0;

    let (_, pr_list) = extract_length_prefixed_str(body, &mut offset, "pr_list")?;
    let (_, service_type) = extract_length_prefixed_str(body, &mut offset, "service_type")?;
    let (_, scope_list) = extract_length_prefixed_str(body, &mut offset, "scope_list")?;
    let (_, predicate) = extract_length_prefixed_str(body, &mut offset, "predicate")?;
    let (_, slp_spi) = extract_length_prefixed_str(body, &mut offset, "slp_spi")?;

    Ok(SrvRqstV2 {
        pr_list,
        service_type,
        scope_list,
        predicate,
        slp_spi,
    })
}

/// Decode un body SrvRply v2 (RFC 2608 section 8.2) : error code, compteur
/// d'URL entries puis les entries elles-memes.
fn parse_srv_rply_v2(body: &[u8]) -> Result<SrvRplyV2<'_>, SrvlocPacketParseError> {
    let mut offset = 0;

    let error_code = extract_error_code(body, &mut offset)?;
    let url_entry_count = read_u16(body, &mut offset)?;

    // Pre-allocation bornee : un compteur hostile ne pilote jamais seul la
    // capacite, chaque entry manquante echouera de toute facon en Truncated.
    let capacity = super::bounded_capacity(
        url_entry_count as usize,
        body.len() - offset,
        URL_ENTRY_V2_MIN_LENGTH,
    );
    let mut url_entries = Vec::with_capacity(capacity);
    for _ in 0..url_entry_count {
        url_entries.push(parse_url_entry_v2(body, &mut offset)?);
    }

    Ok(SrvRplyV2 {
        error_code,
        url_entry_count,
        url_entries,
    })
}

/// Decode une URL entry v2 (RFC 2608 section 4.3) : reserved, lifetime, URL
/// prefixee par sa longueur, puis les authentication blocks bornes.
fn parse_url_entry_v2<'p>(
    body: &'p [u8],
    offset: &mut usize,
) -> Result<UrlEntryV2<'p>, SrvlocPacketParseError> {
    let reserved = read_u8(body, offset)?;
    let lifetime = read_u16(body, offset)?;
    let (url_length, url) = extract_length_prefixed_str(body, offset, "url")?;
    let num_auths = read_u8(body, offset)?;
    let auth_blocks = skip_auth_blocks(body, offset, num_auths)?;

    Ok(UrlEntryV2 {
        reserved,
        lifetime,
        url_length,
        url,
        num_auths,
        auth_blocks,
    })
}

/// Parse un paquet SLP v1 : header commun puis dispatch par code fonction.
fn parse_v1_packet(payload: &[u8]) -> Result<SrvlocPacket<'_>, SrvlocPacketParseError> {
    // Layout v1 (d'apres Wireshark pour DA Advertisement) :
    //  0 : Version (1)
    //  1 : Function (1)
    //  2-3 : Packet Length (u16)
    //  4 : Flags (u8)
    //  5 : Dialect (u8)
    //  6-7 : Language (2 bytes, "en")
    //  8 : Encoding (u8)
    //  9-10 : Transaction ID (u16)
    //
    // Body specifique DA Advert (function 8) :
    //  11-12 : Error Code (u16)
    //  13-14 : URL Length (u16)
    //  ... : URL
    //  ... : Scope List Length (u16)
    //  ... : Scope List

    // Pre-check de longueur : le header fixe v1 couvre les octets 0..8.
    validate_v1_header_length(payload)?;

    let version = extract_version(payload)?;
    let function = extract_function(version, payload[1])?;

    let packet_length = extract_packet_length_v1(&payload[2..4])?;
    // La longueur declaree est validee des son extraction, et non apres les
    // autres champs : c'est la garde principale contre les payloads etrangers
    // (DHCP, issue #3), et la deplacer changerait quelle erreur sort en
    // premier sur un paquet multi-fautes.
    validate_declared_packet_length(packet_length as usize, payload.len())?;

    let flags = extract_flags_v1(payload[4])?;
    let dialect = extract_dialect(payload[5])?;
    let language = extract_language(&payload[6..8])?;

    let mut offset = 8;

    // Encoding et transaction id restent lus pour tout code fonction : ils
    // appartiennent a la partie commune du header v1, pas au body DA Advert.
    let encoding = extract_encoding(payload, &mut offset)?;
    let transaction_id = extract_transaction_id(payload, &mut offset)?;

    // Dispatch par code fonction (issue #50) : seul le DAAdvert (function 8)
    // porte le body error code / url / scope list. Les fonctions non
    // implementees gardent leur body brut dans SrvlocMessage::Raw.
    let (error_code, url_length, url, scope_list_length, scope_list) =
        if function == SRVLOC_FUNCTION_DA_ADVERT {
            let error_code = extract_error_code(payload, &mut offset)?;
            let (url_length, url) = extract_url(payload, &mut offset)?;
            let (scope_list_length, scope_list) = extract_scope_list(payload, &mut offset)?;
            (error_code, url_length, url, scope_list_length, scope_list)
        } else {
            // Champs specifiques au DAAdvert : SrvlocHeaderV1 est une struct
            // publique exhaustive, figee jusqu'a la prochaine majeure
            // (epic #76), on ne peut ni retirer ces champs ni les rendre
            // optionnels. Pour les autres fonctions ils recoivent des valeurs
            // neutres et le body complet reste dans SrvlocMessage::Raw.
            (0, 0, "", 0, "")
        };

    let header_v1 = SrvlocHeaderV1 {
        version,
        function,
        packet_length,
        flags,
        dialect,
        language,
        encoding,
        transaction_id,
        error_code,
        url_length,
        url,
        scope_list_length,
        scope_list,
    };

    // Le reste part dans le payload brut en zero-copy : rien pour un
    // DAAdvert complet, le body entier pour les autres codes fonction.
    // `offset` ne depasse jamais `payload.len()`.
    let remaining = &payload[offset..];

    Ok(SrvlocPacket {
        header: SrvlocHeader::V1(header_v1),
        payload: SrvlocMessage::Raw(remaining),
    })
}

/// Parse un paquet SLP v2 (DA Advert dans ton cas)
fn parse_v2_packet(payload: &[u8]) -> Result<SrvlocPacket<'_>, SrvlocPacketParseError> {
    // Layout SLP v2 :
    //  0 : Version (u8)
    //  1 : Function (u8)
    //  2-4 : Packet Length (u24)
    //  5-6 : Flags (u16)
    //  7-9 : Next Extension Offset (u24)
    //  10-11 : XID (u16)
    //  12-13 : Lang Tag Len (u16)
    //  14.. : Lang Tag (UTF-8)

    // Pre-check de longueur : le header fixe v2 couvre les octets 0..14.
    validate_v2_header_length(payload)?;

    let version = extract_version(payload)?;
    let function = extract_function(version, payload[1])?;

    // version + function deja lus : le curseur reprend a l'octet 2.
    let mut offset = 2;

    let packet_length = extract_packet_length_v2(payload, &mut offset)?;
    // La longueur declaree est validee des son extraction : garde principale
    // contre les payloads etrangers, l'ordre actuel fixe quelle erreur sort
    // en premier sur un paquet multi-fautes.
    validate_declared_packet_length(packet_length as usize, payload.len())?;

    let flags = extract_flags_v2(payload, &mut offset)?;
    let next_extension_offset = extract_next_extension_offset(payload, &mut offset)?;
    let xid = extract_xid(payload, &mut offset)?;
    let lang_tag_len = extract_lang_tag_len(payload, &mut offset)?;
    let lang_tag = extract_lang_tag(payload, &mut offset, lang_tag_len as usize)?;

    let header_v2 = SrvlocHeaderV2 {
        version,
        function,
        packet_length,
        flags,
        next_extension_offset,
        xid,
        lang_tag_len,
        lang_tag,
    };

    // Le body reste porte en brut par SrvlocMessage::Raw (enum figee,
    // epic #76), mais il est valide des maintenant pour les fonctions
    // decodees : un SrvRqst/SrvRply v2 aux longueurs hors bornes est rejete
    // par TryFrom, et SrvlocPacket::body() redecodera sans echec possible.
    let remaining = &payload[offset..];
    parse_v2_body(function, remaining)?;

    Ok(SrvlocPacket {
        header: SrvlocHeader::V2(header_v2),
        payload: SrvlocMessage::Raw(remaining),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DA Advert SLP v1 : url "svc" et scope "sc"
    fn build_v1_packet() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(1); // version
        bytes.push(8); // function : DA Advert
        // packet length : taille totale reelle du message (22 octets), la
        // validation stricte rejette toute incoherence
        bytes.extend_from_slice(&22u16.to_be_bytes());
        bytes.push(0x20); // flags
        bytes.push(0); // dialect
        bytes.extend_from_slice(b"en"); // language
        bytes.push(3); // encoding
        bytes.extend_from_slice(&0x1234u16.to_be_bytes()); // transaction id
        bytes.extend_from_slice(&0u16.to_be_bytes()); // error code
        bytes.extend_from_slice(&3u16.to_be_bytes()); // url length
        bytes.extend_from_slice(b"svc");
        bytes.extend_from_slice(&2u16.to_be_bytes()); // scope list length
        bytes.extend_from_slice(b"sc");
        bytes
    }

    /// Header SLP v1 synthetique : header commun (fonction parametrable)
    /// suivi d'un body brut, longueur declaree coherente.
    fn build_v1_packet_fn(function: u8, body: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(1); // version
        bytes.push(function);
        bytes.extend_from_slice(&((11 + body.len()) as u16).to_be_bytes());
        bytes.push(0x00); // flags
        bytes.push(0); // dialect
        bytes.extend_from_slice(b"en"); // language
        bytes.push(3); // encoding
        bytes.extend_from_slice(&0x1234u16.to_be_bytes()); // transaction id
        bytes.extend_from_slice(body);
        bytes
    }

    /// Header SLP v2 : lang tag "en" + body brut
    fn build_v2_packet_fn(function: u8, body: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(2); // version
        bytes.push(function);
        let total = (16 + body.len()) as u32;
        bytes.extend_from_slice(&total.to_be_bytes()[1..]); // packet length u24
        bytes.extend_from_slice(&0x2000u16.to_be_bytes()); // flags
        bytes.extend_from_slice(&[0, 0, 0]); // next extension offset u24
        bytes.extend_from_slice(&0x4242u16.to_be_bytes()); // xid
        bytes.extend_from_slice(&2u16.to_be_bytes()); // lang tag len
        bytes.extend_from_slice(b"en");
        bytes.extend_from_slice(body);
        bytes
    }

    /// Header SLP v2 DAAdvert (fonction 8), comme avant le dispatch du body.
    fn build_v2_packet(body: &[u8]) -> Vec<u8> {
        build_v2_packet_fn(8, body)
    }

    /// Chaine prefixee par sa longueur u16 (helper de body synthetique).
    fn push_str(bytes: &mut Vec<u8>, s: &str) {
        bytes.extend_from_slice(&(s.len() as u16).to_be_bytes());
        bytes.extend_from_slice(s.as_bytes());
    }

    /// Body SrvRqst v2 synthetique : les cinq chaines RFC 2608 section 8.1.
    fn build_v2_srv_rqst_body() -> Vec<u8> {
        let mut body = Vec::new();
        push_str(&mut body, ""); // PRList
        push_str(&mut body, "service:printer"); // service type
        push_str(&mut body, "DEFAULT"); // scope list
        push_str(&mut body, ""); // predicate
        push_str(&mut body, ""); // SLP SPI
        body
    }

    /// Body SrvRply v2 synthetique : deux URL entries, la seconde portant un
    /// authentication block minimal de 10 octets.
    fn build_v2_srv_rply_body() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0u16.to_be_bytes()); // error code
        body.extend_from_slice(&2u16.to_be_bytes()); // url entry count

        // entry 1 : sans auth block
        body.push(0); // reserved
        body.extend_from_slice(&100u16.to_be_bytes()); // lifetime
        push_str(&mut body, "service:printer://a");
        body.push(0); // num auths

        // entry 2 : un auth block minimal
        body.push(0); // reserved
        body.extend_from_slice(&5u16.to_be_bytes()); // lifetime
        push_str(&mut body, "service:printer://b");
        body.push(1); // num auths
        body.extend_from_slice(&2u16.to_be_bytes()); // BSD
        body.extend_from_slice(&10u16.to_be_bytes()); // longueur du bloc
        body.extend_from_slice(&0u32.to_be_bytes()); // timestamp
        body.extend_from_slice(&0u16.to_be_bytes()); // longueur SPI
        body
    }

    #[test]
    fn test_parse_v1_packet() {
        let bytes = build_v1_packet();
        let packet = SrvlocPacket::try_from(bytes.as_slice()).expect("paquet v1 valide");

        match &packet.header {
            SrvlocHeader::V1(header) => {
                assert_eq!(header.version, 1);
                assert_eq!(header.function, 8);
                assert_eq!(header.packet_length, 22);
                assert_eq!(header.flags, 0x20);
                assert_eq!(header.dialect, 0);
                assert_eq!(header.language, "en");
                assert_eq!(header.encoding, 3);
                assert_eq!(header.transaction_id, 0x1234);
                assert_eq!(header.error_code, 0);
                assert_eq!(header.url_length, 3);
                assert_eq!(header.url, "svc");
                assert_eq!(header.scope_list_length, 2);
                assert_eq!(header.scope_list, "sc");
            }
            other => panic!("attendu header V1, obtenu {other:?}"),
        }

        let SrvlocMessage::Raw(rest) = &packet.payload;
        assert!(rest.is_empty());
    }

    #[test]
    fn test_parse_v1_zero_copy_borrows_from_packet() {
        let bytes = build_v1_packet();
        let packet = SrvlocPacket::try_from(bytes.as_slice()).expect("paquet v1 valide");

        let SrvlocHeader::V1(header) = &packet.header else {
            panic!("attendu header V1");
        };

        // zero-copy : les &str pointent dans le buffer d'origine
        assert_eq!(header.url.as_ptr(), bytes[15..].as_ptr());
        assert_eq!(header.language.as_ptr(), bytes[6..].as_ptr());
    }

    #[test]
    fn test_parse_v1_packet_with_trailing_bytes() {
        // Les octets au-dela des champs parses doivent etre inclus dans la
        // longueur declaree (message = datagramme UDP complet).
        let mut bytes = build_v1_packet();
        bytes.extend_from_slice(&[0xCA, 0xFE]);
        let declared = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&declared.to_be_bytes());

        let packet = SrvlocPacket::try_from(bytes.as_slice()).expect("paquet v1 valide");
        let SrvlocMessage::Raw(rest) = &packet.payload;
        assert_eq!(*rest, [0xCA, 0xFE]);
    }

    #[test]
    fn test_v1_undeclared_trailing_bytes_rejected() {
        let mut bytes = build_v1_packet();
        bytes.extend_from_slice(&[0xCA, 0xFE]);

        assert!(matches!(
            SrvlocPacket::try_from(bytes.as_slice()),
            Err(SrvlocPacketParseError::InconsistentPacketLength {
                declared: 22,
                actual: 24
            })
        ));
    }

    #[test]
    fn test_v1_invalid_function_rejected() {
        let mut bytes = build_v1_packet();
        bytes[1] = 11; // > SrvTypeRply (10), inexistant en SLPv1

        assert!(matches!(
            SrvlocPacket::try_from(bytes.as_slice()),
            Err(SrvlocPacketParseError::UnsupportedFunction {
                version: 1,
                function: 11
            })
        ));
    }

    /// Regression issue #3 : un DHCP Discover reel (op=1 lu comme "version 1")
    /// ne doit plus etre classifie SRVLOC. Sa pseudo-longueur declaree
    /// (htype/hops = 0x0600 = 1536) ne correspond pas aux 272 octets reels.
    #[test]
    fn test_dhcp_discover_is_rejected() {
        let dhcp =
            crate::parse::application::protocols::dhcp::tests_fixtures::DHCP_DISCOVER_PAYLOAD;

        assert!(matches!(
            SrvlocPacket::try_from(&dhcp[..]),
            Err(SrvlocPacketParseError::InconsistentPacketLength {
                declared: 1536,
                actual: 272
            })
        ));
    }

    #[test]
    fn test_parse_v2_packet() {
        let bytes = build_v2_packet(&[]);
        let packet = SrvlocPacket::try_from(bytes.as_slice()).expect("paquet v2 valide");

        match &packet.header {
            SrvlocHeader::V2(header) => {
                assert_eq!(header.version, 2);
                assert_eq!(header.function, 8);
                assert_eq!(header.packet_length, 16);
                assert_eq!(header.flags, 0x2000);
                assert_eq!(header.next_extension_offset, 0);
                assert_eq!(header.xid, 0x4242);
                assert_eq!(header.lang_tag_len, 2);
                assert_eq!(header.lang_tag, "en");
            }
            other => panic!("attendu header V2, obtenu {other:?}"),
        }
    }

    #[test]
    fn test_parse_v2_packet_with_body() {
        let bytes = build_v2_packet(&[0x01, 0x02, 0x03]);
        let packet = SrvlocPacket::try_from(bytes.as_slice()).expect("paquet v2 valide");
        let SrvlocMessage::Raw(rest) = &packet.payload;
        assert_eq!(*rest, [0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_empty_packet() {
        assert!(SrvlocPacket::try_from(&[][..]).is_err());
    }

    #[test]
    fn test_unsupported_version() {
        assert!(matches!(
            SrvlocPacket::try_from(&[3u8, 0, 0, 0][..]),
            Err(SrvlocPacketParseError::UnsupportedVersion(3))
        ));
    }

    #[test]
    fn test_v1_truncated_header() {
        // version 1 mais seulement 4 octets
        assert!(matches!(
            SrvlocPacket::try_from(&[1u8, 8, 0, 24][..]),
            Err(SrvlocPacketParseError::Truncated { .. })
        ));
    }

    #[test]
    fn test_v1_truncated_url() {
        // url_length annonce 100 octets absents
        let mut bytes = build_v1_packet();
        let url_len_offset = 13;
        bytes[url_len_offset] = 0;
        bytes[url_len_offset + 1] = 100;
        assert!(matches!(
            SrvlocPacket::try_from(bytes.as_slice()),
            Err(SrvlocPacketParseError::Truncated { .. })
        ));
    }

    #[test]
    fn test_v1_truncated_scope_list() {
        // scope_list_length annonce 200 octets absents
        let mut bytes = build_v1_packet();
        let scope_len_offset = 18; // apres url "svc"
        bytes[scope_len_offset] = 0;
        bytes[scope_len_offset + 1] = 200;
        assert!(matches!(
            SrvlocPacket::try_from(bytes.as_slice()),
            Err(SrvlocPacketParseError::Truncated { .. })
        ));
    }

    #[test]
    fn test_v1_invalid_utf8_url() {
        let mut bytes = build_v1_packet();
        bytes[15] = 0xFF; // premier octet de l'url
        assert!(matches!(
            SrvlocPacket::try_from(bytes.as_slice()),
            Err(SrvlocPacketParseError::InvalidUtf8("url"))
        ));
    }

    #[test]
    fn test_v1_invalid_utf8_language() {
        let mut bytes = build_v1_packet();
        bytes[6] = 0xC0; // octet UTF-8 invalide dans language
        assert!(matches!(
            SrvlocPacket::try_from(bytes.as_slice()),
            Err(SrvlocPacketParseError::InvalidUtf8("language"))
        ));
    }

    #[test]
    fn test_v2_truncated_header() {
        assert!(matches!(
            SrvlocPacket::try_from(&[2u8, 8, 0, 0, 20][..]),
            Err(SrvlocPacketParseError::Truncated { .. })
        ));
    }

    #[test]
    fn test_v2_lang_tag_len_beyond_buffer() {
        // lang_tag_len annonce 500 octets absents
        let mut bytes = build_v2_packet(&[]);
        bytes[12] = 0x01;
        bytes[13] = 0xF4;
        assert!(matches!(
            SrvlocPacket::try_from(bytes.as_slice()),
            Err(SrvlocPacketParseError::Truncated { .. })
        ));
    }

    #[test]
    fn test_v2_invalid_utf8_lang_tag() {
        let mut bytes = build_v2_packet(&[]);
        bytes[14] = 0xFF; // premier octet du lang tag
        assert!(matches!(
            SrvlocPacket::try_from(bytes.as_slice()),
            Err(SrvlocPacketParseError::InvalidUtf8("lang_tag"))
        ));
    }

    /// Issue #50 : un SrvReq v1 (fonction 1) ne se voit plus appliquer le
    /// layout body DA Advert. Ce body de 2 octets faisait echouer l'ancien
    /// parseur (lecture d'une longueur d'URL au-dela des bornes) ; il doit
    /// desormais rester brut. Paquet synthetique.
    #[test]
    fn test_v1_srv_req_no_longer_gets_da_advert_layout() {
        let bytes = build_v1_packet_fn(1, &[0x00, 0x50]);
        let packet = SrvlocPacket::try_from(bytes.as_slice()).expect("SrvReq v1 valide");

        let SrvlocHeader::V1(header) = &packet.header else {
            panic!("attendu header V1");
        };
        assert_eq!(header.function, 1);
        assert_eq!(header.encoding, 3);
        assert_eq!(header.transaction_id, 0x1234);
        // Champs specifiques DA Advert : valeurs neutres hors fonction 8.
        assert_eq!(header.error_code, 0);
        assert_eq!(header.url, "");
        assert_eq!(header.scope_list, "");

        let SrvlocMessage::Raw(rest) = &packet.payload;
        assert_eq!(*rest, [0x00, 0x50]);
    }

    /// Issue #50 : chaque code fonction v1 hors DAAdvert est accepte avec un
    /// body brut ; le DAAdvert (8) exige toujours son layout complet.
    /// Paquets synthetiques.
    #[test]
    fn test_v1_dispatch_every_function_code() {
        let body = [0xAB, 0xCD, 0xEF];
        for function in 1..=SRVLOC_V1_MAX_FUNCTION {
            let bytes = build_v1_packet_fn(function, &body);
            let result = SrvlocPacket::try_from(bytes.as_slice());

            if function == SRVLOC_FUNCTION_DA_ADVERT {
                // 3 octets ne suffisent pas au body DA Advert.
                assert!(
                    matches!(result, Err(SrvlocPacketParseError::Truncated { .. })),
                    "fonction {function} : le layout DA Advert doit rester exige"
                );
                continue;
            }

            let packet = result.unwrap_or_else(|e| panic!("fonction {function} rejetee : {e}"));
            let SrvlocHeader::V1(header) = &packet.header else {
                panic!("fonction {function} : attendu header V1");
            };
            assert_eq!(header.function, function);
            let SrvlocMessage::Raw(rest) = &packet.payload;
            assert_eq!(*rest, body, "fonction {function} : body brut attendu");
        }
    }

    /// Le DAAdvert v1 conserve son layout : le meme paquet minimal accepte
    /// pour les autres fonctions est refuse en fonction 8. Paquet synthetique.
    #[test]
    fn test_v1_da_advert_still_requires_full_body() {
        let bytes = build_v1_packet_fn(8, &[]);
        assert!(matches!(
            SrvlocPacket::try_from(bytes.as_slice()),
            Err(SrvlocPacketParseError::Truncated { .. })
        ));
    }

    /// body() sur un paquet v1 : le body typed passe par le header V1 pour le
    /// DAAdvert, la methode retourne donc toujours Raw en v1.
    #[test]
    fn test_v1_body_is_raw() {
        let bytes = build_v1_packet_fn(1, &[0x01]);
        let packet = SrvlocPacket::try_from(bytes.as_slice()).expect("paquet v1 valide");
        assert!(matches!(
            packet.body().expect("body v1"),
            SrvlocBody::Raw([0x01])
        ));
    }

    /// Issue #53 : SrvRqst v2 decode (RFC 2608 section 8.1).
    /// Paquet synthetique.
    #[test]
    fn test_parse_v2_srv_rqst_body() {
        let body = build_v2_srv_rqst_body();
        let bytes = build_v2_packet_fn(1, &body);
        let packet = SrvlocPacket::try_from(bytes.as_slice()).expect("SrvRqst v2 valide");

        let SrvlocBody::SrvRqstV2(rqst) = packet.body().expect("body SrvRqst") else {
            panic!("attendu SrvRqstV2");
        };
        assert_eq!(rqst.pr_list, "");
        assert_eq!(rqst.service_type, "service:printer");
        assert_eq!(rqst.scope_list, "DEFAULT");
        assert_eq!(rqst.predicate, "");
        assert_eq!(rqst.slp_spi, "");
    }

    /// Zero-copy : les chaines du body SrvRqst v2 pointent dans le buffer
    /// d'origine. Paquet synthetique.
    #[test]
    fn test_v2_srv_rqst_body_is_zero_copy() {
        let body = build_v2_srv_rqst_body();
        let bytes = build_v2_packet_fn(1, &body);
        let packet = SrvlocPacket::try_from(bytes.as_slice()).expect("SrvRqst v2 valide");

        let SrvlocBody::SrvRqstV2(rqst) = packet.body().expect("body SrvRqst") else {
            panic!("attendu SrvRqstV2");
        };
        // service type : header v2 (16) + PRList vide (2) + prefixe (2).
        assert_eq!(rqst.service_type.as_ptr(), bytes[20..].as_ptr());
    }

    /// Issue #53 : SrvRply v2 decode (RFC 2608 section 8.2), auth block
    /// borne et conserve brut. Paquet synthetique.
    #[test]
    fn test_parse_v2_srv_rply_body() {
        let body = build_v2_srv_rply_body();
        let bytes = build_v2_packet_fn(2, &body);
        let packet = SrvlocPacket::try_from(bytes.as_slice()).expect("SrvRply v2 valide");

        let SrvlocBody::SrvRplyV2(rply) = packet.body().expect("body SrvRply") else {
            panic!("attendu SrvRplyV2");
        };
        assert_eq!(rply.error_code, 0);
        assert_eq!(rply.url_entry_count, 2);
        assert_eq!(rply.url_entries.len(), 2);

        let first = &rply.url_entries[0];
        assert_eq!(first.reserved, 0);
        assert_eq!(first.lifetime, 100);
        assert_eq!(first.url_length, 19);
        assert_eq!(first.url, "service:printer://a");
        assert_eq!(first.num_auths, 0);
        assert!(first.auth_blocks.is_empty());

        let second = &rply.url_entries[1];
        assert_eq!(second.lifetime, 5);
        assert_eq!(second.url, "service:printer://b");
        assert_eq!(second.num_auths, 1);
        assert_eq!(second.auth_blocks.len(), 10);
    }

    /// Les fonctions v2 non implementees restent en Raw. Paquet synthetique.
    #[test]
    fn test_v2_other_functions_stay_raw() {
        let bytes = build_v2_packet_fn(8, &[0x01, 0x02]);
        let packet = SrvlocPacket::try_from(bytes.as_slice()).expect("DAAdvert v2 valide");
        assert!(matches!(
            packet.body().expect("body v2"),
            SrvlocBody::Raw([0x01, 0x02])
        ));
    }

    /// SrvRqst v2 tronque : une chaine annoncee plus longue que le reste du
    /// paquet est refusee des TryFrom. Paquet synthetique.
    #[test]
    fn test_v2_srv_rqst_truncated_string_rejected() {
        let mut body = Vec::new();
        push_str(&mut body, ""); // PRList
        body.extend_from_slice(&500u16.to_be_bytes()); // service type : 500 octets absents
        let bytes = build_v2_packet_fn(1, &body);
        assert!(matches!(
            SrvlocPacket::try_from(bytes.as_slice()),
            Err(SrvlocPacketParseError::Truncated { .. })
        ));
    }

    /// SrvRply v2 : une longueur d'URL au-dela des bornes est refusee des
    /// TryFrom. Paquet synthetique.
    #[test]
    fn test_v2_srv_rply_url_length_beyond_buffer_rejected() {
        let mut body = Vec::new();
        body.extend_from_slice(&0u16.to_be_bytes()); // error code
        body.extend_from_slice(&1u16.to_be_bytes()); // url entry count
        body.push(0); // reserved
        body.extend_from_slice(&100u16.to_be_bytes()); // lifetime
        body.extend_from_slice(&1000u16.to_be_bytes()); // url length hors bornes
        body.push(b'a');
        let bytes = build_v2_packet_fn(2, &body);
        assert!(matches!(
            SrvlocPacket::try_from(bytes.as_slice()),
            Err(SrvlocPacketParseError::Truncated { .. })
        ));
    }

    /// SrvRply v2 : un compteur d'entries hostile (0xFFFF sans octets) est
    /// refuse proprement, sans pre-allocation demesuree. Paquet synthetique.
    #[test]
    fn test_v2_srv_rply_hostile_entry_count_rejected() {
        let mut body = Vec::new();
        body.extend_from_slice(&0u16.to_be_bytes()); // error code
        body.extend_from_slice(&0xFFFFu16.to_be_bytes()); // url entry count
        let bytes = build_v2_packet_fn(2, &body);
        assert!(matches!(
            SrvlocPacket::try_from(bytes.as_slice()),
            Err(SrvlocPacketParseError::Truncated { .. })
        ));
    }

    /// SrvRply v2 : un auth block annoncant une longueur sous le minimum du
    /// format est refuse. Paquet synthetique.
    #[test]
    fn test_v2_srv_rply_undersized_auth_block_rejected() {
        let mut body = Vec::new();
        body.extend_from_slice(&0u16.to_be_bytes()); // error code
        body.extend_from_slice(&1u16.to_be_bytes()); // url entry count
        body.push(0); // reserved
        body.extend_from_slice(&5u16.to_be_bytes()); // lifetime
        push_str(&mut body, "svc");
        body.push(1); // num auths
        body.extend_from_slice(&2u16.to_be_bytes()); // BSD
        body.extend_from_slice(&2u16.to_be_bytes()); // longueur < minimum (10)
        let bytes = build_v2_packet_fn(2, &body);
        assert!(matches!(
            SrvlocPacket::try_from(bytes.as_slice()),
            Err(SrvlocPacketParseError::InconsistentPacketLength {
                declared: 2,
                actual: 10
            })
        ));
    }

    /// SrvRply v2 : une URL en UTF-8 invalide est refusee. Paquet synthetique.
    #[test]
    fn test_v2_srv_rply_invalid_utf8_url_rejected() {
        let mut body = Vec::new();
        body.extend_from_slice(&0u16.to_be_bytes()); // error code
        body.extend_from_slice(&1u16.to_be_bytes()); // url entry count
        body.push(0); // reserved
        body.extend_from_slice(&5u16.to_be_bytes()); // lifetime
        body.extend_from_slice(&1u16.to_be_bytes()); // url length
        body.push(0xFF); // url invalide
        body.push(0); // num auths
        let bytes = build_v2_packet_fn(2, &body);
        assert!(matches!(
            SrvlocPacket::try_from(bytes.as_slice()),
            Err(SrvlocPacketParseError::InvalidUtf8("url"))
        ));
    }
}
