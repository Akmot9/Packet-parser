// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Verifications du decodeur LDAP.
//!
//! L'enveloppe et les operations viennent de la RFC 4511 (§4.1.1, annexe B,
//! et §5.1 : BER, longueurs definies seulement). Le tampon de la couche de
//! securite SASL vient de la RFC 4422 §3.7 (quatre octets de longueur) et
//! sa borne de la RFC 4752 §3.1 (une taille sur trois octets). Les jetons
//! qu'il porte : le Wrap de Kerberos V5 de la RFC 4121 §4.2.6.2, celui de la
//! RFC 1964 §1.2.2 (avec RC4, RFC 4757 §7.3) dans l'enveloppe de la RFC 2743
//! §3.1, et la signature NTLMSSP de [MS-NLMP] §2.2.2.9.
//!
//! Un segment TCP peut couper un message : `extract_element` rend alors le
//! contenu present, et `BerElement::is_truncated` le dit.

use crate::errors::application::ldap::LdapError;
use crate::parse::application::protocols::ldap::{
    LdapAuthentication, LdapBindRequest, LdapOperation, LdapResult, LdapSaslToken,
    LdapSearchRequest,
};

pub const BER_INTEGER: u8 = 0x02;
pub const BER_OCTET_STRING: u8 = 0x04;
pub const BER_ENUMERATED: u8 = 0x0a;
pub const BER_SEQUENCE: u8 = 0x30;

/// `controls [0] Controls OPTIONAL` de l'enveloppe.
pub const LDAP_CONTROLS_TAG: u8 = 0xa0;
/// `simple [0] OCTET STRING` de `AuthenticationChoice`.
pub const LDAP_AUTH_SIMPLE_TAG: u8 = 0x80;
/// `sasl [3] SaslCredentials` de `AuthenticationChoice`.
pub const LDAP_AUTH_SASL_TAG: u8 = 0xa3;

/// Plus grande longueur d'un element BER : 2^31 - 1. La RFC 4511 §5.1 n'en
/// fixe aucune ; celle-ci est du decodeur, pour que l'en-tete et le contenu
/// tiennent ensemble dans un `usize` de 32 bits (#382).
pub const BER_MAX_LENGTH: usize = 0x7fff_ffff;
/// Plus grande longueur d'un tampon SASL : 2^24 - 1, la plus grande taille
/// que la negociation de la RFC 4752 §3.1 sait annoncer.
pub const SASL_MAX_LENGTH: usize = 0x00ff_ffff;
/// Octets de longueur d'un tampon SASL.
pub const SASL_LENGTH_FIELD: usize = 4;
/// Plus court en-tete de jeton lu : seize octets, pour le Wrap de la RFC
/// 4121 comme pour la signature NTLMSSP.
const SASL_MIN_LENGTH: usize = 16;

/// En-tete d'un jeton Wrap de la RFC 4121 : TOK_ID, drapeaux, bourrage, EC,
/// RRC, SND_SEQ.
const GSS_WRAP_HEADER_LENGTH: usize = 16;
/// Ses octets fixes, par position : `TOK_ID` (`05 04`) et le bourrage
/// (`FF`) qui suit les drapeaux.
const GSS_WRAP_FIXED_OCTETS: [(usize, u8); 3] = [(0, 0x05), (1, 0x04), (3, 0xff)];
/// Drapeau `Sealed` : les donnees sont chiffrees.
pub const GSS_WRAP_FLAG_SEALED: u8 = 0x02;

/// Etiquette de l'enveloppe d'un jeton GSS-API (RFC 2743 §3.1) :
/// `[APPLICATION 0]`, construite.
const GSS_FRAMING_TAG: u8 = 0x60;
/// Dans l'enveloppe : l'OID de Kerberos V5 (1.2.840.113554.1.2.2) en DER,
/// puis le `TOK_ID` d'un jeton Wrap de la RFC 1964 (`02 01`).
const GSS_V1_WRAP_PREFIX: [u8; 13] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x02, 0x01,
];
/// Apres le prefixe : SGN_ALG et SEAL_ALG (deux octets chacun), un bourrage
/// `FF FF`, puis SND_SEQ et SGN_CKSUM (huit octets chacun).
const GSS_V1_WRAP_HEADER_LENGTH: usize = GSS_V1_WRAP_PREFIX.len() + 6 + 16;
/// `SEAL_ALG` d'un jeton signe sans etre chiffre.
pub const GSS_V1_SEAL_NONE: u16 = 0xffff;
/// Le confondeur, huit octets aleatoires devant les donnees.
const GSS_V1_CONFOUNDER_LENGTH: usize = 8;
/// Les donnees sont completees par un a huit octets de bourrage, chacun de
/// la valeur de leur nombre (RFC 1964 §1.2.2.3).
const GSS_V1_MAX_PADDING: usize = 8;

/// `NTLMSSP_MESSAGE_SIGNATURE` : version (quatre octets petit-boutistes, 1),
/// huit octets de checksum, numero de sequence.
const NTLM_SIGNATURE_LENGTH: usize = 16;
const NTLM_SIGNATURE_FIXED_OCTETS: [(usize, u8); 4] = [(0, 1), (1, 0), (2, 0), (3, 0)];

/// Octets de longueur lus en forme longue.
const MAX_LENGTH_OCTETS: usize = 4;

/// Un element BER : son etiquette, sa longueur annoncee, et ce que l'entree
/// en porte.
#[derive(Debug, Clone, Copy)]
pub struct BerElement<'a> {
    pub tag: u8,
    /// Longueur annoncee du contenu.
    pub length: usize,
    /// Le contenu, coupe a la fin de l'entree s'il la depasse.
    pub contents: &'a [u8],
    /// Ce qui suit l'element ; vide quand le contenu est coupe.
    pub rest: &'a [u8],
    /// Octets de l'etiquette et de la longueur.
    pub header_length: usize,
}

impl BerElement<'_> {
    pub fn is_truncated(&self) -> bool {
        self.length > self.contents.len()
    }

    /// Octets annonces par l'element, en-tete compris.
    pub fn total_length(&self) -> usize {
        self.header_length + self.length
    }
}

pub fn validate_tag(field: &'static str, actual: u8, expected: u8) -> Result<(), LdapError> {
    if actual != expected {
        return Err(LdapError::UnexpectedTag {
            field,
            expected,
            actual,
        });
    }
    Ok(())
}

/// Lit l'etiquette et la longueur d'un element, en forme courte ou longue.
pub fn extract_element<'a>(
    field: &'static str,
    bytes: &'a [u8],
) -> Result<BerElement<'a>, LdapError> {
    let [tag, first, after @ ..] = bytes else {
        return Err(LdapError::TooShort {
            field,
            expected: 2,
            actual: bytes.len(),
        });
    };
    let (length, header_length) = if *first < 0x80 {
        (usize::from(*first), 2)
    } else {
        let count = usize::from(*first & 0x7f);
        // 0x80 : forme indefinie, que la RFC 4511 §5.1 interdit.
        if count == 0 || count > MAX_LENGTH_OCTETS {
            return Err(LdapError::InvalidLength { field });
        }
        let Some(octets) = after.get(..count) else {
            return Err(LdapError::TooShort {
                field,
                expected: 2 + count,
                actual: bytes.len(),
            });
        };
        let length = octets
            .iter()
            .fold(0usize, |length, octet| (length << 8) | usize::from(*octet));
        (length, 2 + count)
    };
    if length > BER_MAX_LENGTH {
        return Err(LdapError::InvalidLength { field });
    }
    let after_header = &bytes[header_length..];
    let (contents, rest) = after_header.split_at(length.min(after_header.len()));
    Ok(BerElement {
        tag: *tag,
        length,
        contents,
        rest,
        header_length,
    })
}

/// L'enveloppe d'un message : une SEQUENCE. L'etiquette est jugee avant la
/// longueur, pour qu'une entree qui n'est pas du BER sorte sur son premier
/// octet.
pub fn extract_envelope(bytes: &[u8]) -> Result<BerElement<'_>, LdapError> {
    if let Some(tag) = bytes.first() {
        validate_tag("message", *tag, BER_SEQUENCE)?;
    }
    extract_element("message", bytes)
}

/// Lit un element d'un conteneur. Quand le conteneur est entier, un element
/// qui en deborde est une erreur de longueur, pas une entree trop courte.
pub fn extract_inner<'a>(
    field: &'static str,
    container: &'a [u8],
    container_is_truncated: bool,
) -> Result<BerElement<'a>, LdapError> {
    let element = match extract_element(field, container) {
        Err(LdapError::TooShort {
            expected, actual, ..
        }) if !container_is_truncated => {
            return Err(LdapError::LengthOverflow {
                field,
                length: expected,
                available: actual,
            });
        }
        element => element?,
    };
    if element.is_truncated() && !container_is_truncated {
        return Err(LdapError::LengthOverflow {
            field,
            length: element.total_length(),
            available: container.len(),
        });
    }
    Ok(element)
}

/// `MessageID ::= INTEGER (0 .. maxInt)`, maxInt = 2^31 - 1 (RFC 4511
/// §4.1.1.1) : un a quatre octets, le bit de signe nul.
pub fn extract_message_id(element: &BerElement<'_>) -> Result<u32, LdapError> {
    validate_tag("message identifier", element.tag, BER_INTEGER)?;
    if element.is_truncated() {
        return Err(LdapError::TooShort {
            field: "message identifier",
            expected: element.total_length(),
            actual: element.header_length + element.contents.len(),
        });
    }
    extract_unsigned(element.contents).ok_or(LdapError::InvalidMessageId)
}

/// Un INTEGER ou un ENUMERATED positif d'un a quatre octets.
pub fn extract_unsigned(contents: &[u8]) -> Option<u32> {
    let (first, _) = contents.split_first()?;
    if contents.len() > 4 || *first >= 0x80 {
        return None;
    }
    Some(
        contents
            .iter()
            .fold(0u32, |value, octet| (value << 8) | u32::from(*octet)),
    )
}

/// L'operation qu'annonce l'etiquette (RFC 4511 §4.1.1 et annexe B), classe
/// et forme comprises : un UnbindRequest, un DelRequest et un
/// AbandonRequest sont primitifs, les autres construits.
pub fn validate_operation(tag: u8, length: usize) -> Result<LdapOperation, LdapError> {
    let operation = match tag {
        0x60 => LdapOperation::BindRequest,
        0x61 => LdapOperation::BindResponse,
        0x42 => LdapOperation::UnbindRequest,
        0x63 => LdapOperation::SearchRequest,
        0x64 => LdapOperation::SearchResultEntry,
        0x65 => LdapOperation::SearchResultDone,
        0x66 => LdapOperation::ModifyRequest,
        0x67 => LdapOperation::ModifyResponse,
        0x68 => LdapOperation::AddRequest,
        0x69 => LdapOperation::AddResponse,
        0x4a => LdapOperation::DelRequest,
        0x6b => LdapOperation::DelResponse,
        0x6c => LdapOperation::ModifyDnRequest,
        0x6d => LdapOperation::ModifyDnResponse,
        0x6e => LdapOperation::CompareRequest,
        0x6f => LdapOperation::CompareResponse,
        0x50 => LdapOperation::AbandonRequest,
        0x73 => LdapOperation::SearchResultReference,
        0x77 => LdapOperation::ExtendedRequest,
        0x78 => LdapOperation::ExtendedResponse,
        0x79 => LdapOperation::IntermediateResponse,
        _ => return Err(LdapError::UnknownOperation(tag)),
    };
    let valid = match operation {
        // `UnbindRequest ::= [APPLICATION 2] NULL`.
        LdapOperation::UnbindRequest => length == 0,
        // `AbandonRequest ::= [APPLICATION 16] MessageID`.
        LdapOperation::AbandonRequest => (1..=4).contains(&length),
        _ => true,
    };
    if !valid {
        return Err(LdapError::InvalidOperationLength {
            operation: operation.as_u8(),
            length,
        });
    }
    Ok(operation)
}

/// L'operation tient dans la sequence : rend les octets que la sequence
/// annonce apres elle. Ne peut echouer que dans un message coupe, ou les
/// deux longueurs annoncees ne sont pas bornees par l'entree.
pub fn validate_operation_fits(
    message_length: usize,
    identifier: &BerElement<'_>,
    operation: &BerElement<'_>,
) -> Result<usize, LdapError> {
    let available = message_length.saturating_sub(identifier.total_length());
    available
        .checked_sub(operation.total_length())
        .ok_or(LdapError::LengthOverflow {
            field: "operation",
            length: operation.total_length(),
            available,
        })
}

/// Les controles, s'ils suivent l'operation : `[0]`, et rien apres eux dans
/// la sequence. `declared` est ce que la sequence annonce apres
/// l'operation ; `visible`, ce que l'entree en porte.
pub fn extract_controls(visible: &[u8], declared: usize) -> Result<Option<&[u8]>, LdapError> {
    let Some(tag) = visible.first() else {
        // Pas de controles, ou coupes par le segment avant leur etiquette.
        return Ok(None);
    };
    validate_tag("controls", *tag, LDAP_CONTROLS_TAG)?;
    let is_cut = visible.len() < declared;
    let controls = match extract_inner("controls", visible, is_cut) {
        // L'en-tete des controles est coupe par le segment.
        Err(LdapError::TooShort { .. }) => return Ok(None),
        controls => controls?,
    };
    match declared.checked_sub(controls.total_length()) {
        Some(0) => Ok(Some(controls.contents)),
        Some(trailing) => Err(LdapError::TrailingBytes(trailing)),
        None => Err(LdapError::LengthOverflow {
            field: "controls",
            length: controls.total_length(),
            available: declared,
        }),
    }
}

/// Un tampon SASL : sa longueur, l'en-tete de son jeton, et ce que
/// l'entree porte derriere cet en-tete.
#[derive(Debug, Clone, Copy)]
pub struct SaslBuffer<'a> {
    pub length: u32,
    pub token: LdapSaslToken,
    /// Ce qui suit l'en-tete du jeton, coupe a la fin de l'entree.
    pub data: &'a [u8],
    /// Ce qui suit le tampon ; vide quand il est coupe.
    pub rest: &'a [u8],
    pub is_truncated: bool,
}

/// La longueur d'un tampon couvre au moins l'en-tete d'un jeton, et tient
/// sur trois octets.
pub fn validate_sasl_length(length: u32) -> Result<usize, LdapError> {
    usize::try_from(length)
        .ok()
        .filter(|length| (SASL_MIN_LENGTH..=SASL_MAX_LENGTH).contains(length))
        .ok_or(LdapError::InvalidSaslLength(length))
}

/// L'en-tete d'un jeton : lu, avec sa longueur, ou coupe par la fin des
/// octets, avec le nombre d'octets qu'il faudrait au moins.
enum TokenHeader {
    Read(LdapSaslToken, usize),
    Short(usize),
}

/// Les octets fixes presents sont ceux attendus : un octet faux se voit
/// avant de conclure que l'entree est trop courte.
fn has_fixed_octets(token: &[u8], fixed: &[(usize, u8)]) -> bool {
    fixed
        .iter()
        .all(|(index, expected)| token.get(*index).is_none_or(|octet| octet == expected))
}

/// Jeton Wrap de Kerberos V5, RFC 4121 §4.2.6.2.
fn extract_kerberos_wrap(token: &[u8]) -> Result<TokenHeader, LdapError> {
    if !has_fixed_octets(token, &GSS_WRAP_FIXED_OCTETS) {
        return Err(LdapError::UnsupportedSaslToken);
    }
    let Some((header, _)) = token.split_first_chunk::<GSS_WRAP_HEADER_LENGTH>() else {
        return Ok(TokenHeader::Short(GSS_WRAP_HEADER_LENGTH));
    };
    let [_, _, flags, _, e0, e1, r0, r1, sequence @ ..] = *header;
    Ok(TokenHeader::Read(
        LdapSaslToken::KerberosWrap {
            flags,
            extra_count: u16::from_be_bytes([e0, e1]),
            right_rotation_count: u16::from_be_bytes([r0, r1]),
            sequence_number: u64::from_be_bytes(sequence),
        },
        GSS_WRAP_HEADER_LENGTH,
    ))
}

/// Jeton Wrap de Kerberos V5, RFC 1964 §1.2.2, dans l'enveloppe de la RFC
/// 2743 §3.1. L'enveloppe pave le tampon.
fn extract_kerberos_v1_wrap(token: &[u8], length: usize) -> Result<TokenHeader, LdapError> {
    let framing = match extract_element("SASL token", token) {
        Ok(framing) => framing,
        Err(LdapError::TooShort { expected, .. }) => return Ok(TokenHeader::Short(expected)),
        Err(_) => return Err(LdapError::UnsupportedSaslToken),
    };
    let is_prefix = framing
        .contents
        .iter()
        .zip(GSS_V1_WRAP_PREFIX)
        .all(|(octet, expected)| *octet == expected);
    let filler = GSS_V1_WRAP_PREFIX.len() + 4;
    let fixed = [(filler, 0xff), (filler + 1, 0xff)];
    if framing.total_length() != length || !is_prefix || !has_fixed_octets(framing.contents, &fixed)
    {
        return Err(LdapError::UnsupportedSaslToken);
    }
    let header_length = framing.header_length + GSS_V1_WRAP_HEADER_LENGTH;
    let Some(header) = framing.contents.get(..GSS_V1_WRAP_HEADER_LENGTH) else {
        return Ok(TokenHeader::Short(header_length));
    };
    let algorithms = &header[GSS_V1_WRAP_PREFIX.len()..];
    Ok(TokenHeader::Read(
        LdapSaslToken::KerberosV1Wrap {
            signing_algorithm: u16::from_le_bytes([algorithms[0], algorithms[1]]),
            sealing_algorithm: u16::from_le_bytes([algorithms[2], algorithms[3]]),
        },
        header_length,
    ))
}

/// Signature NTLMSSP, [MS-NLMP] §2.2.2.9.
fn extract_ntlm_signature(token: &[u8]) -> Result<TokenHeader, LdapError> {
    if !has_fixed_octets(token, &NTLM_SIGNATURE_FIXED_OCTETS) {
        return Err(LdapError::UnsupportedSaslToken);
    }
    let Some((signature, _)) = token.split_first_chunk::<NTLM_SIGNATURE_LENGTH>() else {
        return Ok(TokenHeader::Short(NTLM_SIGNATURE_LENGTH));
    };
    let [.., s0, s1, s2, s3] = *signature;
    Ok(TokenHeader::Read(
        LdapSaslToken::NtlmSignature {
            sequence_number: u32::from_le_bytes([s0, s1, s2, s3]),
        },
        NTLM_SIGNATURE_LENGTH,
    ))
}

/// Lit la longueur du tampon et l'en-tete de son jeton, que son premier
/// octet designe.
pub fn extract_sasl_buffer(bytes: &[u8]) -> Result<SaslBuffer<'_>, LdapError> {
    let too_short = |expected: usize| LdapError::TooShort {
        field: "SASL buffer",
        expected: SASL_LENGTH_FIELD + expected,
        actual: bytes.len(),
    };
    let Some((length_octets, after)) = bytes.split_first_chunk::<SASL_LENGTH_FIELD>() else {
        return Err(too_short(1));
    };
    let length = u32::from_be_bytes(*length_octets);
    let buffer_length = validate_sasl_length(length)?;
    let (token, rest) = after.split_at(buffer_length.min(after.len()));
    let is_truncated = token.len() < buffer_length;
    let header = match token.first() {
        Some(0x05) => extract_kerberos_wrap(token)?,
        Some(&GSS_FRAMING_TAG) => extract_kerberos_v1_wrap(token, buffer_length)?,
        Some(0x01) => extract_ntlm_signature(token)?,
        Some(_) => return Err(LdapError::UnsupportedSaslToken),
        None => TokenHeader::Short(1),
    };
    match header {
        TokenHeader::Read(token_header, header_length) => Ok(SaslBuffer {
            length,
            token: token_header,
            data: &token[header_length..],
            rest,
            is_truncated,
        }),
        // L'entree s'arrete dans l'en-tete du jeton.
        TokenHeader::Short(expected) if is_truncated => Err(too_short(expected)),
        // Le tampon, entier, est plus court que l'en-tete de son jeton.
        TokenHeader::Short(_) => Err(LdapError::InvalidSaslLength(length)),
    }
}

/// Les messages en clair d'un jeton signe sans etre chiffre, quand ils sont
/// d'un seul tenant.
///
/// RFC 4121 §4.2.4 : le texte puis son checksum de `extra_count` octets, le
/// tout tourne a droite de `right_rotation_count` octets. Deux rotations
/// laissent le texte entier : nulle, le checksum est a la fin ; egale au
/// checksum, il est en tete (ce que fait Active Directory).
///
/// RFC 1964 §1.2.2.3 : un confondeur, le texte, puis un bourrage dont le
/// dernier octet donne la longueur.
///
/// NTLMSSP : la signature ne dit pas si le message est chiffre, la liaison
/// l'a negocie ; rien n'est rendu.
pub fn extract_sasl_plaintext<'a>(
    token: &LdapSaslToken,
    data: &'a [u8],
    is_truncated: bool,
) -> Option<&'a [u8]> {
    match *token {
        LdapSaslToken::KerberosWrap {
            flags,
            extra_count,
            right_rotation_count,
            ..
        } => {
            let checksum = usize::from(extra_count);
            if flags & GSS_WRAP_FLAG_SEALED != 0 {
                None
            } else if right_rotation_count == extra_count {
                data.get(checksum..)
            } else if right_rotation_count == 0 && !is_truncated {
                data.get(..data.len().checked_sub(checksum)?)
            } else {
                None
            }
        }
        LdapSaslToken::KerberosV1Wrap {
            sealing_algorithm, ..
        } => {
            if sealing_algorithm != GSS_V1_SEAL_NONE {
                return None;
            }
            let text = data.get(GSS_V1_CONFOUNDER_LENGTH..)?;
            if is_truncated {
                // Le bourrage est dans un segment suivant.
                return Some(text);
            }
            let padding = usize::from(*text.last()?);
            if !(1..=GSS_V1_MAX_PADDING).contains(&padding) {
                return None;
            }
            text.get(..text.len().checked_sub(padding)?)
        }
        LdapSaslToken::NtlmSignature { .. } => None,
    }
}

/// Un element entier, de l'etiquette attendue, en tete de `bytes`.
fn extract_complete(bytes: &[u8], tag: u8) -> Option<BerElement<'_>> {
    let element = extract_element("field", bytes).ok()?;
    (element.tag == tag && !element.is_truncated()).then_some(element)
}

/// `LDAPResult` (RFC 4511 §4.1.9) : code, DN trouve, message de diagnostic.
pub fn extract_result(body: &[u8]) -> Option<LdapResult<'_>> {
    let code = extract_complete(body, BER_ENUMERATED)?;
    let matched_dn = extract_complete(code.rest, BER_OCTET_STRING)?;
    let diagnostic_message = extract_complete(matched_dn.rest, BER_OCTET_STRING)?;
    Some(LdapResult {
        code: extract_unsigned(code.contents)?,
        matched_dn: matched_dn.contents,
        diagnostic_message: diagnostic_message.contents,
    })
}

/// `BindRequest` (RFC 4511 §4.2) : version de 1 a 127, nom, authentification.
pub fn extract_bind_request(body: &[u8]) -> Option<LdapBindRequest<'_>> {
    let version = extract_complete(body, BER_INTEGER)?;
    let [version_number @ 1..=127] = *version.contents else {
        return None;
    };
    let name = extract_complete(version.rest, BER_OCTET_STRING)?;
    let choice = extract_element("authentication", name.rest).ok()?;
    if choice.is_truncated() {
        return None;
    }
    let authentication = match choice.tag {
        LDAP_AUTH_SIMPLE_TAG => LdapAuthentication::Simple(choice.contents),
        LDAP_AUTH_SASL_TAG => {
            let mechanism = extract_complete(choice.contents, BER_OCTET_STRING)?;
            let credentials = match mechanism.rest {
                [] => None,
                rest => Some(extract_complete(rest, BER_OCTET_STRING)?.contents),
            };
            LdapAuthentication::Sasl {
                mechanism: mechanism.contents,
                credentials,
            }
        }
        tag => LdapAuthentication::Other {
            tag,
            value: choice.contents,
        },
    };
    Some(LdapBindRequest {
        version: version_number,
        name: name.contents,
        authentication,
    })
}

/// Debut d'un `SearchRequest` (RFC 4511 §4.5.1) : objet de base et portee.
pub fn extract_search_request(body: &[u8]) -> Option<LdapSearchRequest<'_>> {
    let base_object = extract_complete(body, BER_OCTET_STRING)?;
    let scope = extract_complete(base_object.rest, BER_ENUMERATED)?;
    let [scope_number] = *scope.contents else {
        return None;
    };
    Some(LdapSearchRequest {
        base_object: base_object.contents,
        scope: scope_number,
    })
}
