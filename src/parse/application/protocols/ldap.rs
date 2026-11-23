// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! LDAP (Lightweight Directory Access Protocol, RFC 4511, #372), l'acces a
//! un annuaire : sur TCP 389, sur TCP 3268 pour le catalogue global d'un
//! domaine Active Directory, et sur UDP 389 (« CLDAP », la recherche sans
//! connexion par laquelle un poste trouve son controleur de domaine).
//!
//! Un message est une SEQUENCE BER : un identifiant de message, une
//! operation (une etiquette de classe APPLICATION) et des controles
//! optionnels. Le corps de l'operation et les controles sont empruntes a
//! l'entree, sans etre decodes ; trois lectures vont plus loin, celles dont
//! un inventaire a besoin : le resultat d'une reponse
//! ([`LdapMessage::result`]), la requete de liaison
//! ([`LdapMessage::bind_request`]), la base et la portee d'une recherche
//! ([`LdapMessage::search_request`]).
//!
//! Apres une liaison SASL qui negocie une couche de securite (RFC 4422
//! §3.7), les messages voyagent dans des tampons : quatre octets de
//! longueur, puis un jeton. Ce decodeur lit les trois jetons d'un domaine
//! Active Directory ([`LdapSaslToken`]) : le Wrap de Kerberos V5 des cles
//! AES (RFC 4121), celui des cles DES et RC4 (RFC 1964) et la signature
//! NTLMSSP. Un jeton Kerberos signe laisse les messages en clair
//! ([`LdapSaslBuffer::messages`]) ; chiffre, seul son en-tete se lit. La
//! signature NTLMSSP ne dit pas si le message est chiffre : la liaison l'a
//! negocie, et rien n'en est lu.
//!
//! Un segment TCP ou un datagramme porte un ou plusieurs PDU a la suite
//! ([`LdapPdu::pdus`]).
//!
//! Detection : regles a port sur TCP 389 et 3268 et sur UDP 389. Un octet
//! `30` et une longueur ne font pas une sonde aveugle : la sonde exige des
//! PDU bien formes qui pavent le payload.
//!
//! Limites, sans etat : un PDU plus long que son segment est coupe
//! ([`LdapPdu::is_truncated`]) et les segments de suite restent `Unknown`.
//! La couche de securite de DIGEST-MD5 (RFC 2831) n'est pas lue. LDAPS (TCP
//! 636 et 3269) est du TLS.

use std::convert::TryFrom;

use crate::checks::application::ldap::{
    GSS_V1_SEAL_NONE, GSS_WRAP_FLAG_SEALED, extract_bind_request, extract_controls,
    extract_envelope, extract_inner, extract_message_id, extract_result, extract_sasl_buffer,
    extract_sasl_plaintext, extract_search_request, validate_operation, validate_operation_fits,
};
use crate::errors::application::ldap::LdapError;

/// One LDAP PDU, the first of the bytes it is read from: a message in the
/// clear, or a buffer of the SASL security layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LdapPdu<'a> {
    /// An `LDAPMessage` (RFC 4511 §4.1.1).
    Message(LdapMessage<'a>),
    /// A buffer of the SASL security layer (RFC 4422 §3.7).
    SaslBuffer(LdapSaslBuffer<'a>),
}

impl<'a> LdapPdu<'a> {
    /// `true` when the PDU goes on in the next TCP segment.
    pub fn is_truncated(&self) -> bool {
        match self {
            Self::Message(message) => message.is_truncated(),
            Self::SaslBuffer(buffer) => buffer.is_truncated(),
        }
    }

    /// The bytes of the payload that follow this PDU: another PDU, or
    /// nothing.
    pub fn rest(&self) -> &'a [u8] {
        match self {
            Self::Message(message) => message.rest(),
            Self::SaslBuffer(buffer) => buffer.rest(),
        }
    }

    /// The PDUs of a TCP segment or of a datagram, in order. The iterator
    /// stops after the first error, or after a PDU that its segment cuts.
    pub fn pdus(payload: &'a [u8]) -> LdapPdus<'a> {
        LdapPdus { rest: payload }
    }

    /// Sonde des regles a port : des PDU bien formes qui pavent le payload.
    /// Seul le dernier peut etre coupe par le segment. TCP coupe ou il
    /// veut : derriere un PDU entier, le suivant peut s'arreter avant la fin
    /// de son en-tete, trop tot pour etre lu. Ce reste ne retire rien au
    /// PDU qui le precede (#382) ; seul, il ne nomme rien.
    pub(crate) fn is_port_match(payload: &'a [u8]) -> bool {
        let mut has_whole_pdu = false;
        for pdu in Self::pdus(payload) {
            match pdu {
                Ok(pdu) => has_whole_pdu |= !pdu.is_truncated(),
                Err(LdapError::TooShort { .. }) => return has_whole_pdu,
                Err(_) => return false,
            }
        }
        !payload.is_empty()
    }
}

impl<'a> TryFrom<&'a [u8]> for LdapPdu<'a> {
    type Error = LdapError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        match bytes.first() {
            // La longueur d'un tampon SASL tient sur trois octets : le
            // premier des quatre est nul, ce qu'une SEQUENCE (`30`) n'est
            // jamais.
            Some(0) => LdapSaslBuffer::try_from(bytes).map(Self::SaslBuffer),
            _ => LdapMessage::try_from(bytes).map(Self::Message),
        }
    }
}

/// Protocol operation of an [`LdapMessage`], numbered by its
/// `[APPLICATION n]` tag (RFC 4511 §4.1.1 and appendix B).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LdapOperation {
    BindRequest = 0,
    BindResponse = 1,
    UnbindRequest = 2,
    SearchRequest = 3,
    SearchResultEntry = 4,
    SearchResultDone = 5,
    ModifyRequest = 6,
    ModifyResponse = 7,
    AddRequest = 8,
    AddResponse = 9,
    DelRequest = 10,
    DelResponse = 11,
    ModifyDnRequest = 12,
    ModifyDnResponse = 13,
    CompareRequest = 14,
    CompareResponse = 15,
    AbandonRequest = 16,
    SearchResultReference = 19,
    ExtendedRequest = 23,
    ExtendedResponse = 24,
    IntermediateResponse = 25,
}

impl LdapOperation {
    /// Number of the `[APPLICATION n]` tag of the operation.
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// `true` for the responses that carry an `LDAPResult`.
    fn has_result(self) -> bool {
        matches!(
            self,
            Self::BindResponse
                | Self::SearchResultDone
                | Self::ModifyResponse
                | Self::AddResponse
                | Self::DelResponse
                | Self::ModifyDnResponse
                | Self::CompareResponse
                | Self::ExtendedResponse
        )
    }
}

/// One `LDAPMessage` (RFC 4511 §4.1.1), the first of the bytes it is read
/// from.
///
/// ```mermaid
/// ---
/// title: LDAPMessage (BER, definite lengths of 1 to 5 bytes)
/// ---
/// packet-beta
/// 0-7: "SEQUENCE = 0x30"
/// 8-15: "length"
/// 16-23: "INTEGER = 0x02"
/// 24-31: "length"
/// 32-47: "message_id (1 to 4 bytes)"
/// 48-55: "operation tag"
/// 56-63: "length"
/// 64-95: "body"
/// 96-103: "[0] = 0xA0 (optional)"
/// 104-111: "length"
/// 112-127: "controls"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct LdapMessage<'a> {
    /// Identifier of the message, from 0 to 2^31 - 1: a response carries
    /// the identifier of its request, and 0 is the unsolicited notification
    /// of a server.
    pub message_id: u32,
    /// Operation that the message carries.
    pub operation: LdapOperation,
    /// Contents of the operation, up to its end or to the end of the
    /// input, whichever comes first.
    pub body: &'a [u8],
    /// Contents of the controls (a sequence of `Control`), when the message
    /// has some and its input reaches them.
    pub controls: Option<&'a [u8]>,
    wire_length: usize,
    visible_length: usize,
    rest: &'a [u8],
}

impl<'a> LdapMessage<'a> {
    /// Number of bytes that the message announces, envelope included.
    pub fn wire_length(&self) -> usize {
        self.wire_length
    }

    /// `true` when the message goes on in the next TCP segment.
    pub fn is_truncated(&self) -> bool {
        self.visible_length < self.wire_length
    }

    /// The bytes that follow this message: another message, or nothing.
    pub fn rest(&self) -> &'a [u8] {
        self.rest
    }

    /// The `LDAPResult` of a response (RFC 4511 §4.1.9). `None` for a
    /// request, a search entry or reference, and when the input stops
    /// before the end of the diagnostic message.
    pub fn result(&self) -> Option<LdapResult<'a>> {
        self.operation
            .has_result()
            .then(|| extract_result(self.body))
            .flatten()
    }

    /// The fields of a bind request (RFC 4511 §4.2). `None` for another
    /// operation, and when the body is cut or is not a `BindRequest`.
    pub fn bind_request(&self) -> Option<LdapBindRequest<'a>> {
        (self.operation == LdapOperation::BindRequest)
            .then(|| extract_bind_request(self.body))
            .flatten()
    }

    /// The base and the scope of a search request (RFC 4511 §4.5.1). `None`
    /// for another operation, and when the body is cut before the scope.
    pub fn search_request(&self) -> Option<LdapSearchRequest<'a>> {
        (self.operation == LdapOperation::SearchRequest)
            .then(|| extract_search_request(self.body))
            .flatten()
    }
}

impl<'a> TryFrom<&'a [u8]> for LdapMessage<'a> {
    type Error = LdapError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let envelope = extract_envelope(bytes)?;
        let is_cut = envelope.is_truncated();
        let identifier = extract_inner("message identifier", envelope.contents, is_cut)?;
        let message_id = extract_message_id(&identifier)?;
        let operation = extract_inner("operation", identifier.rest, is_cut)?;
        let kind = validate_operation(operation.tag, operation.length)?;
        let after_operation = validate_operation_fits(envelope.length, &identifier, &operation)?;
        let controls = extract_controls(operation.rest, after_operation)?;
        Ok(Self {
            message_id,
            operation: kind,
            body: operation.contents,
            controls,
            wire_length: envelope.total_length(),
            visible_length: envelope.header_length + envelope.contents.len(),
            rest: envelope.rest,
        })
    }
}

/// The `LDAPResult` of a response (RFC 4511 §4.1.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct LdapResult<'a> {
    /// Result code: 0 is `success`, 14 `saslBindInProgress`, 32
    /// `noSuchObject`, 49 `invalidCredentials`.
    pub code: u32,
    /// Distinguished name of the last entry that the server matched.
    pub matched_dn: &'a [u8],
    /// Text of the diagnostic, often empty.
    pub diagnostic_message: &'a [u8],
}

/// The fields of a bind request (RFC 4511 §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct LdapBindRequest<'a> {
    /// Version of the protocol, from 1 to 127: 3 for LDAPv3.
    pub version: u8,
    /// Distinguished name that binds, empty for an anonymous or a SASL
    /// bind.
    pub name: &'a [u8],
    /// How the client authenticates.
    pub authentication: LdapAuthentication<'a>,
}

/// The `AuthenticationChoice` of a bind request (RFC 4511 §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LdapAuthentication<'a> {
    /// Simple bind: the password, in the clear on the wire, empty for an
    /// anonymous bind.
    Simple(&'a [u8]),
    /// SASL bind: the name of the mechanism (`GSSAPI`, `GSS-SPNEGO`,
    /// `DIGEST-MD5`...) and its credentials, when the request has some.
    Sasl {
        mechanism: &'a [u8],
        credentials: Option<&'a [u8]>,
    },
    /// Another choice, by its tag and contents: Active Directory uses
    /// `[9]`, `[10]` and `[11]` for its NTLM bind.
    Other { tag: u8, value: &'a [u8] },
}

/// The start of a search request (RFC 4511 §4.5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct LdapSearchRequest<'a> {
    /// Distinguished name of the base of the search, empty for the root
    /// DSE.
    pub base_object: &'a [u8],
    /// Scope: 0 `baseObject`, 1 `singleLevel`, 2 `wholeSubtree`.
    pub scope: u8,
}

/// One buffer of the SASL security layer (RFC 4422 §3.7): four bytes of
/// length, then a token whose header [`LdapSaslToken`] describes.
///
/// ```mermaid
/// ---
/// title: LdapSaslBuffer with a Kerberos V5 Wrap token of RFC 4121 (big-endian)
/// ---
/// packet-beta
/// 0-31: "length u32 (token header + data)"
/// 32-47: "TOK_ID = 05 04"
/// 48-55: "flags"
/// 56-63: "filler = FF"
/// 64-79: "EC u16"
/// 80-95: "RRC u16"
/// 96-159: "SND_SEQ u64"
/// 160-191: "data (length - 16 bytes)"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct LdapSaslBuffer<'a> {
    /// Number of bytes that follow the length: the header of the token,
    /// then the data.
    pub length: u32,
    /// Header of the token.
    pub token: LdapSaslToken,
    /// What follows the header of the token, up to the end of the buffer
    /// or of the input, whichever comes first.
    pub data: &'a [u8],
    is_truncated: bool,
    rest: &'a [u8],
}

impl<'a> LdapSaslBuffer<'a> {
    /// `true` when the buffer goes on in the next TCP segment.
    pub fn is_truncated(&self) -> bool {
        self.is_truncated
    }

    /// The bytes that follow this buffer: another buffer, or nothing.
    pub fn rest(&self) -> &'a [u8] {
        self.rest
    }

    /// The messages of a token that is signed without being sealed, without
    /// their checksum or padding. `None` when the token is sealed, when it
    /// is an NTLMSSP signature, and when the rotation of a Wrap token of
    /// RFC 4121 splits the messages: the decoder reads a rotation of zero,
    /// the checksum at the end, and a rotation of the length of the
    /// checksum, the checksum first, as Active Directory does.
    pub fn plaintext(&self) -> Option<&'a [u8]> {
        extract_sasl_plaintext(&self.token, self.data, self.is_truncated)
    }

    /// The messages of a signed token, in order: nothing when
    /// [`Self::plaintext`] is `None`. The iterator stops after the first
    /// error, or after a message that the segment cuts.
    pub fn messages(&self) -> LdapMessages<'a> {
        LdapMessages {
            rest: self.plaintext().unwrap_or_default(),
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for LdapSaslBuffer<'a> {
    type Error = LdapError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let buffer = extract_sasl_buffer(bytes)?;
        Ok(Self {
            length: buffer.length,
            token: buffer.token,
            data: buffer.data,
            is_truncated: buffer.is_truncated,
            rest: buffer.rest,
        })
    }
}

/// Header of the token of an [`LdapSaslBuffer`]: what signs, and may seal,
/// the messages of the buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LdapSaslToken {
    /// Kerberos V5 Wrap token of RFC 4121 §4.2.6.2, the one of AES keys:
    /// `05 04`, flags, `FF`, then the three fields below.
    #[non_exhaustive]
    KerberosWrap {
        /// Bit 0: sent by the server. Bit 1: sealed. Bit 2: the key is the
        /// subkey of the server.
        flags: u8,
        /// `EC`: the length of the checksum of a signed token, or the count
        /// of filler bytes of a sealed one.
        extra_count: u16,
        /// `RRC`: by how many bytes the data are rotated to the right.
        right_rotation_count: u16,
        /// `SND_SEQ`: sequence number of the token.
        sequence_number: u64,
    },
    /// Kerberos V5 Wrap token of RFC 1964 §1.2.2, the one of DES and RC4
    /// keys (RFC 4757 §7.3), inside the framing of RFC 2743 §3.1: `60`, a
    /// length, the object identifier of Kerberos V5, `02 01`.
    #[non_exhaustive]
    KerberosV1Wrap {
        /// `SGN_ALG`, read little-endian: 0x0000 DES MAC MD5, 0x0011 HMAC.
        signing_algorithm: u16,
        /// `SEAL_ALG`, read little-endian: 0xFFFF when the token is not
        /// sealed, 0x0000 DES, 0x0010 RC4.
        sealing_algorithm: u16,
    },
    /// NTLMSSP message signature (\[MS-NLMP\] §2.2.2.9): a version of 1,
    /// eight bytes of checksum, then the sequence number.
    #[non_exhaustive]
    NtlmSignature {
        /// `SeqNum`: sequence number of the message.
        sequence_number: u32,
    },
}

impl LdapSaslToken {
    /// Whether the data of the buffer are encrypted. `None` for an NTLMSSP
    /// signature, which does not say it: the bind negotiated it.
    pub fn is_sealed(&self) -> Option<bool> {
        match *self {
            Self::KerberosWrap { flags, .. } => Some(flags & GSS_WRAP_FLAG_SEALED != 0),
            Self::KerberosV1Wrap {
                sealing_algorithm, ..
            } => Some(sealing_algorithm != GSS_V1_SEAL_NONE),
            Self::NtlmSignature { .. } => None,
        }
    }
}

/// Iterator over the PDUs of a TCP segment or of a datagram
/// ([`LdapPdu::pdus`]).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct LdapPdus<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for LdapPdus<'a> {
    type Item = Result<LdapPdu<'a>, LdapError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let pdu = LdapPdu::try_from(self.rest);
        // Apres une erreur, la suite du payload n'a plus de frontiere.
        self.rest = pdu.as_ref().map_or(&[], LdapPdu::rest);
        Some(pdu)
    }
}

/// Iterator over the messages of a signed SASL buffer
/// ([`LdapSaslBuffer::messages`]).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct LdapMessages<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for LdapMessages<'a> {
    type Item = Result<LdapMessage<'a>, LdapError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let message = LdapMessage::try_from(self.rest);
        self.rest = message.as_ref().map_or(&[], LdapMessage::rest);
        Some(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Trames reelles de pcaps_exemple/The-Ultimate-PCAP.pcapng : un poste
    // Windows et le controleur de son domaine Active Directory.

    /// BindRequest SASL (GSS-SPNEGO, jeton NTLMSSP) : trame 40032, 80 octets.
    const BIND_REQUEST: &str = "30840000004a0201086084000000410201030400a38400000036040a4753532d53504e45474f04284e544c4d5353500001000000b78208e2000000000000000000000000000000000a00614a0000000f";

    /// BindResponse `invalidCredentials` : trame 40035, 110 octets.
    const BIND_RESPONSE: &str = "30840000006802010961840000005f0a01310400045838303039303330433a204c6461704572723a20445349442d30433039303641422c20636f6d6d656e743a204163636570745365637572697479436f6e74657874206572726f722c2064617461203532652c20763466376300";

    /// Tampon SASL chiffre, jeton Wrap de la RFC 4121 : trame 40284, 75
    /// octets.
    const SEALED: &str = "00000047050406ff0000001c000000003a8d97b0faf47426b0166fdb91195b7956cb80322a85a40831b4b186ab3dd458e4cbcc241e793c4cccb37ec56fbbfe2fe97865d896b9a626c4153f";

    /// Tampon SASL signe qui porte un UnbindRequest : trame 40461, 43 octets.
    const SIGNED_UNBIND: &str =
        "00000027050404ff000c000c000000003d71d7558e337ea57ab97b107c58dbb73084000000050201064200";

    /// Tampon SASL signe qui porte un SearchRequest et un controle
    /// (1.2.840.113556.1.4.1339, critique) : trame 41296, 176 octets.
    const SIGNED_SEARCH: &str = "000000ac050404ff000c000c000000005c18066f6aeee4038fff8e1ba0c6f00930840000008a02010863840000005704000a01000a0100020101020200f0010100870b6f626a656374436c617373308400000032041a636f6e66696775726174696f6e4e616d696e67436f6e7465787404146e54536563757269747944657363726970746f72a0840000002430840000001e0417312e322e3834302e3131333535362e312e342e313333390101ff0400";

    /// SearchRequest CLDAP (ping Netlogon) : trame 39247, datagramme de 175
    /// octets sur UDP 389.
    const CLDAP_REQUEST: &str = "3084000000a90201016384000000a004000a01000a0100020100020100010100a08400000079a3840000001f0409446e73446f6d61696e04126164323032342e77656265726c61622e6465a384000000170404486f7374040f4445534b544f502d36414a5442514da3840000000d04054e74566572040416000000a3840000001e040b446e73486f73744e616d65040f4445534b544f502d36414a5442514d30840000000a04084e65746c6f676f6e";

    /// Sa reponse, deux messages dans un datagramme de 186 octets
    /// (SearchResultEntry puis SearchResultDone) : trame 39248.
    const CLDAP_RESPONSE: &str = "30840000009e020101648400000095040030840000008d30840000008704084e65746c6f676f6e318400000077047517000000fdf30300101b114ed428124e9c1d09a4a351072b066164323032340877656265726c616202646500c0180b766d33392d616432303234c01806414432303234000b564d33392d41443230323400001744656661756c742d46697273742d536974652d4e616d6500c05205000000ffffffff3084000000100201016584000000070a010004000400";

    /// Les 32 premiers octets d'un SearchResultEntry de 2 839 octets que son
    /// segment coupe : trame 40019 (1 440 octets).
    const CUT_ENTRY: &str = "308400000b11020106648400000b080400308400000b003084000000b2041573";

    /// Debut du segment de suite du meme message : trame 40020.
    const CONTINUATION: &str = "2e312e3131333733302e332e342e390418322e31362e3834";

    // Trames reelles de pcaps_exemple/protocols/ldap/ (wiki Wireshark).

    /// BindRequest simple et anonyme, longueurs BER sur un octet (client
    /// OpenLDAP) : ldap-and-search.pcap, trame 4, 14 octets.
    const SIMPLE_BIND: &str = "300c020101600702010304008000";

    /// SearchResultDone `noSuchObject` : meme capture, trame 9.
    const NO_SUCH_OBJECT: &str = "300c02010265070a012004000400";

    /// Tampon SASL signe, jeton Wrap de la RFC 1964 (HMAC, non chiffre), qui
    /// porte un UnbindRequest : ldap-controls-dirsync-01.cap, trame 8, 61
    /// octets.
    const V1_SIGNED_UNBIND: &str = "00000039603706092a864886f71201020202011100ffffffff1418a39b929e3a1801328613112a7dc58804f8e66999eebe308400000005020109420001";

    /// Tampon SASL chiffre, jeton Wrap de la RFC 1964 (HMAC, RC4) :
    /// ldap-krb5-sign-seal-01.cap, trame 12, 102 octets.
    const V1_SEALED: &str = "00000062606006092a864886f712010202020111001000ffff75b15340fbb34295ad58191d21416129eb7ee0027d0a5393af5fa18749f2eefd88d88fc8914e699d11e13d43a050c1f530a79e3ab0b292cb497d8063adbe4bf5bea0ac9552040646090e8d42ce";

    /// Tampon SASL sous signature NTLMSSP, numero de sequence 2 :
    /// ntlm_ldap.pcapng, trame 14, 71 octets.
    const NTLM: &str = "00000043010000004d2f4f85517ceda70200000053e52bc6ae8271b1c7dbf434793147d6961a88f5c1dfd4621d68a011176fd86235a27bb1ede745fe66f18653731d5308218474";

    fn hex(text: &str) -> Vec<u8> {
        hex::decode(text).expect("hexa valide")
    }

    fn message(bytes: &[u8]) -> LdapMessage<'_> {
        LdapMessage::try_from(bytes).expect("LDAPMessage")
    }

    fn buffer(bytes: &[u8]) -> LdapSaslBuffer<'_> {
        LdapSaslBuffer::try_from(bytes).expect("tampon SASL")
    }

    #[test]
    fn bind_request_is_read() {
        let bytes = hex(BIND_REQUEST);
        let message = message(&bytes);
        assert_eq!(message.message_id, 8);
        assert_eq!(message.operation, LdapOperation::BindRequest);
        assert_eq!(message.operation.as_u8(), 0);
        assert_eq!(message.body.len(), 65);
        assert_eq!(message.controls, None);
        assert_eq!(message.wire_length(), 80);
        assert!(!message.is_truncated());
        assert!(message.rest().is_empty());

        let bind = message.bind_request().expect("requete de liaison");
        assert_eq!(bind.version, 3);
        assert_eq!(bind.name, b"");
        let LdapAuthentication::Sasl {
            mechanism,
            credentials,
        } = bind.authentication
        else {
            panic!("liaison SASL attendue");
        };
        assert_eq!(mechanism, b"GSS-SPNEGO");
        let credentials = credentials.expect("jeton");
        assert_eq!(credentials.len(), 40);
        assert!(credentials.starts_with(b"NTLMSSP\0"));

        assert_eq!(message.result(), None);
        assert_eq!(message.search_request(), None);
    }

    #[test]
    fn bind_response_carries_its_result() {
        let bytes = hex(BIND_RESPONSE);
        let message = message(&bytes);
        assert_eq!(message.message_id, 9);
        assert_eq!(message.operation, LdapOperation::BindResponse);
        let result = message.result().expect("LDAPResult");
        assert_eq!(result.code, 49);
        assert_eq!(result.matched_dn, b"");
        assert_eq!(result.diagnostic_message.len(), 88);
        assert!(
            result
                .diagnostic_message
                .starts_with(b"8009030C: LdapErr: DSID-0C0906AB")
        );
        assert_eq!(message.bind_request(), None);
    }

    #[test]
    fn sealed_buffer_keeps_its_header_only() {
        let bytes = hex(SEALED);
        let buffer = buffer(&bytes);
        assert_eq!(buffer.length, 71);
        assert_eq!(
            buffer.token,
            LdapSaslToken::KerberosWrap {
                flags: 0x06,
                extra_count: 0,
                right_rotation_count: 28,
                sequence_number: 0x3a8d_97b0,
            }
        );
        assert_eq!(buffer.token.is_sealed(), Some(true));
        assert_eq!(buffer.data.len(), 55);
        assert!(!buffer.is_truncated());
        assert!(buffer.rest().is_empty());
        assert_eq!(buffer.plaintext(), None);
        assert_eq!(buffer.messages().count(), 0);
    }

    #[test]
    fn signed_buffer_shows_its_message() {
        let bytes = hex(SIGNED_UNBIND);
        let buffer = buffer(&bytes);
        assert_eq!(buffer.length, 39);
        assert_eq!(
            buffer.token,
            LdapSaslToken::KerberosWrap {
                flags: 0x04,
                extra_count: 12,
                right_rotation_count: 12,
                sequence_number: 0x3d71_d755,
            }
        );
        assert_eq!(buffer.token.is_sealed(), Some(false));
        assert_eq!(buffer.data.len(), 23);
        // Le checksum de douze octets precede le message.
        assert_eq!(buffer.plaintext(), Some(&bytes[32..]));

        let messages: Vec<_> = buffer.messages().collect();
        let [Ok(unbind)] = messages.as_slice() else {
            panic!("un message attendu : {messages:?}");
        };
        assert_eq!(unbind.message_id, 6);
        assert_eq!(unbind.operation, LdapOperation::UnbindRequest);
        assert!(unbind.body.is_empty());
        assert_eq!(unbind.wire_length(), 11);
    }

    #[test]
    fn rfc_1964_tokens_are_read() {
        // Signe : un confondeur de huit octets, le message, un octet de
        // bourrage.
        let bytes = hex(V1_SIGNED_UNBIND);
        let signed = buffer(&bytes);
        assert_eq!(signed.length, 57);
        assert_eq!(
            signed.token,
            LdapSaslToken::KerberosV1Wrap {
                signing_algorithm: 0x0011,
                sealing_algorithm: 0xffff,
            }
        );
        assert_eq!(signed.token.is_sealed(), Some(false));
        assert_eq!(signed.data.len(), 20);
        assert_eq!(signed.plaintext(), Some(&bytes[49..60]));
        let unbind = signed.messages().next().expect("un message");
        let unbind = unbind.expect("UnbindRequest");
        assert_eq!(unbind.message_id, 9);
        assert_eq!(unbind.operation, LdapOperation::UnbindRequest);
        assert_eq!(signed.messages().count(), 1);
        // Coupe, le bourrage est ailleurs : tout ce qui suit le confondeur
        // est du texte.
        let cut = buffer(&bytes[..55]);
        assert!(cut.is_truncated());
        assert_eq!(cut.plaintext(), Some(&bytes[49..55]));

        // Chiffre par RC4.
        let bytes = hex(V1_SEALED);
        let sealed = buffer(&bytes);
        assert_eq!(sealed.length, 98);
        assert_eq!(
            sealed.token,
            LdapSaslToken::KerberosV1Wrap {
                signing_algorithm: 0x0011,
                sealing_algorithm: 0x0010,
            }
        );
        assert_eq!(sealed.token.is_sealed(), Some(true));
        assert_eq!(sealed.data.len(), 61);
        assert_eq!(sealed.plaintext(), None);
        assert!(!sealed.is_truncated());
        assert!(sealed.rest().is_empty());
    }

    #[test]
    fn ntlm_signature_is_read() {
        let bytes = hex(NTLM);
        let buffer = buffer(&bytes);
        assert_eq!(buffer.length, 67);
        assert_eq!(
            buffer.token,
            LdapSaslToken::NtlmSignature { sequence_number: 2 }
        );
        // La signature ne dit pas si le message est chiffre.
        assert_eq!(buffer.token.is_sealed(), None);
        assert_eq!(buffer.data.len(), 51);
        assert_eq!(buffer.plaintext(), None);
        assert_eq!(buffer.messages().count(), 0);
        assert!(!buffer.is_truncated());
    }

    #[test]
    fn short_lengths_are_read() {
        let bytes = hex(SIMPLE_BIND);
        let bind = message(&bytes);
        assert_eq!(bind.message_id, 1);
        assert_eq!(bind.wire_length(), 14);
        let request = bind.bind_request().expect("requete de liaison");
        assert_eq!(request.version, 3);
        assert_eq!(request.name, b"");
        assert_eq!(request.authentication, LdapAuthentication::Simple(b""));

        let bytes = hex(NO_SUCH_OBJECT);
        let done = message(&bytes);
        assert_eq!(done.message_id, 2);
        assert_eq!(done.operation, LdapOperation::SearchResultDone);
        assert_eq!(done.result().map(|result| result.code), Some(32));
    }

    #[test]
    fn signed_search_request_has_controls() {
        let bytes = hex(SIGNED_SEARCH);
        let buffer = buffer(&bytes);
        assert_eq!(buffer.length, 172);
        let search = buffer
            .messages()
            .next()
            .expect("un message")
            .expect("SearchRequest");
        assert_eq!(search.message_id, 8);
        assert_eq!(search.operation, LdapOperation::SearchRequest);
        let request = search.search_request().expect("debut de la recherche");
        assert_eq!(request.base_object, b"");
        assert_eq!(request.scope, 0);
        let controls = search.controls.expect("controles");
        assert_eq!(controls.len(), 36);
        assert_eq!(&controls[8..31], b"1.2.840.113556.1.4.1339");
        assert!(search.rest().is_empty());
        assert!(!search.is_truncated());
    }

    #[test]
    fn cldap_datagram_is_one_message() {
        let bytes = hex(CLDAP_REQUEST);
        let message = message(&bytes);
        assert_eq!(message.message_id, 1);
        assert_eq!(message.operation, LdapOperation::SearchRequest);
        assert_eq!(message.body.len(), 160);
        assert_eq!(message.wire_length(), bytes.len());
        let request = message.search_request().expect("debut de la recherche");
        assert_eq!(request.base_object, b"");
        assert_eq!(request.scope, 0);
    }

    #[test]
    fn pdus_follow_each_other() {
        let bytes = hex(CLDAP_RESPONSE);
        let pdus: Vec<_> = LdapPdu::pdus(&bytes).collect();
        let [Ok(LdapPdu::Message(entry)), Ok(LdapPdu::Message(done))] = pdus.as_slice() else {
            panic!("deux messages attendus : {pdus:?}");
        };
        assert_eq!(entry.operation, LdapOperation::SearchResultEntry);
        assert_eq!(entry.message_id, 1);
        assert_eq!(entry.wire_length(), 164);
        assert_eq!(entry.rest().len(), 22);
        assert_eq!(entry.result(), None);
        assert_eq!(done.operation, LdapOperation::SearchResultDone);
        assert_eq!(done.message_id, 1);
        assert_eq!(done.result().map(|result| result.code), Some(0));
        assert!(done.rest().is_empty());

        // Deux tampons SASL dans un segment, puis un message en clair.
        let mut several = hex(SIGNED_UNBIND);
        several.extend(hex(SEALED));
        several.extend(hex(BIND_REQUEST));
        let kinds: Vec<_> = LdapPdu::pdus(&several)
            .map(|pdu| match pdu {
                Ok(LdapPdu::SaslBuffer(buffer)) => format!("{:?}", buffer.token.is_sealed()),
                Ok(LdapPdu::Message(message)) => format!("{:?}", message.operation),
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(kinds, ["Some(false)", "Some(true)", "BindRequest"]);
    }

    #[test]
    fn cut_pdus_are_truncated() {
        let bytes = hex(CUT_ENTRY);
        let entry = message(&bytes);
        assert_eq!(entry.message_id, 6);
        assert_eq!(entry.operation, LdapOperation::SearchResultEntry);
        assert_eq!(entry.wire_length(), 2839);
        assert!(entry.is_truncated());
        assert_eq!(entry.body, &bytes[15..]);
        assert_eq!(entry.controls, None);
        assert!(entry.rest().is_empty());
        assert_eq!(LdapPdu::pdus(&bytes).count(), 1);

        // Un message coupe apres son operation, avant ses controles.
        let search = hex(SIGNED_SEARCH);
        let cut = message(&search[32..search.len() - 42]);
        assert!(cut.is_truncated());
        assert_eq!(cut.controls, None);
        assert_eq!(cut.body.len(), 87);
        // Coupe dans l'en-tete des controles, puis dans leur contenu.
        assert_eq!(message(&search[32..search.len() - 39]).controls, None);
        let partial = message(&search[32..search.len() - 30]);
        assert!(partial.is_truncated());
        assert_eq!(partial.controls.map(<[u8]>::len), Some(6));

        // Un tampon signe coupe : le debut de son message reste lisible.
        let cut = &search[..60];
        let buffer = buffer(cut);
        assert!(buffer.is_truncated());
        assert_eq!(buffer.data.len(), 40);
        let inner = buffer.messages().next().expect("un message");
        let inner = inner.expect("debut du SearchRequest");
        assert_eq!(inner.message_id, 8);
        assert!(inner.is_truncated());
        assert!(LdapPdu::try_from(cut).expect("tampon").is_truncated());

        // Un en-tete coupe n'est pas un message.
        assert_eq!(
            LdapMessage::try_from(&bytes[..8]),
            Err(LdapError::TooShort {
                field: "message identifier",
                expected: 3,
                actual: 2,
            })
        );
        assert_eq!(
            LdapSaslBuffer::try_from(&search[..19]),
            Err(LdapError::TooShort {
                field: "SASL buffer",
                expected: 20,
                actual: 19,
            })
        );
    }

    #[test]
    fn signed_plaintext_follows_the_rotation() {
        // Meme jeton, rotation nulle : le checksum passe a la fin.
        let original = hex(SIGNED_UNBIND);
        let mut rotated = original[..20].to_vec();
        rotated.extend(&original[32..]);
        rotated.extend(&original[20..32]);
        rotated[10..12].copy_from_slice(&[0, 0]);
        let buffer = buffer(&rotated);
        assert_eq!(buffer.plaintext(), Some(&original[32..]));
        // Coupe, la fin du texte n'est plus connue.
        let cut = LdapSaslBuffer::try_from(&rotated[..40]).expect("tampon coupe");
        assert_eq!(cut.plaintext(), None);

        // Une autre rotation separe le texte en deux morceaux.
        let mut split = original.clone();
        split[10..12].copy_from_slice(&[0, 5]);
        let buffer = LdapSaslBuffer::try_from(split.as_slice()).expect("tampon");
        assert_eq!(buffer.plaintext(), None);
        assert_eq!(buffer.messages().count(), 0);
    }

    #[test]
    fn malformed_messages_are_refused() {
        let invalid = |bytes: &[u8]| LdapMessage::try_from(bytes).expect_err("refus attendu");
        assert_eq!(
            invalid(&[]),
            LdapError::TooShort {
                field: "message",
                expected: 2,
                actual: 0,
            }
        );
        assert_eq!(
            invalid(&[0x31, 0x05, 0x02, 0x01, 0x01, 0x42, 0x00]),
            LdapError::UnexpectedTag {
                field: "message",
                expected: 0x30,
                actual: 0x31,
            }
        );
        // Longueur indefinie, sur cinq octets, puis de 2^31 octets.
        for length in [&[0x80][..], &[0x85, 0, 0, 0, 0, 7], &[0x84, 0x80, 0, 0, 0]] {
            let mut bytes = vec![0x30];
            bytes.extend(length);
            bytes.extend([0x02, 0x01, 0x01, 0x42, 0x00]);
            assert_eq!(
                invalid(&bytes),
                LdapError::InvalidLength { field: "message" },
                "{length:02x?}"
            );
        }
        assert_eq!(
            invalid(&[0x30, 0x05, 0x04, 0x01, 0x01, 0x42, 0x00]),
            LdapError::UnexpectedTag {
                field: "message identifier",
                expected: 0x02,
                actual: 0x04,
            }
        );
        // Identifiant negatif, vide, puis sur cinq octets.
        for identifier in [&[0x01, 0x80][..], &[0x00], &[0x05, 0, 0, 0, 0, 1]] {
            let mut contents = vec![0x02];
            contents.extend(identifier);
            contents.extend([0x42, 0x00]);
            let mut bytes = vec![0x30, contents.len() as u8];
            bytes.extend(contents);
            assert_eq!(invalid(&bytes), LdapError::InvalidMessageId);
        }
        // Etiquette universelle, puis un UnbindRequest construit.
        for tag in [0x04, 0x62, 0x7a] {
            assert_eq!(
                invalid(&[0x30, 0x05, 0x02, 0x01, 0x01, tag, 0x00]),
                LdapError::UnknownOperation(tag)
            );
        }
        assert_eq!(
            invalid(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x42, 0x01, 0x00]),
            LdapError::InvalidOperationLength {
                operation: 2,
                length: 1,
            }
        );
        assert_eq!(
            invalid(&[0x30, 0x05, 0x02, 0x01, 0x01, 0x50, 0x00]),
            LdapError::InvalidOperationLength {
                operation: 16,
                length: 0,
            }
        );
        // L'operation deborde d'une sequence entiere.
        assert_eq!(
            invalid(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x60, 0x02, 0x00]),
            LdapError::LengthOverflow {
                field: "operation",
                length: 4,
                available: 3,
            }
        );
        // Elle deborde de la longueur annoncee d'une sequence coupee.
        assert_eq!(
            invalid(&[0x30, 0x08, 0x02, 0x01, 0x01, 0x60, 0x09, 0x00]),
            LdapError::LengthOverflow {
                field: "operation",
                length: 11,
                available: 5,
            }
        );
        // Apres l'operation : autre chose que des controles, puis des
        // octets derriere les controles.
        assert_eq!(
            invalid(&[0x30, 0x07, 0x02, 0x01, 0x01, 0x42, 0x00, 0x04, 0x00]),
            LdapError::UnexpectedTag {
                field: "controls",
                expected: 0xa0,
                actual: 0x04,
            }
        );
        assert_eq!(
            invalid(&[
                0x30, 0x09, 0x02, 0x01, 0x01, 0x42, 0x00, 0xa0, 0x00, 0x05, 0x00
            ]),
            LdapError::TrailingBytes(2)
        );

        // Un AbandonRequest et des controles vides sont bien formes.
        let abandon = message(&[0x30, 0x08, 0x02, 0x01, 0x02, 0x50, 0x01, 0x01, 0xa0, 0x00]);
        assert_eq!(abandon.operation, LdapOperation::AbandonRequest);
        assert_eq!(abandon.body, [0x01]);
        assert_eq!(abandon.controls, Some(&[][..]));
    }

    #[test]
    fn malformed_buffers_are_refused() {
        let invalid = |frame: &str, edit: &dyn Fn(&mut Vec<u8>)| {
            let mut bytes = hex(frame);
            edit(&mut bytes);
            LdapSaslBuffer::try_from(bytes.as_slice()).expect_err("refus attendu")
        };
        // Plus court que tout en-tete de jeton, puis plus de 2^24 - 1 octets.
        assert_eq!(
            invalid(SEALED, &|bytes| bytes[3] = 15),
            LdapError::InvalidSaslLength(15)
        );
        assert_eq!(
            invalid(SEALED, &|bytes| bytes[0] = 1),
            LdapError::InvalidSaslLength(0x0100_0047)
        );
        // RFC 4121 : autre TOK_ID, bourrage absent. Premier octet inconnu.
        for (index, value) in [(5, 0x05), (7, 0x00), (4, 0x02)] {
            assert_eq!(
                invalid(SEALED, &|bytes| bytes[index] = value),
                LdapError::UnsupportedSaslToken,
                "octet {index}"
            );
        }
        // RFC 1964 : enveloppe plus courte que le tampon, autre OID, autre
        // TOK_ID (un jeton MIC, `01 01`), bourrage absent.
        for (index, value) in [(5, 0x36), (14, 0x03), (17, 0x01), (23, 0x00)] {
            assert_eq!(
                invalid(V1_SIGNED_UNBIND, &|bytes| bytes[index] = value),
                LdapError::UnsupportedSaslToken,
                "octet {index}"
            );
        }
        // Un tampon entier plus court que l'en-tete de son jeton.
        assert_eq!(
            invalid(V1_SIGNED_UNBIND, &|bytes| {
                bytes.truncate(4 + 30);
                bytes[3] = 30;
                bytes[5] = 28;
            }),
            LdapError::InvalidSaslLength(30)
        );
        // NTLMSSP : autre version.
        assert_eq!(
            invalid(NTLM, &|bytes| bytes[5] = 1),
            LdapError::UnsupportedSaslToken
        );
        // Un octet fixe faux se voit avant la fin de l'en-tete.
        assert_eq!(
            LdapSaslBuffer::try_from(&[0, 0, 0, 0x47, 0x05, 0x05][..]),
            Err(LdapError::UnsupportedSaslToken)
        );
        // Les bits de drapeau reserves sont ignores (RFC 4121 §4.2.2).
        let mut reserved = hex(SEALED);
        reserved[6] |= 0x80;
        assert_eq!(buffer(&reserved).token.is_sealed(), Some(true));
        // Un bourrage hors de 1 a 8 : le texte d'un jeton signe n'a plus
        // de fin connue.
        let mut padding = hex(V1_SIGNED_UNBIND);
        *padding.last_mut().expect("octet") = 9;
        assert_eq!(buffer(&padding).plaintext(), None);

        // L'entree s'arrete dans l'en-tete du jeton.
        for (frame, length, expected) in [
            (SEALED, 19, 20),
            (V1_SIGNED_UNBIND, 5, 6),
            (V1_SIGNED_UNBIND, 40, 41),
            (NTLM, 4, 5),
            (NTLM, 12, 20),
        ] {
            assert_eq!(
                LdapSaslBuffer::try_from(&hex(frame)[..length]),
                Err(LdapError::TooShort {
                    field: "SASL buffer",
                    expected,
                    actual: length,
                }),
                "{frame} coupe a {length}"
            );
        }

        // Un PDU qui ne s'ouvre ni par `30` ni par `00` n'est pas un tampon.
        assert_eq!(
            LdapPdu::try_from(&hex(CONTINUATION)[..]),
            Err(LdapError::UnexpectedTag {
                field: "message",
                expected: 0x30,
                actual: 0x2e,
            })
        );
    }

    #[test]
    fn probe_wants_pdus_that_tile_the_payload() {
        for frame in [
            BIND_REQUEST,
            BIND_RESPONSE,
            SEALED,
            SIGNED_UNBIND,
            SIGNED_SEARCH,
            CLDAP_REQUEST,
            CLDAP_RESPONSE,
            CUT_ENTRY,
            SIMPLE_BIND,
            NO_SUCH_OBJECT,
            V1_SIGNED_UNBIND,
            V1_SEALED,
            NTLM,
        ] {
            assert!(LdapPdu::is_port_match(&hex(frame)), "{frame}");
        }
        assert!(!LdapPdu::is_port_match(&[]));
        assert!(!LdapPdu::is_port_match(&hex(CONTINUATION)));

        // Des octets derriere un PDU entier le refusent.
        let mut trailing = hex(SIGNED_UNBIND);
        trailing.extend(hex(SEALED));
        assert!(LdapPdu::is_port_match(&trailing));
        trailing.extend([0xde, 0xad]);
        assert!(!LdapPdu::is_port_match(&trailing));

        // L'iterateur s'arrete a la premiere erreur.
        let items: Vec<_> = LdapPdu::pdus(&trailing).collect();
        assert_eq!(items.len(), 3);
        assert!(items[2].is_err());

        // TCP coupe ou il veut : derriere un PDU entier, le debut du
        // suivant, trop court pour etre lu, ne retire rien (#382). Une
        // enveloppe coupee dans son etiquette, dans sa longueur, dans son
        // identifiant ; un tampon SASL coupe dans sa longueur, dans
        // l'en-tete de son jeton.
        let sealed = hex(SEALED);
        for start in [
            &[0x30][..],
            &[0x30, 0x84, 0x00],
            &[0x30, 0x0c, 0x02],
            &[0x00, 0x00],
            &sealed[..10],
        ] {
            let mut cut = hex(SIGNED_UNBIND);
            cut.extend(start);
            let items: Vec<_> = LdapPdu::pdus(&cut).collect();
            assert_eq!(items.len(), 2, "{start:02x?}");
            assert!(
                matches!(items[1], Err(LdapError::TooShort { .. })),
                "{start:02x?} : {:?}",
                items[1]
            );
            assert!(LdapPdu::is_port_match(&cut), "{start:02x?}");
            // Seul, ce debut ne nomme rien.
            assert!(!LdapPdu::is_port_match(start), "{start:02x?}");
        }
    }

    /// Synthetique : la reponse de bind reelle, dont l'enveloppe et
    /// l'operation annoncent 2^24 octets de plus, ce qu'un tampon SASL ne
    /// peut pas porter mais qu'un message en clair peut (#382).
    #[test]
    fn ber_lengths_are_not_bound_by_the_sasl_limit() {
        let mut bytes = hex(BIND_RESPONSE);
        assert_eq!(bytes[..6], [0x30, 0x84, 0x00, 0x00, 0x00, 0x68]);
        assert_eq!(bytes[9..15], [0x61, 0x84, 0x00, 0x00, 0x00, 0x5f]);
        (bytes[2], bytes[11]) = (0x01, 0x01);
        let message = LdapMessage::try_from(bytes.as_slice()).expect("message coupe");
        assert_eq!(message.message_id, 9);
        assert_eq!(message.operation, LdapOperation::BindResponse);
        assert!(message.is_truncated());
        assert_eq!(message.wire_length(), 6 + 0x0100_0068);
        assert!(LdapPdu::is_port_match(&bytes));

        // La borne du decodeur : 2^31 - 1 octets.
        (bytes[2], bytes[11]) = (0x7f, 0x7f);
        (bytes[3], bytes[4], bytes[5]) = (0xff, 0xff, 0xff);
        (bytes[12], bytes[13], bytes[14]) = (0xff, 0xff, 0xf6);
        let message = LdapMessage::try_from(bytes.as_slice()).expect("message coupe");
        assert_eq!(message.wire_length(), 6 + 0x7fff_ffff);
        bytes[2] = 0x80;
        assert_eq!(
            LdapMessage::try_from(bytes.as_slice()).map(|_| ()),
            Err(LdapError::InvalidLength { field: "message" })
        );

        // Un tampon SASL garde la sienne, 2^24 - 1 octets.
        let mut buffer = hex(SEALED);
        buffer[0] = 0x01;
        assert_eq!(
            LdapSaslBuffer::try_from(buffer.as_slice()).map(|_| ()),
            Err(LdapError::InvalidSaslLength(0x0100_0047))
        );
    }
}
