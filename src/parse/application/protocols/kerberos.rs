// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Kerberos V5 (RFC 4120, #379), l'authentification par tickets : l'echange
//! d'un client avec le centre de distribution de cles (KDC) de son royaume,
//! sur UDP 88 et TCP 88. Dans un domaine Active Directory, le KDC est le
//! controleur de domaine.
//!
//! Un message est un element DER `[APPLICATION n]` qui porte une SEQUENCE de
//! champs numerotes ; les deux premiers sont la version du protocole
//! (`pvno`, 5) et le type du message (`msg-type`), qui repete le numero de
//! l'etiquette. Ce decodeur verifie cet en-tete et emprunte les champs sans
//! les decoder ([`KerberosMessage::field`]). Cinq lectures vont plus loin,
//! pour les trois messages de l'echange avec le KDC (KDC-REQ, KDC-REP,
//! KRB-ERROR) : le code d'erreur, le royaume, le royaume du client, le nom
//! du client et celui du service. Les parties chiffrees (tickets,
//! authentifiants, pre-authentification) ne sont pas lues.
//!
//! Sur UDP, un datagramme porte un message. Sur TCP, chaque message suit
//! quatre octets de longueur ([`KerberosRecord`], RFC 4120 §7.2.2).
//!
//! Detection : regles a port sur UDP 88 et TCP 88. L'en-tete est assez long
//! pour une sonde aveugle, mais le depot n'a pas de capture de Kerberos hors
//! de son port : un autre port se declare par Decode As.
//!
//! Limites, sans etat : un message plus long que son segment est coupe
//! ([`KerberosMessage::is_truncated`]) et les segments de suite restent
//! `Unknown`. Kerberos porte par un autre protocole (GSS-API dans LDAP ou
//! SMB, kpasswd sur le port 464) n'est pas cherche.

use std::convert::TryFrom;

use crate::checks::application::kerberos::{
    DerContents, KERBEROS_RECORD_MARK_LENGTH, extract_element, extract_field, extract_integer,
    extract_message_type, extract_name_string, extract_principal_name, extract_record_length,
    extract_sequence, extract_sequence_fields, extract_string, extract_ticket, validate_header,
    validate_record_length,
};
use crate::errors::application::kerberos::KerberosError;

/// Type of a [`KerberosMessage`]: the number of its `[APPLICATION n]` tag
/// and the value of its `msg-type` field (RFC 4120 §5.10 and §7.5.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KerberosMessageType {
    /// AS-REQ (10): a client asks the authentication service for a ticket.
    AsReq,
    /// AS-REP (11): the answer to an AS-REQ.
    AsRep,
    /// TGS-REQ (12): a client asks the ticket-granting service for a
    /// service ticket.
    TgsReq,
    /// TGS-REP (13): the answer to a TGS-REQ.
    TgsRep,
    /// AP-REQ (14): a client authenticates to a service.
    ApReq,
    /// AP-REP (15): the answer to an AP-REQ.
    ApRep,
    /// KRB-SAFE (20): application data with a checksum.
    Safe,
    /// KRB-PRIV (21): encrypted application data.
    Priv,
    /// KRB-CRED (22): credentials forwarded to another host.
    Cred,
    /// KRB-ERROR (30).
    Error,
}

impl KerberosMessageType {
    pub(crate) const ALL: [Self; 10] = [
        Self::AsReq,
        Self::AsRep,
        Self::TgsReq,
        Self::TgsRep,
        Self::ApReq,
        Self::ApRep,
        Self::Safe,
        Self::Priv,
        Self::Cred,
        Self::Error,
    ];

    /// The number of the type, from 10 to 30.
    pub fn code(self) -> u8 {
        match self {
            Self::AsReq => 10,
            Self::AsRep => 11,
            Self::TgsReq => 12,
            Self::TgsRep => 13,
            Self::ApReq => 14,
            Self::ApRep => 15,
            Self::Safe => 20,
            Self::Priv => 21,
            Self::Cred => 22,
            Self::Error => 30,
        }
    }

    /// AS-REQ ou TGS-REQ : un KDC-REQ (RFC 4120 §5.4.1).
    pub(crate) fn is_kdc_request(self) -> bool {
        matches!(self, Self::AsReq | Self::TgsReq)
    }

    /// AS-REP ou TGS-REP : un KDC-REP (RFC 4120 §5.4.2).
    fn is_kdc_reply(self) -> bool {
        matches!(self, Self::AsRep | Self::TgsRep)
    }
}

/// One Kerberos V5 message (RFC 4120 §5), the first of the bytes it is read
/// from.
///
/// ```mermaid
/// ---
/// title: KerberosMessage (DER, definite lengths of 1 to 5 bytes), here an AS-REP
/// ---
/// packet-beta
/// 0-7: "[APPLICATION 11] = 0x6B"
/// 8-15: "length"
/// 16-23: "SEQUENCE = 0x30"
/// 24-31: "length"
/// 32-39: "[0] = 0xA0"
/// 40-47: "length = 3"
/// 48-71: "pvno: INTEGER 5 = 02 01 05"
/// 72-79: "[1] = 0xA1"
/// 80-87: "length = 3"
/// 88-111: "msg-type: INTEGER 11 = 02 01 0B"
/// 112-143: "fields [2] and following"
/// ```
///
/// In an AS-REQ and a TGS-REQ, `pvno` is the field `[1]` and `msg-type` the
/// field `[2]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct KerberosMessage<'a> {
    /// Type of the message: its tag and its `msg-type` field agree, and its
    /// `pvno` field is 5.
    pub message_type: KerberosMessageType,
    fields: &'a [u8],
    wire_length: usize,
    is_truncated: bool,
    rest: &'a [u8],
}

impl<'a> KerberosMessage<'a> {
    /// Number of bytes that the message announces, tag and length included.
    pub fn wire_length(&self) -> usize {
        self.wire_length
    }

    /// `true` when the message goes on in the next TCP segment.
    pub fn is_truncated(&self) -> bool {
        self.is_truncated
    }

    /// The bytes that follow this message.
    pub fn rest(&self) -> &'a [u8] {
        self.rest
    }

    /// Contents of the field `[number]` of the message, `pvno` and
    /// `msg-type` included: one DER element. `None` when the message has no
    /// such field or when the input stops before it; the last field that
    /// the input holds is returned cut.
    pub fn field(&self, number: u8) -> Option<&'a [u8]> {
        self.contents(number).map(|contents| contents.bytes)
    }

    /// The `error-code` of a KRB-ERROR (RFC 4120 §7.5.9): 6 is
    /// `KDC_ERR_C_PRINCIPAL_UNKNOWN`, 24 `KDC_ERR_PREAUTH_FAILED`, 25
    /// `KDC_ERR_PREAUTH_REQUIRED`, 52 `KRB_ERR_RESPONSE_TOO_BIG`. `None`
    /// for another message.
    pub fn error_code(&self) -> Option<i32> {
        (self.message_type == KerberosMessageType::Error)
            .then(|| extract_integer(self.contents(6)?))
            .flatten()
    }

    /// The realm of the service: `realm` in the body of an AS-REQ or a
    /// TGS-REQ, in the ticket of an AS-REP or a TGS-REP, and in a
    /// KRB-ERROR. `None` for another message, and when the input stops
    /// before the field.
    pub fn realm(&self) -> Option<&'a [u8]> {
        let kind = self.message_type;
        let realm = if kind.is_kdc_request() {
            extract_field(self.request_body()?, 2)?
        } else if kind.is_kdc_reply() {
            extract_field(self.ticket()?, 1)?
        } else if kind == KerberosMessageType::Error {
            self.contents(9)?
        } else {
            return None;
        };
        extract_string(realm)
    }

    /// The realm of the client: `crealm` in an AS-REP, a TGS-REP or a
    /// KRB-ERROR that has one. In a request, the client and the service
    /// share [`KerberosMessage::realm`].
    pub fn client_realm(&self) -> Option<&'a [u8]> {
        let kind = self.message_type;
        let number = if kind.is_kdc_reply() {
            3
        } else if kind == KerberosMessageType::Error {
            7
        } else {
            return None;
        };
        extract_string(self.contents(number)?)
    }

    /// The name of the client: `cname` in the body of an AS-REQ or a
    /// TGS-REQ, in an AS-REP or a TGS-REP, and in a KRB-ERROR, when the
    /// message has one.
    pub fn client_name(&self) -> Option<KerberosPrincipalName<'a>> {
        let kind = self.message_type;
        let name = if kind.is_kdc_request() {
            extract_field(self.request_body()?, 1)?
        } else if kind.is_kdc_reply() {
            self.contents(4)?
        } else if kind == KerberosMessageType::Error {
            self.contents(8)?
        } else {
            return None;
        };
        extract_principal_name(name)
    }

    /// The name of the service: `sname` in the body of an AS-REQ or a
    /// TGS-REQ, in the ticket of an AS-REP or a TGS-REP, and in a
    /// KRB-ERROR.
    pub fn service_name(&self) -> Option<KerberosPrincipalName<'a>> {
        let kind = self.message_type;
        let name = if kind.is_kdc_request() {
            extract_field(self.request_body()?, 3)?
        } else if kind.is_kdc_reply() {
            extract_field(self.ticket()?, 2)?
        } else if kind == KerberosMessageType::Error {
            self.contents(10)?
        } else {
            return None;
        };
        extract_principal_name(name)
    }

    /// Sonde de la regle a port d'UDP : un message entier, seul dans son
    /// datagramme.
    pub(crate) fn is_port_match(payload: &'a [u8]) -> bool {
        Self::try_from(payload)
            .is_ok_and(|message| !message.is_truncated() && message.rest().is_empty())
    }

    fn contents(&self, number: u8) -> Option<DerContents<'a>> {
        let fields = DerContents {
            bytes: self.fields,
            is_cut: self.is_truncated,
        };
        extract_field(fields, number)
    }

    /// Les champs du `req-body` d'un KDC-REQ, son champ `[4]`.
    fn request_body(&self) -> Option<DerContents<'a>> {
        extract_sequence_fields(self.contents(4)?)
    }

    /// Les champs du `ticket` d'un KDC-REP, son champ `[5]`.
    fn ticket(&self) -> Option<DerContents<'a>> {
        extract_ticket(self.contents(5)?)
    }
}

impl<'a> TryFrom<&'a [u8]> for KerberosMessage<'a> {
    type Error = KerberosError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        // L'etiquette est jugee avant la longueur, pour qu'une entree qui
        // n'est pas du Kerberos sorte sur son premier octet.
        let message_type = extract_message_type(bytes)?;
        let message = extract_element("message", bytes)?;
        let sequence = extract_sequence(&message)?;
        validate_header(&sequence, message_type)?;
        Ok(Self {
            message_type,
            fields: sequence.contents,
            wire_length: message.total_length(),
            is_truncated: message.is_truncated(),
            rest: message.rest,
        })
    }
}

/// A `PrincipalName` (RFC 4120 §5.2.2): the name of a client or of a
/// service, without its realm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct KerberosPrincipalName<'a> {
    /// Type of the name (RFC 4120 §6.2): 1 is `NT-PRINCIPAL` (a user), 2
    /// `NT-SRV-INST` (a service and its instance, such as `krbtgt` and a
    /// realm), 3 `NT-SRV-HST` (a service and its host).
    pub name_type: i32,
    strings: &'a [u8],
}

impl<'a> KerberosPrincipalName<'a> {
    pub(crate) fn new(name_type: i32, strings: &'a [u8]) -> Self {
        Self { name_type, strings }
    }

    /// The components of the name, in order: `krbtgt` then `EXAMPLE.COM`
    /// for the ticket-granting service of a realm. The bytes are those of
    /// the wire: ASCII by the RFC, UTF-8 or a local code page in practice.
    pub fn components(&self) -> KerberosNameComponents<'a> {
        KerberosNameComponents { rest: self.strings }
    }
}

/// Iterator over the components of a name
/// ([`KerberosPrincipalName::components`]).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct KerberosNameComponents<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for KerberosNameComponents<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let (string, rest) = extract_name_string(self.rest)?;
        self.rest = rest;
        Some(string)
    }
}

/// One record of Kerberos over TCP (RFC 4120 §7.2.2): four bytes of length,
/// then the message, the first of the bytes it is read from.
///
/// ```mermaid
/// ---
/// title: KerberosRecord (big-endian)
/// ---
/// packet-beta
/// 0-0: "0"
/// 1-31: "length of the message (31 bits)"
/// 32-63: "KerberosMessage (length bytes)"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct KerberosRecord<'a> {
    /// Length of the message, from the record mark: that of the DER
    /// element of the message.
    pub length: u32,
    /// The message, cut when the segment stops before its end.
    pub message: KerberosMessage<'a>,
}

impl<'a> KerberosRecord<'a> {
    /// `true` when the message goes on in the next TCP segment.
    pub fn is_truncated(&self) -> bool {
        self.message.is_truncated()
    }

    /// The bytes of the segment that follow this record: another record, or
    /// nothing.
    pub fn rest(&self) -> &'a [u8] {
        self.message.rest()
    }

    /// The records of a TCP segment, in order. The iterator stops after
    /// the first error, or after a record that its segment cuts.
    pub fn records(payload: &'a [u8]) -> KerberosRecords<'a> {
        KerberosRecords { rest: payload }
    }

    /// Sonde de la regle a port de TCP : des enregistrements bien formes
    /// qui pavent le segment. Seul le dernier peut etre coupe. TCP coupe ou
    /// il veut : derriere un enregistrement entier, le suivant peut
    /// s'arreter dans sa marque ou dans l'en-tete de son message, trop tot
    /// pour etre lu. Ce reste ne retire rien a l'enregistrement qui le
    /// precede (#382) ; seul, il ne nomme rien.
    pub(crate) fn is_port_match(payload: &'a [u8]) -> bool {
        let mut has_whole_record = false;
        for record in Self::records(payload) {
            match record {
                Ok(record) => has_whole_record |= !record.is_truncated(),
                Err(KerberosError::TooShort { .. }) => return has_whole_record,
                Err(_) => return false,
            }
        }
        !payload.is_empty()
    }
}

impl<'a> TryFrom<&'a [u8]> for KerberosRecord<'a> {
    type Error = KerberosError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let length = extract_record_length(bytes)?;
        let message = KerberosMessage::try_from(&bytes[KERBEROS_RECORD_MARK_LENGTH..])?;
        validate_record_length(length, message.wire_length())?;
        Ok(Self { length, message })
    }
}

/// Iterator over the records of a TCP segment
/// ([`KerberosRecord::records`]).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct KerberosRecords<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for KerberosRecords<'a> {
    type Item = Result<KerberosRecord<'a>, KerberosError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let record = KerberosRecord::try_from(self.rest);
        // Apres une erreur, la suite du segment n'a plus de frontiere.
        self.rest = record.as_ref().map_or(&[], KerberosRecord::rest);
        Some(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Trames reelles de pcaps_exemple/protocols/kerberos/ (corpus de nDPI).

    /// AS-REQ sur UDP : ndpi_kerberos-error.pcap, trame 1, 287 octets.
    const AS_REQUEST: &str = "6a82011b30820117a103020105a20302010aa35830563048a103020102a241043f303da003020117a2360434b60e0b505f98104206f62503b8e0e7c82d842e6f01e5c7f0e1540d1ea4c7e89181e69691e0c41d775649bd7fa5ac4b1874a91915300aa10402020095a2020400a481b03081ada00703050000810000a11f301da003020101a11630141b04686f73741b0c6d75732d6e2d636a30373039a2111b0f4c494e55582e5348454c4c2e434f4da3243022a003020102a11b30191b066b72627467741b0f4c494e55582e5348454c4c2e434f4da511180f32303232303232333037343630335aa611180f32303232303330343037343630335aa706020447a1fa99a81a301802011702011202011102011402011302011002011902011a";

    /// Sa reponse, une KRB-ERROR `KRB_ERR_RESPONSE_TOO_BIG` (52) : meme
    /// capture, trame 2, 102 octets.
    const ERROR: &str = "7e643062a003020105a10302011ea411180f32303232303232323037343630345aa50502030ec26da603020134a9111b0f4c494e55582e5348454c4c2e434f4daa243022a003020102a11b30191b066b72627467741b0f4c494e55582e5348454c4c2e434f4d";

    /// Les 165 premiers octets d'un AS-REP de 1 256 octets, jusqu'au debut
    /// de la partie chiffree du ticket : ndpi_kerberos-short-realm.pcap,
    /// trame 4. Coupe ici comme un segment TCP le couperait.
    const CUT_AS_REPLY: &str = "6b8204e4308204e0a003020105a10302010ba21a30183016a103020103a20f040d44454e5944432e434f4d646573a30c1b0a44454e5944432e434f4da410300ea003020101a10730051b03646573a582036c6182036830820364a003020105a10c1b0a44454e5944432e434f4da21f301da003020102a11630141b066b72627467741b0a44454e5944432e434f4da382032c30820328a003020117a103020102a282031a04";

    /// AS-REQ sur TCP, marque d'enregistrement comprise : ndpi_kerberos.pcap,
    /// trame 1, 239 octets.
    const TCP_AS_REQUEST: &str = "000000eb6a81e83081e5a103020105a20302010aa31530133011a10402020080a20904073005a0030101ffa481c13081bea00703050040810010a1183016a003020101a10f300d1b0b6a6f686e736f6e2d706324a2101b0e686170707963726166742e6f7267a3233021a003020102a11a30181b066b72627467741b0e686170707963726166742e6f7267a511180f32303337303931333032343830355aa611180f32303337303931333032343830355aa70602044ec01617a81530130201120201110201170201180202ff79020103a91d301b3019a003020114a11204104a4f484e534f4e2d5043202020202020";

    /// Sa reponse, une KRB-ERROR `KDC_ERR_PREAUTH_REQUIRED` (25) : meme
    /// capture, trame 2, 278 octets.
    const TCP_ERROR: &str = "000001127e82010e3082010aa003020105a10302011ea411180f32303139303230353033333834385aa5050203063520a603020119a9101b0e686170707963726166742e6f7267aa233021a003020102a11a30181b066b72627467741b0e686170707963726166742e6f7267ac81a70481a43081a1307ea103020113a277047530733034a003020112a12d1b2b484150505943524146542e4f5247686f73746a6f686e736f6e2d70632e686170707963726166742e6f72673005a0030201173034a003020103a12d1b2b484150505943524146542e4f5247686f73746a6f686e736f6e2d70632e686170707963726166742e6f72673009a103020102a20204003009a103020110a20204003009a10302010fa2020400";

    fn hex(text: &str) -> Vec<u8> {
        hex::decode(text).expect("hexa valide")
    }

    fn message(bytes: &[u8]) -> KerberosMessage<'_> {
        KerberosMessage::try_from(bytes).expect("message Kerberos")
    }

    fn components<'a>(name: Option<KerberosPrincipalName<'a>>) -> (i32, Vec<&'a [u8]>) {
        let name = name.expect("nom");
        (name.name_type, name.components().collect())
    }

    #[test]
    fn as_request_is_read() {
        let bytes = hex(AS_REQUEST);
        let request = message(&bytes);
        assert_eq!(request.message_type, KerberosMessageType::AsReq);
        assert_eq!(request.message_type.code(), 10);
        assert_eq!(request.wire_length(), 287);
        assert!(!request.is_truncated());
        assert!(request.rest().is_empty());
        assert!(KerberosMessage::is_port_match(&bytes));

        // Dans un KDC-REQ, pvno est le champ [1] et msg-type le champ [2].
        assert_eq!(request.field(0), None);
        assert_eq!(request.field(1), Some(&[0x02, 0x01, 0x05][..]));
        assert_eq!(request.field(2), Some(&[0x02, 0x01, 0x0a][..]));
        assert_eq!(request.field(3).map(<[u8]>::len), Some(88));
        assert_eq!(request.field(5), None);

        assert_eq!(request.realm(), Some(&b"LINUX.SHELL.COM"[..]));
        assert_eq!(
            components(request.client_name()),
            (1, vec![&b"host"[..], b"mus-n-cj0709"])
        );
        assert_eq!(
            components(request.service_name()),
            (2, vec![&b"krbtgt"[..], b"LINUX.SHELL.COM"])
        );
        assert_eq!(request.client_realm(), None);
        assert_eq!(request.error_code(), None);
    }

    #[test]
    fn error_is_read() {
        let bytes = hex(ERROR);
        let error = message(&bytes);
        assert_eq!(error.message_type, KerberosMessageType::Error);
        assert_eq!(error.wire_length(), 102);
        // Hors d'un KDC-REQ, pvno est le champ [0] et msg-type le champ [1].
        assert_eq!(error.field(0), Some(&[0x02, 0x01, 0x05][..]));
        assert_eq!(error.field(1), Some(&[0x02, 0x01, 0x1e][..]));
        assert_eq!(error.error_code(), Some(52));
        assert_eq!(error.realm(), Some(&b"LINUX.SHELL.COM"[..]));
        assert_eq!(
            components(error.service_name()),
            (2, vec![&b"krbtgt"[..], b"LINUX.SHELL.COM"])
        );
        // Cette erreur ne nomme pas le client.
        assert_eq!(error.client_realm(), None);
        assert_eq!(error.client_name(), None);
    }

    #[test]
    fn reply_names_its_service_in_the_ticket() {
        let bytes = hex(CUT_AS_REPLY);
        let reply = message(&bytes);
        assert_eq!(reply.message_type, KerberosMessageType::AsRep);
        assert_eq!(reply.wire_length(), 1256);
        assert!(reply.is_truncated());
        assert!(reply.rest().is_empty());
        // Un datagramme porte un message entier.
        assert!(!KerberosMessage::is_port_match(&bytes));

        assert_eq!(reply.client_realm(), Some(&b"DENYDC.COM"[..]));
        assert_eq!(components(reply.client_name()), (1, vec![&b"des"[..]]));
        assert_eq!(reply.realm(), Some(&b"DENYDC.COM"[..]));
        assert_eq!(
            components(reply.service_name()),
            (2, vec![&b"krbtgt"[..], b"DENYDC.COM"])
        );
        assert_eq!(reply.error_code(), None);
        // Le ticket est le dernier champ que l'entree porte : il est rendu
        // coupe, et la partie chiffree de la reponse n'est pas la.
        assert_eq!(reply.field(5).map(<[u8]>::len), Some(165 - 82));
        assert_eq!(reply.field(6), None);
    }

    #[test]
    fn tcp_record_carries_one_message() {
        let bytes = hex(TCP_AS_REQUEST);
        let record = KerberosRecord::try_from(bytes.as_slice()).expect("enregistrement");
        assert_eq!(record.length, 235);
        assert_eq!(record.message.wire_length(), 235);
        assert!(!record.is_truncated());
        assert!(record.rest().is_empty());
        assert_eq!(record.message.message_type, KerberosMessageType::AsReq);
        assert_eq!(record.message.realm(), Some(&b"happycraft.org"[..]));
        assert_eq!(
            components(record.message.client_name()),
            (1, vec![&b"johnson-pc$"[..]])
        );
        assert!(KerberosRecord::is_port_match(&bytes));
        // Sans sa marque, ce n'est pas un enregistrement ; avec, ce n'est
        // pas un message.
        assert!(!KerberosRecord::is_port_match(&bytes[4..]));
        assert!(!KerberosMessage::is_port_match(&bytes));

        let bytes = hex(TCP_ERROR);
        let record = KerberosRecord::try_from(bytes.as_slice()).expect("enregistrement");
        assert_eq!(record.length, 274);
        assert_eq!(record.message.error_code(), Some(25));
        assert_eq!(record.message.realm(), Some(&b"happycraft.org"[..]));
    }

    /// Synthetique : les deux enregistrements reels mis bout a bout, ce que
    /// le corpus ne montre pas.
    #[test]
    fn records_follow_each_other() {
        let mut bytes = hex(TCP_AS_REQUEST);
        bytes.extend(hex(TCP_ERROR));
        let kinds: Vec<_> = KerberosRecord::records(&bytes)
            .map(|record| record.map(|record| record.message.message_type))
            .collect();
        assert_eq!(
            kinds,
            [
                Ok(KerberosMessageType::AsReq),
                Ok(KerberosMessageType::Error)
            ]
        );
        assert!(KerberosRecord::is_port_match(&bytes));

        // Des octets qui ne sont pas un enregistrement arretent la lecture.
        bytes.extend([0, 0, 0, 1, 0xff]);
        let records: Vec<_> = KerberosRecord::records(&bytes).collect();
        assert_eq!(records.len(), 3);
        assert_eq!(
            records[2].as_ref().map(|_| ()),
            Err(&KerberosError::UnknownMessageTag(0xff))
        );
        assert!(!KerberosRecord::is_port_match(&bytes));
        assert!(!KerberosRecord::is_port_match(&[]));
    }

    /// Synthetique : l'enregistrement reel, puis le debut de l'autre, que
    /// TCP coupe dans sa marque ou dans l'en-tete de son message (#382).
    #[test]
    fn record_start_behind_a_whole_record_keeps_the_probe() {
        let whole = hex(TCP_AS_REQUEST);
        let next = hex(TCP_ERROR);
        // La marque (4 octets), les deux etiquettes et leurs longueurs (8),
        // pvno (5) et msg-type (5) : l'en-tete se lit a 22 octets.
        for cut in 1..22 {
            let mut bytes = whole.clone();
            bytes.extend(&next[..cut]);
            let records: Vec<_> = KerberosRecord::records(&bytes).collect();
            assert_eq!(records.len(), 2, "{cut}");
            assert!(
                matches!(records[1], Err(KerberosError::TooShort { .. })),
                "{cut} : {:?}",
                records[1]
            );
            assert!(KerberosRecord::is_port_match(&bytes), "{cut}");
            // Seul, ce debut ne nomme rien.
            assert!(!KerberosRecord::is_port_match(&next[..cut]), "{cut}");
        }
        let mut bytes = whole.clone();
        bytes.extend(&next[..22]);
        let records: Vec<_> = KerberosRecord::records(&bytes)
            .collect::<Result<_, _>>()
            .expect("deux enregistrements");
        assert!(!records[0].is_truncated() && records[1].is_truncated());
        assert!(KerberosRecord::is_port_match(&bytes));

        // Un debut faux fait toujours refuser le segment : une etiquette
        // qui n'est pas celle d'un message, une longueur DER indefinie.
        for tail in [&[0, 0, 0, 1, 0xff][..], &[0, 0, 1, 0x12, 0x7e, 0x80]] {
            let mut bytes = whole.clone();
            bytes.extend(tail);
            assert!(!KerberosRecord::is_port_match(&bytes), "{tail:02x?}");
        }
    }

    /// L'enregistrement reel, coupe comme un segment le couperait.
    #[test]
    fn cut_record_is_truncated() {
        let bytes = hex(TCP_AS_REQUEST);
        let record = KerberosRecord::try_from(&bytes[..120]).expect("enregistrement coupe");
        assert_eq!(record.length, 235);
        assert!(record.is_truncated());
        assert!(record.rest().is_empty());
        assert_eq!(record.message.message_type, KerberosMessageType::AsReq);
        // Le nom du client et le royaume precedent la coupure ; elle tombe
        // dans la premiere composante du nom du service, dont il reste le
        // type.
        assert_eq!(
            components(record.message.client_name()),
            (1, vec![&b"johnson-pc$"[..]])
        );
        assert_eq!(record.message.realm(), Some(&b"happycraft.org"[..]));
        assert_eq!(components(record.message.service_name()), (2, vec![]));
        assert!(KerberosRecord::is_port_match(&bytes[..120]));

        // Vingt octets portent tout l'en-tete : la marque, les deux
        // etiquettes et leurs longueurs, pvno et msg-type.
        assert!(KerberosRecord::is_port_match(&bytes[..20]));
        // Coupe avant la fin de msg-type : rien a nommer.
        assert_eq!(
            KerberosRecord::try_from(&bytes[..19]),
            Err(KerberosError::TooShort {
                field: "msg-type",
                expected: 5,
                actual: 4
            })
        );
        assert_eq!(
            KerberosRecord::try_from(&bytes[..3]),
            Err(KerberosError::TooShort {
                field: "record mark",
                expected: 4,
                actual: 3
            })
        );
    }

    /// L'AS-REQ reel, modifie octet par octet.
    #[test]
    fn malformed_messages_are_refused() {
        let bytes = hex(AS_REQUEST);
        let with = |index: usize, value: u8| {
            let mut bytes = bytes.clone();
            bytes[index] = value;
            KerberosMessage::try_from(bytes.as_slice()).map(|_| ())
        };
        // L'etiquette : aucune des dix de la RFC 4120.
        assert_eq!(with(0, 0x69), Err(KerberosError::UnknownMessageTag(0x69)));
        assert_eq!(with(0, 0x30), Err(KerberosError::UnknownMessageTag(0x30)));
        // Un TGS-REQ dont msg-type dit AS-REQ.
        assert_eq!(
            with(0, 0x6c),
            Err(KerberosError::MessageTypeMismatch { expected: 12 })
        );
        assert_eq!(
            with(17, 12),
            Err(KerberosError::MessageTypeMismatch { expected: 10 })
        );
        // Un AS-REP range pvno en [0] : ici il est en [1].
        assert_eq!(
            with(0, 0x6b),
            Err(KerberosError::UnexpectedTag {
                field: "pvno",
                expected: 0xa0,
                actual: 0xa1
            })
        );
        assert_eq!(with(12, 4), Err(KerberosError::InvalidProtocolVersion));
        assert_eq!(
            with(4, 0x31),
            Err(KerberosError::UnexpectedTag {
                field: "sequence",
                expected: 0x30,
                actual: 0x31
            })
        );
        // Longueur indefinie, ou sur plus de quatre octets.
        assert_eq!(
            with(1, 0x80),
            Err(KerberosError::InvalidLength { field: "message" })
        );
        assert_eq!(
            with(1, 0x85),
            Err(KerberosError::InvalidLength { field: "message" })
        );
        // La SEQUENCE ne remplit pas le message, ou en deborde.
        assert_eq!(
            with(7, 0x16),
            Err(KerberosError::SequenceLengthMismatch {
                message: 283,
                sequence: 282
            })
        );
        assert_eq!(
            with(7, 0x18),
            Err(KerberosError::LengthOverflow {
                field: "sequence",
                length: 284,
                available: 283
            })
        );
        assert_eq!(
            KerberosMessage::try_from(&[][..]).map(|_| ()),
            Err(KerberosError::TooShort {
                field: "message",
                expected: 2,
                actual: 0
            })
        );

        // Un octet de trop, ou de moins, dans un datagramme.
        let mut long = bytes.clone();
        long.push(0);
        assert_eq!(message(&long).rest(), [0]);
        assert!(!KerberosMessage::is_port_match(&long));
        assert!(message(&bytes[..286]).is_truncated());
        assert!(!KerberosMessage::is_port_match(&bytes[..286]));
    }

    #[test]
    fn record_mark_announces_its_message() {
        let bytes = hex(TCP_AS_REQUEST);
        let with = |index: usize, value: u8| {
            let mut bytes = bytes.clone();
            bytes[index] = value;
            KerberosRecord::try_from(bytes.as_slice()).map(|_| ())
        };
        assert_eq!(
            with(3, 0xec),
            Err(KerberosError::RecordLengthMismatch {
                record: 236,
                message: 235
            })
        );
        // Le bit de poids fort de la marque est reserve.
        assert_eq!(
            with(0, 0x80),
            Err(KerberosError::RecordLengthMismatch {
                record: 0x8000_00eb,
                message: 235
            })
        );
    }

    /// Synthetique : les cinq types que l'echange avec le KDC ne porte pas
    /// (AP-REQ, AP-REP, KRB-SAFE, KRB-PRIV, KRB-CRED), reduits a leur
    /// en-tete et a un champ [2] vide.
    #[test]
    fn other_message_types_are_read() {
        for (code, kind) in [
            (14, KerberosMessageType::ApReq),
            (15, KerberosMessageType::ApRep),
            (20, KerberosMessageType::Safe),
            (21, KerberosMessageType::Priv),
            (22, KerberosMessageType::Cred),
        ] {
            let bytes = [
                0x60 | code,
                0x0e,
                0x30,
                0x0c,
                0xa0,
                0x03,
                0x02,
                0x01,
                0x05,
                0xa1,
                0x03,
                0x02,
                0x01,
                code,
                0xa2,
                0x00,
            ];
            let other = message(&bytes);
            assert_eq!(other.message_type, kind);
            assert_eq!(other.message_type.code(), code);
            assert_eq!(other.field(2), Some(&[][..]));
            // Les lectures de l'echange avec le KDC ne s'y appliquent pas.
            assert_eq!(other.realm(), None);
            assert_eq!(other.client_realm(), None);
            assert_eq!(other.client_name(), None);
            assert_eq!(other.service_name(), None);
            assert_eq!(other.error_code(), None);
        }
    }
}
