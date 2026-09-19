// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! IOR (Interoperable Object Reference, CORBA formal/04-03-12 §13.6) : la
//! reference d'objet que GIOP transporte dans un `LOCATION_FORWARD`, un
//! `OBJECT_FORWARD` ou une `TargetAddress::ReferenceAddr`. C'est le champ qui
//! dit **vers quel hote et quel port** le client est redirige.

use super::cursor::Cursor;
use crate::{
    checks::application::giop::validate_profile_count, errors::application::giop::GiopParseError,
};

/// `IOP::TAG_INTERNET_IOP` : profil IIOP (hote, port, object key).
pub const TAG_INTERNET_IOP: u32 = 0;
/// `IOP::TAG_MULTIPLE_COMPONENTS`.
pub const TAG_MULTIPLE_COMPONENTS: u32 = 1;
/// `IOP::TAG_UIPMC` : profil multicast MIOP (groupe UDP).
pub const TAG_UIPMC: u32 = 3;

/// `IOP::TaggedProfile` : un tag et son encapsulation brute (zero-copy).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TaggedProfile<'a> {
    pub tag: u32,
    /// Encapsulation CDR du profil, octet d'endianness compris.
    pub profile_data: &'a [u8],
}

/// `IOP::IOR` : type_id du Repository et liste de profils.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Ior<'a> {
    /// Repository ID, par exemple `IDL:omg.org/CosNaming/NamingContext:1.0`.
    /// Vide pour une reference nil.
    pub type_id: &'a str,
    pub profiles: Vec<TaggedProfile<'a>>,
}

/// `IIOP::ProfileBody` (§15.7.2), decode depuis un profil
/// [`TAG_INTERNET_IOP`]. Les `components` de IIOP 1.1+ ne sont pas decodes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct IiopProfile<'a> {
    pub major_version: u8,
    pub minor_version: u8,
    pub host: &'a str,
    pub port: u16,
    pub object_key: &'a [u8],
}

impl<'a> TaggedProfile<'a> {
    pub(super) fn parse(cur: &mut Cursor<'a>) -> Result<Self, GiopParseError> {
        let tag = cur.read_u32()?;
        let profile_data = cur.read_octet_sequence()?;
        Ok(TaggedProfile { tag, profile_data })
    }

    /// Decode le profil IIOP. `None` si le tag n'est pas
    /// [`TAG_INTERNET_IOP`] ou si l'encapsulation est illisible : un profil
    /// illisible ne doit pas faire echouer le message qui le porte.
    pub fn iiop(&self) -> Option<IiopProfile<'a>> {
        if self.tag != TAG_INTERNET_IOP {
            return None;
        }
        let mut cur = Cursor::encapsulation(self.profile_data).ok()?;
        let major_version = cur.read_u8().ok()?;
        let minor_version = cur.read_u8().ok()?;
        let host = cur.read_str().ok()?;
        let port = cur.read_u16().ok()?;
        let object_key = cur.read_octet_sequence().ok()?;
        Some(IiopProfile {
            major_version,
            minor_version,
            host,
            port,
            object_key,
        })
    }
}

impl<'a> Ior<'a> {
    pub(super) fn parse(cur: &mut Cursor<'a>) -> Result<Self, GiopParseError> {
        let type_id = cur.read_str()?;
        let count = cur.read_u32()? as usize;
        // Borne le compteur avant toute allocation ou boucle.
        validate_profile_count(count, cur.remaining())?;
        let mut profiles = Vec::with_capacity(count);
        for _ in 0..count {
            profiles.push(TaggedProfile::parse(cur)?);
        }
        Ok(Ior { type_id, profiles })
    }

    /// Premier profil IIOP lisible : l'hote et le port vers lesquels la
    /// reference pointe.
    pub fn iiop(&self) -> Option<IiopProfile<'a>> {
        self.profiles.iter().find_map(TaggedProfile::iiop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encapsulation IIOP 1.0 big-endian : host "h", port 2809, key "k".
    fn iiop_profile_be() -> Vec<u8> {
        let mut p = vec![0x00, 1, 0, 0]; // endianness BE, version 1.0, padding
        p.extend_from_slice(&2u32.to_be_bytes()); // host len ("h" + NUL)
        p.extend_from_slice(b"h\0");
        p.extend_from_slice(&2809u16.to_be_bytes()); // port, deja aligne sur 2
        p.extend_from_slice(&1u32.to_be_bytes()); // object_key len
        p.push(b'k');
        p
    }

    #[test]
    fn iiop_profile_decodes_host_port_and_key() {
        let data = iiop_profile_be();
        let profile = TaggedProfile {
            tag: TAG_INTERNET_IOP,
            profile_data: &data,
        };
        let iiop = profile.iiop().expect("profil IIOP lisible");
        assert_eq!((iiop.major_version, iiop.minor_version), (1, 0));
        assert_eq!(iiop.host, "h");
        assert_eq!(iiop.port, 2809);
        assert_eq!(iiop.object_key, b"k");
    }

    #[test]
    fn non_iiop_or_unreadable_profile_yields_none() {
        let data = iiop_profile_be();
        assert!(
            TaggedProfile {
                tag: TAG_UIPMC,
                profile_data: &data
            }
            .iiop()
            .is_none()
        );
        assert!(
            TaggedProfile {
                tag: TAG_INTERNET_IOP,
                profile_data: &data[..5]
            }
            .iiop()
            .is_none()
        );
    }

    #[test]
    fn ior_rejects_a_forged_profile_count_before_allocating() {
        let mut body = Vec::new();
        body.extend_from_slice(&1u32.to_be_bytes()); // type_id : ""
        body.push(0);
        body.extend_from_slice(&[0, 0, 0]); // padding
        body.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes()); // compte forge

        let mut cur = Cursor::new(&body, false);
        assert!(matches!(
            Ior::parse(&mut cur),
            Err(GiopParseError::InvalidProfileCount {
                count: 0xFFFF_FFFF,
                available: 0
            })
        ));
    }
}
