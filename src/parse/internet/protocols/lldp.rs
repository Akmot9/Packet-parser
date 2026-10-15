// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! LLDP, Link Layer Discovery Protocol (IEEE 802.1AB) : chaque equipement
//! annonce a ses voisins directs, en multicast Ethernet (EtherType
//! `0x88CC`), qui il est — chassis, port, nom, description, capacites,
//! adresses de gestion — et, par des TLV d'organisation, ce que PROFINET,
//! IEEE 802.1, IEEE 802.3 ou LLDP-MED veulent y ajouter. Sans IP ni
//! transport, la trame se decode dans la couche internet, comme GOOSE et
//! PTP.
//!
//! Le LLDPDU est une suite de TLV (sept bits de type, neuf de longueur)
//! qui s'ouvre sur Chassis ID, Port ID et Time To Live, dans cet ordre, et
//! se clot sur un TLV End of LLDPDU ; ce qui le suit est le bourrage d'une
//! trame Ethernet courte. Le decodeur garde chaque TLV, valeur empruntee a
//! la trame, et lit la structure des TLV de base et l'en-tete (OUI,
//! sous-type) des TLV d'organisation.

use std::{
    convert::TryFrom,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use crate::{
    checks::internet::lldp::{
        MANAGEMENT_ADDRESS_FIELD_LENGTHS, MANAGEMENT_OID_MAX_LENGTH, MANDATORY_TLVS,
        TLV_END_OF_LLDPDU, TLV_HEADER_LENGTH, TLV_MANAGEMENT_ADDRESS,
        TLV_ORGANIZATIONALLY_SPECIFIC, TLV_PORT_DESCRIPTION, TLV_SYSTEM_CAPABILITIES,
        TLV_SYSTEM_DESCRIPTION, TLV_SYSTEM_NAME, split_tlv, validate_tlv_length,
    },
    errors::internet::lldp::LldpParseError,
    parse::{application::protocols::bounded_capacity, data_link::mac_addres::MacAddress},
};

/// Sous-type d'adresse reseau (registre IANA des familles d'adresses) d'un
/// identifiant ou d'une adresse de gestion : IPv4 (1), IPv6 (2).
fn network_address(family: u8, address: &[u8]) -> Option<IpAddr> {
    match (family, address.len()) {
        (1, 4) => Some(IpAddr::V4(Ipv4Addr::new(
            address[0], address[1], address[2], address[3],
        ))),
        (2, 16) => {
            let octets: [u8; 16] = address.try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

/// L'identifiant du chassis (TLV 1) ou du port (TLV 2) : un sous-type et ses
/// octets.
///
/// ```mermaid
/// ---
/// title: LldpId
/// ---
/// packet-beta
/// 0-6: "TLV type"
/// 7-15: "TLV length"
/// 16-23: "Subtype"
/// 24-63: "Id (1 to 255 bytes)"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct LldpId<'a> {
    /// Chassis ID : 1 composant de chassis, 2 alias d'interface, 3 composant
    /// de port, 4 adresse MAC, 5 adresse reseau, 6 nom d'interface, 7
    /// attribue localement. Port ID : 1 alias d'interface, 2 composant de
    /// port, 3 adresse MAC, 4 adresse reseau, 5 nom d'interface, 6
    /// identifiant de circuit d'agent, 7 attribue localement.
    pub subtype: u8,
    pub id: &'a [u8],
}

impl<'a> LldpId<'a> {
    /// L'identifiant en texte, quand il est de l'UTF-8.
    pub fn as_text(&self) -> Option<&'a str> {
        std::str::from_utf8(self.id).ok()
    }

    /// L'adresse MAC d'un identifiant de six octets.
    pub fn as_mac(&self) -> Option<MacAddress> {
        self.id.try_into().ok().map(MacAddress)
    }

    /// L'adresse reseau : une famille IANA puis l'adresse.
    pub fn as_network_address(&self) -> Option<IpAddr> {
        let (&family, address) = self.id.split_first()?;
        network_address(family, address)
    }
}

/// Chassis ID dont le sous-type est une adresse MAC.
pub const CHASSIS_ID_MAC_ADDRESS: u8 = 4;
/// Chassis ID dont le sous-type est une adresse reseau.
pub const CHASSIS_ID_NETWORK_ADDRESS: u8 = 5;
/// Port ID dont le sous-type est une adresse MAC.
pub const PORT_ID_MAC_ADDRESS: u8 = 3;
/// Port ID dont le sous-type est une adresse reseau.
pub const PORT_ID_NETWORK_ADDRESS: u8 = 4;

/// Un TLV du LLDPDU : son type et sa valeur, empruntee a la trame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct LldpTlv<'a> {
    pub tlv_type: u8,
    pub value: &'a [u8],
}

impl<'a> LldpTlv<'a> {
    /// Le nom du type de TLV (IEEE 802.1AB §8.4).
    pub fn type_name(&self) -> &'static str {
        match self.tlv_type {
            0 => "End of LLDPDU",
            1 => "Chassis ID",
            2 => "Port ID",
            3 => "Time To Live",
            4 => "Port Description",
            5 => "System Name",
            6 => "System Description",
            7 => "System Capabilities",
            8 => "Management Address",
            127 => "Organizationally Specific",
            _ => "Reserved",
        }
    }

    /// La valeur en texte, quand elle est de l'UTF-8.
    pub fn as_text(&self) -> Option<&'a str> {
        std::str::from_utf8(self.value).ok()
    }
}

/// Capacites d'un equipement (TLV 7) : ce qu'il sait faire et ce qui est
/// active, un bit par fonction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SystemCapabilities {
    pub capabilities: u16,
    pub enabled: u16,
}

impl SystemCapabilities {
    pub const OTHER: u16 = 0x0001;
    pub const REPEATER: u16 = 0x0002;
    pub const BRIDGE: u16 = 0x0004;
    pub const WLAN_ACCESS_POINT: u16 = 0x0008;
    pub const ROUTER: u16 = 0x0010;
    pub const TELEPHONE: u16 = 0x0020;
    pub const DOCSIS_CABLE_DEVICE: u16 = 0x0040;
    pub const STATION_ONLY: u16 = 0x0080;
    pub const C_VLAN_COMPONENT: u16 = 0x0100;
    pub const S_VLAN_COMPONENT: u16 = 0x0200;
    pub const TWO_PORT_MAC_RELAY: u16 = 0x0400;

    /// La fonction est-elle activee ?
    pub fn is_enabled(&self, capability: u16) -> bool {
        self.enabled & capability != 0
    }
}

/// Une adresse de gestion (TLV 8) : ou administrer l'equipement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ManagementAddress<'a> {
    /// Famille d'adresse IANA : 1 IPv4, 2 IPv6, 6 MAC...
    pub address_subtype: u8,
    pub address: &'a [u8],
    /// Numerotation de l'interface : 1 inconnue, 2 ifIndex, 3 port systeme.
    pub interface_subtype: u8,
    pub interface_number: u32,
    /// L'OID de l'objet SNMP qui decrit l'adresse, souvent vide.
    pub oid: &'a [u8],
}

impl<'a> TryFrom<&'a [u8]> for ManagementAddress<'a> {
    type Error = LldpParseError;

    /// La valeur d'un TLV 8 : longueur, sous-type et adresse, sous-type et
    /// numero d'interface, longueur et OID — qui doivent la paver.
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        let invalid = || LldpParseError::InvalidManagementAddress;
        let length = usize::from(*value.first().ok_or_else(invalid)?);
        if !MANAGEMENT_ADDRESS_FIELD_LENGTHS.contains(&length) {
            return Err(invalid());
        }
        let field = value.get(1..1 + length).ok_or_else(invalid)?;
        let [interface_subtype, n0, n1, n2, n3, oid_length, ref oid @ ..] = value[1 + length..]
        else {
            return Err(invalid());
        };
        if oid.len() != usize::from(oid_length) || oid.len() > MANAGEMENT_OID_MAX_LENGTH {
            return Err(invalid());
        }
        Ok(ManagementAddress {
            address_subtype: field[0],
            address: &field[1..],
            interface_subtype,
            interface_number: u32::from_be_bytes([n0, n1, n2, n3]),
            oid,
        })
    }
}

impl ManagementAddress<'_> {
    /// L'adresse IP, pour les familles IPv4 et IPv6.
    pub fn ip(&self) -> Option<IpAddr> {
        network_address(self.address_subtype, self.address)
    }
}

/// Un TLV d'organisation (type 127) : l'OUI de l'organisation qui le
/// definit, son sous-type et son information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct OrganizationTlv<'a> {
    pub oui: [u8; 3],
    pub subtype: u8,
    pub info: &'a [u8],
}

impl OrganizationTlv<'_> {
    /// L'organisation, pour les OUI des TLV les plus courants.
    pub fn organization(&self) -> Option<&'static str> {
        Some(match self.oui {
            [0x00, 0x80, 0xc2] => "IEEE 802.1",
            [0x00, 0x12, 0x0f] => "IEEE 802.3",
            [0x00, 0x0e, 0xcf] => "PROFINET",
            [0x00, 0x12, 0xbb] => "LLDP-MED",
            [0x00, 0x80, 0x63] => "Hirschmann",
            [0x00, 0x01, 0x42] => "Cisco",
            _ => return None,
        })
    }
}

/// Un LLDPDU (IEEE 802.1AB §8) : ses trois TLV obligatoires et tous ses
/// TLV, dans l'ordre du fil.
///
/// ```mermaid
/// ---
/// title: LldpPacket
/// ---
/// packet-beta
/// 0-15: "Chassis ID TLV (4 to 258 bytes)"
/// 16-31: "Port ID TLV (4 to 258 bytes)"
/// 32-63: "Time To Live TLV (4 bytes)"
/// 64-79: "Optional TLVs (variable)"
/// 80-95: "End of LLDPDU TLV (2 bytes)"
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LldpPacket<'a> {
    pub chassis_id: LldpId<'a>,
    pub port_id: LldpId<'a>,
    /// Duree de validite de l'annonce, en secondes ; 0 retire l'equipement.
    pub time_to_live: u16,
    /// Tous les TLV, les trois obligatoires compris, jusqu'au TLV End of
    /// LLDPDU inclus quand la trame en porte un.
    pub tlvs: Vec<LldpTlv<'a>>,
    /// Ce qui suit le TLV End of LLDPDU : le bourrage d'une trame courte.
    pub padding: &'a [u8],
}

impl<'a> LldpPacket<'a> {
    /// Le premier TLV d'un type.
    pub fn tlv(&self, tlv_type: u8) -> Option<LldpTlv<'a>> {
        self.tlvs
            .iter()
            .copied()
            .find(|tlv| tlv.tlv_type == tlv_type)
    }

    /// Description du port (TLV 4), en texte.
    pub fn port_description(&self) -> Option<&'a str> {
        self.tlv(TLV_PORT_DESCRIPTION)?.as_text()
    }

    /// Nom de l'equipement (TLV 5), en texte.
    pub fn system_name(&self) -> Option<&'a str> {
        self.tlv(TLV_SYSTEM_NAME)?.as_text()
    }

    /// Description de l'equipement (TLV 6) : constructeur, modele, logiciel.
    pub fn system_description(&self) -> Option<&'a str> {
        self.tlv(TLV_SYSTEM_DESCRIPTION)?.as_text()
    }

    /// Capacites de l'equipement (TLV 7).
    pub fn system_capabilities(&self) -> Option<SystemCapabilities> {
        let value = self.tlv(TLV_SYSTEM_CAPABILITIES)?.value;
        let [c0, c1, e0, e1] = *value else {
            return None;
        };
        Some(SystemCapabilities {
            capabilities: u16::from_be_bytes([c0, c1]),
            enabled: u16::from_be_bytes([e0, e1]),
        })
    }

    /// Les adresses de gestion (TLV 8), dans l'ordre du fil.
    pub fn management_addresses(&self) -> impl Iterator<Item = ManagementAddress<'a>> + '_ {
        self.tlvs
            .iter()
            .filter(|tlv| tlv.tlv_type == TLV_MANAGEMENT_ADDRESS)
            .filter_map(|tlv| ManagementAddress::try_from(tlv.value).ok())
    }

    /// Les TLV d'organisation (type 127), dans l'ordre du fil.
    pub fn organization_tlvs(&self) -> impl Iterator<Item = OrganizationTlv<'a>> + '_ {
        self.tlvs
            .iter()
            .filter(|tlv| tlv.tlv_type == TLV_ORGANIZATIONALLY_SPECIFIC)
            .filter_map(|tlv| {
                let [o0, o1, o2, subtype, ref info @ ..] = *tlv.value else {
                    return None;
                };
                Some(OrganizationTlv {
                    oui: [o0, o1, o2],
                    subtype,
                    info,
                })
            })
    }
}

impl<'a> TryFrom<&'a [u8]> for LldpPacket<'a> {
    type Error = LldpParseError;

    /// Decode le LLDPDU qui suit l'EtherType `0x88CC`.
    fn try_from(payload: &'a [u8]) -> Result<Self, Self::Error> {
        let mut tlvs = Vec::with_capacity(bounded_capacity(16, payload.len(), TLV_HEADER_LENGTH));
        let mut offset = 0;
        let mut end = None;
        while offset < payload.len() {
            let (tlv_type, value, next) = split_tlv(payload, offset)?;
            let position = tlvs.len();
            if let Some(&expected) = MANDATORY_TLVS.get(position)
                && tlv_type != expected
            {
                return Err(LldpParseError::MissingMandatoryTlv {
                    position,
                    expected,
                    found: Some(tlv_type),
                });
            }
            validate_tlv_length(tlv_type, value.len())?;
            if tlv_type == TLV_MANAGEMENT_ADDRESS {
                ManagementAddress::try_from(value)?;
            }
            tlvs.push(LldpTlv { tlv_type, value });
            offset = next;
            if tlv_type == TLV_END_OF_LLDPDU {
                end = Some(offset);
                break;
            }
        }
        if let Some(&expected) = MANDATORY_TLVS.get(tlvs.len()) {
            return Err(LldpParseError::MissingMandatoryTlv {
                position: tlvs.len(),
                expected,
                found: None,
            });
        }
        let id = |tlv: LldpTlv<'a>| LldpId {
            subtype: tlv.value[0],
            id: &tlv.value[1..],
        };
        let ttl = tlvs[2].value;
        Ok(LldpPacket {
            chassis_id: id(tlvs[0]),
            port_id: id(tlvs[1]),
            time_to_live: u16::from_be_bytes([ttl[0], ttl[1]]),
            padding: &payload[end.unwrap_or(payload.len())..],
            tlvs,
        })
    }
}

impl LldpPacket<'_> {
    /// Sonde LLDP sans EtherType (`Internet::try_from`) : en plus du
    /// decodage, un TLV End of LLDPDU et un bourrage nul.
    pub(crate) fn is_blind_match(payload: &[u8]) -> bool {
        LldpPacket::try_from(payload).is_ok_and(|packet| {
            packet
                .tlvs
                .last()
                .is_some_and(|tlv| tlv.tlv_type == TLV_END_OF_LLDPDU)
                && packet.padding.iter().all(|&byte| byte == 0)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `protocols/profinet/cisagov_profinet_io_cm_mixed_1.pcap`, trame 29,
    /// apres l'EtherType : un commutateur Siemens SCALANCE X208, chassis et
    /// port attribues localement, une adresse de gestion IPv4 nulle, deux
    /// TLV PROFINET (etat du port, MAC du chassis) et un TLV IEEE 802.3.
    const SCALANCE: &str = concat!(
        "0214077369656d656e732d783230382d737769746368040907706f72742d303034060200140c",
        "325369656d656e732041472053494d41544943205337204d554c5449504f5254205343414c41",
        "4e43452058203230302046414d0e040080008010140501000000000200000004082b06010401",
        "81c06efe08000ecf0200000000fe0a000ecf05000e8cef75c5fe0900120f01036c0000100000",
    );

    /// `The-Ultimate-PCAP.pcapng`, trame 2165, apres l'EtherType : un Cisco
    /// C2960, chassis MAC, port nomme, deux adresses de gestion (IPv4 et
    /// IPv6), une description de 243 octets.
    const C2960: &str = concat!(
        "02070400211bae31800406054769302f31060200780a1943434e502d4c41422d53312e776562",
        "65726e65747a2e6e65740cf3436973636f20494f5320536f6674776172652c20433239363020",
        "536f667477617265202843323936302d4c414e424153454b392d4d292c2056657273696f6e20",
        "31352e302832295345392c2052454c4541534520534f4654574152452028666331290a546563",
        "686e6963616c20537570706f72743a20687474703a2f2f7777772e636973636f2e636f6d2f74",
        "656368737570706f72740a436f707972696768742028632920313938362d3230313520627920",
        "436973636f2053797374656d732c20496e632e0a436f6d70696c6564205475652030312d4465",
        "632d31352030373a30372062792070726f645f72656c5f7465616d0812476967616269744574",
        "6865726e6574302f310e0400040004100c0501c0a8790a030000000000101811022003005160",
        "1201210000000000000010030000000000fe0900120f0103800000000000",
    );

    fn decode(hex_payload: &str) -> Vec<u8> {
        hex::decode(hex_payload).expect("valid hex")
    }

    #[test]
    fn test_scalance_announcement() {
        let payload = decode(SCALANCE);
        let packet = LldpPacket::try_from(payload.as_slice()).expect("LLDPDU");
        assert_eq!(packet.chassis_id.subtype, 7);
        assert_eq!(packet.chassis_id.as_text(), Some("siemens-x208-switch"));
        assert_eq!(packet.port_id.as_text(), Some("port-004"));
        assert_eq!(packet.time_to_live, 20);
        assert_eq!(
            packet.system_description(),
            Some("Siemens AG SIMATIC S7 MULTIPORT SCALANCE X 200 FAM")
        );
        assert_eq!(packet.system_name(), None);
        let capabilities = packet.system_capabilities().expect("capacites");
        assert!(capabilities.is_enabled(SystemCapabilities::STATION_ONLY));
        let addresses: Vec<_> = packet.management_addresses().collect();
        assert_eq!(addresses.len(), 1);
        assert_eq!(addresses[0].ip(), Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert_eq!(
            (
                addresses[0].interface_subtype,
                addresses[0].interface_number
            ),
            (2, 4)
        );
        assert_eq!(addresses[0].oid.len(), 8);
        let organizations: Vec<_> = packet
            .organization_tlvs()
            .map(|tlv| (tlv.organization(), tlv.subtype))
            .collect();
        assert_eq!(
            organizations,
            [
                (Some("PROFINET"), 2),
                (Some("PROFINET"), 5),
                (Some("IEEE 802.3"), 1)
            ]
        );
        assert_eq!(
            packet
                .tlvs
                .iter()
                .map(|tlv| tlv.tlv_type)
                .collect::<Vec<_>>(),
            [1, 2, 3, 6, 7, 8, 127, 127, 127, 0]
        );
        assert!(packet.padding.is_empty());
        assert!(LldpPacket::is_blind_match(&payload));
    }

    #[test]
    fn test_cisco_announcement() {
        let payload = decode(C2960);
        let packet = LldpPacket::try_from(payload.as_slice()).expect("LLDPDU");
        assert_eq!(packet.chassis_id.subtype, CHASSIS_ID_MAC_ADDRESS);
        assert_eq!(
            packet.chassis_id.as_mac(),
            Some(MacAddress([0x00, 0x21, 0x1b, 0xae, 0x31, 0x80]))
        );
        assert_eq!(
            (packet.port_id.subtype, packet.port_id.as_text()),
            (5, Some("Gi0/1"))
        );
        assert_eq!(packet.time_to_live, 120);
        assert_eq!(packet.system_name(), Some("CCNP-LAB-S1.webernetz.net"));
        assert_eq!(packet.port_description(), Some("GigabitEthernet0/1"));
        assert_eq!(packet.tlv(6).map(|tlv| tlv.value.len()), Some(243));
        let ips: Vec<_> = packet
            .management_addresses()
            .filter_map(|a| a.ip())
            .collect();
        assert_eq!(
            ips,
            [
                "192.168.121.10".parse::<IpAddr>().unwrap(),
                "2003:51:6012:121::10".parse().unwrap()
            ]
        );
        let capabilities = packet.system_capabilities().unwrap();
        assert!(capabilities.is_enabled(SystemCapabilities::BRIDGE));
        assert!(!capabilities.is_enabled(SystemCapabilities::ROUTER));
    }

    #[test]
    fn test_management_address_fields() {
        // Le Cisco C2960 : 192.168.121.10, numero de port systeme 0, sans OID.
        let value = [0x05, 0x01, 0xc0, 0xa8, 0x79, 0x0a, 0x03, 0, 0, 0, 0, 0x00];
        let address = ManagementAddress::try_from(&value[..]).expect("adresse");
        assert_eq!(
            address.ip(),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 121, 10)))
        );
        assert_eq!(
            (address.interface_subtype, address.interface_number),
            (3, 0)
        );
        assert!(address.oid.is_empty());
        // Un OID annonce plus long que la valeur, une adresse trop courte, un
        // octet de trop.
        for value in [
            &[0x05, 0x01, 1, 2, 3, 4, 2, 0, 0, 0, 1, 0x03, 1][..],
            &[0x01, 0x01, 2, 0, 0, 0, 1, 0x00][..],
            &[0x05, 0x01, 1, 2, 3, 4, 2, 0, 0, 0, 1, 0x00, 0xff][..],
        ] {
            assert_eq!(
                ManagementAddress::try_from(value),
                Err(LldpParseError::InvalidManagementAddress),
                "{value:02x?}"
            );
        }
    }

    #[test]
    fn test_padding_and_missing_end() {
        let mut payload = decode(SCALANCE);
        payload.extend([0; 6]);
        let packet = LldpPacket::try_from(payload.as_slice()).expect("bourrage");
        assert_eq!(packet.padding, &[0; 6]);
        assert!(LldpPacket::is_blind_match(&payload));
        // Un bourrage non nul se decode, mais ne passe pas la sonde aveugle.
        payload.push(0x55);
        assert!(LldpPacket::try_from(payload.as_slice()).is_ok());
        assert!(!LldpPacket::is_blind_match(&payload));
        // Sans TLV End, les TLV courent jusqu'a la fin de la trame.
        let payload = decode(SCALANCE);
        let without_end = &payload[..payload.len() - 2];
        let packet = LldpPacket::try_from(without_end).expect("sans End");
        assert_eq!(packet.tlvs.last().map(|tlv| tlv.tlv_type), Some(127));
        assert!(!LldpPacket::is_blind_match(without_end));
    }

    #[test]
    fn test_mandatory_tlvs_and_lengths() {
        let payload = decode(SCALANCE);
        // Port ID avant Chassis ID.
        let swapped = [&payload[22..33], &payload[..22], &payload[33..]].concat();
        assert_eq!(
            LldpPacket::try_from(swapped.as_slice()),
            Err(LldpParseError::MissingMandatoryTlv {
                position: 0,
                expected: 1,
                found: Some(2)
            })
        );
        // Une trame qui s'arrete apres le Port ID.
        assert_eq!(
            LldpPacket::try_from(&payload[..33]),
            Err(LldpParseError::MissingMandatoryTlv {
                position: 2,
                expected: 3,
                found: None
            })
        );
        // Un TTL de trois octets, un TLV qui deborde.
        let mut bad_ttl = payload.clone();
        bad_ttl[34] = 0x03;
        assert!(LldpPacket::try_from(bad_ttl.as_slice()).is_err());
        assert!(LldpPacket::try_from(&payload[..payload.len() - 3]).is_err());
        assert!(LldpPacket::try_from(&[][..]).is_err());
    }
}
