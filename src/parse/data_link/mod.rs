// parsed_packet/data_link/mod.rs

pub mod mac_addres;
use mac_addres::MacAddress;

pub mod ethertype;

use crate::{checks::data_link::validate_data_link_length, errors::data_link::DataLinkError};
use ethertype::Ethertype;

#[derive(Debug)]
pub struct DataLink<'a> {
    pub destination_mac: MacAddress,
    pub source_mac: MacAddress,
    pub ethertype: Ethertype,
    pub payload: &'a [u8],
}

impl<'a> TryFrom<&'a [u8]> for DataLink<'a> {
    type Error = DataLinkError;

    fn try_from(packets: &'a [u8]) -> Result<Self, Self::Error> {
        validate_data_link_length(packets)?;

        Ok(DataLink {
            destination_mac: MacAddress::try_from(&packets[0..6])?,
            source_mac: MacAddress::try_from(&packets[6..12])?,
            ethertype: Ethertype::from(u16::from_be_bytes([packets[12], packets[13]])),
            payload: &packets[14..],
        })
    }
}

#[cfg(test)]
mod tests {

    use crate::errors::data_link::DataLinkError;
    use crate::parse::data_link::mac_addres::MacAddress;
    use crate::parse::data_link::{DataLink, Ethertype};

    #[test]
    fn test_datalink_try_from_valid_packet() {
        let raw_packet: [u8; 18] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Destination MAC
            0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, // Source MAC
            0x08, 0x00, // Ethertype (IPv4)
            0x45, 0x00, 0x00, 0x54, // Payload (IPv4 Header fragment)
        ];

        let datalink =
            DataLink::try_from(raw_packet.as_ref()).expect("Failed to parse valid packet");

        assert_eq!(
            datalink.destination_mac,
            MacAddress::try_from(&raw_packet[0..6]).unwrap()
        );
        assert_eq!(
            datalink.source_mac,
            MacAddress::try_from(&raw_packet[6..12]).unwrap()
        );
        assert_eq!(datalink.ethertype, Ethertype::from(0x0800)); // IPv4 Ethertype
        assert_eq!(datalink.payload, &raw_packet[14..]);
    }

    #[test]
    fn test_datalink_try_from_invalid_length() {
        let short_packet: [u8; 10] = [0x00; 10];

        let result = DataLink::try_from(short_packet.as_ref());
        assert!(matches!(result, Err(DataLinkError::DataLinkTooShort(_))));
    }

    #[test]
    fn test_datalink_try_from_ethertype_parsing() {
        let raw_packet: [u8; 18] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Destination MAC
            0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, // Source MAC
            0x86, 0xDD, // Ethertype (IPv6)
            0x60, 0x00, 0x00, 0x00, // IPv6 Header fragment
        ];

        let datalink = DataLink::try_from(raw_packet.as_ref()).unwrap();
        assert_eq!(datalink.ethertype, Ethertype::from(0x86DD)); // IPv6 Ethertype
    }

    #[test]
    fn test_datalink_try_from_ethertype_unknown() {
        let raw_packet: [u8; 18] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Destination MAC
            0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, // Source MAC
            0xAB, 0xCD, // Inconnu Ethertype
            0x12, 0x34, 0x56, 0x78, // Payload quelconque
        ];

        let datalink = DataLink::try_from(raw_packet.as_ref()).unwrap();
        assert_eq!(datalink.ethertype, Ethertype::from(0xABCD)); // Ethertype inconnu, mais accepté
    }
}
