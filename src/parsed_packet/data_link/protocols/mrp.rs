use std::fmt;
use uuid::Uuid;

use crate::{errors::data_link::protocol::MRPParseError, parsed_packet::data_link::mac_addres::MacAddress};

#[derive(Debug, PartialEq)]
pub struct MRPData {
    pub version: u16,
    pub tlv_headers: Vec<MRPTLVHeader>,
}

#[derive(Debug, PartialEq)]
pub struct MRPTLVHeader {
    pub tlv_type: u8,
    pub length: u8,
    pub data: MRPTLVData,
}

#[derive(Debug, PartialEq)]
pub enum MRPTLVData {
    MRPTest(MRPTestData),
    MRPCommon(MRPCommonData),
    MRPOption(MRPOptionData),
    MRPEnd,
}

#[derive(Debug, PartialEq)]
pub struct MRPTestData {
    pub prio: u16,
    pub sa: MacAddress,
    pub port_role: u16,
    pub ring_state: u16,
    pub transition: u16,
    pub timestamp: u32,
}

#[derive(Debug, PartialEq)]
pub struct MRPCommonData {
    pub sequence_id: u16,
    pub domain_uuid: Uuid,
}

#[derive(Debug, PartialEq)]
pub struct MRPOptionData {
    pub manufacturer_oui: [u8; 3],
    pub ed1_type: u8,
    pub ed1_manufacturer_data: u16,
}

use std::convert::TryFrom;

impl TryFrom<&[u8]> for MRPData {
    type Error = MRPParseError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() < 2 {
            return Err(MRPParseError::InsufficientData {
                required: 2,
                found: data.len(),
            });
        }

        let version = parse_u16(&data[0..2]);
        let mut offset = 2;
        let mut tlv_headers = Vec::new();

        while offset < data.len() {
            if offset + 2 > data.len() {
                return Err(MRPParseError::InsufficientData {
                    required: offset + 2,
                    found: data.len(),
                });
            }

            let tlv_type = data[offset];
            let length = data[offset + 1] as usize;

            if offset + 2 + length > data.len() {
                return Err(MRPParseError::InsufficientData {
                    required: offset + 2 + length,
                    found: data.len(),
                });
            }

            let tlv_data = &data[offset + 2..offset + 2 + length];

            let tlv_header = match tlv_type {
                0x02 => MRPTLVHeader {
                    tlv_type,
                    length: length as u8,
                    data: MRPTLVData::MRPTest(MRPTestData {
                        prio: parse_u16(&tlv_data[0..2]),
                        sa: parse_mac_address(&tlv_data[2..8]),
                        port_role: parse_u16(&tlv_data[8..10]),
                        ring_state: parse_u16(&tlv_data[10..12]),
                        transition: parse_u16(&tlv_data[12..14]),
                        timestamp: parse_u32(&tlv_data[14..18]),
                    }),
                },
                0x01 => MRPTLVHeader {
                    tlv_type,
                    length: length as u8,
                    data: MRPTLVData::MRPCommon(MRPCommonData {
                        sequence_id: parse_u16(&tlv_data[0..2]),
                        domain_uuid: Uuid::from_slice(&tlv_data[2..18])
                            .map_err(|_| MRPParseError::InvalidUUID)?,
                    }),
                },
                0x7f => MRPTLVHeader {
                    tlv_type,
                    length: length as u8,
                    data: MRPTLVData::MRPOption(MRPOptionData {
                        manufacturer_oui: [tlv_data[0], tlv_data[1], tlv_data[2]],
                        ed1_type: tlv_data[3],
                        ed1_manufacturer_data: parse_u16(&tlv_data[4..6]),
                    }),
                },
                0x00 => MRPTLVHeader {
                    tlv_type,
                    length: 0,
                    data: MRPTLVData::MRPEnd,
                },
                _ => {
                    return Err(MRPParseError::UnknownTLVType { tlv_type });
                }
            };

            tlv_headers.push(tlv_header);
            offset += 2 + length;
        }

        Ok(MRPData {
            version,
            tlv_headers,
        })
    }
}

pub fn parse_mac_address(data: &[u8]) -> MacAddress {
    MacAddress::try_from(data).unwrap()
}

pub fn parse_u16(data: &[u8]) -> u16 {
    u16::from_be_bytes([data[0], data[1]])
}

pub fn parse_u32(data: &[u8]) -> u32 {
    u32::from_be_bytes([data[0], data[1], data[2], data[3]])
}

impl fmt::Display for MRPData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MRP Version: {:#06x}\n", self.version)?;
        for header in &self.tlv_headers {
            write!(f, "{}", header)?;
        }
        Ok(())
    }
}

impl fmt::Display for MRPTLVHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "  TLV Type: {:#04x}, Length: {}\n  Data:\n{}",
            self.tlv_type, self.length, self.data
        )
    }
}

impl fmt::Display for MRPTLVData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MRPTLVData::MRPTest(data) => write!(f, "{}", data),
            MRPTLVData::MRPCommon(data) => write!(f, "{}", data),
            MRPTLVData::MRPOption(data) => write!(f, "{}", data),
            MRPTLVData::MRPEnd => write!(f, "  End of MRP Data\n"),
        }
    }
}

impl fmt::Display for MRPTestData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "    MRP Test Data:\n      Prio: {:#06x}\n      SA: {}\n      Port Role: {:#06x}\n      Ring State: {:#06x}\n      Transition: {:#06x}\n      Timestamp: {:#010x}\n",
            self.prio, self.sa, self.port_role, self.ring_state, self.transition, self.timestamp
        )
    }
}

impl fmt::Display for MRPCommonData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "    MRP Common Data:\n      Sequence ID: {:#06x}\n      Domain UUID: {}\n",
            self.sequence_id, self.domain_uuid
        )
    }
}

impl fmt::Display for MRPOptionData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "    MRP Option Data:\n      Manufacturer OUI: {:02x}:{:02x}:{:02x}\n      Ed1 Type: {:#04x}\n      Ed1 Manufacturer Data: {:#06x}\n",
            self.manufacturer_oui[0],
            self.manufacturer_oui[1],
            self.manufacturer_oui[2],
            self.ed1_type,
            self.ed1_manufacturer_data
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mac_address() {
        let mac_bytes = vec![0x00, 0x0e, 0x8c, 0xe0, 0x2f, 0x22];
        let mac = parse_mac_address(&mac_bytes);
        assert_eq!(mac, MacAddress([0x00, 0x0e, 0x8c, 0xe0, 0x2f, 0x22]));
    }

    #[test]
    fn test_parse_u16() {
        let bytes = vec![0x12, 0x34];
        let value = parse_u16(&bytes);
        assert_eq!(value, 0x1234);
    }

    #[test]
    fn test_parse_u32() {
        let bytes = vec![0x12, 0x34, 0x56, 0x78];
        let value = parse_u32(&bytes);
        assert_eq!(value, 0x12345678);
    }

    #[test]
    fn test_parse_mrp_data() {
        let payload: Vec<u8> = vec![
            0x00, 0x01, 0x02, 0x12, 0xa0, 0x00, 0x00, 0x0e, 0x8c, 0xe0, 0x2f, 0x22, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x19, 0xfa, 0x3f, 0xd4, 0x01, 0x12, 0x05, 0x7e, 0xc3, 0xd6,
            0x87, 0xfe, 0x78, 0x9e, 0x03, 0xa1, 0xac, 0xdb, 0xe5, 0xbf, 0xcb, 0xbc, 0x27, 0xb6,
            0x7f, 0x06, 0x08, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let mrp_data = MRPData::try_from(payload.as_slice()).expect("Failed to parse MRP data");
        //print(!("{}", mrp_data);

        // Assertions pour vérifier que les données sont correctes
        assert_eq!(mrp_data.version, 0x0001);
        assert_eq!(mrp_data.tlv_headers.len(), 4);

        if let MRPTLVData::MRPTest(data) = &mrp_data.tlv_headers[0].data {
            assert_eq!(data.prio, 0xa000);
            assert_eq!(data.sa.to_string(), "00:0e:8c:e0:2f:22");
            assert_eq!(data.port_role, 0x0000);
            assert_eq!(data.ring_state, 0x0000);
            assert_eq!(data.transition, 0x0001);
            assert_eq!(data.timestamp, 0x19fa3fd4);
        } else {
            panic!("Expected MRPTest data");
        }

        if let MRPTLVData::MRPCommon(data) = &mrp_data.tlv_headers[1].data {
            assert_eq!(data.sequence_id, 0x057e);
            assert_eq!(
                data.domain_uuid,
                Uuid::parse_str("c3d687fe-789e-03a1-acdb-e5bfcbbc27b6").unwrap()
            );
        } else {
            panic!("Expected MRPCommon data");
        }

        if let MRPTLVData::MRPOption(data) = &mrp_data.tlv_headers[2].data {
            assert_eq!(data.manufacturer_oui, [0x08, 0x00, 0x06]);
            assert_eq!(data.ed1_type, 0x00);
            assert_eq!(data.ed1_manufacturer_data, 0x0000);
        } else {
            panic!("Expected MRPOption data");
        }

        if let MRPTLVData::MRPEnd = &mrp_data.tlv_headers[3].data {
            // Correct end
        } else {
            panic!("Expected MRPEnd data");
        }
    }

    #[test]
    fn test_insufficient_data_error() {
        let data = vec![0x00]; // Pas assez de données pour le header
        let result = MRPData::try_from(&data[..]);
        assert_eq!(
            result,
            Err(MRPParseError::InsufficientData {
                required: 2,
                found: 1
            })
        );
    }

    #[test]
    fn test_unknown_tlv_type_error() {
        let data = vec![0x00, 0x01, 0x99, 0x02, 0xaa, 0xbb];
        let result = MRPData::try_from(&data[..]);
        assert_eq!(
            result,
            Err(MRPParseError::UnknownTLVType { tlv_type: 0x99 })
        );
    }
}
