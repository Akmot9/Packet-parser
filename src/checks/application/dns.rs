// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use crate::errors::application::dns::{DnsHeaderError, DnsPacketError, DnsQueryParseError};

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

pub fn validate_and_parse_count(bytes: &[u8]) -> Result<[u16; 4], DnsHeaderError> {
    let questions_count = u16::from_be_bytes([bytes[0], bytes[1]]);
    let answers_count = u16::from_be_bytes([bytes[2], bytes[3]]);
    let authorities_count = u16::from_be_bytes([bytes[4], bytes[5]]);
    let additionals_count = u16::from_be_bytes([bytes[6], bytes[7]]);

    if questions_count == 0 && (answers_count > 0 || authorities_count > 0 || additionals_count > 0)
    {
        return Err(DnsHeaderError::InvalidCounts);
    }

    Ok([
        questions_count,
        answers_count,
        authorities_count,
        additionals_count,
    ])
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
