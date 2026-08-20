// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use std::fmt;

use crate::{
    checks::application::dns::{
        check_packet_length, parse_and_validate_llmnr_counts, parse_count_allow_empty_question,
        validate_and_parse_count, verify_dns_flags, verify_llmnr_flags, verify_mdns_flags,
    },
    errors::application::dns::DnsHeaderError,
};

#[derive(Debug)]
pub struct DnsHeader {
    pub transaction_id: u16,
    pub flags: u16,
    pub counts: [u16; 4], // questions_count, answers_count, authorities_count, additionals_count
}

impl TryFrom<&[u8]> for DnsHeader {
    type Error = DnsHeaderError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        check_packet_length(bytes)?;

        let transaction_id = u16::from_be_bytes([bytes[0], bytes[1]]);
        // println!("transaction_id: {}", transaction_id);
        let flags = verify_dns_flags(u16::from_be_bytes([bytes[2], bytes[3]]))?;
        // println!("flags: {}", flags);
        let counts = validate_and_parse_count(&bytes[4..12])?;
        // println!("transaction_id: {}, flags: {}, counts: {:?}", transaction_id, flags, counts);
        Ok(Self {
            transaction_id,
            flags,
            counts,
        })
    }
}

impl DnsHeader {
    /// Like [`TryFrom::try_from`], but tolerates an empty question section
    /// (mDNS responses, RFC 6762 §6).
    pub(crate) fn try_from_mdns(bytes: &[u8]) -> Result<Self, DnsHeaderError> {
        check_packet_length(bytes)?;

        let transaction_id = u16::from_be_bytes([bytes[0], bytes[1]]);
        let flags = verify_mdns_flags(u16::from_be_bytes([bytes[2], bytes[3]]))?;
        let counts = parse_count_allow_empty_question(&bytes[4..12])?;
        Ok(Self {
            transaction_id,
            flags,
            counts,
        })
    }

    /// Like [`TryFrom::try_from`], but with the LLMNR flag layout and count
    /// rules (RFC 4795 section 2.1.1) : opcode 0 uniquement, 4 bits Z a zero,
    /// rcode nul en requete, bits C/T libres, QDCOUNT exactement 1.
    pub(crate) fn try_from_llmnr(bytes: &[u8]) -> Result<Self, DnsHeaderError> {
        check_packet_length(bytes)?;

        let transaction_id = u16::from_be_bytes([bytes[0], bytes[1]]);
        let flags = verify_llmnr_flags(u16::from_be_bytes([bytes[2], bytes[3]]))?;
        // QR est le bit 15 : 0 pour une requete, 1 pour une reponse.
        let is_query = flags & 0x8000 == 0;
        let counts = parse_and_validate_llmnr_counts(&bytes[4..12], is_query)?;
        Ok(Self {
            transaction_id,
            flags,
            counts,
        })
    }
}

impl fmt::Display for DnsHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DnsHeader {{ transaction_id: {}, flags: {}, questions_count: {}, answers_count: {}, authorities_count: {}, additionals_count: {} }}",
            self.transaction_id,
            self.flags,
            self.counts[0],
            self.counts[1],
            self.counts[2],
            self.counts[3],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::application::dns::DnsFlagsError;

    #[test]
    fn test_check_packet_length() {
        let short_data = vec![0; 11];
        assert!(check_packet_length(&short_data).is_err());

        let valid_data = vec![0; 12];
        assert!(check_packet_length(&valid_data).is_ok());
    }

    #[test]
    fn test_validate_and_parse_count() {
        let valid_data = vec![0, 1, 0, 2, 0, 3, 0, 4];
        let counts = validate_and_parse_count(&valid_data).unwrap();
        assert_eq!(counts, [1, 2, 3, 4]);

        let invalid_data = vec![0, 0, 0, 1, 0, 0, 0, 0];
        assert!(validate_and_parse_count(&invalid_data).is_err());
    }

    #[test]
    fn test_validate_and_parse_count_with_zero_questions() {
        let invalid_data = vec![0, 0, 0, 1, 0, 1, 0, 1];
        let result = validate_and_parse_count(&invalid_data);
        assert!(
            result.is_err(),
            "Expected an error due to zero questions and non-zero resource records"
        );
    }

    #[test]
    fn test_dns_header_try_from() {
        let data = vec![0, 1, 0, 2, 0, 1, 0, 2, 0, 3, 0, 4];
        let header = DnsHeader::try_from(&data[..]).unwrap();
        assert_eq!(header.transaction_id, 1);
        assert_eq!(header.flags, 2);
        assert_eq!(header.counts, [1, 2, 3, 4]);

        let invalid_data = vec![0, 1, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0];
        assert!(DnsHeader::try_from(&invalid_data[..]).is_err());
    }

    #[test]
    fn test_dns_header_with_zero_questions() {
        let invalid_data = vec![0, 1, 0, 2, 0, 0, 0, 1, 0, 1, 0, 1];
        let result = DnsHeader::try_from(&invalid_data[..]);
        assert!(
            result.is_err(),
            "Expected an error due to zero questions and non-zero resource records"
        );
    }

    // En-tetes synthetiques : ils ciblent les regles de validation LLMNR.
    #[test]
    fn test_llmnr_header_accepts_query_with_single_question() {
        let data = [
            0x37, 0x4c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let header = DnsHeader::try_from_llmnr(&data).unwrap();
        assert_eq!(header.transaction_id, 0x374c);
        assert_eq!(header.counts, [1, 0, 0, 0]);
    }

    #[test]
    fn test_llmnr_header_rejects_query_with_answer_records() {
        let data = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];

        assert!(matches!(
            DnsHeader::try_from_llmnr(&data),
            Err(DnsHeaderError::InvalidCounts)
        ));
    }

    #[test]
    fn test_llmnr_header_accepts_response_with_answer_records() {
        // Reponse (QR=1) avec une question et une answer.
        let data = [
            0x00, 0x00, 0x80, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];

        let header = DnsHeader::try_from_llmnr(&data).unwrap();
        assert_eq!(header.counts, [1, 1, 0, 0]);
    }

    #[test]
    fn test_llmnr_header_rejects_ra_position_as_z_bit() {
        // Flags 0x0180 : RD+RA en DNS classique — en LLMNR, le bit 7 fait
        // partie de Z et doit etre nul.
        let data = [
            0x00, 0x00, 0x01, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        assert!(matches!(
            DnsHeader::try_from_llmnr(&data),
            Err(DnsHeaderError::FlagsError(DnsFlagsError::InvalidZField(
                0b1000
            )))
        ));
    }

    #[test]
    fn test_mdns_header_rejects_nonzero_opcode() {
        let data = [
            0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        assert!(matches!(
            DnsHeader::try_from_mdns(&data),
            Err(DnsHeaderError::FlagsError(DnsFlagsError::InvalidOpcode(1)))
        ));
    }

    #[test]
    fn test_mdns_header_rejects_nonzero_rcode() {
        let data = [
            0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        assert!(matches!(
            DnsHeader::try_from_mdns(&data),
            Err(DnsHeaderError::FlagsError(DnsFlagsError::InvalidRCode(1)))
        ));
    }
}
