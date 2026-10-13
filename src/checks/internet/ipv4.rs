// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use crate::errors::internet::ipv4::Ipv4Error;

pub const IPV4_MIN_HEADER_LEN: usize = 20;
pub const IPV4_MAX_HEADER_LEN: usize = 60;

pub fn validate_ipv4_min_length(data: &[u8]) -> Result<(), Ipv4Error> {
    if data.len() < IPV4_MIN_HEADER_LEN {
        return Err(Ipv4Error::InvalidLength {
            expected: IPV4_MIN_HEADER_LEN,
            actual: data.len(),
        });
    }
    Ok(())
}

pub fn validate_ipv4_version(version: u8) -> Result<(), Ipv4Error> {
    if version != 4 {
        return Err(Ipv4Error::InvalidVersion(version));
    }
    Ok(())
}

pub fn validate_ipv4_header_length(header_len: usize) -> Result<(), Ipv4Error> {
    if !(IPV4_MIN_HEADER_LEN..=IPV4_MAX_HEADER_LEN).contains(&header_len) {
        return Err(Ipv4Error::InvalidHeaderLength(header_len));
    }
    Ok(())
}

pub fn validate_ipv4_header_available(data_len: usize, header_len: usize) -> Result<(), Ipv4Error> {
    if data_len < header_len {
        return Err(Ipv4Error::InvalidLength {
            expected: header_len,
            actual: data_len,
        });
    }
    Ok(())
}

/// Une longueur totale nulle est celle d'un paquet capture avant que la
/// carte ne le segmente (TSO, LSO de Windows) : la pile ne l'ecrit pas. Le
/// paquet court alors jusqu'a la fin de la trame, comme le lit tshark
/// (`ip.tso_support`, vrai par defaut) (#168).
pub fn validate_ipv4_total_length(
    total_length: u16,
    header_len: usize,
    data_len: usize,
) -> Result<(), Ipv4Error> {
    if total_length == 0 {
        return Ok(());
    }
    let total_length = total_length as usize;
    if total_length < header_len || total_length > data_len {
        return Err(Ipv4Error::InvalidTotalLength {
            expected: total_length,
            actual: data_len,
            min_header_len: header_len,
        });
    }
    Ok(())
}
