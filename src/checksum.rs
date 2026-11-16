// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! **Opt-in** verification of IPv4, TCP and UDP checksums.
//!
//! Parsing never validates checksums: on a capture taken on the sending
//! side, hardware checksum offloading often leaves checksums uncomputed, and
//! a mandatory validation would reject perfectly healthy traffic. These
//! functions let the consumer validate when its context allows it.
//!
//! Each function returns:
//! - `Some(true)`: checksum present and correct;
//! - `Some(false)`: checksum present and incorrect;
//! - `None`: not verifiable (packet too short, or UDP checksum absent, that
//!   is value 0, which IPv4 allows).

use std::net::IpAddr;

/// Somme en complément à un (RFC 1071) sur une suite de tranches, comme si
/// elles étaient contiguës.
fn ones_complement_sum(chunks: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    let mut pending: Option<u8> = None;

    for chunk in chunks {
        for &byte in *chunk {
            match pending.take() {
                Some(high) => sum += u32::from(u16::from_be_bytes([high, byte])),
                None => pending = Some(byte),
            }
        }
    }
    if let Some(high) = pending {
        sum += u32::from(u16::from_be_bytes([high, 0]));
    }

    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    // La boucle a replie la somme sur 16 bits : le masque ne retire rien.
    (sum & 0xFFFF) as u16
}

/// Verifies the checksum of an IPv4 header (`packet` starts at octet 0 of
/// the IP header).
pub fn verify_ipv4_header_checksum(packet: &[u8]) -> Option<bool> {
    if packet.len() < 20 {
        return None;
    }
    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    if !(20..=60).contains(&ihl) || packet.len() < ihl {
        return None;
    }
    // La somme de l'en-tête complet (checksum inclus) vaut 0xFFFF quand il
    // est correct.
    Some(ones_complement_sum(&[&packet[..ihl]]) == 0xFFFF)
}

/// Pseudo-en-tête v4/v6 (RFC 793 / RFC 8200 §8.1) pour TCP et UDP.
fn pseudo_header_sum(
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    length: u32,
) -> Option<Vec<u8>> {
    match (source, destination) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let mut bytes = Vec::with_capacity(12);
            bytes.extend_from_slice(&src.octets());
            bytes.extend_from_slice(&dst.octets());
            bytes.push(0);
            bytes.push(protocol);
            #[expect(
                clippy::cast_possible_truncation,
                reason = "le pseudo-en-tete IPv4 porte la longueur sur 16 bits"
            )]
            let length = length as u16;
            bytes.extend_from_slice(&length.to_be_bytes());
            Some(bytes)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let mut bytes = Vec::with_capacity(40);
            bytes.extend_from_slice(&src.octets());
            bytes.extend_from_slice(&dst.octets());
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(&[0, 0, 0, protocol]);
            Some(bytes)
        }
        _ => None, // familles d'adresses mélangées
    }
}

/// Verifies the checksum of a complete TCP segment (`segment` = TCP header +
/// data), with the source and destination IP addresses of the carrying packet.
pub fn verify_tcp_checksum(source: IpAddr, destination: IpAddr, segment: &[u8]) -> Option<bool> {
    if segment.len() < 20 {
        return None;
    }
    let pseudo = pseudo_header_sum(source, destination, 6, u32::try_from(segment.len()).ok()?)?;
    Some(ones_complement_sum(&[&pseudo, segment]) == 0xFFFF)
}

/// Verifies the checksum of a complete UDP datagram (`datagram` = UDP header +
/// data). Returns `None` when the checksum is 0 (not computed, which IPv4
/// allows).
pub fn verify_udp_checksum(source: IpAddr, destination: IpAddr, datagram: &[u8]) -> Option<bool> {
    if datagram.len() < 8 {
        return None;
    }
    let checksum = u16::from_be_bytes([datagram[6], datagram[7]]);
    if checksum == 0 {
        return None;
    }
    let pseudo = pseudo_header_sum(source, destination, 17, u32::try_from(datagram.len()).ok()?)?;
    Some(ones_complement_sum(&[&pseudo, datagram]) == 0xFFFF)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// En-tête IPv4 réel avec checksum correct (0xB1E6).
    fn valid_ipv4_header() -> Vec<u8> {
        vec![
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ]
    }

    #[test]
    fn test_verify_ipv4_header_checksum_valid() {
        assert_eq!(
            verify_ipv4_header_checksum(&valid_ipv4_header()),
            Some(true)
        );
    }

    #[test]
    fn test_verify_ipv4_header_checksum_corrupted() {
        let mut header = valid_ipv4_header();
        header[15] ^= 0xFF;
        assert_eq!(verify_ipv4_header_checksum(&header), Some(false));
    }

    #[test]
    fn test_verify_ipv4_header_checksum_too_short() {
        assert_eq!(verify_ipv4_header_checksum(&[0x45, 0x00]), None);
    }

    #[test]
    fn test_verify_udp_checksum_valid() {
        // Datagramme UDP forgé : ports 1234→80, 4 octets de données, checksum
        // calculé sur le pseudo-en-tête 10.0.0.1 → 10.0.0.2.
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let mut datagram = vec![
            0x04, 0xd2, // source port 1234
            0x00, 0x50, // dest port 80
            0x00, 0x0c, // length 12
            0x00, 0x00, // checksum (à calculer)
            0xde, 0xad, 0xbe, 0xef,
        ];
        let pseudo = pseudo_header_sum(src, dst, 17, datagram.len() as u32).unwrap();
        let checksum = !ones_complement_sum(&[&pseudo, &datagram]);
        datagram[6..8].copy_from_slice(&checksum.to_be_bytes());

        assert_eq!(verify_udp_checksum(src, dst, &datagram), Some(true));

        datagram[8] ^= 0xFF;
        assert_eq!(verify_udp_checksum(src, dst, &datagram), Some(false));
    }

    #[test]
    fn test_verify_udp_checksum_absent_is_unverifiable() {
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let datagram = [
            0x04, 0xd2, 0x00, 0x50, 0x00, 0x0c, 0x00, 0x00, // checksum 0
            0xde, 0xad, 0xbe, 0xef,
        ];

        assert_eq!(verify_udp_checksum(src, dst, &datagram), None);
    }

    #[test]
    fn test_verify_tcp_checksum_valid() {
        let src = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        // En-tête TCP minimal (20 octets) sans données.
        let mut segment = vec![
            0x04, 0xd2, 0x00, 0x50, // ports
            0x00, 0x00, 0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x50, 0x02, 0x20, 0x00, // data offset 5, SYN, window
            0x00, 0x00, // checksum (à calculer)
            0x00, 0x00, // urgent pointer
        ];
        let pseudo = pseudo_header_sum(src, dst, 6, segment.len() as u32).unwrap();
        let checksum = !ones_complement_sum(&[&pseudo, &segment]);
        segment[16..18].copy_from_slice(&checksum.to_be_bytes());

        assert_eq!(verify_tcp_checksum(src, dst, &segment), Some(true));

        segment[4] ^= 0x01;
        assert_eq!(verify_tcp_checksum(src, dst, &segment), Some(false));
    }

    #[test]
    fn test_mixed_address_families_unverifiable() {
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst = "2001:db8::1".parse().unwrap();
        let datagram = [0u8; 20];

        assert_eq!(verify_udp_checksum(src, dst, &datagram), None);
    }
}
