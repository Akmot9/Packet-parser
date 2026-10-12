// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

pub mod ams;
pub mod asterix;
pub mod bitcoin;
pub mod copt;
pub mod dhcp;
pub mod dhcpv6;
pub mod dis;
pub mod dns;
pub mod ethernet_ip;
pub mod ftp;
pub mod giop;
pub mod http;
pub mod ike;
pub mod modbus_tcp;
pub mod mqtt;
pub mod netbios;
pub mod nntp;
pub mod ntp;
pub mod opcua;
pub mod openvpn;
pub mod postgresql;
pub mod ptp;
pub mod quic;
pub mod rtps;
pub mod s7comm;
pub mod smtp;
pub mod snmp;
pub mod srvloc;
pub mod ssdp;
pub mod ssh;
pub mod stanag5066;
pub mod tls;
pub mod umas;

/// Octet qu'une ligne d'un protocole texte (FTP, SMTP, NNTP) ne porte jamais.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TextOctetFault {
    /// CR ou LF hors d'une paire CRLF.
    BareLineBreak { offset: usize },
    /// Caractere de controle autre que TAB et la paire CRLF (NUL, ESC, DEL...).
    ControlCharacter { offset: usize, byte: u8 },
}

/// Premier octet de `text` qu'une ligne de commande ou de reponse FTP, SMTP ou
/// NNTP ne porte jamais : un CR ou un LF nu (RFC 959 §5.3.2, RFC 5321 §2.3.8,
/// RFC 3977 §3.1.1), ou un caractere de controle autre que TAB (NUL, ESC,
/// DEL...).
///
/// Issue #109 : les quatre entrees du fuzz nocturne qui ont fait echouer
/// l'oracle FTP (#107) etaient des commandes `STOR` hors port dont l'argument,
/// ou ce qui suivait la ligne, portait de tels octets. Sur les 200 segments
/// FTP, SMTP et NNTP du corpus `pcaps_exemple/`, aucun n'en porte : le refus
/// ne coute aucun faux negatif mesurable.
pub(crate) fn find_text_line_fault(text: &[u8]) -> Option<TextOctetFault> {
    scan_octets(text, |byte| (byte < 0x20 && byte != b'\t') || byte == 0x7F)
}

/// Premier octet interdit dans un bloc de donnees NNTP (RFC 3977 §3.1.1 : hors
/// des fins de ligne, ni NUL, ni CR, ni LF). Le bloc n'est pas forcement du
/// texte UTF-8 et les autres caracteres de controle y sont admis.
pub(crate) fn find_data_block_fault(block: &[u8]) -> Option<TextOctetFault> {
    scan_octets(block, |byte| byte == 0)
}

fn scan_octets(octets: &[u8], is_control: impl Fn(u8) -> bool) -> Option<TextOctetFault> {
    let mut offset = 0;
    while let Some(&byte) = octets.get(offset) {
        match byte {
            b'\r' if octets.get(offset + 1) == Some(&b'\n') => offset += 2,
            b'\r' | b'\n' => return Some(TextOctetFault::BareLineBreak { offset }),
            byte if is_control(byte) => {
                return Some(TextOctetFault::ControlCharacter { offset, byte });
            }
            _ => offset += 1,
        }
    }
    None
}

#[cfg(test)]
mod text_octet_tests {
    use super::{TextOctetFault, find_data_block_fault, find_text_line_fault};

    #[test]
    fn crlf_pairs_tab_and_printable_text_pass() {
        assert_eq!(find_text_line_fault(b"STOR fichier.bin\r\n"), None);
        assert_eq!(find_text_line_fault(b"HDR\tSubject\t12-20\r\n"), None);
        assert_eq!(
            find_text_line_fault("RETR caf\u{e9}.txt\r\n".as_bytes()),
            None
        );
        assert_eq!(find_text_line_fault(b"211-A\r\n B\r\n211 End.\r\n"), None);
        assert_eq!(find_text_line_fault(b""), None);
    }

    #[test]
    fn a_bare_cr_or_lf_is_reported_at_its_offset() {
        assert_eq!(
            find_text_line_fault(b"STOR a\nb\r\n"),
            Some(TextOctetFault::BareLineBreak { offset: 6 })
        );
        assert_eq!(
            find_text_line_fault(b"STOR a\rb\r\n"),
            Some(TextOctetFault::BareLineBreak { offset: 6 })
        );
        // Un CR final sans LF est nu lui aussi.
        assert_eq!(
            find_text_line_fault(b"STOR a\r"),
            Some(TextOctetFault::BareLineBreak { offset: 6 })
        );
        // Un LF qui suit un CRLF complet est nu.
        assert_eq!(
            find_text_line_fault(b"STOR a\r\n\n"),
            Some(TextOctetFault::BareLineBreak { offset: 8 })
        );
    }

    #[test]
    fn control_characters_other_than_tab_are_reported() {
        for (payload, offset, byte) in [
            (&b"STOR a\x00b\r\n"[..], 6, 0x00),
            (&b"STOR a\x17b\r\n"[..], 6, 0x17),
            (&b"STOR a\x1b[0m\r\n"[..], 6, 0x1B),
            (&b"STOR a\x7f\r\n"[..], 6, 0x7F),
            (&b"STOR +2\r\n\x17\x15"[..], 9, 0x17),
        ] {
            assert_eq!(
                find_text_line_fault(payload),
                Some(TextOctetFault::ControlCharacter { offset, byte }),
                "payload {payload:?}"
            );
        }
    }

    #[test]
    fn a_data_block_only_rejects_nul_and_bare_line_breaks() {
        assert_eq!(
            find_data_block_fault(b"224 data follows\r\n1\tSubject\r\n.\r\n"),
            None
        );
        // Un article peut porter d'autres octets de controle, et du non-UTF-8.
        assert_eq!(find_data_block_fault(b"\x1b[0m\xff\xfe\r\n"), None);
        assert_eq!(
            find_data_block_fault(b"ARTICLE 1\r\n\x17\x15\x00"),
            Some(TextOctetFault::ControlCharacter {
                offset: 13,
                byte: 0x00
            })
        );
        assert_eq!(
            find_data_block_fault(b"ARTICLE 1\r\nbody\nmore\r\n"),
            Some(TextOctetFault::BareLineBreak { offset: 15 })
        );
    }
}
