// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use super::probes::*;
use super::rules::*;
use super::*;
use crate::parse::application::protocols::ntp::NtpPacket;
use crate::parse::application::protocols::wireguard::WireGuardPacket;

/// Payload TCP minimal pour exercer la table hors ports standards.
fn tcp_transport<'a>(payload: &'a [u8]) -> Transport<'a> {
    Transport {
        protocol: TransportProtocol::Tcp,
        source_port: Some(40_000),
        destination_port: Some(50_000),
        payload: Some(payload),
        details: None,
    }
}

/// Issue #66 : un verbe propre a un protocole est detecte hors port ;
/// un verbe partage reste inconnu hors port.
#[test]
fn unambiguous_verbs_classify_off_port_shared_verbs_do_not() {
    for (payload, expected) in [
        (&b"PASV\r\n"[..], "FTP"),
        (&b"STOR fichier.bin\r\n"[..], "FTP"),
        (&b"EHLO client.example\r\n"[..], "SMTP"),
        (&b"MAIL FROM:<a@b.example>\r\n"[..], "SMTP"),
        (&b"ARTICLE 12345\r\n"[..], "NNTP"),
        (&b"XOVER 1-5\r\n"[..], "NNTP"),
    ] {
        let transport = tcp_transport(payload);
        let label = classify(&transport, &[]).map(|a| a.protocol.label());
        assert_eq!(label, Some(expected), "payload {payload:?}");
    }

    // QUIT existe dans les trois protocoles : jamais par contenu seul.
    let transport = tcp_transport(b"QUIT\r\n");
    let label = classify(&transport, &[]).map(|a| a.protocol.label());
    assert_ne!(label, Some("FTP"));
    assert_ne!(label, Some("SMTP"));
    assert_ne!(label, Some("NNTP"));
}

/// Issue #66, l'autre moitie de la regle : un verbe propre a FTP en tete
/// du payload ne suffit pas, il faut une commande complete. Sans ce test,
/// reduire la sonde a sa garde `starts_with_one_of` passait inapercu.
#[test]
fn unambiguous_verbs_require_a_complete_command() {
    for payload in [
        &b"STOR\r\n"[..],          // STOR exige un argument
        &b"PASV extra\r\n"[..],    // PASV n'en prend aucun
        &b"STOR fichier.bin"[..],  // ligne sans CRLF
        &b"RETR \xff\xfe\r\n"[..], // UTF-8 invalide
    ] {
        let transport = tcp_transport(payload);
        let label = classify(&transport, &[]).map(|a| a.protocol.label());
        assert_ne!(label, Some("FTP"), "payload {payload:?}");
    }
}

/// Issue #109 : un CR ou un LF nu, ou un octet de controle, dans
/// l'argument ou apres la ligne de commande, et le payload n'est plus une
/// commande complete — pour les trois protocoles texte.
#[test]
fn unambiguous_verbs_reject_bare_line_breaks_and_control_bytes() {
    for (payload, label) in [
        (&b"STOR a\nb\r\n"[..], "FTP"),
        (&b"STOR a\rb\r\n"[..], "FTP"),
        (&b"STOR a\x00b\r\n"[..], "FTP"),
        (&b"STOR +2\r\n\x17\x15\x00\x17"[..], "FTP"),
        (&b"MAIL FROM:<a\nb@c.example>\r\n"[..], "SMTP"),
        (&b"EHLO host\x1b[0m\r\n"[..], "SMTP"),
        (&b"ARTICLE 1\n2\r\n"[..], "NNTP"),
        (&b"XOVER 1-5\r\n\x00"[..], "NNTP"),
    ] {
        let transport = tcp_transport(payload);
        let found = classify(&transport, &[]).map(|a| a.protocol.label());
        assert_ne!(found, Some(label), "payload {payload:?}");
    }
}

/// Issue #108 (trouve par la cible `policy_dispatch`) : la tabulation
/// separe aussi un verbe NNTP de ses arguments (RFC 3977 §3.1), et la
/// garde a cout constant doit la laisser passer comme l'espace. FTP et
/// SMTP ne coupent que sur l'espace : `STOR\tx` reste inconnu.
#[test]
fn nntp_tab_separator_is_detected_off_port() {
    for (payload, expected) in [
        (&b"ARTICLE\t12345\r\n"[..], Some("NNTP")),
        (&b"XOVER\t1-5\r\n"[..], Some("NNTP")),
        (&b"ARTICLE 12345\r\n"[..], Some("NNTP")),
        (&b"STOR\tfichier.bin\r\n"[..], None),
        (&b"MAIL\tFROM:<a@b.example>\r\n"[..], None),
    ] {
        let transport = tcp_transport(payload);
        let label = classify(&transport, &[])
            .map(|a| a.protocol.label())
            .filter(|label| matches!(*label, "FTP" | "SMTP" | "NNTP"));
        assert_eq!(label, expected, "payload {payload:?}");
    }
}

/// Issue #109 : les quatre entrees du fuzz nocturne qui ont fait echouer
/// l'oracle FTP de `parse_packetflow` (#107), rejouees telles quelles par
/// le point d'entree public. Trames synthetiques produites par libFuzzer
/// (runs 33303582320, 35430998713, 35500009371 et 35705447950) : IPv4 a
/// options (IHL 14), TCP hors port, commande `STOR` suivie d'octets de
/// controle. Aucune ne doit plus sortir `FTP`.
#[test]
fn nightly_fuzz_inputs_of_107_are_not_ftp() {
    const PREFIX: [u8; 32] = [
        0x00, 0x25, 0x8a, 0x9a, 0x9a, 0x0d, 0x00, 0x00, 0x00, 0x0a, 0xfd, 0xfb, 0x08, 0x00, 0x4e,
        0x00, 0x00, 0x63, 0x8a, 0x9a, 0x00, 0x00, 0x4e, 0x06, 0x4e, 0xff, 0x4e, 0x4e, 0x00, 0x00,
        0x00, 0x00,
    ];
    let frames: [&[u8]; 4] = [
        // Run 33303582320 (30 aout) : TCP 255 -> 20046, `STOR SPSH-*\x17\x14\x00\n\r\n`.
        &[
            0xfd, 0x00, 0x0a, 0xff, 0xff, 0x08, 0x25, 0x00, 0x4e, 0xff, 0xff, 0x00, 0x34, 0x0e,
            0x4f, 0x9a, 0x0e, 0x51, 0xf3, 0x49, 0x4f, 0x4e, 0x7e, 0x4a, 0x00, 0x00, 0x00, 0x81,
            0x00, 0x00, 0x00, 0x00, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x4e, 0x4e,
            0x00, 0x00, 0x00, 0x00, 0xfd, 0x00, 0x0a, 0xff, 0x50, 0x54, 0x00, 0x00, 0x00, 0x29,
            0x4e, 0x53, 0x53, 0x54, 0x4f, 0x52, 0x20, 0x53, 0x50, 0x53, 0x48, 0x2d, 0x2a, 0x17,
            0x14, 0x00, 0x0a, 0x0d, 0x0a, 0x17, 0x15, 0x00, 0x17, 0x00, 0x00, 0x10,
        ],
        // Run 35430998713 (19 septembre) : TCP 5888 -> 30464, `STOR PSH-*\x17\x14  \r\n`.
        &[
            0xfd, 0x00, 0x0a, 0xff, 0xff, 0x08, 0x25, 0x00, 0x4e, 0xff, 0xff, 0x00, 0x34, 0x0e,
            0x4f, 0x9a, 0x0e, 0x51, 0xf3, 0x49, 0x4f, 0x4e, 0x7e, 0x4a, 0x00, 0x00, 0x00, 0x81,
            0x00, 0x00, 0x00, 0x00, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x15, 0x17, 0x00, 0x77, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x9a, 0x0e, 0x50, 0x54, 0x00, 0x00, 0x00, 0x4e,
            0x53, 0x53, 0x53, 0x54, 0x4f, 0x52, 0x20, 0x50, 0x53, 0x48, 0x2d, 0x2a, 0x17, 0x14,
            0x20, 0x20, 0x0d, 0x0a, 0x17, 0x15, 0x00, 0x17, 0x00, 0x00, 0x10,
        ],
        // Run 35500009371 (20 septembre) : TCP 0 -> 0, `STOR PSH-*\x17\x14\x00 \r\n`
        // (longueur IP 96, octets 16-17 differents du prefixe commun).
        &[
            0xfd, 0x00, 0x0a, 0xff, 0xff, 0x00, 0x25, 0x00, 0x4e, 0xff, 0xff, 0x00, 0x34, 0x0e,
            0x4f, 0x9a, 0x0e, 0x51, 0xf3, 0x49, 0x4f, 0x4e, 0x7e, 0x4a, 0x00, 0x00, 0x81, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x15, 0x77, 0x17, 0x00, 0x01, 0x00, 0x9a, 0x0e, 0x50, 0x54, 0x00, 0x00, 0x00, 0x4e,
            0x53, 0x53, 0x53, 0x54, 0x4f, 0x52, 0x20, 0x50, 0x53, 0x48, 0x2d, 0x2a, 0x17, 0x14,
            0x00, 0x20, 0x0d, 0x0a, 0x17, 0x15, 0x00, 0x17,
        ],
        // Run 35705447950 (22 septembre) : TCP 1 -> 0, `STOR +2\r\n` puis
        // `\x17\x15\x00\x17\n\r\n...` — la ligne de commande est saine.
        &[
            0xfd, 0x00, 0x0a, 0xff, 0xd8, 0x00, 0x02, 0x01, 0x4e, 0xff, 0xff, 0x00, 0x36, 0x0e,
            0x4f, 0x9a, 0x0e, 0x51, 0xf3, 0x49, 0x4f, 0x4e, 0x7e, 0x4a, 0x00, 0x00, 0x00, 0x81,
            0x00, 0x00, 0x00, 0x00, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x9a, 0x0e, 0x50, 0x54, 0x00, 0x00, 0x00, 0x4e,
            0x53, 0x50, 0x53, 0x54, 0x4f, 0x52, 0x20, 0x2b, 0x32, 0x0d, 0x0a, 0x17, 0x15, 0x00,
            0x17, 0x0a, 0x0d, 0x0a, 0x17, 0x15, 0x00, 0x17, 0x00, 0x00, 0x10,
        ],
    ];
    for (index, tail) in frames.iter().enumerate() {
        let mut frame = PREFIX.to_vec();
        if index == 2 {
            frame[17] = 0x60; // longueur IP 96
        }
        frame.extend_from_slice(tail);
        let flow = crate::PacketFlow::try_from(frame.as_slice())
            .unwrap_or_else(|error| panic!("entree {index} : {error}"));
        let labels: Vec<_> = flow
            .flatten()
            .into_iter()
            .filter_map(|flow| flow.application.as_ref())
            .map(|application| application.protocol.label())
            .collect();
        assert!(!labels.contains(&"FTP"), "entree {index} : {labels:?}");
        let transport = flow.transport.as_ref().expect("TCP");
        assert_eq!(transport.protocol, TransportProtocol::Tcp, "entree {index}");
        assert!(
            transport
                .payload
                .is_some_and(|payload| payload.starts_with(b"STOR ")),
            "entree {index} : le payload doit rester la commande STOR du fuzz"
        );
    }
}

/// Issue #65 : un port declare par l'appelant etend les gardes — port ET
/// contenu — sans changer le comportement par defaut.
#[test]
fn decode_as_extends_port_guards_without_replacing_them() {
    // USER est un verbe partage : jamais detecte hors port par defaut...
    let transport = tcp_transport(b"USER alice\r\n");
    assert_ne!(
        classify(&transport, &[]).map(|a| a.protocol.label()),
        Some("FTP")
    );
    // ... mais l'appelant peut declarer que 50 000 porte du FTP.
    let decode_as = [(50_000_u16, DecodeAsProtocol::Ftp)];
    assert_eq!(
        classify(&transport, &decode_as).map(|a| a.protocol.label()),
        Some("FTP")
    );
    // Le port declare ne suffit jamais : contenu non-FTP refuse.
    let garbage = tcp_transport(b"\x16\x03\x03\x00\x10aaaaaaaaaaaaaaaa");
    assert_ne!(
        classify(&garbage, &decode_as).map(|a| a.protocol.label()),
        Some("FTP")
    );
    // La garde de transport du protocole reste appliquee : declarer un
    // port DNS datagramme sur du TCP ne sonde pas la forme datagramme.
    let decode_udp_only = [(50_000_u16, DecodeAsProtocol::Mdns)];
    assert_ne!(
        classify(&transport, &decode_udp_only).map(|a| a.protocol.label()),
        Some("mDNS")
    );
}

/// UDP 4500 (RFC 3948) : marqueur non-ESP puis IKE, ESP a SPI non nul,
/// NAT-keepalive d'un octet ; ailleurs, rien sans Decode As (#124).
#[test]
fn udp_4500_demultiplexes_ike_esp_and_keepalive() {
    // IKEv2 minimal : en-tete seul, IKE_SA_INIT de l'initiateur.
    const IKE: [u8; 28] = [
        0x62, 0xf9, 0x4c, 0x98, 0x87, 0x71, 0x5a, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x20, 0x22,
        0x08, 0, 0, 0, 0, 0, 0, 0, 28,
    ];
    const MARKED_IKE: [u8; 32] = {
        let mut marked = [0u8; 32];
        let mut i = 0;
        while i < 28 {
            marked[i + 4] = IKE[i];
            i += 1;
        }
        marked
    };
    const ESP: [u8; 12] = [0xcb, 0xb7, 0xa0, 0xc6, 0, 0, 0, 1, 0x2b, 0x0f, 0x39, 0xc7];
    const KEEPALIVE: [u8; 1] = [0xff];
    let transport = |port: u16, payload: &'static [u8]| Transport {
        protocol: TransportProtocol::Udp,
        source_port: Some(port),
        destination_port: Some(port),
        payload: Some(payload),
        details: None,
    };
    let label = |port: u16, payload: &'static [u8], decode_as: &[(u16, DecodeAsProtocol)]| {
        classify(&transport(port, payload), decode_as).map(|a| a.protocol.label())
    };
    assert_eq!(label(4500, &MARKED_IKE, &[]), Some("IKE"));
    assert_eq!(label(500, &IKE, &[]), Some("IKE"));
    assert_eq!(label(4500, &IKE, &[]), Some("IKE"));
    assert_eq!(label(4500, &ESP, &[]), Some("ESP"));
    assert_eq!(label(4500, &KEEPALIVE, &[]), Some("NAT-keepalive"));
    // UDP 500 ne porte ni ESP ni keepalive.
    assert_eq!(label(500, &ESP, &[]), Some("Unknown"));
    assert_eq!(label(500, &KEEPALIVE, &[]), Some("Unknown"));
    // Un autre port : rien, sauf declaration.
    assert_eq!(label(4501, &MARKED_IKE, &[]), Some("Unknown"));
    assert_eq!(label(4501, &ESP, &[]), Some("Unknown"));
    assert_eq!(label(4501, &KEEPALIVE, &[]), Some("Unknown"));
    assert_eq!(
        label(4501, &MARKED_IKE, &[(4501, DecodeAsProtocol::Ike)]),
        Some("IKE")
    );
    assert_eq!(
        label(4501, &ESP, &[(4501, DecodeAsProtocol::Esp)]),
        Some("ESP")
    );
    assert_eq!(
        label(4501, &ESP, &[(4501, DecodeAsProtocol::Ike)]),
        Some("Unknown")
    );
}

/// #167 : sur TCP 502, l'enveloppe MBAP suffit, UMAS d'abord ; ailleurs,
/// le code fonction et la taille de la PDU doivent concorder. Requete
/// Read Holding Registers de Modbus.pcap (trame 1), puis la meme portant
/// le code 0x41, defini par l'utilisateur.
#[test]
fn modbus_is_lenient_on_port_502_and_strict_elsewhere() {
    const READ: [u8; 12] = [0x00, 0xd1, 0, 0, 0, 6, 0x01, 0x03, 0x00, 0x01, 0x00, 0x01];
    const USER_DEFINED: [u8; 12] = [0x00, 0xd1, 0, 0, 0, 6, 0x01, 0x41, 0x00, 0x01, 0x00, 0x01];
    // UMAS : code 0x5A, session 0, fonction 0x02 (Read ID).
    const UMAS: [u8; 10] = [0x00, 0x01, 0, 0, 0, 4, 0x00, 0x5a, 0x00, 0x02];
    let label = |protocol: TransportProtocol, port: u16, payload: &'static [u8]| {
        let transport = Transport {
            protocol,
            source_port: Some(40_000),
            destination_port: Some(port),
            payload: Some(payload),
            details: None,
        };
        classify(&transport, &[]).map(|a| a.protocol.label())
    };
    let tcp = TransportProtocol::Tcp;
    assert_eq!(label(tcp, 502, &READ), Some("ModbusTCP"));
    assert_eq!(label(tcp, 40_001, &READ), Some("ModbusTCP"));
    assert_eq!(label(tcp, 502, &USER_DEFINED), Some("ModbusTCP"));
    assert_ne!(label(tcp, 40_001, &USER_DEFINED), Some("ModbusTCP"));
    assert_eq!(label(tcp, 502, &UMAS), Some("UMAS"));
    assert_eq!(label(tcp, 40_001, &UMAS), Some("UMAS"));
    // Sur UDP, le port 502 seul, sous sa propre etiquette (#257) : aucune
    // sonde sans port, et UMAS n'y est pas distingue.
    let udp = TransportProtocol::Udp;
    assert_eq!(label(udp, 502, &READ), Some("ModbusUDP"));
    assert_eq!(label(udp, 502, &USER_DEFINED), Some("ModbusUDP"));
    assert_eq!(label(udp, 502, &UMAS), Some("ModbusUDP"));
    assert_eq!(label(udp, 40_001, &READ), Some("Unknown"));
    // Un autre port UDP se declare ; la declaration ne vaut pas sur TCP.
    let declared = |protocol: TransportProtocol| {
        let transport = Transport {
            protocol,
            source_port: Some(40_000),
            destination_port: Some(40_001),
            payload: Some(&USER_DEFINED),
            details: None,
        };
        classify(&transport, &[(40_001, DecodeAsProtocol::ModbusUdp)]).map(|a| a.protocol.label())
    };
    assert_eq!(declared(udp), Some("ModbusUDP"));
    assert_eq!(declared(tcp), Some("Unknown"));
}

/// #164 : sur UDP 123, le decodeur NTP tolerant ; sur tout autre port,
/// la sonde aveugle stricte. Synthetique : une reponse NTPv4 de serveur
/// (stratum 2, poll 6, precision -20), puis la meme avec une precision
/// de +5 (2^5 s) ou cinq octets de trop apres l'en-tete.
#[test]
fn ntp_is_lenient_on_port_123_and_strict_elsewhere() {
    const REPLY: [u8; 48] = {
        let mut reply = [0u8; 48];
        reply[0] = 0x24;
        reply[1] = 2;
        reply[2] = 6;
        reply[3] = 0xec;
        reply[12] = 192;
        reply[13] = 0;
        reply[14] = 2;
        reply[15] = 1;
        // Receive puis transmit, en 2026.
        reply[32] = 0xec;
        reply[33] = 0x7c;
        reply[40] = 0xec;
        reply[41] = 0x7c;
        reply[47] = 1;
        reply
    };
    const COARSE: [u8; 48] = {
        let mut coarse = REPLY;
        coarse[3] = 5;
        coarse
    };
    // Le poll de 49 d'un datagramme Gnutella du corpus nDPI.
    const SLOW_POLL: [u8; 48] = {
        let mut slow = REPLY;
        slow[2] = 49;
        slow
    };
    const PADDED: [u8; 53] = {
        let mut padded = [0u8; 53];
        let mut i = 0;
        while i < 48 {
            padded[i] = REPLY[i];
            i += 1;
        }
        padded
    };
    let label = |port: u16, payload: &'static [u8]| {
        let transport = Transport {
            protocol: TransportProtocol::Udp,
            source_port: Some(port),
            destination_port: Some(40_000),
            payload: Some(payload),
            details: None,
        };
        classify(&transport, &[]).map(|a| a.protocol.label())
    };
    assert_eq!(label(123, &REPLY), Some("NTP"));
    assert_eq!(label(40_001, &REPLY), Some("NTP"));
    for payload in [&COARSE[..], &SLOW_POLL[..], &PADDED[..]] {
        assert_eq!(label(123, payload), Some("NTP"));
        assert_ne!(label(40_001, payload), Some("NTP"));
    }
    // Jamais sur TCP, port 123 compris.
    let tcp = Transport {
        protocol: TransportProtocol::Tcp,
        source_port: Some(123),
        destination_port: Some(40_000),
        payload: Some(&REPLY),
        details: None,
    };
    assert_ne!(classify(&tcp, &[]).map(|a| a.protocol.label()), Some("NTP"));
}

/// #164 : la sonde aveugle lit tout le datagramme, pas les PROBE_CAP
/// premiers octets — un champ d'extension qui finit au plafond et des
/// octets au-dela ne font pas un paquet NTP. Synthetique.
#[test]
fn ntp_blind_probe_reads_the_whole_datagram() {
    let mut datagram = vec![0u8; 48];
    datagram[..4].copy_from_slice(&[0x24, 2, 6, 0xec]);
    datagram[32..34].copy_from_slice(&[0xec, 0x7c]);
    datagram[40..42].copy_from_slice(&[0xec, 0x7c]);
    let field = PROBE_CAP - 48;
    datagram.extend_from_slice(&[0x01, 0x04]);
    datagram.extend_from_slice(&(field as u16).to_be_bytes());
    datagram.resize(PROBE_CAP, 0);
    let label = |payload: &[u8]| {
        let transport = Transport {
            protocol: TransportProtocol::Udp,
            source_port: Some(40_000),
            destination_port: Some(40_001),
            payload: Some(payload),
            details: None,
        };
        classify(&transport, &[]).map(|a| a.protocol.label())
    };
    assert_eq!(label(&datagram), Some("NTP"));
    datagram.extend_from_slice(&[0; 100]);
    assert_ne!(label(&datagram), Some("NTP"));
}

/// #184 : la sonde ASTERIX lit tout le datagramme, comme la sonde NTP
/// aveugle (#164) : des blocs qui finissent au plafond, suivis d'un octet
/// ou d'un bloc d'une categorie non supportee, ne font pas un datagramme
/// ASTERIX ; un bloc valide a cheval sur le plafond en fait un, comme
/// sept blocs dont le dernier le chevauche. Synthetique : records CAT 048
/// minimaux, FSPEC `80` et I048/010.
#[test]
fn asterix_probe_reads_the_whole_datagram() {
    let block = |records: usize| {
        let mut block = vec![0x30];
        block.extend_from_slice(&((3 + 3 * records) as u16).to_be_bytes());
        for _ in 0..records {
            block.extend_from_slice(&[0x80, 0x19, 0xc9]);
        }
        block
    };
    let label = |payload: &[u8]| {
        let transport = Transport {
            protocol: TransportProtocol::Udp,
            source_port: Some(40_000),
            destination_port: Some(8600),
            payload: Some(payload),
            details: None,
        };
        classify(&transport, &[]).map(|a| a.protocol.label())
    };
    let exact = block((PROBE_CAP - 3) / 3);
    assert_eq!(exact.len(), PROBE_CAP);
    assert_eq!(label(&exact), Some("ASTERIX"));

    let mut trailing = exact.clone();
    trailing.push(0x00);
    assert_ne!(label(&trailing), Some("ASTERIX"));

    let mut unsupported = exact.clone();
    unsupported.extend_from_slice(&[0x0a, 0x00, 0x06, 0x80, 0x19, 0xc9]);
    assert_ne!(label(&unsupported), Some("ASTERIX"));

    // Un bloc valide a cheval sur le plafond, puis sept blocs dont seul
    // le dernier le chevauche.
    let straddling = block(7000);
    assert!(straddling.len() > PROBE_CAP);
    assert_eq!(label(&straddling), Some("ASTERIX"));

    let thousand = block(1000);
    let seven = thousand.repeat(7);
    assert!(6 * thousand.len() < PROBE_CAP && PROBE_CAP < seven.len());
    assert_eq!(label(&seven), Some("ASTERIX"));
}

/// #184 : hors port 53, la sonde DNS aveugle exige des sections qui
/// consomment exactement le datagramme (#118), lu en entier comme par la
/// sonde NTP aveugle (#164) : des sections qui finissent au plafond et des
/// octets au-dela ne font pas un message DNS ; une reponse exacte plus
/// longue que le plafond en fait un, sur le port 53 aussi, ou la regle de
/// port, qui ne lit que le plafond, la refuse. Synthetique : une reponse
/// `example.com TXT` de PROBE_CAP octets, puis cent octets nuls ; la meme
/// a 20 000 octets de TXT.
#[test]
fn dns_blind_probe_does_not_accept_a_capped_prefix() {
    let label_from = |source_port: u16, payload: &[u8]| {
        let transport = Transport {
            protocol: TransportProtocol::Udp,
            source_port: Some(source_port),
            destination_port: Some(40_001),
            payload: Some(payload),
            details: None,
        };
        classify(&transport, &[]).map(|a| a.protocol.label())
    };
    let label = |payload: &[u8]| label_from(40_000, payload);
    // Une question, une reponse TXT de `rdlength` octets de chaines.
    let response = |rdlength: usize| {
        let mut response = vec![0xbe, 0xef, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        response.extend_from_slice(b"\x07example\x03com\x00\x00\x10\x00\x01");
        response.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0, 0, 0, 60]);
        response.extend_from_slice(&(rdlength as u16).to_be_bytes());
        let mut left = rdlength;
        while left > 0 {
            let chunk = (left - 1).min(255);
            response.push(chunk as u8);
            response.extend(std::iter::repeat_n(b'a', chunk));
            left -= 1 + chunk;
        }
        response
    };
    // 41 octets precedent les chaines : en-tete, question, puis la
    // reponse jusqu'a RDLENGTH.
    let mut capped = response(PROBE_CAP - response(0).len());
    assert_eq!(capped.len(), PROBE_CAP);
    assert_eq!(label(&capped), Some("DNS"));

    capped.extend_from_slice(&[0; 100]);
    assert_ne!(label(&capped), Some("DNS"));

    let long = response(20_000);
    assert_eq!(long.len(), 20_041);
    assert!(long.len() > PROBE_CAP);
    assert_eq!(label(&long), Some("DNS"));
    assert_eq!(label_from(53, &long), Some("DNS"));
}

/// #185 : au-dela de PROBE_CAP, chaque sonde juge le payload que son
/// decodeur lira. Payloads synthetiques des tableaux de l'issue : pour
/// les decodeurs qui exigent le pavage exact du buffer (SNMP, Modbus/TCP,
/// PostgreSQL, MQTT), un message exact de plus de PROBE_CAP octets est
/// etiquete et le meme message suivi d'octets en trop ne l'est plus ;
/// pour ceux dont une longueur declaree doit tenir (NBSS, DNS sur TCP,
/// TLS), un message complet de plus de PROBE_CAP octets est etiquete.
#[test]
fn whole_payload_probes_judge_the_payload_beyond_the_cap() {
    let label = |protocol: TransportProtocol, source: u16, destination: u16, payload: &[u8]| {
        let transport = Transport {
            protocol,
            source_port: Some(source),
            destination_port: Some(destination),
            payload: Some(payload),
            details: None,
        };
        classify(&transport, &[]).map(|a| a.protocol.label())
    };
    let tcp = |destination: u16, payload: &[u8]| {
        label(TransportProtocol::Tcp, 50_000, destination, payload)
    };
    let udp = |destination: u16, payload: &[u8]| {
        label(TransportProtocol::Udp, 40_000, destination, payload)
    };
    let ber_length = |n: usize| -> Vec<u8> {
        assert!(n < 65_536);
        if n < 128 {
            vec![n as u8]
        } else if n < 256 {
            vec![0x81, n as u8]
        } else {
            vec![0x82, (n >> 8) as u8, n as u8]
        }
    };
    let tlv = |tag: u8, value: &[u8]| -> Vec<u8> {
        let mut tlv = vec![tag];
        tlv.extend(ber_length(value.len()));
        tlv.extend_from_slice(value);
        tlv
    };

    // SNMPv2c GetResponse, une seule variable OCTET STRING de `size`
    // octets : la longueur du message vaut size + 45 au-dela de 256.
    let snmp = |size: usize| -> Vec<u8> {
        let mut varbind = tlv(0x06, &[0x2b, 0x06, 0x01]);
        varbind.extend(tlv(0x04, &vec![b'v'; size]));
        let varbinds = tlv(0x30, &tlv(0x30, &varbind));
        let mut pdu = vec![0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00];
        pdu.extend(varbinds);
        let mut message = vec![0x02, 0x01, 0x01];
        message.extend(tlv(0x04, b"public"));
        message.extend(tlv(0xa2, &pdu));
        tlv(0x30, &message)
    };
    let exact = snmp(20_005);
    assert_eq!(exact.len(), 20_050);
    assert!(exact.len() > PROBE_CAP);
    assert_eq!(udp(161, &exact), Some("SNMP"));
    assert_eq!(udp(40_001, &exact), Some("SNMP"));
    assert_eq!(tcp(50_001, &exact), Some("SNMP"));
    let mut trailing = snmp(PROBE_CAP - 45);
    assert_eq!(trailing.len(), PROBE_CAP);
    assert_eq!(udp(161, &trailing), Some("SNMP"));
    trailing.extend_from_slice(&[0; 100]);
    assert_eq!(udp(161, &trailing), Some("Unknown"));
    assert_eq!(udp(40_001, &trailing), Some("Unknown"));
    assert_eq!(tcp(50_001, &trailing), Some("Unknown"));

    // Modbus/TCP : des ADU de douze octets (Read Holding Registers, dix
    // registres), 1 536 pour PROBE_CAP.
    let adus = |count: usize| -> Vec<u8> {
        let mut adus = Vec::with_capacity(12 * count);
        for i in 0..count {
            adus.extend_from_slice(&(i as u16).to_be_bytes());
            adus.extend_from_slice(&[0, 0, 0, 6, 1, 3, 0, 0, 0, 10]);
        }
        adus
    };
    let mut capped = adus(PROBE_CAP / 12);
    assert_eq!(capped.len(), PROBE_CAP);
    assert_eq!(tcp(502, &capped), Some("ModbusTCP"));
    assert_eq!(tcp(50_001, &capped), Some("ModbusTCP"));
    capped.push(0);
    assert_eq!(tcp(502, &capped), Some("Unknown"));
    assert_eq!(tcp(50_001, &capped), Some("Unknown"));
    let straddling = adus(PROBE_CAP / 12 + 1);
    assert!(straddling.len() > PROBE_CAP);
    assert_eq!(tcp(502, &straddling), Some("ModbusTCP"));
    assert_eq!(tcp(50_001, &straddling), Some("ModbusTCP"));

    // PostgreSQL sur son port : 300 DataRow d'une colonne de 80 octets,
    // puis ReadyForQuery (27 306 octets). A l'aveugle : un Query de
    // 20 005 octets.
    let mut rows = Vec::new();
    for _ in 0..300 {
        rows.push(b'D');
        rows.extend_from_slice(&90u32.to_be_bytes());
        rows.extend_from_slice(&1u16.to_be_bytes());
        rows.extend_from_slice(&80u32.to_be_bytes());
        rows.extend(std::iter::repeat_n(b'x', 80));
    }
    rows.extend_from_slice(&[b'Z', 0, 0, 0, 5, b'I']);
    assert_eq!(rows.len(), 27_306);
    assert_eq!(tcp(5432, &rows), Some("PostgreSQL"));
    let mut query = vec![b'Q'];
    query.extend_from_slice(&20_004u32.to_be_bytes());
    query.extend_from_slice(b"SELECT '");
    query.extend(std::iter::repeat_n(b'a', 20_004 - 4 - 8 - 2));
    query.extend_from_slice(b"'\0");
    assert_eq!(query.len(), 20_005);
    assert_eq!(tcp(50_001, &query), Some("PostgreSQL"));

    // MQTT : un PUBLISH exact de 20 004 octets, puis deux octets nuls.
    let mut publish = vec![0x30, 0xa0, 0x9c, 0x01, 0x00, 0x01, b'a'];
    publish.extend(std::iter::repeat_n(b'p', 20_004 - publish.len()));
    assert_eq!(tcp(50_001, &publish), Some("MQTT"));
    publish.extend_from_slice(&[0, 0]);
    assert_eq!(tcp(50_001, &publish), Some("Unknown"));

    // NBSS sur 445 : une longueur declaree de 30 000.
    let mut nbss = vec![0x00, 0x00, 0x75, 0x30];
    nbss.extend(std::iter::repeat_n(0x5a, 30_000));
    assert_eq!(tcp(445, &nbss), Some("NBSS"));

    // DNS sur TCP 53 : un message de 20 039 octets prefixe de sa
    // longueur, une reponse TXT (la forme de #184).
    let mut response = vec![0xbe, 0xef, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    response.extend_from_slice(b"\x07example\x03com\x00\x00\x10\x00\x01");
    response.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0, 0, 0, 60]);
    let rdlength = 20_039 - response.len() - 2;
    response.extend_from_slice(&(rdlength as u16).to_be_bytes());
    let mut left = rdlength;
    while left > 0 {
        let chunk = (left - 1).min(255);
        response.push(chunk as u8);
        response.extend(std::iter::repeat_n(b'a', chunk));
        left -= 1 + chunk;
    }
    assert_eq!(response.len(), 20_039);
    let mut dns_tcp = (response.len() as u16).to_be_bytes().to_vec();
    dns_tcp.extend_from_slice(&response);
    assert_eq!(dns_tcp.len(), 20_041);
    assert_eq!(tcp(53, &dns_tcp), Some("DNS"));
    // Et la reponse exacte sur UDP 53, par la regle de port cette fois.
    assert_eq!(udp(53, &response), Some("DNS"));

    // TLS 1.2 : un record application_data de 2^14 + 2048 octets de
    // fragment, le maximum de la RFC 5246 §6.2.3, 18 437 avec l'en-tete.
    let mut record = vec![0x17, 0x03, 0x03, 0x48, 0x00];
    record.extend(std::iter::repeat_n(0xc3, PROBE_CAP));
    assert_eq!(record.len(), 18_437);
    assert_eq!(tcp(50_001, &record), Some("TLS"));
}

/// #185 : les sondes des protocoles texte gardent le plafond, que
/// l'oracle du fuzz recopie — une commande FTP de plus de PROBE_CAP
/// octets est jugee sur son prefixe, donc refusee, et une commande qui
/// tient sous le plafond suivie d'octets au-dela est acceptee sur le
/// prefixe comme en 11.6.0.
#[test]
fn text_probes_keep_the_cap() {
    let mut stor = b"STOR ".to_vec();
    stor.extend(std::iter::repeat_n(b'a', 20_000));
    stor.extend_from_slice(b"\r\n");
    let transport = tcp_transport(&stor);
    assert_eq!(
        classify(&transport, &[]).map(|a| a.protocol.label()),
        Some("Unknown")
    );
    let mut stor = b"STOR a\r\n".to_vec();
    stor.resize(PROBE_CAP, 0);
    assert_ne!(
        classify(&tcp_transport(&stor), &[]).map(|a| a.protocol.label()),
        Some("FTP")
    );
}

/// #164 : la regle NTP est la derniere regle de port — un datagramme
/// qui part du port 123 vers un port a regle (ici une requete DNS vers
/// 53) garde l'etiquette de ce port, meme quand ses octets forment un
/// en-tete NTP. Synthetique : requete DNS de 48 octets avec EDNS,
/// identifiant 0x2302 (lu VN 4, mode 3, stratum 2), drapeau RD.
#[test]
fn ntp_port_rule_comes_after_the_other_port_rules() {
    const QUERY: [u8; 48] = [
        0x23, 0x02, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 15, b'a', b'b',
        b'c', b'd', b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'l', b'm', b'n', b'o', 3, b'c',
        b'o', b'm', 0, 0x00, 0x01, 0x00, 0x01, 0, 0x00, 0x29, 0x04, 0xd0, 0, 0, 0, 0, 0x00, 0x00,
    ];
    assert!(NtpPacket::try_from(&QUERY[..]).is_ok());
    let transport = Transport {
        protocol: TransportProtocol::Udp,
        source_port: Some(123),
        destination_port: Some(53),
        payload: Some(&QUERY),
        details: None,
    };
    assert_eq!(
        classify(&transport, &[]).map(|a| a.protocol.label()),
        Some("DNS")
    );
}

/// 51820 est un port ephemere (#169, revue) : un paquet ESP de 148 octets
/// au SPI `0x01......` a la forme d'une initiation WireGuard, une reponse
/// DNS de 92 octets a l'identifiant `0x02..` celle d'une reponse
/// WireGuard. La regle de port WireGuard vient donc apres les leurs. Et
/// sur 51820, un datagramme DCE/RPC (`04 00 28 00`, octets reserves non
/// nuls) n'est pas des donnees WireGuard, comme pour tshark.
#[test]
fn wireguard_port_rule_comes_after_the_other_udp_port_rules() {
    let label = |source: u16, destination: u16, payload: &[u8]| {
        let transport = Transport {
            protocol: TransportProtocol::Udp,
            source_port: Some(source),
            destination_port: Some(destination),
            payload: Some(payload),
            details: None,
        };
        classify(&transport, &[]).map(|a| a.protocol.label())
    };
    let mut esp = vec![0x01, 0x02, 0x03, 0x04, 0, 0, 0, 1];
    esp.extend((0..140).map(|i| (i * 7 + 3) as u8));
    assert_eq!(esp.len(), 148);
    assert!(WireGuardPacket::is_port_udp_match(&esp));
    assert_eq!(label(51820, 4500, &esp), Some("ESP"));

    let mut dns = vec![
        0x02, 0xab, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l',
        b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x10, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01,
        0, 0, 0, 60, 0, 51, 50,
    ];
    dns.extend([b'a'; 50]);
    assert_eq!(dns.len(), 92);
    assert!(WireGuardPacket::is_port_udp_match(&dns));
    assert_eq!(label(53, 51820, &dns), Some("DNS"));

    let mut dcerpc = vec![0x04, 0x00, 0x28, 0x00];
    dcerpc.extend([0x10; 76]);
    assert!(WireGuardPacket::try_from(dcerpc.as_slice()).is_ok());
    assert_ne!(label(49153, 51820, &dcerpc), Some("WireGuard"));
    assert_eq!(
        classify(
            &Transport {
                protocol: TransportProtocol::Udp,
                source_port: Some(49153),
                destination_port: Some(51820),
                payload: Some(&dcerpc),
                details: None,
            },
            &[(51820, DecodeAsProtocol::WireGuard)]
        )
        .map(|a| a.protocol.label()),
        Some("WireGuard"),
        "un port declare reste tolerant"
    );

    let keepalive =
        hex::decode("0400000006f47dab03000000000000001956e2b6651dd4f59cb23092a0d09671").unwrap();
    assert_eq!(label(40000, 51820, &keepalive), Some("WireGuard"));
}

/// Valmet DNA : sur UDP 2517, une famille de message inconnue a
/// l'en-tete coherent est acceptee, et la balise de 42 octets sur
/// 4516 -> 4517 ; hors de ces ports, seules les deux familles connues
/// passent a l'aveugle, la balise et les familles inconnues restent
/// « Unknown » sauf par Decode As. Trames reelles de
/// pcaps_exemple/protocols/valmet_dna/valmet-dna-multicast-anon.pcap
/// (telegramme d'etat de la trame 1, balise de la trame 591).
#[test]
fn valmet_dna_is_lenient_on_its_ports_and_strict_elsewhere() {
    let label =
        |source: u16, destination: u16, payload: &[u8], decode_as: &[(u16, DecodeAsProtocol)]| {
            let transport = Transport {
                protocol: TransportProtocol::Udp,
                source_port: Some(source),
                destination_port: Some(destination),
                payload: Some(payload),
                details: None,
            };
            classify(&transport, decode_as).map(|a| a.protocol.label())
        };
    let status = hex::decode(concat!(
        "ab01801d00ff007c00000fff001003b00000048ace4818e03d0018803f000000",
        "000000000a0002010005000000000003010120200000000000001d00018a0052",
        "c59c00000001ef00ab0100000000000000000000000000000000000000000000",
        "00000000000000000000540f5bf154059702000000000000000009d609d6",
    ))
    .unwrap();
    assert_eq!(label(2517, 2517, &status, &[]), Some("Valmet DNA"));
    assert_eq!(label(40000, 40001, &status, &[]), Some("Valmet DNA"));

    let mut unknown_kind = status.clone();
    unknown_kind[11] = 0xFE;
    assert_eq!(label(2517, 2517, &unknown_kind, &[]), Some("Valmet DNA"));
    assert_eq!(label(40000, 40001, &unknown_kind, &[]), Some("Unknown"));
    assert_eq!(
        label(
            40000,
            40001,
            &unknown_kind,
            &[(40001, DecodeAsProtocol::ValmetDna)]
        ),
        Some("Valmet DNA")
    );

    let beacon = hex::decode(concat!(
        "00000000abcc0006238000003e0f252702d8ffe0000000000000000086950900",
        "0003010120200a000209",
    ))
    .unwrap();
    assert_eq!(label(4516, 4517, &beacon, &[]), Some("Valmet DNA"));
    assert_eq!(label(40000, 40001, &beacon, &[]), Some("Unknown"));
    assert_eq!(
        label(
            40000,
            40001,
            &beacon,
            &[(40000, DecodeAsProtocol::ValmetDna)]
        ),
        Some("Valmet DNA")
    );
    // La garde de transport reste : le meme telegramme sur TCP n'est pas
    // du Valmet DNA, Decode As compris.
    let tcp = Transport {
        protocol: TransportProtocol::Tcp,
        source_port: Some(2517),
        destination_port: Some(2517),
        payload: Some(&status),
        details: None,
    };
    assert_ne!(
        classify(&tcp, &[(2517, DecodeAsProtocol::ValmetDna)]).map(|a| a.protocol.label()),
        Some("Valmet DNA")
    );
}

/// Java RMI (#313) : l'en-tete de flux, le Call et le Return se reconnaissent
/// sur tout port TCP ; les messages courts (Ping, PingAck, DgcAck) sur 1099
/// et par Decode As seulement ; rien de JRMP sur UDP. Trames reelles de
/// pcaps_exemple/protocols/java_rmi/jdk11-loopback.pcap.
#[test]
fn java_rmi_is_blind_for_calls_and_port_guarded_for_short_messages() {
    let label = |protocol: TransportProtocol,
                 source: u16,
                 destination: u16,
                 payload: &[u8],
                 decode_as: &[(u16, DecodeAsProtocol)]| {
        let transport = Transport {
            protocol,
            source_port: Some(source),
            destination_port: Some(destination),
            payload: Some(payload),
            details: None,
        };
        classify(&transport, decode_as).map(|a| a.protocol.label())
    };
    use TransportProtocol::{Tcp, Udp};
    // Trame 4 : en-tete StreamProtocol ; trame 60 : `Station.add(2, 3)` ;
    // trame 61 : son retour.
    let header = hex::decode("4a524d4900024b").unwrap();
    let call = hex::decode(concat!(
        "50aced0005772a18ab9a4555f8f98abfcb98ab000001a1e8ed9c5b8001ffffffff",
        "94a9af306652c3a60000000200000003",
    ))
    .unwrap();
    let ret = hex::decode("51aced0005771301bfcb98ab000001a1e8ed9c5b800a00000005").unwrap();
    for message in [&header, &call, &ret] {
        assert_eq!(label(Tcp, 53372, 50050, message, &[]), Some("Java RMI"));
        assert_eq!(label(Tcp, 36556, 1099, message, &[]), Some("Java RMI"));
        assert_ne!(label(Udp, 53372, 50050, message, &[]), Some("Java RMI"));
    }

    // Trames 36, 37 et 53 : Ping, PingAck et DgcAck.
    let dgc_ack = hex::decode("54bfcb98ab000001a1e8ed9c5b8007").unwrap();
    for message in [&[0x52][..], &[0x53][..], &dgc_ack] {
        assert_eq!(label(Tcp, 36568, 1099, message, &[]), Some("Java RMI"));
        assert_eq!(label(Tcp, 53372, 50050, message, &[]), Some("Unknown"));
        assert_eq!(
            label(
                Tcp,
                53372,
                50050,
                message,
                &[(50050, DecodeAsProtocol::JavaRmi)]
            ),
            Some("Java RMI")
        );
        assert_ne!(
            label(
                Udp,
                36568,
                1099,
                message,
                &[(1099, DecodeAsProtocol::JavaRmi)]
            ),
            Some("Java RMI")
        );
    }
}

/// Anti-derive (revue 10.4.0) : chaque protocole Decode-As doit se
/// resoudre vers une etiquette et une sonde que la table connait — les
/// deux encodages ne peuvent pas diverger silencieusement.
#[test]
fn decode_as_protocols_resolve_to_table_rules() {
    use ProbeId as P;
    // `ALL` sort de la meme liste que l'enum : aucune variante n'echappe a
    // ce test (#274).
    let all = DecodeAsProtocol::ALL;
    // Decode As plus tolerant que la regle de port, a dessein : un port
    // declare est du WireGuard, octets reserves de Cloudflare compris
    // (le recours que l'heuristique de Wireshark indique), la ou 51820
    // n'est qu'un port ephemere (#169). La table doit connaitre la sonde
    // jumelle.
    let lenient_twins = [
        (ProbeId::WireGuard, ProbeId::WireGuardPort),
        (ProbeId::Nmf, ProbeId::NmfBlind),
        (ProbeId::Rtcp, ProbeId::RtcpBlind),
    ];
    // RTP n'a pas de regle dans la table, a dessein (#364) : deux bits
    // fixes ne font pas une sonde aveugle sans faux positif. Decode As est
    // la seule facon de le nommer.
    let decode_as_only = [ProbeId::Rtp];
    for protocol in all {
        for transport in [TransportProtocol::Tcp, TransportProtocol::Udp] {
            let (label, _, probe) = protocol.rule(transport);
            if decode_as_only
                .iter()
                .any(|only| *only as u32 == probe as u32)
            {
                assert!(
                    !RULES.iter().any(|rule| rule.label == label),
                    "{label} : Decode As seulement, mais la table le nomme"
                );
                continue;
            }
            let table_probe = lenient_twins
                .iter()
                .find(|(lenient, _)| *lenient as u32 == probe as u32)
                .map_or(probe, |(_, twin)| *twin);
            assert!(
                RULES
                    .iter()
                    .any(|rule| rule.label == label && rule.probe as u32 == table_probe as u32),
                "{label} (sonde {:?}) absent de la table",
                probe as u32
            );
        }
    }
    let _ = [P::Snmp]; // use alias
}

/// Decode As EtherNet/IP suit ses regles aveugles (#288) : sur TCP, des
/// messages complets qui pavent le segment, la sonde de la regle TCP ; sur
/// UDP, un seul message. Un port declare n'est jamais plus strict que la
/// table sans port.
#[test]
fn decode_as_ethernet_ip_follows_the_transport() {
    let (label, guard, probe) = DecodeAsProtocol::EthernetIp.rule(TransportProtocol::Tcp);
    assert_eq!(label, ApplicationProtocol::EthernetIp);
    assert!(matches!(guard, Guard::Tcp));
    assert_eq!(probe as u32, ProbeId::EthernetIpTcp as u32);
    let (_, _, probe) = DecodeAsProtocol::EthernetIp.rule(TransportProtocol::Udp);
    assert_eq!(probe as u32, ProbeId::EthernetIp as u32);
}

/// Les ports terminaux de la table ne sont pas contournables par
/// Decode-As : un paquet mDNS sur UDP 5353 declare "DNS" par l'appelant
/// reste arbitre par la regle terminale.
#[test]
fn decode_as_cannot_override_terminal_reserved_ports() {
    // Requete mDNS reelle minimaliste : en-tete + une question.
    let mdns_query =
        hex::decode("000000000001000000000000045f687474045f746370056c6f63616c00000c0001")
            .expect("fixture");
    let transport = Transport {
        protocol: TransportProtocol::Udp,
        source_port: Some(5353),
        destination_port: Some(5353),
        payload: Some(&mdns_query),
        details: None,
    };
    let decode_as = [(5353_u16, DecodeAsProtocol::Dns)];
    assert_eq!(
        classify(&transport, &decode_as).map(|a| a.protocol.label()),
        Some("mDNS"),
        "la regle terminale de la table garde la main sur 5353"
    );
}

/// `ProbeId::COUNT` est le nombre de variantes (#212). Toute variante
/// est construite par une regle de `RULES` ou de Decode As (une variante
/// jamais construite echoue au lint `dead_code`, clippy `-D warnings`) :
/// le plus grand identifiant qu'elles portent est donc la derniere
/// variante. Une sonde ajoutee en fin d'enum sans deplacer
/// `ProbeId::LAST` fait echouer ce test.
#[test]
fn probe_count_is_the_number_of_variants() {
    let decode_as = DecodeAsProtocol::ALL.iter().flat_map(|protocol| {
        [TransportProtocol::Tcp, TransportProtocol::Udp]
            .map(|transport| protocol.rule(transport).2 as u32)
    });
    let highest = RULES
        .iter()
        .map(|rule| rule.probe as u32)
        .chain(decode_as)
        .max()
        .expect("la table a des regles");
    assert_eq!(highest, ProbeId::LAST as u32);
    assert_eq!(ProbeId::COUNT, highest + 1);
    assert_eq!(ProbeId::LAST.bit(), 1 << (ProbeId::COUNT - 1));
}

/// L'invariant central de la table : une regle a port sans garde de
/// transport serait un retour de l'override port-seul (issue #25).
/// Seule DNS/53 est volontairement bi-transport.
#[test]
fn port_rules_carry_a_transport_guard() {
    for rule in RULES.iter().filter(|rule| rule.ports.is_some()) {
        assert!(
            !matches!(rule.guard, Guard::Any) || rule.label.label() == "DNS",
            "regle a port sans garde de transport : {}",
            rule.label
        );
    }
}

/// SIP (#342) : sonde aveugle sur TCP comme sur UDP, sur tout port, disjointe
/// de HTTP et de SSDP. Decode As le rend sur un port qu'une autre regle garde.
#[test]
fn sip_is_blind_on_both_transports_and_disjoint_from_http_and_ssdp() {
    let label = |protocol: TransportProtocol,
                 source: u16,
                 destination: u16,
                 payload: &[u8],
                 decode_as: &[(u16, DecodeAsProtocol)]| {
        let transport = Transport {
            protocol,
            source_port: Some(source),
            destination_port: Some(destination),
            payload: Some(payload),
            details: None,
        };
        classify(&transport, decode_as).map(|a| a.protocol.label())
    };
    use TransportProtocol::{Tcp, Udp};
    // Synthetique : les formes de RFC 3261 §24.2, F1 et F2.
    let invite = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
        Via: SIP/2.0/TCP pc33.atlanta.com;branch=z9hG4bKnashds8\r\n\
        To: Bob <sip:bob@biloxi.com>\r\n\
        From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
        Call-ID: a84b4c76e66710\r\n\
        CSeq: 314159 INVITE\r\n\
        Content-Length: 0\r\n\
        \r\n";
    let ringing = b"SIP/2.0 180 Ringing\r\n\
        v: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds8\r\n\
        t: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
        f: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
        i: a84b4c76e66710\r\n\
        CSeq: 314159 INVITE\r\n\
        \r\n";
    for message in [&invite[..], &ringing[..]] {
        for protocol in [Tcp, Udp] {
            assert_eq!(label(protocol, 5060, 5060, message, &[]), Some("SIP"));
            assert_eq!(label(protocol, 40000, 12345, message, &[]), Some("SIP"));
        }
    }

    // HTTP et SSDP restent les leurs, sur le port de SIP compris.
    let http = b"OPTIONS / HTTP/1.1\r\nHost: biloxi.com\r\n\r\n";
    assert_eq!(label(Tcp, 40000, 5060, http, &[]), Some("HTTP"));
    let ssdp = b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\
        NT: upnp:rootdevice\r\nNTS: ssdp:alive\r\n\r\n";
    assert_eq!(label(Udp, 40000, 1900, ssdp, &[]), Some("SSDP"));
    assert_eq!(label(Udp, 40000, 5060, ssdp, &[]), Some("Unknown"));

    // Sans CSeq, la tete n'est pas SIP, ni HTTP.
    let text = std::str::from_utf8(invite).unwrap();
    let without_cseq = text.replace("CSeq: 314159 INVITE\r\n", "");
    assert_eq!(
        label(Tcp, 40000, 5060, without_cseq.as_bytes(), &[]),
        Some("Unknown")
    );

    // mDNS garde 5353 (RFC 6762) : un echec n'y retombe sur aucune autre
    // sonde, et Decode As ne contourne pas un port reserve.
    assert_eq!(label(Udp, 40000, 5353, invite, &[]), None);
    assert_eq!(
        label(Udp, 40000, 5353, invite, &[(5353, DecodeAsProtocol::Sip)]),
        None
    );
    // Decode As passe avant la table, sur les deux transports.
    for protocol in [Tcp, Udp] {
        assert_eq!(
            label(
                protocol,
                40000,
                2000,
                invite,
                &[(2000, DecodeAsProtocol::Sip)]
            ),
            Some("SIP")
        );
    }
}

/// RTCP (#354) : la sonde aveugle, derniere de la cascade UDP, veut un SR ou un RR en
/// tete, ou un message de retour seul ; un port declare prend tout
/// datagramme bien forme. Octets synthetiques.
#[test]
fn rtcp_is_blind_on_reports_and_declared_otherwise() {
    use TransportProtocol::{Tcp, Udp};
    let label =
        |protocol: TransportProtocol, payload: &[u8], decode_as: &[(u16, DecodeAsProtocol)]| {
            let transport = Transport {
                protocol,
                source_port: Some(40001),
                destination_port: Some(40003),
                payload: Some(payload),
                details: None,
            };
            classify(&transport, decode_as).map(|a| a.protocol.label())
        };
    let declared = [(40003, DecodeAsProtocol::Rtcp)];
    // Receiver Report sans bloc : en-tete et SSRC.
    let report = [0x80, 201, 0, 1, 0x12, 0x34, 0x56, 0x78];
    assert_eq!(label(Udp, &report, &[]), Some("RTCP"));
    assert_eq!(label(Tcp, &report, &[]), Some("Unknown"));

    // BYE seul : bien forme, hors de la sonde aveugle.
    let bye = [0x81, 203, 0, 1, 0x12, 0x34, 0x56, 0x78];
    assert_eq!(label(Udp, &bye, &[]), Some("Unknown"));
    assert_eq!(label(Udp, &bye, &declared), Some("RTCP"));
    assert_eq!(label(Tcp, &bye, &declared), Some("Unknown"));

    // Un octet de trop : les longueurs ne pavent plus le datagramme.
    let mut long = report.to_vec();
    long.push(0);
    assert_eq!(label(Udp, &long, &declared), Some("Unknown"));
}

/// DCE/RPC (#356) : l'en-tete commun sur TCP, sur n'importe quel port.
/// Octets synthetiques : un Shutdown de seize octets.
#[test]
fn dcerpc_is_blind_on_tcp_only() {
    use TransportProtocol::{Tcp, Udp};
    let label = |protocol: TransportProtocol, payload: &[u8]| {
        let transport = Transport {
            protocol,
            source_port: Some(49152),
            destination_port: Some(49667),
            payload: Some(payload),
            details: None,
        };
        classify(&transport, &[]).map(|a| a.protocol.label())
    };
    let shutdown = [5, 0, 17, 3, 0x10, 0, 0, 0, 16, 0, 0, 0, 1, 0, 0, 0];
    assert_eq!(label(Tcp, &shutdown), Some("DCE/RPC"));
    assert_eq!(label(Udp, &shutdown), Some("Unknown"));

    // Version 4 (sans connexion) et octets reserves de drep non nuls.
    let mut v4 = shutdown;
    v4[0] = 4;
    assert_eq!(label(Tcp, &v4), Some("Unknown"));
    let mut drep = shutdown;
    drep[6] = 1;
    assert_eq!(label(Tcp, &drep), Some("Unknown"));

    // Des octets apres le fragment qui ne sont pas un second PDU.
    let mut trailing = shutdown.to_vec();
    trailing.extend([0xde, 0xad]);
    assert_eq!(label(Tcp, &trailing), Some("Unknown"));
}

/// CAPWAP (#355) : un en-tete RFC 5415 ou un preambule DTLS, sur UDP 5246
/// et 5247 seulement. Octets synthetiques.
#[test]
fn capwap_is_named_on_its_two_udp_ports_only() {
    use TransportProtocol::{Tcp, Udp};
    let label = |protocol: TransportProtocol, port: u16, payload: &[u8]| {
        let transport = Transport {
            protocol,
            source_port: Some(40000),
            destination_port: Some(port),
            payload: Some(payload),
            details: None,
        };
        classify(&transport, &[]).map(|a| a.protocol.label())
    };
    // En-tete de deux mots, WBID 1, puis un message de controle.
    let control = [0x00, 0x10, 0x02, 0x00, 0, 0, 0, 0, 0, 0, 0, 1];
    assert_eq!(label(Udp, 5246, &control), Some("CAPWAP"));
    assert_eq!(label(Udp, 5247, &control), Some("CAPWAP"));
    assert_eq!(label(Udp, 5248, &control), Some("Unknown"));
    assert_eq!(label(Tcp, 5246, &control), Some("Unknown"));

    // Preambule DTLS : un enregistrement handshake DTLS 1.0 de deux octets.
    let dtls = [
        0x01, 0, 0, 0, 22, 0xfe, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0xaa, 0xbb,
    ];
    assert_eq!(label(Udp, 5246, &dtls), Some("CAPWAP"));
    let mut cut = dtls;
    cut[16] = 3; // longueur au-dela du datagramme
    assert_eq!(label(Udp, 5246, &cut), Some("Unknown"));

    // Refus : version 1, HLEN d'un mot, WBID nul, bits reserves, bit L ou
    // decalage sans bit F.
    for (index, value) in [
        (0, 0x10),
        (1, 0x08),
        (2, 0x00),
        (3, 0x01),
        (3, 0x40),
        (7, 0x08),
        (7, 0x01),
    ] {
        let mut bad = control;
        bad[index] = value;
        assert_eq!(label(Udp, 5246, &bad), Some("Unknown"), "octet {index}");
    }
    // Avec le bit F, un fragment a decalage non nul est admis.
    let mut fragment = control;
    fragment[3] = 0x80;
    fragment[7] = 0x08;
    assert_eq!(label(Udp, 5247, &fragment), Some("CAPWAP"));
}

/// Skinny (#370) : des messages qui pavent le segment, sur TCP 2000 ou sur
/// un port declare, jamais ailleurs. Octets synthetiques : un KeepAlive de
/// douze octets, version d'en-tete 0x11.
#[test]
fn skinny_is_named_on_tcp_2000_only() {
    use TransportProtocol::{Tcp, Udp};
    let label = |protocol: TransportProtocol,
                 source: u16,
                 destination: u16,
                 payload: &[u8],
                 decode_as: &[(u16, DecodeAsProtocol)]| {
        let transport = Transport {
            protocol,
            source_port: Some(source),
            destination_port: Some(destination),
            payload: Some(payload),
            details: None,
        };
        classify(&transport, decode_as).map(|a| a.protocol.label())
    };
    let keep_alive = [4, 0, 0, 0, 0x11, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(label(Tcp, 49152, 2000, &keep_alive, &[]), Some("Skinny"));
    assert_eq!(label(Tcp, 2000, 49152, &keep_alive, &[]), Some("Skinny"));
    assert_eq!(label(Tcp, 49152, 2001, &keep_alive, &[]), Some("Unknown"));
    assert_eq!(label(Udp, 49152, 2000, &keep_alive, &[]), Some("Unknown"));

    // Un autre port se declare, sous la meme garde de transport.
    let declared = [(2001, DecodeAsProtocol::Skinny)];
    assert_eq!(
        label(Tcp, 49152, 2001, &keep_alive, &declared),
        Some("Skinny")
    );
    assert_eq!(
        label(Udp, 49152, 2001, &keep_alive, &declared),
        Some("Unknown")
    );

    // Deux messages qui pavent le segment ; deux octets de trop le refusent.
    let mut two = keep_alive.to_vec();
    two.extend([8, 0, 0, 0, 0x11, 0, 0, 0, 3, 0, 0, 0, 5, 0, 0, 0]);
    assert_eq!(label(Tcp, 49152, 2000, &two, &[]), Some("Skinny"));
    two.extend([0xde, 0xad]);
    assert_eq!(label(Tcp, 49152, 2000, &two, &[]), Some("Unknown"));

    // Refus sur le port : longueur sous l'identifiant, version d'en-tete
    // inconnue, identifiant hors plage, message coupe de plus de 64 Kio.
    for (index, value) in [(0, 3), (4, 1), (5, 1), (9, 2), (11, 1), (2, 1)] {
        let mut bad = keep_alive;
        bad[index] = value;
        assert_eq!(
            label(Tcp, 49152, 2000, &bad, &[]),
            Some("Unknown"),
            "octet {index}"
        );
    }

    // 2000 est aussi un port ephemere : une requete HTTP qui en part garde
    // son etiquette.
    let http = b"GET / HTTP/1.1\r\nHost: example.org\r\n\r\n";
    assert_eq!(label(Tcp, 2000, 80, http, &[]), Some("HTTP"));
}

/// Syslog (#374) : un message par datagramme sur UDP 514, des trames de la
/// RFC 6587 sur TCP 514 et 601, ou sur un port declare, jamais ailleurs.
/// Octets synthetiques.
#[test]
fn syslog_is_named_on_its_ports_only() {
    use TransportProtocol::{Tcp, Udp};
    let label = |protocol: TransportProtocol,
                 source: u16,
                 destination: u16,
                 payload: &[u8],
                 decode_as: &[(u16, DecodeAsProtocol)]| {
        let transport = Transport {
            protocol,
            source_port: Some(source),
            destination_port: Some(destination),
            payload: Some(payload),
            details: None,
        };
        classify(&transport, decode_as).map(|a| a.protocol.label())
    };
    let message = b"<13>Feb  5 17:32:18 host app: text";
    let line = b"<13>Feb  5 17:32:18 host app: text\n";
    let counted = b"34 <13>Feb  5 17:32:18 host app: text";

    assert_eq!(label(Udp, 49152, 514, message, &[]), Some("Syslog"));
    assert_eq!(label(Udp, 514, 49152, message, &[]), Some("Syslog"));
    assert_eq!(label(Udp, 49152, 515, message, &[]), Some("Unknown"));
    // 601 n'est un port syslog que sur TCP.
    assert_eq!(label(Udp, 49152, 601, message, &[]), Some("Unknown"));
    for payload in [&message[..], line, counted] {
        assert_eq!(label(Tcp, 49152, 514, payload, &[]), Some("Syslog"));
        assert_eq!(label(Tcp, 49152, 601, payload, &[]), Some("Syslog"));
        assert_eq!(label(Tcp, 49152, 515, payload, &[]), Some("Unknown"));
    }

    // Un datagramme est un message : le comptage d'octets n'existe que sur
    // TCP.
    assert_eq!(label(Udp, 49152, 514, counted, &[]), Some("Unknown"));
    // Sur TCP, chaque ligne s'ouvre par une priorite ; un datagramme, lui,
    // garde ses LF dans son contenu.
    let two_lines = b"<13>first\nsecond\n";
    assert_eq!(label(Tcp, 49152, 514, two_lines, &[]), Some("Unknown"));
    assert_eq!(label(Udp, 49152, 514, two_lines, &[]), Some("Syslog"));

    // Un autre port se declare, sur TCP comme sur UDP, chacun sous sa forme.
    let declared = [(1514, DecodeAsProtocol::Syslog)];
    assert_eq!(label(Udp, 49152, 1514, message, &declared), Some("Syslog"));
    assert_eq!(label(Tcp, 49152, 1514, counted, &declared), Some("Syslog"));
    assert_eq!(label(Udp, 49152, 1514, counted, &declared), Some("Unknown"));

    // Refus sur le port : pas de priorite, priorite hors bornes, le debut
    // d'une session rsh sur TCP 514.
    for payload in [&b"text without priority"[..], b"<192>text", b"<01>text"] {
        assert_eq!(label(Udp, 49152, 514, payload, &[]), Some("Unknown"));
        assert_eq!(label(Tcp, 49152, 514, payload, &[]), Some("Unknown"));
    }
    let rsh = b"1021\0root\0root\0ls\0";
    assert_eq!(label(Tcp, 1022, 514, rsh, &[]), Some("Unknown"));
}

/// LDAP (#372) : des PDU qui pavent le payload, sur TCP 389 et 3268, sur
/// UDP 389 ou sur un port declare, jamais ailleurs. Octets synthetiques :
/// un UnbindRequest de sept octets, et l'en-tete d'un tampon SASL chiffre
/// suivi de quatre octets de donnees.
#[test]
fn ldap_is_named_on_its_ports_only() {
    use TransportProtocol::{Tcp, Udp};
    let label = |protocol: TransportProtocol,
                 source: u16,
                 destination: u16,
                 payload: &[u8],
                 decode_as: &[(u16, DecodeAsProtocol)]| {
        let transport = Transport {
            protocol,
            source_port: Some(source),
            destination_port: Some(destination),
            payload: Some(payload),
            details: None,
        };
        classify(&transport, decode_as).map(|a| a.protocol.label())
    };
    let unbind = [0x30, 0x05, 0x02, 0x01, 0x01, 0x42, 0x00];
    let sealed = [
        0, 0, 0, 20, 0x05, 0x04, 0x06, 0xff, 0, 0, 0, 0x1c, 0, 0, 0, 0, 0, 0, 0, 1, 0xde, 0xad,
        0xbe, 0xef,
    ];
    for payload in [&unbind[..], &sealed[..]] {
        assert_eq!(label(Tcp, 49152, 389, payload, &[]), Some("LDAP"));
        assert_eq!(label(Tcp, 389, 49152, payload, &[]), Some("LDAP"));
        assert_eq!(label(Tcp, 49152, 3268, payload, &[]), Some("LDAP"));
        assert_eq!(label(Udp, 49152, 389, payload, &[]), Some("LDAP"));
        // Le catalogue global n'existe que sur TCP.
        assert_eq!(label(Udp, 49152, 3268, payload, &[]), Some("Unknown"));
        assert_eq!(label(Tcp, 49152, 390, payload, &[]), Some("Unknown"));
        assert_eq!(label(Udp, 49152, 390, payload, &[]), Some("Unknown"));
    }

    // Un autre port se declare, sur TCP comme sur UDP.
    let declared = [(10389, DecodeAsProtocol::Ldap)];
    assert_eq!(label(Tcp, 49152, 10389, &unbind, &declared), Some("LDAP"));
    assert_eq!(label(Udp, 49152, 10389, &unbind, &declared), Some("LDAP"));

    // Deux PDU qui pavent le segment ; deux octets de trop le refusent.
    let mut two = sealed.to_vec();
    two.extend(unbind);
    assert_eq!(label(Tcp, 49152, 389, &two, &[]), Some("LDAP"));
    two.extend([0xde, 0xad]);
    assert_eq!(label(Tcp, 49152, 389, &two, &[]), Some("Unknown"));

    // Refus sur le port : pas une SEQUENCE, longueur indefinie, identifiant
    // qui n'est pas un INTEGER, operation inconnue, UnbindRequest non vide.
    for (index, value) in [(0, 0x31), (1, 0x80), (2, 0x04), (5, 0x62), (6, 0x01)] {
        let mut bad = unbind;
        bad[index] = value;
        assert_eq!(
            label(Tcp, 49152, 389, &bad, &[]),
            Some("Unknown"),
            "octet {index}"
        );
    }
    // Tampon SASL : longueur sous l'en-tete du jeton, autre jeton, bourrage.
    for (index, value) in [(3, 15), (0, 1), (4, 0x60), (5, 0x05), (7, 0x00)] {
        let mut bad = sealed;
        bad[index] = value;
        assert_eq!(
            label(Tcp, 49152, 389, &bad, &[]),
            Some("Unknown"),
            "octet {index}"
        );
    }

    // 3268 est aussi un port ephemere : une requete HTTP qui en part garde
    // son etiquette.
    let http = b"GET / HTTP/1.1\r\nHost: example.org\r\n\r\n";
    assert_eq!(label(Tcp, 3268, 80, http, &[]), Some("HTTP"));
}

/// NMF (#352) : la sonde aveugle prend un preambule ou une enveloppe qui
/// s'ouvre comme [MC-NBFSE] ; l'accuse de preambule, un octet, ne se nomme
/// que sur un port declare. Octets synthetiques.
#[test]
fn nmf_is_blind_on_preamble_and_envelope_only() {
    use TransportProtocol::{Tcp, Udp};
    let label =
        |protocol: TransportProtocol, payload: &[u8], decode_as: &[(u16, DecodeAsProtocol)]| {
            let transport = Transport {
                protocol,
                source_port: Some(40000),
                destination_port: Some(40002),
                payload: Some(payload),
                details: None,
            };
            classify(&transport, decode_as).map(|a| a.protocol.label())
        };
    let declared = [(40002, DecodeAsProtocol::Nmf)];

    let preamble = b"\x00\x01\x00\x01\x02\x02\x0dnet.tcp://h/s\x03\x08\x0c";
    assert_eq!(label(Tcp, preamble, &[]), Some("NMF"));
    assert_eq!(label(Udp, preamble, &[]), Some("Unknown"));

    // Enveloppe a taille, table de chaines vide, s:Envelope.
    let envelope = [0x06, 0x07, 0x00, 0x56, 0x02, 0x0B, 0x01, 0x73, 0x04];
    assert_eq!(label(Tcp, &envelope, &[]), Some("NMF"));

    // Preamble Ack : un octet, hors de la sonde aveugle.
    assert_eq!(label(Tcp, &[0x0B], &[]), Some("Unknown"));
    assert_eq!(label(Tcp, &[0x0B], &declared), Some("NMF"));
    assert_eq!(label(Udp, &[0x0B], &declared), Some("Unknown"));

    // Un segment de suite ne se decoupe pas en enregistrements.
    assert_eq!(label(Tcp, &[0x45, 0x17, 0x14], &declared), Some("Unknown"));
}
/// RTP (#353, #364) : jamais a l'aveugle, deux bits fixes ne suffisent pas ;
/// un port declare par Decode As prend tout paquet bien forme, sur UDP
/// seulement. Octets synthetiques : un en-tete de douze octets et une
/// charge de quatre.
#[test]
fn rtp_is_named_on_a_declared_udp_port_only() {
    use TransportProtocol::{Tcp, Udp};
    let label =
        |protocol: TransportProtocol, payload: &[u8], decode_as: &[(u16, DecodeAsProtocol)]| {
            let transport = Transport {
                protocol,
                source_port: Some(40000),
                destination_port: Some(40002),
                payload: Some(payload),
                details: None,
            };
            classify(&transport, decode_as).map(|a| a.protocol.label())
        };
    let declared = [(40002, DecodeAsProtocol::Rtp)];
    let plain = [
        0x80, 0x60, 0x00, 0x01, 0x00, 0x00, 0x00, 0xA0, 0x12, 0x34, 0x56, 0x78, 1, 2, 3, 4,
    ];
    assert_eq!(label(Udp, &plain, &[]), Some("Unknown"));
    assert_eq!(label(Udp, &plain, &declared), Some("RTP"));
    assert_eq!(label(Tcp, &plain, &declared), Some("Unknown"));

    // Un CSRC : bien forme, donc nomme sur le port declare.
    let mut mixed = plain.to_vec();
    mixed[0] = 0x81;
    assert_eq!(label(Udp, &mixed, &[]), Some("Unknown"));
    assert_eq!(label(Udp, &mixed, &declared), Some("RTP"));

    // `0xC8` en deuxieme octet : un Sender Report de RTCP, jamais du RTP.
    let mut rtcp = plain.to_vec();
    rtcp[1] = 0xC8;
    assert_eq!(label(Udp, &rtcp, &declared), Some("Unknown"));

    // Version 1 : refusee meme sur un port declare.
    let mut old = plain.to_vec();
    old[0] = 0x40;
    assert_eq!(label(Udp, &old, &declared), Some("Unknown"));
}

/// La liste aveugle de la table, figee : un protocole ajoute ou deplace s'y
/// voit.
#[test]
fn blind_rules_order_is_frozen() {
    let blind: Vec<&str> = RULES
        .iter()
        .filter(|rule| rule.ports.is_none())
        .map(|rule| rule.label.label())
        .collect();
    assert_eq!(
        blind,
        [
            "S7Comm",
            "FTP",
            "SMTP",
            "NNTP",
            "NTP",
            "RTPS",
            "Valmet DNA",
            "ASTERIX",
            "DIS",
            "DNP3",
            "RADIUS",
            "BACnet/IP",
            "Bitcoin",
            "OPC UA",
            // TCP, puis UDP (#288).
            "EtherNet/IP",
            "EtherNet/IP",
            "PostgreSQL",
            "DNS",
            "SNMP",
            "TLS",
            "SSH",
            "SIP",
            "HTTP",
            "SSH",
            "GIOP",
            "Java RMI",
            "DHCP",
            "SRVLOC",
            "UMAS",
            "ModbusTCP",
            "QUIC",
            "WireGuard",
            "RTCP",
            "NMF",
            "DCE/RPC",
            "MQTT",
        ],
        "S7Comm est promu en tete (priorite sur COTP), et les verbes \
             non-ambigus FTP/SMTP/NNTP ne valent que hors de leurs ports \
             (issue #66, veto de port)"
    );
}

/// Les gardes de la sonde HTTP (#249) ne refusent rien que les decodeurs
/// acceptent : sur des requetes et des reponses valides, precedees de chaque
/// blanc Unicode, puis alterees octet par octet, « le decodeur accepte »
/// implique toujours « la garde accepte ». Une garde trop stricte changerait
/// des etiquettes sans qu'aucun autre test le voie.
#[test]
fn http_guards_never_refuse_what_the_decoders_accept() {
    use crate::checks::application::http::{may_start_request, may_start_response};
    use crate::parse::application::protocols::http::{HttpRequest, HttpResponse};

    fn check(payload: &[u8], accepted: &mut usize) {
        if HttpRequest::try_from(payload).is_ok() {
            *accepted += 1;
            assert!(may_start_request(payload), "requete refusee : {payload:?}");
        }
        if HttpResponse::try_from(payload).is_ok() {
            *accepted += 1;
            assert!(may_start_response(payload), "reponse refusee : {payload:?}");
        }
    }

    let seeds: [&[u8]; 6] = [
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        b"POST /submit HTTP/1.0\r\nContent-Length: 2\r\n\r\nok",
        b"OPTIONS * HTTP/2",
        b"CONNECT example.com:443 HTTP/1.1\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\n",
        b"HTTP/1.0 404 Not Found",
    ];
    let whitespace: Vec<char> = (0..=u32::from(char::MAX))
        .filter_map(char::from_u32)
        .filter(|character| character.is_whitespace())
        .collect();
    let mut accepted = 0;

    for seed in seeds {
        check(seed, &mut accepted);
        // Un blanc, puis deux, devant chaque graine.
        for first in &whitespace {
            for second in whitespace.iter().map(Some).chain([None]) {
                let mut payload = first.to_string();
                payload.extend(second);
                let mut payload = payload.into_bytes();
                payload.extend_from_slice(seed);
                check(&payload, &mut accepted);
            }
        }
        // Chaque octet de la premiere ligne remplace par chaque valeur.
        for index in 0..seed.len().min(24) {
            for value in 0..=u8::MAX {
                let mut payload = seed.to_vec();
                payload[index] = value;
                check(&payload, &mut accepted);
            }
        }
    }
    // Le test n'est pas vide : graines, variantes a blancs et alterations
    // acceptees par les decodeurs.
    assert!(accepted > 2_000, "{accepted} cas acceptes seulement");
}

/// AMS (#290) : sur TCP 48898, l'en-tete AMS/TCP de 6 octets precede chaque
/// message ; la regle UDP 48899 lit l'en-tete AMS nu. Chaque transport n'a
/// que sa forme, Decode As compris.
#[test]
fn ams_reads_its_tcp_header_on_tcp_and_the_bare_header_on_udp() {
    // ADS Read Request construit a la main, lu « ADS Read (2) » par tshark.
    let ams_tcp = hex::decode(concat!(
        "00002c000000",
        "c0a8016401015303c0a801650101e880",
        "020004000c0000000000000007000000",
        "05f000000000000004000000"
    ))
    .expect("fixture");
    let bare = &ams_tcp[6..];
    let on = |protocol, port, payload| Transport {
        protocol,
        source_port: Some(33_000),
        destination_port: Some(port),
        payload: Some(payload),
        details: None,
    };
    let label = |transport: &Transport<'_>, decode_as: &[(u16, DecodeAsProtocol)]| {
        classify(transport, decode_as).map(|a| a.protocol.label())
    };

    assert_eq!(
        label(&on(TransportProtocol::Tcp, 48898, &ams_tcp), &[]),
        Some("AMS")
    );
    assert_ne!(
        label(&on(TransportProtocol::Tcp, 48898, bare), &[]),
        Some("AMS")
    );
    assert_eq!(
        label(&on(TransportProtocol::Udp, 48899, bare), &[]),
        Some("AMS")
    );
    assert_ne!(
        label(&on(TransportProtocol::Udp, 48899, &ams_tcp), &[]),
        Some("AMS")
    );

    let decode_as = [(50_000_u16, DecodeAsProtocol::Ams)];
    assert_eq!(
        label(&on(TransportProtocol::Tcp, 50_000, &ams_tcp), &decode_as),
        Some("AMS")
    );
    assert_ne!(
        label(&on(TransportProtocol::Tcp, 50_000, bare), &decode_as),
        Some("AMS")
    );
    assert_eq!(
        label(&on(TransportProtocol::Udp, 50_000, bare), &decode_as),
        Some("AMS")
    );
}
