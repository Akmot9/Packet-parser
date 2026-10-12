// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Snapshot de classification applicative sur le corpus reel (audit 8.1.0
//! §5.3, prerequis a toute refonte du dispatch L7) : l'histogramme
//! {etiquette -> nombre de flux} sur `pcaps_exemple/protocols/` (hors
//! `s7comm/`, couvert par sa propre regression, selection < 2 Mo) est fige.
//!
//! Une regression de classification — un protocole qui cesse d'etre reconnu,
//! un faux positif qui apparait — casse ce test avec un diff lisible. Toute
//! evolution volontaire du dispatch doit mettre a jour l'attendu **dans le
//! meme commit**, avec sa justification.

use std::collections::BTreeMap;
use std::path::Path;

use packet_parser::parse;

mod common;
use common::{FileRead, collect_capture_files, read_capture};

/// Etiquette d'un flux : son protocole applicatif, ou un marqueur explicite.
const NO_APPLICATION: &str = "(sans application)";
const LINK_ERROR: &str = "(erreur L2)";

fn classification_histogram() -> BTreeMap<String, usize> {
    let protocol_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("pcaps_exemple")
        .join("protocols");
    let mut captures = Vec::new();
    collect_capture_files(protocol_dir.as_path(), &mut captures);
    captures.sort();
    assert!(!captures.is_empty(), "corpus introuvable");

    let mut histogram: BTreeMap<String, usize> = BTreeMap::new();
    for path in &captures {
        let FileRead::Frames { frames, .. } = read_capture(path) else {
            continue;
        };
        for (link_type, data) in &frames {
            let Ok(flow) = parse(*link_type, data) else {
                *histogram.entry(LINK_ERROR.to_string()).or_default() += 1;
                continue;
            };
            for flattened in flow.flatten() {
                let label = flattened
                    .application
                    .as_ref()
                    .map_or(NO_APPLICATION, |application| {
                        application.application_protocol
                    });
                *histogram.entry(label.to_string()).or_default() += 1;
            }
        }
    }
    histogram
}

#[test]
fn application_classification_histogram_is_frozen() {
    let actual = classification_histogram();

    // Fige le 2026-08-19 sur 58 captures (2 893 trames), avant la refonte du
    // dispatch L7 en table declarative. Les 42 « erreur L2 » sont les trames
    // de mqtt_packets_MosquittoLinux.pcap et consorts au LINKTYPE non
    // supporte, deja comptees par la regression s7comm.
    //
    // Evolutions volontaires (meme jour) :
    // - DNS 102 -> 104 : correction NXDOMAIN — l'exigence aa=1 sur rcode 3
    //   rejetait les reponses des resolveurs recursifs
    //   (dns_query_nonexistent.pcapng#2, dns_lab.pcapng#18) ;
    // - NTP 4 -> 0, TLS 584 -> 587, Unknown 419 -> 418 : gardes de transport
    //   sur les sondes aveugles. Les quatre « NTP » etaient des faux positifs
    //   sur du TCP (dont trois Encrypted Alerts TLS de dump.pcapng, 0x15 lu
    //   comme LI/VN/mode) — le corpus n'a aucune vraie capture NTP
    //   (protocols/ntp/ ne contient qu'un .gitkeep).
    //
    // 2026-08-20 (issue #57) : ajout de protocols/ethernet_ip/ (3 captures
    // ITI/ICS-Security-Tools, 13 trames). Les 4 trames EtherNet/IP reelles
    // (ListIdentity requete/reponse, SendRRData, SendUnitData) creent
    // l'entree "EtherNet/IP" ; les 9 trames restantes d'enip_test.pcap sont
    // du handshake/teardown TCP sans payload -> "(sans application)"
    // 1233 -> 1242.
    //
    // 2026-08-20 (issue #5) : ajout de protocols/openvpn/ (2 samples publics
    // de la wiki Wireshark, 878 trames, session tls-auth sur UDP puis TCP
    // 1194). Le module openvpn n'etant pas encore cable dans le dispatch,
    // aucune etiquette OpenVPN : les 766 trames portant un message OpenVPN
    // sortent "Unknown" (439 datagrammes UDP + 327 segments TCP a payload,
    // comptes par `tshark -Y openvpn` moins la trame ICMP ci-dessous) ;
    // les 112 restantes n'ont pas de L7 (111 segments TCP purs
    // handshake/ACK sans payload, plus la trame UDP 440 — un ICMP port
    // unreachable qui embarque l'extrait du datagramme OpenVPN, que tshark
    // compte "openvpn" mais que la crate classe ICMP). "(sans application)"
    // 1242 -> 1354, "Unknown" 418 -> 1184. Au cablage du port 1194, ces 766
    // "Unknown" deviendront l'entree "OpenVPN".
    //
    // 2026-08-20 (issue #58) : ajout de protocols/giop/corba.pcap (corpus de
    // tests nDPI, 28 trames, verifie avec tshark 4.6.6). Les 3 messages GIOP
    // qui tiennent dans leur segment TCP (trames 4, 6, 12 : Request "echo" et
    // deux Reply) creent l'entree "GIOP" ; 9 trames TCP sans payload
    // (handshake/ACK) vont en "(sans application)" ; les 16 restantes sortent
    // "Unknown" (+16, 1184 -> 1200) : 10 datagrammes UDP MIOP (le dispatch ne
    // sonde GIOP que sur TCP), 5 segments d'un Request/Reply GIOP deborde de
    // son segment (s=4152/4017, tronque par la segmentation TCP) et 1 message
    // ZIOP (GIOP compresse, magic "ZIOP", hors perimetre).
    //
    // Constate lors du meme gel (travaux concurrents deja presents dans
    // l'arbre, hors issue #58) :
    // - les 5 trames de protocols/ftp/ sortent desormais en flux aplatis
    //   "IP-in-IP" (externe) + "FTP" (interne), soit +5 "FTP", +5 "IP-in-IP"
    //   et -5 "(sans application)" (1354 + 9 - 5 = 1358) ;
    // - le cablage OpenVPN (issue #5) est arrive : les 766 trames OpenVPN
    //   annoncees ci-dessus quittent "Unknown" pour l'entree "OpenVPN"
    //   (1184 + 16 - 766 = 434).
    //
    // 2026-09-19 (epic #76, GIOP complet) : dix captures rejoignent
    // protocols/giop/ — trois pieces jointes du tracker Wireshark et sept
    // captures du labo omniORB (voir SOURCE.md), 372 trames recoupees avec
    // tshark 4.6.6 :
    // - "GIOP" 3 -> 123 : +119 messages des nouvelles captures, et +1 pour la
    //   trame 8 de corba.pcap — le premier segment d'un message qui deborde
    //   de son segment TCP est desormais accepte et marque `truncated` au
    //   lieu d'etre rejete (elle quitte "Unknown") ;
    // - "HTTP" 62 -> 72 : les 10 `GET /PM.LTEOMS-...` de la capture #11616
    //   (`http.request` en compte 10) ;
    // - "(sans application)" 1358 -> 1566 : +208 segments TCP sans payload
    //   (`tcp.len==0` : 133+2+5+9+10+11+11+11+8+8) ;
    // - "Unknown" 434 -> 468 : +35 segments de continuation (suite d'un
    //   message GIOP ou d'une reponse HTTP, sans magic : non reconnaissables
    //   sans etat), -1 pour la trame 8 de corba.pcap.
    //
    // 2026-09-20 (issue #10, UMAS) : +1 capture protocols/umas/umas.pcap
    // (corpus nDPI, 191 trames Ethernet/IPv4/TCP), et le code fonction
    // Modbus 0x5A reconnu comme UMAS :
    // - "UMAS" 0 -> 181 : les 180 trames 0x5A de la nouvelle capture, plus
    //   la trame 229 de protocols/modbus/MODBUS-TestDataPart2.pcap, une
    //   requete UMAS adressee a un automate qui la refuse (sa reponse, code
    //   fonction 0xDA, est une exception Modbus et reste ModbusTCP) ;
    // - "ModbusTCP" 383 -> 382 : cette seule trame change d'etiquette ;
    // - "(sans application)" 1566 -> 1577 : les 11 trames TCP sans payload
    //   de la nouvelle capture.
    //
    // 2026-09-20 (issue #95, LINKTYPE_NULL) : +1 capture
    // protocols/opcua/opcua_loopback.pcap (corpus nDPI, 381 trames en
    // encapsulation loopback BSD), que le decodeur de liaison rend enfin
    // lisible — elles echouaient toutes en UnsupportedLinkType :
    // - "OPC UA" 0 -> 187 : parite exacte avec `tshark -Y opcua` ;
    // - "(sans application)" 1577 -> 1771 : les 194 trames TCP sans payload
    //   de la capture, ce que tshark compte aussi.
    // "(erreur L2)" ne bouge pas : aucune de ces trames n'echoue au L2.
    //
    // 2026-09-30 (ASTERIX) : +2 captures dans protocols/asterix/ —
    // cat048_multicast.pcap (203 datagrammes CAT 048 sur UDP 8611/8612,
    // capture du mainteneur anonymisee) et cat_034_048.pcap (100
    // datagrammes CAT 034 + 048, echantillon CroatiaControlLtd/asterix,
    // GPL-2.0), voir SOURCE.md. La sonde structurelle etiquette
    // exactement ces 303 trames (`tshark -Y asterix` en compte autant) :
    // - "ASTERIX" 0 -> 303 ;
    // - rien d'autre ne bouge : aucune trame du reste du corpus ne passe la
    //   sonde (tous les data blocks d'une categorie connue, records
    //   decoupes selon l'UAP jusqu'au dernier octet), et aucune trame
    //   ASTERIX n'etait volee par une sonde precedente.
    //
    // 2026-10-08 (lot defense, epopee #125) : +34 captures, 57 190 trames —
    // 6 dans protocols/asterix/, puis rtps/, ptp/, stanag5066/, dis/ et
    // ipsec/ (voir le SOURCE.md de chaque dossier et
    // docs/protocoles-defense.md). Aucun decodeur ne change : ces captures
    // attendent leurs issues (#119 a #124), et l'histogramme fige ce que la
    // crate en fait aujourd'hui, recoupe avec tshark 4.6.6 :
    // - "ASTERIX" 303 -> 13 739 : +11 881 datagrammes de
    //   wireshark_8579_radardata.pcap, exactement ceux qui ne portent que du
    //   CAT 034/048 (tshark en compte autant), et +1 555 datagrammes CAT 021
    //   de wireshark_9953_cat021023.pcap ;
    // - "Unknown" 468 -> 42 276 (+41 808) : 36 353 trames de radardata.pcap,
    //   dont ses 30 047 datagrammes ASTERIX qui portent une categorie non
    //   decodee (001, 002, 008, 062, 063, 065 — #119) ; 721 datagrammes
    //   ASTERIX des autres nouvelles captures (CAT 023/247, 062/065, 008) ;
    //   et les 4 734 trames a payload des cinq nouveaux dossiers, qu'aucune
    //   regle ne reconnait encore (RTPS 231, PTP sur UDP 3 221, STANAG 5066
    //   39, DIS 393, IKE/ESP 850) ;
    // - "(sans application)" 1 771 -> 3 618 (+1 847) : 1 530 fragments IPv4,
    //   92 IGMP et 45 trames hors IPv4 (LOOP, DTP, CDP, HP, ARP, ICMPv6) de
    //   radardata.pcap ; 107 trames PTP en couche 2 (EtherType 0x88F7, nomme
    //   mais pas decode) ; 8 ESP natifs ; 16 fragments IPv4 de
    //   RTPS_Discovery.pcapng ; 47 segments TCP sans payload des captures
    //   STANAG 5066 ; 2 ICMP de la NodeB ;
    // - "STP" 0 -> 95 et "DHCP" 6 -> 9 : BPDU et echanges DHCP reels de
    //   radardata.pcap (tshark : 95 et 3) ;
    // - "SRVLOC" 0 -> 1 : la requete SLPv2 de radardata.pcap (tshark : 1).
    //   Les 829 PTP Delay_Req de ptp/wireshark_6126_nodeb_startup.pcap, dont
    //   l'en-tete a la forme d'un SLPv1, sont rejetes par le champ language,
    //   qui doit etre un code ISO 639 de deux lettres (#117) ;
    // - "DNS" reste a 104 : les 37 datagrammes du flux radar
    //   225.10.1.1:20201 de radardata.pcap, en-tetes vides suivis d'octets en
    //   trop, sont rejetes par la sonde aveugle stricte (#118).
    //
    // Decodeur PTP (#121) : "PTP" 0 -> 3 221, exactement les messages PTP
    // sur UDP 319/320 de ptp/ que tshark voit (3 217 PTPv2 et 4 PTPv1), qui
    // quittent "Unknown" (42 276 -> 39 055). Les 107 trames PTP en couche 2
    // restent "(sans application)" : PTP y est la couche internet (EtherType
    // 0x88F7), verifiee trame par trame par tests/ptp_golden.rs.
    //
    // 2026-10-12 (issue #133, PROFINET) : +7 captures dans
    // protocols/profinet/, 2 685 trames dont 232 PN-RT (voir SOURCE.md) : deux
    // traces de cisagov/icsnpp-profinet-io-cm (BSD-3), trois d'ITI/ICS-
    // Security-Tools (CC-BY-4.0, dont la piece jointe du wiki Wireshark
    // PROFINET/DCP) et deux du labo de miguelob/ICS-Hacking (GPL-3.0). Aucun
    // decodeur ne change ; recoupe avec tshark 4.6.6 :
    // - "NBNS" 0 -> 731, "LLMNR" 0 -> 136, "SSDP" 0 -> 24, "DHCP" 9 -> 71,
    //   "DHCPv6" 4 -> 32 : le bruit Windows de mixed_1 (tshark : nbns 731,
    //   llmnr 136, ssdp 24, dhcp 62, dhcpv6 28) ;
    // - "mDNS" 4 -> 12 : les 8 datagrammes mDNS (4 IPv4, 4 IPv6) de
    //   miguelob_pn.pcapng ;
    // - "Unknown" 39 055 -> 40 177 (+1 122) : 1 000 datagrammes DCE/RPC du
    //   PROFINET IO-CM sur UDP 34964 (950 + 38 + 12), qu'aucune regle ne
    //   nomme ; 88 annonces Dropbox LAN sync (db-lsp-disc, UDP 17500), 32
    //   datagrammes UDP 1947 et 2 NetBIOS Datagram (UDP 138) de mixed_1 ;
    // - "(sans application)" 3 618 -> 4 192 (+574) : les 232 trames PN-RT
    //   (EtherType 0x8892 : 164 + 10 + 4 + 14 + 4 + 18 + 18), sans transport,
    //   dont la crate rend 103 `internet = Profinet` et 129 `corrupted`
    //   (tests/profinet_corpus.rs fige ce partage, point de depart de #133) ;
    //   205 LLDP ; 25 ARP ; 67 ICMPv6 ; 45 IGMP.
    //
    // 2026-10-12 (provenance du corpus, suite de #104) : deux fichiers
    // fabriques retires, contraires a la regle « trames reelles uniquement »
    // — protocols/http/simple-http-request.pcap (1 trame : MAC
    // 00:11:22:33:44:55, epoch 1 710 000 000 exactement, User-Agent
    // « SampleClient/1.0 ») et capwap-multi-wtp.pcap (24 trames rejouees
    // depuis capwap-only.pcap avec des MAC aa:bb:cc:… et des horodatages
    // ronds). Seul mouvement : "HTTP" 72 -> 71, la trame fabriquee.
    //
    // 2026-10-12 (#119, ASTERIX multi-categories) : le decodeur gagne huit
    // categories (001, 002, 008, 023, 062, 063, 065, 247), les deux UAP de
    // CAT 001 et le Random Field Sequencing. "ASTERIX" 13 739 -> 44 507
    // (+30 768) et "Unknown" 40 177 -> 9 409 (-30 768), exactement :
    // - les 30 047 datagrammes de radardata.pcap qui portent une categorie
    //   jusque-la non decodee, dont les 96 sur lesquels tshark bute (I002/050
    //   de deux octets, voir SOURCE.md et asterix_tshark_limits.tsv) ;
    // - les 721 datagrammes des autres captures : 668 de cat62_re.pcap, 33
    //   CAT 023/247 de cat021023.pcap, 19 de cat008only(-2).pcap, 1 de
    //   cat_062_065.pcap.
    // Parite item par item avec tshark sur 44 411 trames
    // (tests/asterix_golden.rs). Rien d'autre ne bouge.
    //
    // 2026-10-12 (#120, RTPS) : "RTPS" 0 -> 231 et "Unknown" 9 409 -> 9 178
    // (-231) : exactement les trames RTPS de protocols/rtps/ hors fragments
    // IPv4 (tshark en compte 237, dont 6 par reassemblage), en parite trame
    // par trame (tests/rtps_golden.rs). La sonde est aveugle (magic + pavage
    // exact) : rien d'autre ne bouge dans le reste du corpus.
    //
    // 2026-10-12 (#122, STANAG 5066 SIS) : "STANAG 5066" 0 -> 34 et "Unknown"
    // 9 178 -> 9 144 (-34) : les segments TCP 5066 de protocols/stanag5066/
    // qui commencent un S_PDU, en parite avec tshark sans reassemblage
    // (tests/stanag5066_golden.rs). Les 5 segments de continuation, sans
    // preambule, restent "Unknown" — tshark non plus ne les etiquette pas
    // sans reassembler.
    //
    // 2026-10-12 (#123, DIS) : "DIS" 0 -> 390 et "Unknown" 9 144 -> 8 754
    // (-390) : les trames de protocols/dis/ dont les PDU pavent exactement
    // le datagramme, par la sonde aveugle (UDP 3000, 6993 et 22999). Les 3
    // Set Data de wireshark_3492_dis_test2.pcap (UDP 6993) annoncent 48
    // octets pour 160 : "Unknown" sans Decode As, DIS avec
    // (tests/dis_golden.rs, parite tshark sur les 393).
    //
    // 2026-10-12 (#124, IKE et ESP) : "IKE" 0 -> 535 (UDP 500 et 4500 de
    // protocols/ipsec/, nus ou derriere le marqueur non-ESP), "ESP" 0 -> 315
    // (ESP dans UDP 4500), "Unknown" 8 754 -> 7 904 (-850). Les 8 ESP natifs
    // (protocole IP 50) restent sans application, comme ICMP : leur SPI est
    // dans `TransportDetails::Esp` (tests/ipsec_golden.rs, parite tshark sur
    // les 858).
    //
    // 2026-10-12 (#98, corpus PostgreSQL de Zeek, 14 captures, 331 segments a
    // payload) : "PostgreSQL" 0 -> 278 (276 segments en parite tshark + les
    // 2 retransmissions de psql-login-no-role.pcap, que tshark ne dissèque
    // pas), "TLS" 587 -> 613 (+26 : la session TLS apres le `S` de
    // psql-aws-ssl-preferred/require), "HTTP" 71 -> 72 (+1 : la requete de
    // http-on-port-5432.pcap, negatif), "Unknown" 7 904 -> 7 930 (+26 : les
    // 18 segments MySQL et 4 HTTP des negatifs, 4 segments TLS retransmis ou
    // coupes), "(sans application)" 4 192 -> 4 392 (+200 : les ACK).
    //
    // 2026-10-12 (#99, corpus DNP3 de Zeek, 16 captures, 423 trames) :
    // "DNP3" 0 -> 218 (les 218 trames de liaison, toutes a l'aveugle, TCP et
    // UDP, dont les 2 de dnp3_read_p20001.pcap sur le port 20001), "Unknown"
    // 7 930 -> 7 932 (+2 : deux segments de dnp3.pcap, port 2803, qui ne
    // sont pas du DNP3), "(sans application)" 4 392 -> 4 595 (+203 : les
    // ACK).
    let expected: BTreeMap<String, usize> = [
        (LINK_ERROR, 42_usize),
        (NO_APPLICATION, 4595),
        ("ASTERIX", 44_507),
        ("DHCP", 71),
        ("DIS", 390),
        ("DNP3", 218),
        ("DHCPv6", 32),
        ("DNS", 104),
        ("ESP", 315),
        ("EtherNet/IP", 4),
        ("FTP", 5),
        ("GIOP", 123),
        ("HTTP", 72),
        ("IKE", 535),
        ("IP-in-IP", 5),
        ("LLMNR", 136),
        ("MQTT", 38),
        ("NBNS", 731),
        ("ModbusTCP", 382),
        ("UMAS", 181),
        ("NNTP", 6),
        ("OPC UA", 187),
        ("OpenVPN", 766),
        ("PTP", 3221),
        ("PostgreSQL", 278),
        ("SMTP", 6),
        ("SRVLOC", 1),
        ("SSDP", 24),
        ("STP", 95),
        ("TLS", 613),
        ("RTPS", 231),
        ("STANAG 5066", 34),
        ("Unknown", 7_932),
        ("mDNS", 12),
    ]
    .into_iter()
    .map(|(label, count)| (label.to_string(), count))
    .collect();

    assert_eq!(
        actual, expected,
        "\nhistogramme observe (a figer dans `expected` si le changement est voulu) :\n{:#?}\n",
        actual
    );
}
