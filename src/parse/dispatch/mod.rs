// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Dispatch applicatif L7 declaratif (audit 8.1.0 §5.3, issues #20, #25, #29).
//!
//! L'ancienne implementation empilait trois mecanismes de priorite — ordre
//! d'une cascade, gardes de port appliquees inegalement, et un override ou le
//! port ecrasait le contenu — repartis sur deux fichiers. Ici, **une seule
//! table ordonnee** porte tout : garde de transport, garde de port
//! optionnelle, sonde. L'ordre du tableau est la priorite, inspectable et
//! testable.
//!
//! Invariants :
//! - une regle a port n'etiquette que si **port et contenu** concordent — le
//!   port seul ne decide jamais (fin de l'override OPC UA, issue #25) ;
//! - chaque sonde s'execute **au plus une fois** par payload : les echecs
//!   sont memoises par [`ProbeId`] (fin du double sondage PostgreSQL et
//!   SNMP, issue #29) ;
//! - chaque sonde juge les octets que son decodeur lira : le payload entier,
//!   que les decodeurs exigent souvent pave jusqu'au dernier octet (SNMP,
//!   Modbus/TCP, ASTERIX...) ou couvert par une longueur declaree (NBSS,
//!   DNS sur TCP, TLS...). Seules les sondes des protocoles texte (FTP, SMTP,
//!   NNTP, HTTP), qui valident tout le texte en UTF-8, ne lisent que
//!   [`PROBE_CAP`] octets : la borne de l'issue #20, qui plafonnait jadis
//!   toutes les sondes (#184, #185), et que l'oracle du fuzz recopie.

use super::application::Application;
use super::transport::Transport;
use super::transport::protocols::TransportProtocol;

mod ports;
mod probes;
#[cfg(test)]
mod tests;

use ports::*;
use probes::*;

/// Transport requis par une regle.
#[derive(Clone, Copy)]
enum Guard {
    Tcp,
    Udp,
    /// Sonde de contenu valable quel que soit le transport.
    Any,
}

impl Guard {
    const fn admits(self, protocol: TransportProtocol) -> bool {
        match self {
            Self::Tcp => matches!(protocol, TransportProtocol::Tcp),
            Self::Udp => matches!(protocol, TransportProtocol::Udp),
            Self::Any => true,
        }
    }
}

/// Une regle du dispatch : `label` est retenu si la garde de transport
/// admet le paquet, que la garde de port (si presente) matche un des deux
/// ports, et que la sonde accepte le contenu.
struct Rule {
    label: &'static str,
    guard: Guard,
    ports: Option<fn(Option<u16>) -> bool>,
    /// Ports qui interdisent la regle : sur les ports standards de la
    /// famille des protocoles textuels, un verbe distinctif est souvent du
    /// *contenu* (corps SMTP DATA, article NNTP) — le port l'emporte.
    ports_veto: Option<fn(Option<u16>) -> bool>,
    probe: ProbeId,
    /// Regle terminale : si son port matche, le verdict est definitif meme
    /// quand la sonde echoue (mDNS : le port 5353 est reserve, RFC 6762 —
    /// la sonde DNS generique ne doit pas re-etiqueter ces octets).
    terminal_on_port: bool,
}

const fn rule(label: &'static str, guard: Guard, probe: ProbeId) -> Rule {
    Rule {
        label,
        guard,
        ports: None,
        ports_veto: None,
        probe,
        terminal_on_port: false,
    }
}

const fn port_rule(
    label: &'static str,
    guard: Guard,
    ports: fn(Option<u16>) -> bool,
    probe: ProbeId,
) -> Rule {
    Rule {
        label,
        guard,
        ports: Some(ports),
        ports_veto: None,
        probe,
        terminal_on_port: false,
    }
}

/// La table : l'ordre est la priorite. D'abord les regles a port (signature
/// faible confirmee par le port, ou priorite sur un port standard), puis les
/// sondes aveugles dans l'ordre historique de `Application::try_from` — cet
/// ordre est porteur de semantique (S7Comm avant COTP, DHCP avant SRVLOC,
/// MQTT en dernier) et verrouille par le snapshot `tests/golden_pcaps.rs`.
/// Les regles sans garde ni veto de port sont aussi, dans cet ordre, la
/// cascade de `Application::try_from` ([`classify_blind`], #216).
static RULES: &[Rule] = &[
    port_rule("SNMP", Guard::Udp, is_snmp_udp_port, ProbeId::Snmp),
    port_rule("DHCPv6", Guard::Udp, is_dhcpv6_udp_port, ProbeId::Dhcpv6),
    // Signature assez forte pour le probing aveugle sur TCP, et doit gagner
    // sur l'etiquette COTP generique, y compris sur le port 102.
    rule("S7Comm", Guard::Tcp, ProbeId::S7Comm),
    port_rule("COTP", Guard::Tcp, is_iso_tsap_tcp_port, ProbeId::CotpTpkt),
    // FTP, SMTP et NNTP partagent la meme forme de reponse ("code SP texte
    // CRLF") et plusieurs commandes : strictement gardes par port.
    port_rule("FTP", Guard::Tcp, is_ftp_tcp_port, ProbeId::Ftp),
    port_rule("SMTP", Guard::Tcp, is_smtp_tcp_port, ProbeId::Smtp),
    port_rule("NNTP", Guard::Tcp, is_nntp_tcp_port, ProbeId::Nntp),
    // Detection hors port standard (issue #66) : certains verbes
    // n'appartiennent qu'a un seul des trois protocoles textuels — eux seuls
    // sont detectes par contenu, les verbes partages (QUIT, LIST, MODE...)
    // et les reponses (formes octet pour octet identiques) restent gardes
    // par port ci-dessus.
    Rule {
        label: "FTP",
        guard: Guard::Tcp,
        ports: None,
        ports_veto: Some(is_text_protocol_port),
        probe: ProbeId::FtpUnambiguous,
        terminal_on_port: false,
    },
    Rule {
        label: "SMTP",
        guard: Guard::Tcp,
        ports: None,
        ports_veto: Some(is_text_protocol_port),
        probe: ProbeId::SmtpUnambiguous,
        terminal_on_port: false,
    },
    Rule {
        label: "NNTP",
        guard: Guard::Tcp,
        ports: None,
        ports_veto: Some(is_text_protocol_port),
        probe: ProbeId::NntpUnambiguous,
        terminal_on_port: false,
    },
    // mDNS reprend le format DNS mais ses reponses omettent souvent la
    // question (RFC 6762 §6) : validateur dedie, et port terminal.
    Rule {
        label: "mDNS",
        guard: Guard::Udp,
        ports: Some(is_mdns_udp_port),
        ports_veto: None,
        probe: ProbeId::Mdns,
        terminal_on_port: true,
    },
    // LLMNR partage le format DNS ; comme mDNS, son port UDP 5355 est
    // reserve (RFC 4795) et terminal — la sonde DNS generique ne doit pas
    // re-etiqueter ces octets.
    Rule {
        label: "LLMNR",
        guard: Guard::Udp,
        ports: Some(is_llmnr_udp_port),
        ports_veto: None,
        probe: ProbeId::Llmnr,
        terminal_on_port: true,
    },
    // SSDP est du HTTPU sur le port multicast reserve 1900.
    port_rule("SSDP", Guard::Udp, is_ssdp_udp_port, ProbeId::Ssdp),
    // NetBIOS : name service sur UDP 137, session service sur TCP 139 et
    // TCP 445 (SMB direct hosting, meme framing a 4 octets).
    port_rule("NBNS", Guard::Udp, is_nbns_udp_port, ProbeId::Nbns),
    port_rule("NBSS", Guard::Tcp, is_nbss_tcp_port, ProbeId::Nbss),
    // OpenVPN : datagramme nu sur UDP 1194, prefixe de longueur sur TCP.
    port_rule("OpenVPN", Guard::Udp, is_openvpn_port, ProbeId::OpenVpnUdp),
    port_rule("OpenVPN", Guard::Tcp, is_openvpn_port, ProbeId::OpenVpnTcp),
    port_rule("AMS", Guard::Tcp, is_ams_tcp_port, ProbeId::Ams),
    port_rule("AMS", Guard::Udp, is_ams_udp_port, ProbeId::Ams),
    // QUIC 1-RTT (Short Header) : en-tete volontairement opaque (RFC 9000
    // §17.3), une heuristique gardee par le port est le maximum stateless.
    port_rule(
        "QUIC",
        Guard::Udp,
        is_quic_udp_port,
        ProbeId::QuicShortHeader,
    ),
    // Priorites de port sur sondes par ailleurs aveugles : le port ne suffit
    // jamais, mais il fait passer la sonde avant le reste de la cascade.
    port_rule("OPC UA", Guard::Tcp, is_opcua_tcp_port, ProbeId::Opcua),
    // DNS : la forme datagramme n'existe que sur UDP, et TCP prefixe chaque
    // message de sa longueur (RFC 1035 §4.2). Sonder la forme datagramme sur
    // du TCP etiquetait "DNS" des fragments de reassemblage (trame 6 de
    // dns_axfr.pcapng) : chaque transport n'a que sa forme.
    port_rule("DNS", Guard::Tcp, is_dns_port, ProbeId::DnsTcp),
    port_rule("DNS", Guard::Udp, is_dns_port, ProbeId::Dns),
    // PTP (IEEE 1588) : UDP 319 et 320 (annexes D et E). Garde par port : un
    // Delay_Req a exactement la forme d'un en-tete SLPv1 (#117), et le
    // seul messageType ne distingue pas PTP d'un payload quelconque. En
    // couche 2 (EtherType 0x88F7), PTP est decode par la couche internet.
    port_rule("PTP", Guard::Udp, is_ptp_port, ProbeId::Ptp),
    // DIS (IEEE 1278.1) : pas de port IANA, 3000 par usage. Sur ce port, la
    // lecture tolere une longueur declaree plus courte que le datagramme
    // (trois PDU reels du corpus) ; ailleurs, la sonde aveugle ci-dessous
    // exige que les PDU pavent exactement le datagramme (#123).
    port_rule("DIS", Guard::Udp, is_dis_udp_port, ProbeId::DisLenient),
    // RADIUS (RFC 2865) sur ses ports : 1812/1813, les anciens 1645/1646,
    // 3799 (RFC 5176). La meme sonde revient a l'aveugle plus bas (#101).
    port_rule("RADIUS", Guard::Udp, is_radius_udp_port, ProbeId::Radius),
    // BACnet/IP (ASHRAE 135, annexe J) sur ses ports 47808 a 47823 ; la
    // meme sonde revient a l'aveugle plus bas (#102).
    port_rule("BACnet/IP", Guard::Udp, is_bacnet_udp_port, ProbeId::Bacnet),
    // Valmet DNA (reseau de process Metso/Valmet, proprietaire) : UDP 2517
    // pour les messages `AB 01`, 4516 -> 4517 pour la balise — les ports
    // observes, le protocole n'en a pas d'enregistre a son nom. Sur ces
    // ports, une famille de message inconnue est acceptee avec son corps en
    // octets ; ailleurs, la sonde aveugle plus bas n'accepte que les deux
    // familles connues.
    port_rule(
        "Valmet DNA",
        Guard::Udp,
        is_valmet_dna_udp_port,
        ProbeId::ValmetDna,
    ),
    // RDP (MS-RDPBCGR) : TCP 3389. Garde par port : TPKT, COTP et MCS sont
    // aussi la pile de T.120 et d'ISO sur TCP, un autre port se declare par
    // Decode As. Apres une negociation TLS ou CredSSP, les segments
    // suivants sont du TLS et etiquetes TLS (#100).
    port_rule("RDP", Guard::Tcp, is_rdp_tcp_port, ProbeId::Rdp),
    // IEC 60870-5-104 : TCP 2404. Garde par port : `0x68` et une longueur
    // sont deux octets, trop peu pour sonder tout segment TCP ; un autre
    // port se declare par Decode As (#102).
    port_rule("IEC 104", Guard::Tcp, is_iec104_tcp_port, ProbeId::Iec104),
    // PostgreSQL sur son port : decodage et forme compatible suffisent — un
    // Terminate, un ReadyForQuery ou un mot de passe seuls dans leur
    // segment, la reponse d'un octet a SSLRequest (S ou N) — la ou la sonde
    // aveugle ci-dessous exige une preuve forte. Mesure sur le corpus Zeek :
    // aucun faux positif sur HTTP et MySQL rejoues sur 5432 (#98).
    port_rule(
        "PostgreSQL",
        Guard::Tcp,
        is_postgresql_tcp_port,
        ProbeId::PostgresqlPort,
    ),
    // IKE (RFC 7296, RFC 2408) : UDP 500, et UDP 4500 derriere le marqueur
    // non-ESP de la RFC 3948. Garde par port : un en-tete de vingt-huit
    // octets a version et longueur plausibles n'est pas une signature
    // suffisante pour sonder tout datagramme (#124).
    port_rule("IKE", Guard::Udp, is_ike_udp_port, ProbeId::Ike),
    // ESP dans UDP 4500 (RFC 3948 §2.1) : SPI non nul en tete, la suite ne
    // se decoupe qu'avec l'association de securite ; puis le NAT-keepalive
    // d'un octet (§2.3). ESP natif (protocole IP 50) est decode par la couche
    // transport.
    port_rule("ESP", Guard::Udp, is_nat_t_udp_port, ProbeId::EspNatT),
    port_rule(
        "NAT-keepalive",
        Guard::Udp,
        is_nat_t_udp_port,
        ProbeId::NatKeepalive,
    ),
    // STANAG 5066 SIS : TCP 5066 (port IANA). Garde par port : le preambule
    // `90 EB 00`, un type et une taille sont trois octets fixes et deux
    // contraintes — trop peu pour une sonde aveugle sur tout segment TCP ;
    // un autre port se declare par Decode As (#122).
    port_rule(
        "STANAG 5066",
        Guard::Tcp,
        is_stanag5066_tcp_port,
        ProbeId::Stanag5066,
    ),
    // Modbus/TCP sur TCP 502 (IANA `mbap`) : l'enveloppe MBAP suffit quand le
    // port confirme, UMAS d'abord, protocole le plus specifique ; ailleurs,
    // la sonde aveugle stricte plus bas (#167).
    port_rule("UMAS", Guard::Tcp, is_modbus_tcp_port, ProbeId::Umas),
    port_rule(
        "ModbusTCP",
        Guard::Tcp,
        is_modbus_tcp_port,
        ProbeId::ModbusTcp,
    ),
    // WireGuard : UDP 51820, le port des exemples de `wg(8)` — aucun port
    // IANA. Comme pour l'heuristique de tshark, la forme du message suffit
    // a une initiation ou une reponse, octets reserves compris (Cloudflare
    // s'en sert), et un cookie ou des donnees ont des octets reserves nuls.
    // 51820 est un port ephemere : apres les autres regles de port, pour
    // qu'un paquet ESP, IKE ou DNS dont le pair l'a tire au hasard garde
    // son etiquette. Ailleurs, la sonde aveugle plus bas (#103).
    port_rule(
        "WireGuard",
        Guard::Udp,
        is_wireguard_udp_port,
        ProbeId::WireGuardPort,
    ),
    // NTP (RFC 5905) : UDP 123, en derniere regle de port — la place
    // qu'avait la sonde aveugle, si bien que rien ne change sur ce port :
    // le decodeur tolerant suffit quand le port confirme (#164).
    port_rule("NTP", Guard::Udp, is_ntp_udp_port, ProbeId::Ntp),
    // --- cascade aveugle, ordre historique de `Application::try_from`,
    // avec les gardes de transport que les RFC imposent : sonder NTP sur du
    // TCP etiquetait "NTP" des Encrypted Alerts TLS (0x15 = LI/VN/mode
    // plausible — trames 44/329/614 de dump.pcapng). Seuls les protocoles
    // reellement bi-transport restent en Guard::Any. ---
    // NTP hors du port 123 : l'ancien decodeur laissait passer un datagramme
    // aleatoire sur 250 (43 faux positifs sur 59 etiquettes NTP dans le
    // corpus nDPI : QUIC, KCP, PFCP, NetBIOS...). La sonde exige aussi un
    // poll, une precision et un root delay qu'une implementation emet, des
    // champs d'extension et un MAC qui finissent avec le datagramme, Receive
    // avant Transmit et, au stratum 0, un identifiant nul, ASCII ou
    // `127.0.0.1` (#164). Reste qu'une requete DNS de 48 octets avec EDNS sur soixante
    // a la forme d'un paquet NTP : hors du port 53, elle sort NTP.
    rule("NTP", Guard::Udp, ProbeId::NtpBlind),
    // RTPS (DDS) : magic `RTPS` puis des sous-messages qui pavent exactement
    // le datagramme. Sonde aveugle sur UDP : Cyclone DDS et Connext Micro
    // emploient des ports unicast aleatoires (#120).
    rule("RTPS", Guard::Udp, ProbeId::Rtps),
    // Valmet DNA : magie `AB 01`, longueur egale au datagramme moins deux et
    // une famille connue a sa taille exacte — plus de 64 bits de contrainte,
    // assez pour se passer du port.
    rule("Valmet DNA", Guard::Udp, ProbeId::ValmetDnaBlind),
    // ASTERIX (surveillance aerienne) circule en UDP, le plus souvent en
    // multicast et sans port fixe : sonde structurelle (tous les data
    // blocks d'une categorie connue, records decoupes exactement selon
    // l'UAP). Avant DNS, dont la forme datagramme est moins contrainte.
    rule("ASTERIX", Guard::Udp, ProbeId::Asterix),
    // DIS : en-tete de douze octets (version 1 a 7, type 1 a 72, famille de
    // la norme) et pavage exact du datagramme par ses PDU.
    rule("DIS", Guard::Udp, ProbeId::Dis),
    // DNP3 (IEEE 1815) : `05 64`, un CRC-16/DNP sur l'en-tete et sur chaque
    // bloc de seize octets — une signature qui se passe du port 20000, sur
    // TCP comme sur UDP (#99).
    rule("DNP3", Guard::Any, ProbeId::Dnp3),
    // RADIUS : code connu, longueur egale au datagramme, attributs qui le
    // pavent — assez contraint pour se passer du port (#101).
    rule("RADIUS", Guard::Udp, ProbeId::Radius),
    // BACnet/IP : `0x81`, une fonction BVLC, une longueur egale au
    // datagramme, un NPDU de version 1 — assez contraint pour se passer du
    // port (#102).
    rule("BACnet/IP", Guard::Udp, ProbeId::Bacnet),
    rule("Bitcoin", Guard::Tcp, ProbeId::Bitcoin),
    rule("OPC UA", Guard::Tcp, ProbeId::Opcua),
    // EtherNet/IP est reellement bi-transport (TCP 44818, UDP 2222).
    rule("EtherNet/IP", Guard::Any, ProbeId::EthernetIp),
    // PostgreSQL ne circule que sur TCP : la garde manquait et la sonde
    // s'executait deux fois (issue #29).
    rule("PostgreSQL", Guard::Tcp, ProbeId::Postgresql),
    // Forme datagramme : UDP uniquement (RFC 1035 §4.2.1) — sur TCP elle ne
    // peut matcher que des fragments, la forme prefixee est port-guardee.
    // Hors port 53, sonde stricte : sections consommant tout le datagramme
    // et au moins un enregistrement (issue #118).
    rule("DNS", Guard::Udp, ProbeId::DnsBlind),
    // SNMP sur TCP existe (RFC 3430) meme s'il est rare : bi-transport.
    rule("SNMP", Guard::Any, ProbeId::Snmp),
    rule("TLS", Guard::Tcp, ProbeId::Tls),
    // SSH avant HTTP : prefixe litteral `SSH-` + version exacte, aucun
    // recouvrement avec les methodes HTTP.
    rule("SSH", Guard::Tcp, ProbeId::Ssh),
    rule("HTTP", Guard::Tcp, ProbeId::Http),
    // GIOP/IIOP est transporte par TCP.
    rule("GIOP", Guard::Tcp, ProbeId::Giop),
    // DHCP avant SRVLOC : un BOOTP mimait un en-tete SLP (issue #3).
    rule("DHCP", Guard::Udp, ProbeId::Dhcp),
    // SLP accepte TCP et UDP (RFC 2608 §6.1) : bi-transport.
    rule("SRVLOC", Guard::Any, ProbeId::Srvloc),
    // UMAS avant ModbusTCP : il est porte par une enveloppe Modbus valide,
    // donc la sonde Modbus reconnaitrait aussi ses trames. Le protocole le
    // plus specifique gagne l'etiquette, comme S7Comm devant COTP.
    rule("UMAS", Guard::Tcp, ProbeId::Umas),
    // Modbus/TCP hors du port 502 : l'enveloppe MBAP (identifiant de
    // protocole nul, longueur qui pave le segment) est aussi celle de tout
    // message prefixe de deux octets et d'une longueur sur quatre — LDAP,
    // DICOM, Elasticsearch ; chaque PDU doit en plus porter un code fonction
    // courant et la taille qu'il impose (#167).
    rule("ModbusTCP", Guard::Tcp, ProbeId::ModbusTcpBlind),
    rule("QUIC", Guard::Udp, ProbeId::QuicLongHeader),
    // WireGuard hors de 51820 : un octet de type, trois octets reserves nuls,
    // une taille fixe ou, pour les donnees, un compteur sous 2^60 et un
    // paquet clair complete a seize octets ou arrete a la MTU. Derniere sonde
    // UDP : un Transport Data n'a pour lui que `04 00 00 00` et ces
    // contraintes (#103).
    rule("WireGuard", Guard::Udp, ProbeId::WireGuardBlind),
    // MQTT (TCP) en dernier : en-tete fixe peu discriminant.
    rule("MQTT", Guard::Tcp, ProbeId::Mqtt),
];

/// Protocole que l'appelant peut associer a un port supplementaire via
/// [`crate::ParseConfig`] (« Decode As », issue #65). La regle de la table
/// vaut aussi ici : le port declare ne suffit jamais, la sonde de contenu
/// doit accepter le payload, et la garde de transport du protocole reste
/// appliquee.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecodeAsProtocol {
    Ftp,
    Smtp,
    Nntp,
    Cotp,
    Dns,
    Mdns,
    Llmnr,
    Ssdp,
    Nbns,
    Nbss,
    Snmp,
    Dhcpv6,
    OpcUa,
    PostgreSql,
    ModbusTcp,
    EthernetIp,
    Ams,
    QuicShortHeader,
    OpenVpn,
    Ptp,
    Stanag5066,
    Dis,
    /// IKE nu ou derriere le marqueur non-ESP (UDP).
    Ike,
    /// ESP encapsule dans UDP (RFC 3948), SPI non nul en tete.
    Esp,
    /// RDP : TPKT, COTP X.224 et MCS (TCP).
    Rdp,
    /// IEC 60870-5-104 : APDU `0x68` sur TCP.
    Iec104,
    /// WireGuard sur UDP : la forme du message, octets reserves compris
    /// quel que soit le type.
    WireGuard,
    /// Valmet DNA sur UDP : messages `AB 01` de toute famille, et la balise.
    ValmetDna,
}

impl DecodeAsProtocol {
    /// (etiquette, garde, sonde) de la regle equivalente de la table. DNS
    /// choisit sa forme selon le transport : datagramme sur UDP, prefixe de
    /// longueur sur TCP (RFC 1035 §4.2).
    fn rule(self, protocol: TransportProtocol) -> (&'static str, Guard, ProbeId) {
        match self {
            Self::Ftp => ("FTP", Guard::Tcp, ProbeId::Ftp),
            Self::Smtp => ("SMTP", Guard::Tcp, ProbeId::Smtp),
            Self::Nntp => ("NNTP", Guard::Tcp, ProbeId::Nntp),
            Self::Cotp => ("COTP", Guard::Tcp, ProbeId::CotpTpkt),
            Self::Dns => match protocol {
                TransportProtocol::Tcp => ("DNS", Guard::Tcp, ProbeId::DnsTcp),
                _ => ("DNS", Guard::Udp, ProbeId::Dns),
            },
            Self::Mdns => ("mDNS", Guard::Udp, ProbeId::Mdns),
            Self::Llmnr => ("LLMNR", Guard::Udp, ProbeId::Llmnr),
            Self::Ssdp => ("SSDP", Guard::Udp, ProbeId::Ssdp),
            Self::Nbns => ("NBNS", Guard::Udp, ProbeId::Nbns),
            Self::Nbss => ("NBSS", Guard::Tcp, ProbeId::Nbss),
            Self::Snmp => ("SNMP", Guard::Any, ProbeId::Snmp),
            Self::Dhcpv6 => ("DHCPv6", Guard::Udp, ProbeId::Dhcpv6),
            Self::OpcUa => ("OPC UA", Guard::Tcp, ProbeId::Opcua),
            Self::PostgreSql => ("PostgreSQL", Guard::Tcp, ProbeId::PostgresqlPort),
            Self::ModbusTcp => ("ModbusTCP", Guard::Tcp, ProbeId::ModbusTcp),
            Self::EthernetIp => ("EtherNet/IP", Guard::Any, ProbeId::EthernetIp),
            Self::Ams => ("AMS", Guard::Any, ProbeId::Ams),
            Self::QuicShortHeader => ("QUIC", Guard::Udp, ProbeId::QuicShortHeader),
            Self::OpenVpn => match protocol {
                TransportProtocol::Tcp => ("OpenVPN", Guard::Tcp, ProbeId::OpenVpnTcp),
                _ => ("OpenVPN", Guard::Udp, ProbeId::OpenVpnUdp),
            },
            Self::Ptp => ("PTP", Guard::Udp, ProbeId::Ptp),
            Self::Stanag5066 => ("STANAG 5066", Guard::Tcp, ProbeId::Stanag5066),
            Self::Dis => ("DIS", Guard::Udp, ProbeId::DisLenient),
            Self::Ike => ("IKE", Guard::Udp, ProbeId::Ike),
            Self::Esp => ("ESP", Guard::Udp, ProbeId::EspNatT),
            Self::Rdp => ("RDP", Guard::Tcp, ProbeId::Rdp),
            Self::Iec104 => ("IEC 104", Guard::Tcp, ProbeId::Iec104),
            Self::WireGuard => ("WireGuard", Guard::Udp, ProbeId::WireGuard),
            Self::ValmetDna => ("Valmet DNA", Guard::Udp, ProbeId::ValmetDna),
        }
    }
}

/// Classe un payload sans port ni transport : la cascade de
/// `Application::try_from`, derivee de la table (#216). Ce sont les regles
/// sans garde ni veto de port, dans l'ordre de la table, avec les memes
/// sondes que [`classify`] et la meme memoisation. Faute de transport, leur
/// garde de transport n'est pas appliquee : une signature TCP peut
/// etiqueter un datagramme. Cette API est donc moins sure que `parse`, qui
/// voit les ports et le transport ; elle le restera jusqu'a #209.
pub(crate) fn classify_blind(payload: &[u8]) -> &'static str {
    let mut failed_probes: ProbeMask = 0;
    for rule in RULES {
        if rule.ports.is_some() || rule.ports_veto.is_some() {
            continue;
        }
        let bit = rule.probe.bit();
        if failed_probes & bit == 0 && run_probe(rule.probe, payload) {
            return rule.label;
        }
        failed_probes |= bit;
    }
    "Unknown"
}

/// Classifie le payload d'une couche transport. `None` signifie « rien a
/// sonder » (pas de payload, payload vide, ou port mDNS sans contenu mDNS) ;
/// un payload sonde sans succes reste etiquete `"Unknown"`, comme
/// `Application::try_from`.
pub(super) fn classify(
    transport: &Transport<'_>,
    decode_as: &[(u16, DecodeAsProtocol)],
) -> Option<Application> {
    let payload = transport.payload?;
    if payload.is_empty() {
        return None;
    }
    let mut failed_probes: ProbeMask = 0;

    // Ports declares par l'appelant (« Decode As ») : evalues avant la
    // table, port ET contenu, garde de transport conservee. Un echec est
    // memoise comme ceux de la table. Les ports que la table declare
    // terminaux (mDNS 5353, LLMNR 5355 — reserves par leurs RFC) ne sont
    // jamais contournables : « etendre les gardes sans les remplacer ».
    if !decode_as.is_empty() && !matches_terminal_reserved_port(transport) {
        for (port, protocol) in decode_as {
            if transport.source_port != Some(*port) && transport.destination_port != Some(*port) {
                continue;
            }
            let (label, guard, probe) = protocol.rule(transport.protocol);
            if !guard.admits(transport.protocol) {
                continue;
            }
            let bit = probe.bit();
            if failed_probes & bit == 0 && run_probe(probe, payload) {
                return Some(Application {
                    application_protocol: label,
                });
            }
            failed_probes |= bit;
        }
    }
    for rule in RULES {
        if !rule.guard.admits(transport.protocol) {
            continue;
        }
        if let Some(ports) = rule.ports
            && !(ports(transport.source_port) || ports(transport.destination_port))
        {
            continue;
        }
        if let Some(veto) = rule.ports_veto
            && (veto(transport.source_port) || veto(transport.destination_port))
        {
            continue;
        }

        let bit = rule.probe.bit();
        let matched = failed_probes & bit == 0 && run_probe(rule.probe, payload);
        if matched {
            return Some(Application {
                application_protocol: rule.label,
            });
        }
        failed_probes |= bit;
        if rule.terminal_on_port {
            return None;
        }
    }

    Some(Application {
        application_protocol: "Unknown",
    })
}

/// Un des deux ports touche-t-il une regle terminale de la table (port
/// reserve par RFC) ? Source unique : la table elle-meme.
fn matches_terminal_reserved_port(transport: &Transport<'_>) -> bool {
    RULES.iter().any(|rule| {
        rule.terminal_on_port
            && rule.guard.admits(transport.protocol)
            && rule.ports.is_some_and(|ports| {
                ports(transport.source_port) || ports(transport.destination_port)
            })
    })
}
