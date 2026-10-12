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
//! - le probing ne lit que [`PROBE_CAP`] octets : un payload heberge par un
//!   segment jumbo (GRO 64 Ko) ne coute plus un parse integral par sonde
//!   (issue #20). La borne depasse le plus grand message legitime qu'une
//!   sonde doive voir en entier (un record TLS chiffre : 5 + 16 Ko + tag).

use super::application::Application;
use super::application::protocols::ams::AmsPacket;
use super::application::protocols::asterix::AsterixPacket;
use super::application::protocols::bitcoin::BitcoinPacket;
use super::application::protocols::dhcp::DhcpPacket;
use super::application::protocols::dhcpv6::Dhcpv6Packet;
use super::application::protocols::dis::DisPacket;
use super::application::protocols::dnp3::Dnp3Packet;
use super::application::protocols::dns::DnsPacket;
use super::application::protocols::ethernet_ip::EtherNetIpPacket;
use super::application::protocols::ftp::FtpMessage;
use super::application::protocols::giop::GiopPacket;
use super::application::protocols::http::HttpRequest;
use super::application::protocols::ike::{IkePacket, UdpEncapsulation};
use super::application::protocols::modbus_tcp::ModbusTcpPacket;
use super::application::protocols::mqtt::MqttPacket;
use super::application::protocols::netbios::{NbnsPacket, NbssPacket};
use super::application::protocols::nntp::NntpMessage;
use super::application::protocols::ntp::NtpPacket;
use super::application::protocols::opcua::OpcuaPacket;
use super::application::protocols::openvpn::OpenVpnPacket;
use super::application::protocols::postgresql::{
    is_likely_postgresql_payload, is_plausible_postgresql_payload,
};
use super::application::protocols::ptp::PtpPacket;
use super::application::protocols::quic::QuicPacket;
use super::application::protocols::radius::RadiusPacket;
use super::application::protocols::rtps::RtpsPacket;
use super::application::protocols::s7comm::S7CommPacket;
use super::application::protocols::smtp::SmtpMessage;
use super::application::protocols::snmp::SnmpPacket;
use super::application::protocols::srvloc::SrvlocPacket;
use super::application::protocols::ssdp::SsdpPacket;
use super::application::protocols::ssh::SshPacket;
use super::application::protocols::stanag5066::SisPdu;
use super::application::protocols::tls::TlsPacket;
use super::application::protocols::umas::UmasPacket;
use super::cotp_from_tpkt;
use super::transport::Transport;
use super::transport::protocols::TransportProtocol;
use super::transport::protocols::esp::EspPacket;
use crate::checks::application::quic::is_plausible_short_header;

/// Nombre d'octets soumis aux sondes. Au-dela, seul le prefixe est sonde :
/// la classification est un verdict sur l'en-tete applicatif, pas sur la
/// charge complete, et cette borne supprime le cout pathologique des
/// segments jumbo hostiles mesures par l'audit (x2545).
///
/// Recopie par l'oracle FTP du fuzz : voir [`FTP_ONLY_VERBS`].
const PROBE_CAP: usize = 18 * 1024;

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

/// Identite d'une sonde de contenu. Deux regles peuvent partager la meme
/// sonde (port prioritaire puis repli aveugle) : la memoisation par identite
/// garantit qu'elle ne s'execute qu'une fois par payload. Un bit du masque
/// u64 par identifiant.
#[derive(Clone, Copy)]
#[repr(u32)]
enum ProbeId {
    Snmp,
    Dhcpv6,
    S7Comm,
    CotpTpkt,
    Ftp,
    Smtp,
    Nntp,
    Mdns,
    Llmnr,
    Ssdp,
    Nbns,
    Nbss,
    OpenVpnUdp,
    OpenVpnTcp,
    Ams,
    FtpUnambiguous,
    SmtpUnambiguous,
    NntpUnambiguous,
    QuicShortHeader,
    Ntp,
    Asterix,
    Bitcoin,
    Opcua,
    EthernetIp,
    Postgresql,
    /// Port 5432 ou port declare : decodage et forme compatible suffisent,
    /// sans la preuve forte qu'exige la sonde aveugle (#98).
    PostgresqlPort,
    Dns,
    DnsTcp,
    Tls,
    Ssh,
    Http,
    Giop,
    Dhcp,
    Srvloc,
    ModbusTcp,
    Umas,
    QuicLongHeader,
    Mqtt,
    DnsBlind,
    Ptp,
    Rtps,
    Stanag5066,
    Dis,
    DisLenient,
    Dnp3,
    Radius,
    Ike,
    EspNatT,
    NatKeepalive,
}

fn run_probe(probe: ProbeId, payload: &[u8], full_payload: &[u8]) -> bool {
    match probe {
        ProbeId::Snmp => SnmpPacket::try_from(payload).is_ok(),
        ProbeId::Dhcpv6 => Dhcpv6Packet::try_from(payload).is_ok(),
        ProbeId::S7Comm => S7CommPacket::try_from(payload).is_ok(),
        ProbeId::CotpTpkt => cotp_from_tpkt(payload).is_some(),
        ProbeId::Ftp => FtpMessage::try_from(payload).is_ok(),
        ProbeId::Smtp => SmtpMessage::try_from(payload).is_ok(),
        ProbeId::Nntp => NntpMessage::try_from(payload).is_ok(),
        ProbeId::Mdns => DnsPacket::try_from_mdns(payload).is_ok(),
        ProbeId::Llmnr => DnsPacket::try_from_llmnr(payload).is_ok(),
        ProbeId::Ssdp => SsdpPacket::try_from(payload).is_ok(),
        ProbeId::Nbns => NbnsPacket::try_from(payload).is_ok(),
        ProbeId::Nbss => NbssPacket::try_from(payload).is_ok(),
        ProbeId::OpenVpnUdp => OpenVpnPacket::try_from(payload).is_ok(),
        // Le prefixe u16 du record TCP est verifie contre le payload REEL :
        // le plafond de sondage tronquerait a tort un record legitime plus
        // grand que PROBE_CAP pourtant entierement present dans le segment.
        ProbeId::OpenVpnTcp => OpenVpnPacket::from_tcp_stream(full_payload).is_ok(),
        ProbeId::FtpUnambiguous => is_unambiguous_ftp_command(payload),
        ProbeId::SmtpUnambiguous => is_unambiguous_smtp_command(payload),
        ProbeId::NntpUnambiguous => is_unambiguous_nntp_command(payload),
        ProbeId::Ams => AmsPacket::try_from(payload).is_ok(),
        ProbeId::QuicShortHeader => is_plausible_short_header(payload),
        ProbeId::Ntp => NtpPacket::try_from(payload).is_ok(),
        ProbeId::Asterix => AsterixPacket::try_from(payload).is_ok(),
        ProbeId::Bitcoin => BitcoinPacket::try_from(payload).is_ok(),
        ProbeId::Opcua => OpcuaPacket::try_from(payload).is_ok(),
        ProbeId::EthernetIp => EtherNetIpPacket::try_from(payload).is_ok(),
        ProbeId::Postgresql => is_likely_postgresql_payload(payload),
        ProbeId::PostgresqlPort => is_plausible_postgresql_payload(payload),
        ProbeId::Dns => DnsPacket::try_from(payload).is_ok(),
        ProbeId::DnsTcp => DnsPacket::try_from_tcp(payload).is_ok(),
        ProbeId::Tls => TlsPacket::try_from(payload).is_ok(),
        ProbeId::Ssh => SshPacket::try_from(payload).is_ok(),
        ProbeId::Http => HttpRequest::try_from(payload).is_ok(),
        // Garde a cout constant : la sonde est tentee sur chaque paquet TCP, et
        // le Result d'un GiopPacket (qui porte desormais tout le message
        // decode) coute a construire et a liberer meme quand le magic echoue.
        ProbeId::Giop => payload.starts_with(b"GIOP") && GiopPacket::try_from(payload).is_ok(),
        ProbeId::Dhcp => DhcpPacket::try_from(payload).is_ok(),
        ProbeId::Srvloc => SrvlocPacket::try_from(payload).is_ok(),
        ProbeId::Umas => UmasPacket::try_from(payload).is_ok(),
        ProbeId::ModbusTcp => ModbusTcpPacket::try_from(payload).is_ok(),
        ProbeId::QuicLongHeader => QuicPacket::try_from(payload).is_ok(),
        ProbeId::Mqtt => MqttPacket::try_from(payload).is_ok(),
        // Sur le payload plafonne : un datagramme plus long que PROBE_CAP ne
        // peut pas prouver qu'il est consomme exactement, et reste Unknown.
        ProbeId::DnsBlind => DnsPacket::is_blind_udp_match(payload),
        ProbeId::Ptp => PtpPacket::try_from_udp(payload).is_ok(),
        ProbeId::Stanag5066 => SisPdu::try_from(payload).is_ok(),
        // Sur le payload reel : la sonde aveugle exige que les PDU pavent
        // exactement le datagramme. Sur le port 3000 ou un port declare, la
        // longueur declaree peut etre fausse (#123) : lecture tolerante.
        ProbeId::Dis => DisPacket::try_from(full_payload).is_ok(),
        ProbeId::DisLenient => DisPacket::try_from_lenient(full_payload).is_ok(),
        // Sur le payload reel : les trames de liaison, chacune verifiee par
        // ses CRC, doivent paver tout le segment ou datagramme.
        ProbeId::Dnp3 => Dnp3Packet::try_from(full_payload).is_ok(),
        // Sur le payload reel : la longueur declaree couvre tout le datagramme.
        ProbeId::Radius => RadiusPacket::try_from(full_payload).is_ok(),
        // Sur le payload reel : la longueur de l'en-tete IKE couvre tout le
        // message. Nu (UDP 500) ou derriere le marqueur non-ESP (UDP 4500).
        ProbeId::Ike => IkePacket::from_udp(full_payload).is_ok(),
        ProbeId::EspNatT => matches!(
            UdpEncapsulation::classify(payload),
            Ok(UdpEncapsulation::Esp(esp)) if EspPacket::try_from(esp).is_ok()
        ),
        ProbeId::NatKeepalive => matches!(
            UdpEncapsulation::classify(payload),
            Ok(UdpEncapsulation::Keepalive)
        ),
        // Garde a cout constant sur le magic, comme GIOP ; puis le payload REEL :
        // les sous-messages doivent paver tout le datagramme, et un DATA_FRAG de
        // 60 Ko depasse PROBE_CAP sans cesser d'etre du RTPS.
        ProbeId::Rtps => {
            (full_payload.starts_with(b"RTPS") || full_payload.starts_with(b"RTPX"))
                && RtpsPacket::try_from(full_payload).is_ok()
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
    // ESP dans UDP 4500 (RFC 3948 §2.1) : SPI non nul en tete, le reste est
    // chiffre ; puis le NAT-keepalive d'un octet (§2.3). ESP natif
    // (protocole IP 50) est decode par la couche transport.
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
    // --- cascade aveugle, ordre historique de `Application::try_from`,
    // avec les gardes de transport que les RFC imposent : sonder NTP sur du
    // TCP etiquetait "NTP" des Encrypted Alerts TLS (0x15 = LI/VN/mode
    // plausible — trames 44/329/614 de dump.pcapng). Seuls les protocoles
    // reellement bi-transport restent en Guard::Any. ---
    rule("NTP", Guard::Udp, ProbeId::Ntp),
    // RTPS (DDS) : magic `RTPS` puis des sous-messages qui pavent exactement
    // le datagramme. Sonde aveugle sur UDP : Cyclone DDS et Connext Micro
    // emploient des ports unicast aleatoires (#120).
    rule("RTPS", Guard::Udp, ProbeId::Rtps),
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
    rule("ModbusTCP", Guard::Tcp, ProbeId::ModbusTcp),
    rule("QUIC", Guard::Udp, ProbeId::QuicLongHeader),
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
        }
    }
}

/// Classifie le payload d'une couche transport. `None` signifie « rien a
/// sonder » (pas de payload, payload vide, ou port mDNS sans contenu mDNS) ;
/// un payload sonde sans succes reste etiquete `"Unknown"`, comme
/// l'historique `Application::try_from`.
pub(super) fn classify(
    transport: &Transport<'_>,
    decode_as: &[(u16, DecodeAsProtocol)],
) -> Option<Application> {
    let payload = transport.payload?;
    if payload.is_empty() {
        return None;
    }
    let probed = &payload[..payload.len().min(PROBE_CAP)];

    let mut failed_probes: u64 = 0;

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
            let bit = 1u64 << probe as u64;
            if failed_probes & bit == 0 && run_probe(probe, probed, payload) {
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

        let bit = 1u64 << rule.probe as u64;
        let matched = failed_probes & bit == 0 && run_probe(rule.probe, probed, payload);
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

/// Verbes que seul FTP definit (RFC 959/2428). RETR figure dans la liste de
/// l'issue #66 bien que POP3 le partage : la crate ne classe pas POP3, et le
/// verbe est valide avec la syntaxe FTP. POST est exclu du set NNTP (HTTP).
///
/// L'oracle de `fuzz/fuzz_targets/parse_packetflow.rs` recopie cette liste,
/// les ports de [`is_text_protocol_port`] et [`is_ftp_tcp_port`], et
/// [`PROBE_CAP`] : toute modification s'y reporte. Elargir la detection sans
/// lui fait echouer le fuzzing nocturne sur un comportement voulu ; la
/// restreindre le relache en silence.
const FTP_ONLY_VERBS: [&str; 11] = [
    "RETR", "STOR", "PASV", "APPE", "RNFR", "RNTO", "MKD", "CDUP", "EPSV", "EPRT", "NLST",
];
const SMTP_ONLY_VERBS: [&str; 4] = ["EHLO", "HELO", "MAIL", "RCPT"];
const NNTP_ONLY_VERBS: [&str; 7] = [
    "ARTICLE",
    "XOVER",
    "XHDR",
    "IHAVE",
    "LISTGROUP",
    "NEWGROUPS",
    "NEWNEWS",
];

/// Garde a cout constant : le payload doit commencer par un des verbes
/// (casse ignoree) suivi d'un espace, d'une tabulation ou d'un CR. Sans
/// elle, chaque payload TCP paierait le parseur textuel complet — mesure a
/// 554 ns pour NNTP sur le paquet de reference de verbench, dont la
/// construction d'une String d'erreur.
///
/// La tabulation est un separateur NNTP (RFC 3977 §3.1) que le parseur
/// accepte ; sans elle ici, `ARTICLE\t12345` sortait `Unknown` hors port —
/// trouve par la cible de fuzz `policy_dispatch` (#108). FTP et SMTP ne
/// coupent que sur l'espace : leur parseur refuse ensuite le verbe.
fn starts_with_one_of(payload: &[u8], verbs: &[&str]) -> bool {
    verbs.iter().any(|verb| {
        let verb = verb.as_bytes();
        payload.len() > verb.len()
            && payload[..verb.len()].eq_ignore_ascii_case(verb)
            && matches!(payload[verb.len()], b' ' | b'\t' | b'\r')
    })
}

/// Une commande complete (syntaxe et arite validees par le parseur du
/// protocole) dont le verbe n'existe que dans ce protocole.
fn is_unambiguous_ftp_command(payload: &[u8]) -> bool {
    starts_with_one_of(payload, &FTP_ONLY_VERBS)
        && matches!(
            FtpMessage::try_from(payload),
            Ok(FtpMessage::Command { verb, .. })
                if FTP_ONLY_VERBS.iter().any(|only| only.eq_ignore_ascii_case(verb))
        )
}

fn is_unambiguous_smtp_command(payload: &[u8]) -> bool {
    starts_with_one_of(payload, &SMTP_ONLY_VERBS)
        && matches!(
            SmtpMessage::try_from(payload),
            Ok(SmtpMessage::Command { verb, .. })
                if SMTP_ONLY_VERBS.iter().any(|only| only.eq_ignore_ascii_case(verb))
        )
}

fn is_unambiguous_nntp_command(payload: &[u8]) -> bool {
    starts_with_one_of(payload, &NNTP_ONLY_VERBS)
        && matches!(
            NntpMessage::try_from(payload),
            Ok(NntpMessage::Command { verb, .. })
                if NNTP_ONLY_VERBS.iter().any(|only| only.eq_ignore_ascii_case(verb))
        )
}

/// Ports standards de la famille texte FTP/SMTP/NNTP : les regles de port
/// ci-dessus y ont deja tranche, et un verbe distinctif y est probablement
/// du contenu en transit (corps DATA, article) — jamais reclasse.
///
/// Recopie par l'oracle FTP du fuzz : voir [`FTP_ONLY_VERBS`].
fn is_text_protocol_port(port: Option<u16>) -> bool {
    matches!(port, Some(21 | 25 | 587 | 119))
}

fn is_snmp_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(161 | 162))
}

fn is_dhcpv6_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(546 | 547))
}

/// ISO-TSAP (TPKT/COTP, notamment S7comm).
fn is_iso_tsap_tcp_port(port: Option<u16>) -> bool {
    matches!(port, Some(102))
}

/// Beckhoff AMS/ADS sur TCP.
fn is_ams_tcp_port(port: Option<u16>) -> bool {
    matches!(port, Some(48898))
}

/// Beckhoff AMS/ADS discovery sur UDP.
fn is_ams_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(48899))
}

/// QUIC (HTTP/3) : UDP 443.
fn is_quic_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(443))
}

/// DIS : UDP 3000, le port d'usage que Wireshark enregistre par defaut.
fn is_dis_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(3000))
}

/// PostgreSQL : TCP 5432 (IANA `postgresql`).
fn is_postgresql_tcp_port(port: Option<u16>) -> bool {
    matches!(port, Some(5432))
}

/// RADIUS : UDP 1812/1813 (IANA), 1645/1646 (historiques), 3799 (RFC 5176).
fn is_radius_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(1812 | 1813 | 1645 | 1646 | 3799))
}

/// IKE : UDP 500 (IANA `isakmp`) et 4500 (IANA `ipsec-nat-t`).
fn is_ike_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(500 | 4500))
}

/// ESP encapsule et NAT-keepalive : UDP 4500 seulement (RFC 3948).
fn is_nat_t_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(4500))
}

/// STANAG 5066 SIS : TCP 5066 (IANA `stanag-5066`).
fn is_stanag5066_tcp_port(port: Option<u16>) -> bool {
    matches!(port, Some(5066))
}

/// FTP control channel : TCP 21.
///
/// Recopie par l'oracle FTP du fuzz : voir [`FTP_ONLY_VERBS`].
fn is_ftp_tcp_port(port: Option<u16>) -> bool {
    matches!(port, Some(21))
}

/// SMTP en clair ou avec STARTTLS : TCP 25 (relais) et 587 (soumission).
/// Le port 465 transporte du TLS implicite et ne peut pas contenir
/// directement une commande SMTP dans le payload inspecte ici.
fn is_smtp_tcp_port(port: Option<u16>) -> bool {
    matches!(port, Some(25 | 587))
}

/// NNTP en clair ou avec STARTTLS : TCP 119. Le port 563 transporte du TLS
/// implicite et ne peut pas contenir directement une commande NNTP ici.
fn is_nntp_tcp_port(port: Option<u16>) -> bool {
    matches!(port, Some(119))
}

/// LLMNR : UDP 5355 (port reserve, RFC 4795).
fn is_llmnr_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(5355))
}

/// SSDP : UDP 1900 (UPnP Device Architecture).
fn is_ssdp_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(1900))
}

/// NetBIOS Name Service : UDP 137 (RFC 1002).
fn is_nbns_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(137))
}

/// NetBIOS Session Service : TCP 139, et TCP 445 (SMB direct hosting).
fn is_nbss_tcp_port(port: Option<u16>) -> bool {
    matches!(port, Some(139 | 445))
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

/// OpenVPN : port officiel 1194 (TCP et UDP).
fn is_openvpn_port(port: Option<u16>) -> bool {
    matches!(port, Some(1194))
}

/// mDNS : UDP 5353 (port reserve, RFC 6762).
fn is_mdns_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(5353))
}

fn is_opcua_tcp_port(port: Option<u16>) -> bool {
    matches!(port, Some(4840 | 12001))
}

/// PTP : 319 (messages d'evenement) et 320 (messages generaux).
fn is_ptp_port(port: Option<u16>) -> bool {
    matches!(port, Some(319 | 320))
}

/// DNS classique : 53, sur UDP comme sur TCP.
fn is_dns_port(port: Option<u16>) -> bool {
    matches!(port, Some(53))
}

#[cfg(test)]
mod tests {
    use super::*;

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
            let label = classify(&transport, &[]).map(|a| a.application_protocol);
            assert_eq!(label, Some(expected), "payload {payload:?}");
        }

        // QUIT existe dans les trois protocoles : jamais par contenu seul.
        let transport = tcp_transport(b"QUIT\r\n");
        let label = classify(&transport, &[]).map(|a| a.application_protocol);
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
            let label = classify(&transport, &[]).map(|a| a.application_protocol);
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
            let found = classify(&transport, &[]).map(|a| a.application_protocol);
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
                .map(|a| a.application_protocol)
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
            0x00, 0x25, 0x8a, 0x9a, 0x9a, 0x0d, 0x00, 0x00, 0x00, 0x0a, 0xfd, 0xfb, 0x08, 0x00,
            0x4e, 0x00, 0x00, 0x63, 0x8a, 0x9a, 0x00, 0x00, 0x4e, 0x06, 0x4e, 0xff, 0x4e, 0x4e,
            0x00, 0x00, 0x00, 0x00,
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
                .map(|application| application.application_protocol)
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
            classify(&transport, &[]).map(|a| a.application_protocol),
            Some("FTP")
        );
        // ... mais l'appelant peut declarer que 50 000 porte du FTP.
        let decode_as = [(50_000_u16, DecodeAsProtocol::Ftp)];
        assert_eq!(
            classify(&transport, &decode_as).map(|a| a.application_protocol),
            Some("FTP")
        );
        // Le port declare ne suffit jamais : contenu non-FTP refuse.
        let garbage = tcp_transport(b"\x16\x03\x03\x00\x10aaaaaaaaaaaaaaaa");
        assert_ne!(
            classify(&garbage, &decode_as).map(|a| a.application_protocol),
            Some("FTP")
        );
        // La garde de transport du protocole reste appliquee : declarer un
        // port DNS datagramme sur du TCP ne sonde pas la forme datagramme.
        let decode_udp_only = [(50_000_u16, DecodeAsProtocol::Mdns)];
        assert_ne!(
            classify(&transport, &decode_udp_only).map(|a| a.application_protocol),
            Some("mDNS")
        );
    }

    /// UDP 4500 (RFC 3948) : marqueur non-ESP puis IKE, ESP a SPI non nul,
    /// NAT-keepalive d'un octet ; ailleurs, rien sans Decode As (#124).
    #[test]
    fn udp_4500_demultiplexes_ike_esp_and_keepalive() {
        // IKEv2 minimal : en-tete seul, IKE_SA_INIT de l'initiateur.
        const IKE: [u8; 28] = [
            0x62, 0xf9, 0x4c, 0x98, 0x87, 0x71, 0x5a, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x20,
            0x22, 0x08, 0, 0, 0, 0, 0, 0, 0, 28,
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
            classify(&transport(port, payload), decode_as).map(|a| a.application_protocol)
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

    /// Anti-derive (revue 10.4.0) : chaque protocole Decode-As doit se
    /// resoudre vers une etiquette et une sonde que la table connait — les
    /// deux encodages ne peuvent pas diverger silencieusement.
    #[test]
    fn decode_as_protocols_resolve_to_table_rules() {
        use ProbeId as P;
        let all = [
            DecodeAsProtocol::Ftp,
            DecodeAsProtocol::Smtp,
            DecodeAsProtocol::Nntp,
            DecodeAsProtocol::Cotp,
            DecodeAsProtocol::Dns,
            DecodeAsProtocol::Mdns,
            DecodeAsProtocol::Llmnr,
            DecodeAsProtocol::Ssdp,
            DecodeAsProtocol::Nbns,
            DecodeAsProtocol::Nbss,
            DecodeAsProtocol::Snmp,
            DecodeAsProtocol::Dhcpv6,
            DecodeAsProtocol::OpcUa,
            DecodeAsProtocol::PostgreSql,
            DecodeAsProtocol::ModbusTcp,
            DecodeAsProtocol::EthernetIp,
            DecodeAsProtocol::Ams,
            DecodeAsProtocol::QuicShortHeader,
            DecodeAsProtocol::OpenVpn,
            DecodeAsProtocol::Ptp,
            DecodeAsProtocol::Stanag5066,
            DecodeAsProtocol::Dis,
            DecodeAsProtocol::Ike,
            DecodeAsProtocol::Esp,
        ];
        for protocol in all {
            for transport in [TransportProtocol::Tcp, TransportProtocol::Udp] {
                let (label, _, probe) = protocol.rule(transport);
                assert!(
                    RULES
                        .iter()
                        .any(|rule| rule.label == label && rule.probe as u32 == probe as u32),
                    "{label} (sonde {:?}) absent de la table",
                    probe as u32
                );
            }
        }
        let _ = [P::Snmp]; // use alias
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
            classify(&transport, &decode_as).map(|a| a.application_protocol),
            Some("mDNS"),
            "la regle terminale de la table garde la main sur 5353"
        );
    }

    /// La memoisation exige un identifiant de sonde par bit d'un u64.
    #[test]
    fn probe_ids_fit_the_memoization_bitmask() {
        for rule in RULES {
            assert!((rule.probe as u32) < 64);
        }
    }

    /// L'invariant central de la table : une regle a port sans garde de
    /// transport serait un retour de l'override port-seul (issue #25).
    /// Seule DNS/53 est volontairement bi-transport.
    #[test]
    fn port_rules_carry_a_transport_guard() {
        for rule in RULES.iter().filter(|rule| rule.ports.is_some()) {
            assert!(
                !matches!(rule.guard, Guard::Any) || rule.label == "DNS",
                "regle a port sans garde de transport : {}",
                rule.label
            );
        }
    }

    /// La cascade aveugle de la table couvre exactement les protocoles de
    /// `Application::try_from`, dans le meme ordre — le dispatch transport
    /// ne doit pas silencieusement diverger du probing public.
    #[test]
    fn blind_rules_mirror_the_public_cascade_order() {
        let blind: Vec<&str> = RULES
            .iter()
            .filter(|rule| rule.ports.is_none())
            .map(|rule| rule.label)
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
                "ASTERIX",
                "DIS",
                "DNP3",
                "RADIUS",
                "Bitcoin",
                "OPC UA",
                "EtherNet/IP",
                "PostgreSQL",
                "DNS",
                "SNMP",
                "TLS",
                "SSH",
                "HTTP",
                "GIOP",
                "DHCP",
                "SRVLOC",
                "UMAS",
                "ModbusTCP",
                "QUIC",
                "MQTT",
            ],
            "S7Comm est promu en tete (priorite sur COTP), les verbes \
             non-ambigus FTP/SMTP/NNTP sont propres au dispatch transport \
             (issue #66), le reste suit l'ordre historique de \
             Application::try_from"
        );
    }
}
