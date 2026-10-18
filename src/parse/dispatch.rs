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
use super::application::protocols::ams::AmsPacket;
use super::application::protocols::asterix::AsterixPacket;
use super::application::protocols::bacnet::BacnetPacket;
use super::application::protocols::bitcoin::BitcoinPacket;
use super::application::protocols::dhcp::DhcpPacket;
use super::application::protocols::dhcpv6::Dhcpv6Packet;
use super::application::protocols::dis::DisPacket;
use super::application::protocols::dnp3::Dnp3Packet;
use super::application::protocols::dns::DnsPacket;
use super::application::protocols::ethernet_ip::EtherNetIpPacket;
use super::application::protocols::ftp::FtpMessage;
use super::application::protocols::giop::GiopPacket;
use super::application::protocols::http::{HttpRequest, HttpResponse};
use super::application::protocols::iec104::Iec104Packet;
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
use super::application::protocols::rdp::RdpPacket;
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
use super::application::protocols::wireguard::WireGuardPacket;
use super::cotp_from_tpkt;
use super::transport::Transport;
use super::transport::protocols::TransportProtocol;
use super::transport::protocols::esp::EspPacket;
use crate::checks::application::quic::is_plausible_short_header;

/// Nombre d'octets soumis aux sondes des protocoles texte (FTP, SMTP, NNTP,
/// HTTP), qui valident tout leur texte en UTF-8 : au-dela, seul le prefixe
/// est sonde. Jusqu'a la 11.6.0, toutes les sondes lisaient ce prefixe, pour
/// supprimer le cout pathologique des segments jumbo hostiles mesures par
/// l'audit (x2545, issue #20) ; mais un decodeur qui exige le pavage exact
/// du buffer, ou une longueur declaree qui y tient, ne juge alors plus le
/// payload qu'il lira : au-dela du plafond, la sonde etiquetait ce que le
/// decodeur refuse (SNMP, Modbus/TCP) ou ratait un message complet (NBSS,
/// DNS sur TCP, PostgreSQL, TLS) — #184 pour ASTERIX et DNS aveugle, #185
/// pour les vingt-quatre autres. Les autres sondes lisent le payload reel
/// depuis ; sur UDP il est borne par le datagramme, et sur TCP le cout
/// reste lineaire dans la taille du segment, chaque decodeur s'arretant a
/// la premiere erreur de structure.
///
/// La borne depasse un record TLS 1.3 (5 + 2^14 + 256, RFC 8446 §5.2) mais
/// pas le maximum de TLS 1.2 (5 + 2^14 + 2048 = 18 437, RFC 5246 §6.2.3) :
/// c'est pourquoi la sonde TLS lit le segment entier.
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
    NtpBlind,
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
    ModbusTcpBlind,
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
    Bacnet,
    Rdp,
    Iec104,
    Ike,
    EspNatT,
    NatKeepalive,
    WireGuard,
    WireGuardBlind,
    WireGuardPort,
}

/// Sonde `probe` sur le payload reel. Les sondes des protocoles texte ne
/// lisent que [`PROBE_CAP`] octets ; toutes les autres jugent les octets que
/// leur decodeur lira (#184, #185).
fn run_probe(probe: ProbeId, payload: &[u8]) -> bool {
    let text = &payload[..payload.len().min(PROBE_CAP)];
    match probe {
        // Le message doit paver exactement le datagramme ou le segment.
        ProbeId::Snmp => SnmpPacket::try_from(payload).is_ok(),
        ProbeId::Dhcpv6 => Dhcpv6Packet::try_from(payload).is_ok(),
        // TPKT : la longueur declaree doit tenir dans le segment.
        ProbeId::S7Comm => S7CommPacket::try_from(payload).is_ok(),
        ProbeId::CotpTpkt => cotp_from_tpkt(payload).is_some(),
        // Protocoles texte : tout le prefixe est valide en UTF-8, et l'oracle
        // du fuzz recopie le plafond.
        ProbeId::Ftp => FtpMessage::try_from(text).is_ok(),
        ProbeId::Smtp => SmtpMessage::try_from(text).is_ok(),
        ProbeId::Nntp => NntpMessage::try_from(text).is_ok(),
        // Les sections doivent consommer exactement le datagramme.
        ProbeId::Mdns => DnsPacket::try_from_mdns(payload).is_ok(),
        ProbeId::Llmnr => DnsPacket::try_from_llmnr(payload).is_ok(),
        // Tout le payload est valide en UTF-8.
        ProbeId::Ssdp => SsdpPacket::try_from(payload).is_ok(),
        ProbeId::Nbns => NbnsPacket::try_from(payload).is_ok(),
        // La longueur declaree doit tenir dans le segment.
        ProbeId::Nbss => NbssPacket::try_from(payload).is_ok(),
        ProbeId::OpenVpnUdp => OpenVpnPacket::try_from(payload).is_ok(),
        // Le prefixe u16 du record TCP est verifie contre le payload reel.
        ProbeId::OpenVpnTcp => OpenVpnPacket::from_tcp_stream(payload).is_ok(),
        ProbeId::FtpUnambiguous => is_unambiguous_ftp_command(text),
        ProbeId::SmtpUnambiguous => is_unambiguous_smtp_command(text),
        ProbeId::NntpUnambiguous => is_unambiguous_nntp_command(text),
        // `cb_data` doit egaler ce qui suit l'en-tete.
        ProbeId::Ams => AmsPacket::try_from(payload).is_ok(),
        ProbeId::QuicShortHeader => is_plausible_short_header(payload),
        ProbeId::Ntp => NtpPacket::try_from(payload).is_ok(),
        // Les champs d'extension et le MAC doivent finir exactement avec le
        // datagramme.
        ProbeId::NtpBlind => NtpPacket::is_blind_udp_match(payload),
        // Tous les data blocks doivent paver le datagramme jusqu'a son
        // dernier octet.
        ProbeId::Asterix => AsterixPacket::try_from(payload).is_ok(),
        // La longueur declaree doit egaler le segment.
        ProbeId::Bitcoin => BitcoinPacket::try_from(payload).is_ok(),
        // Les chunks doivent paver le segment.
        ProbeId::Opcua => OpcuaPacket::try_from(payload).is_ok(),
        // La longueur declaree doit egaler ce qui suit l'en-tete.
        ProbeId::EthernetIp => EtherNetIpPacket::try_from(payload).is_ok(),
        // Les messages doivent paver le segment.
        ProbeId::Postgresql => is_likely_postgresql_payload(payload),
        ProbeId::PostgresqlPort => is_plausible_postgresql_payload(payload),
        // Les sections doivent consommer exactement le datagramme ; sur TCP,
        // la longueur prefixee doit tenir dans le segment.
        ProbeId::Dns => DnsPacket::try_from(payload).is_ok(),
        ProbeId::DnsTcp => DnsPacket::try_from_tcp(payload).is_ok(),
        // Un record TLS 1.2 va jusqu'a 18 437 octets, au-dela de PROBE_CAP.
        ProbeId::Tls => TlsPacket::try_from(payload).is_ok(),
        ProbeId::Ssh => SshPacket::try_from(payload).is_ok(),
        // Requete ou reponse (#176) : la tete, jusqu'au premier CRLF CRLF,
        // est validee en UTF-8 et ligne par ligne ; sans separateur, tout le
        // prefixe est la tete.
        ProbeId::Http => {
            HttpRequest::try_from(text).is_ok() || HttpResponse::try_from(text).is_ok()
        }
        // Garde a cout constant : la sonde est tentee sur chaque paquet TCP, et
        // le Result d'un GiopPacket (qui porte desormais tout le message
        // decode) coute a construire et a liberer meme quand le magic echoue.
        ProbeId::Giop => payload.starts_with(b"GIOP") && GiopPacket::try_from(payload).is_ok(),
        ProbeId::Dhcp => DhcpPacket::try_from(payload).is_ok(),
        // La longueur declaree doit egaler le payload.
        ProbeId::Srvloc => SrvlocPacket::try_from(payload).is_ok(),
        // Les MBAP doivent paver le segment.
        ProbeId::Umas => UmasPacket::try_from(payload).is_ok(),
        ProbeId::ModbusTcp => ModbusTcpPacket::try_from(payload).is_ok(),
        ProbeId::ModbusTcpBlind => ModbusTcpPacket::is_blind_tcp_match(payload),
        // La longueur de l'en-tete long doit tenir dans le datagramme.
        ProbeId::QuicLongHeader => QuicPacket::try_from(payload).is_ok(),
        // Les paquets doivent paver le segment.
        ProbeId::Mqtt => MqttPacket::try_from(payload).is_ok(),
        // Les sections doivent consommer exactement le datagramme, au-dela de
        // PROBE_CAP compris. Les noms, bornes a 255 octets (RFC 1035 §3.1),
        // gardent le decodage lineaire jusqu'a la taille maximale d'un
        // datagramme.
        ProbeId::DnsBlind => DnsPacket::is_blind_udp_match(payload),
        // Rien ne doit suivre le message.
        ProbeId::Ptp => PtpPacket::try_from_udp(payload).is_ok(),
        // Le trailer est verifie a la fin du S_PDU declare.
        ProbeId::Stanag5066 => SisPdu::try_from(payload).is_ok(),
        // La sonde aveugle exige que les PDU pavent exactement le datagramme.
        // Sur le port 3000 ou un port declare, la longueur declaree peut etre
        // fausse (#123) : lecture tolerante.
        ProbeId::Dis => DisPacket::try_from(payload).is_ok(),
        ProbeId::DisLenient => DisPacket::try_from_lenient(payload).is_ok(),
        // Les trames de liaison, chacune verifiee par ses CRC, doivent paver
        // tout le segment ou datagramme.
        ProbeId::Dnp3 => Dnp3Packet::try_from(payload).is_ok(),
        // La longueur declaree couvre tout le datagramme.
        ProbeId::Radius => RadiusPacket::try_from(payload).is_ok(),
        // La longueur BVLC couvre tout le datagramme.
        ProbeId::Bacnet => BacnetPacket::try_from(payload).is_ok(),
        // TPKT, COTP X.224 et une connexion ou un PDU MCS lisibles ; un TPKT
        // peut deborder du segment.
        ProbeId::Rdp => RdpPacket::try_from(payload).is_ok(),
        // Un APDU peut deborder du segment.
        ProbeId::Iec104 => Iec104Packet::try_from(payload).is_ok(),
        // La longueur de l'en-tete IKE couvre tout le message. Nu (UDP 500) ou
        // derriere le marqueur non-ESP (UDP 4500).
        ProbeId::Ike => IkePacket::from_udp(payload).is_ok(),
        ProbeId::EspNatT => matches!(
            UdpEncapsulation::classify(payload),
            Ok(UdpEncapsulation::Esp(esp)) if EspPacket::try_from(esp).is_ok()
        ),
        ProbeId::NatKeepalive => matches!(
            UdpEncapsulation::classify(payload),
            Ok(UdpEncapsulation::Keepalive)
        ),
        // Un message par datagramme, de taille fixe ou, pour les donnees,
        // jusqu'a la fin du datagramme.
        ProbeId::WireGuard => WireGuardPacket::try_from(payload).is_ok(),
        ProbeId::WireGuardPort => WireGuardPacket::is_port_udp_match(payload),
        ProbeId::WireGuardBlind => WireGuardPacket::is_blind_udp_match(payload),
        // Garde a cout constant sur le magic, comme GIOP ; puis les
        // sous-messages doivent paver tout le datagramme, et un DATA_FRAG de
        // 60 Ko depasse PROBE_CAP sans cesser d'etre du RTPS.
        ProbeId::Rtps => {
            (payload.starts_with(b"RTPS") || payload.starts_with(b"RTPX"))
                && RtpsPacket::try_from(payload).is_ok()
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
    // BACnet/IP (ASHRAE 135, annexe J) sur ses ports 47808 a 47823 ; la
    // meme sonde revient a l'aveugle plus bas (#102).
    port_rule("BACnet/IP", Guard::Udp, is_bacnet_udp_port, ProbeId::Bacnet),
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

        let bit = 1u64 << rule.probe as u64;
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

/// Modbus/TCP : TCP 502 (IANA `mbap`).
fn is_modbus_tcp_port(port: Option<u16>) -> bool {
    matches!(port, Some(502))
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

/// NTP : UDP 123 (IANA `ntp`), source d'un serveur, destination d'un
/// client, les deux en mode symetrique.
fn is_ntp_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(123))
}

/// QUIC (HTTP/3) : UDP 443.
fn is_quic_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(443))
}

/// WireGuard : UDP 51820, le port des exemples de `wg(8)` et `wg-quick(8)`
/// (aucun port IANA ; sans `ListenPort`, wg choisit un port au hasard).
fn is_wireguard_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(51820))
}

/// DIS : UDP 3000, le port d'usage que Wireshark enregistre par defaut.
fn is_dis_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(3000))
}

/// PostgreSQL : TCP 5432 (IANA `postgresql`).
fn is_postgresql_tcp_port(port: Option<u16>) -> bool {
    matches!(port, Some(5432))
}

/// IEC 60870-5-104 : TCP 2404 (IANA `iec-104`).
fn is_iec104_tcp_port(port: Option<u16>) -> bool {
    matches!(port, Some(2404))
}

/// RDP : TCP 3389 (IANA `ms-wbt-server`).
fn is_rdp_tcp_port(port: Option<u16>) -> bool {
    matches!(port, Some(3389))
}

/// BACnet/IP : UDP 47808 (0xBAC0, IANA `bacnet`) et les quinze ports
/// suivants que l'annexe J laisse aux reseaux multiples.
fn is_bacnet_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(47808..=47823))
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
            classify(&transport, &[]).map(|a| a.application_protocol)
        };
        let tcp = TransportProtocol::Tcp;
        assert_eq!(label(tcp, 502, &READ), Some("ModbusTCP"));
        assert_eq!(label(tcp, 40_001, &READ), Some("ModbusTCP"));
        assert_eq!(label(tcp, 502, &USER_DEFINED), Some("ModbusTCP"));
        assert_ne!(label(tcp, 40_001, &USER_DEFINED), Some("ModbusTCP"));
        assert_eq!(label(tcp, 502, &UMAS), Some("UMAS"));
        assert_eq!(label(tcp, 40_001, &UMAS), Some("UMAS"));
        // Jamais sur UDP, port 502 compris.
        assert_ne!(label(TransportProtocol::Udp, 502, &READ), Some("ModbusTCP"));
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
            classify(&transport, &[]).map(|a| a.application_protocol)
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
        assert_ne!(
            classify(&tcp, &[]).map(|a| a.application_protocol),
            Some("NTP")
        );
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
            classify(&transport, &[]).map(|a| a.application_protocol)
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
            classify(&transport, &[]).map(|a| a.application_protocol)
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
            classify(&transport, &[]).map(|a| a.application_protocol)
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
            classify(&transport, &[]).map(|a| a.application_protocol)
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
            classify(&transport, &[]).map(|a| a.application_protocol),
            Some("Unknown")
        );
        let mut stor = b"STOR a\r\n".to_vec();
        stor.resize(PROBE_CAP, 0);
        assert_ne!(
            classify(&tcp_transport(&stor), &[]).map(|a| a.application_protocol),
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
            b'o', b'm', 0, 0x00, 0x01, 0x00, 0x01, 0, 0x00, 0x29, 0x04, 0xd0, 0, 0, 0, 0, 0x00,
            0x00,
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
            classify(&transport, &[]).map(|a| a.application_protocol),
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
            classify(&transport, &[]).map(|a| a.application_protocol)
        };
        let mut esp = vec![0x01, 0x02, 0x03, 0x04, 0, 0, 0, 1];
        esp.extend((0..140).map(|i| (i * 7 + 3) as u8));
        assert_eq!(esp.len(), 148);
        assert!(WireGuardPacket::is_port_udp_match(&esp));
        assert_eq!(label(51820, 4500, &esp), Some("ESP"));

        let mut dns = vec![
            0x02, 0xab, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l',
            b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x10, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x10, 0x00,
            0x01, 0, 0, 0, 60, 0, 51, 50,
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
            .map(|a| a.application_protocol),
            Some("WireGuard"),
            "un port declare reste tolerant"
        );

        let keepalive =
            hex::decode("0400000006f47dab03000000000000001956e2b6651dd4f59cb23092a0d09671")
                .unwrap();
        assert_eq!(label(40000, 51820, &keepalive), Some("WireGuard"));
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
            DecodeAsProtocol::Rdp,
            DecodeAsProtocol::Iec104,
            DecodeAsProtocol::WireGuard,
        ];
        // Decode As plus tolerant que la regle de port, a dessein : un port
        // declare est du WireGuard, octets reserves de Cloudflare compris
        // (le recours que l'heuristique de Wireshark indique), la ou 51820
        // n'est qu'un port ephemere (#169). La table doit connaitre la sonde
        // jumelle.
        let lenient_twins = [(ProbeId::WireGuard, ProbeId::WireGuardPort)];
        for protocol in all {
            for transport in [TransportProtocol::Tcp, TransportProtocol::Udp] {
                let (label, _, probe) = protocol.rule(transport);
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
                "BACnet/IP",
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
                "WireGuard",
                "MQTT",
            ],
            "S7Comm est promu en tete (priorite sur COTP), les verbes \
             non-ambigus FTP/SMTP/NNTP sont propres au dispatch transport \
             (issue #66), le reste suit l'ordre historique de \
             Application::try_from"
        );
    }
}
