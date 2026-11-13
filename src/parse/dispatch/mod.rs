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
use super::application::protocols::valmet_dna::ValmetDnaPacket;
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

/// Masque de memoisation de [`classify`] : un bit par [`ProbeId`].
type ProbeMask = u128;

/// Identite d'une sonde de contenu. Deux regles peuvent partager la meme
/// sonde (port prioritaire puis repli aveugle) : la memoisation par identite
/// garantit qu'elle ne s'execute qu'une fois par payload. Un bit du masque
/// [`ProbeMask`] par identifiant.
///
/// Limite : 128 identifiants (`ProbeMask::BITS`). Une variante s'ajoute en
/// fin d'enum et devient [`ProbeId::LAST`]. L'assertion qui suit l'enum
/// refuse de compiler au-dela de la limite, et le test
/// `probe_count_is_the_number_of_variants` verifie que `LAST` est bien la
/// derniere variante (#212). Au-dela, `1 << 128` paniquerait en debug et
/// replierait le bit sur celui de `Snmp` en release.
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
    /// Sur ses ports : en-tete coherent, famille connue ou non, ou la
    /// balise de 42 octets. A l'aveugle : les deux familles connues a leur
    /// taille exacte seulement.
    ValmetDna,
    ValmetDnaBlind,
}

impl ProbeId {
    /// La derniere variante de l'enum : a deplacer quand une sonde s'ajoute.
    const LAST: Self = Self::ValmetDnaBlind;
    /// Nombre d'identifiants ; les discriminants vont de 0 a `COUNT - 1`.
    const COUNT: u32 = Self::LAST as u32 + 1;

    /// Le bit de cette sonde dans le masque de memoisation.
    const fn bit(self) -> ProbeMask {
        1 << self as u32
    }
}

const _: () = assert!(
    ProbeId::COUNT <= ProbeMask::BITS,
    "ProbeId depasse la largeur du masque de memoisation (ProbeMask)"
);

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
        // La longueur declaree couvre tout le datagramme moins deux ; le
        // telegramme d'etat fait 126 octets, l'etiquette pave le message.
        ProbeId::ValmetDna => ValmetDnaPacket::is_port_udp_match(payload),
        ProbeId::ValmetDnaBlind => ValmetDnaPacket::is_blind_udp_match(payload),
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

/// Verbes que seul FTP definit (RFC 959/2428). RETR figure dans la liste de
/// l'issue #66 bien que POP3 le partage : la crate ne classe pas POP3, et le
/// verbe est valide avec la syntaxe FTP. POST est exclu du set NNTP (HTTP).
///
/// L'oracle de `fuzz/oracles/text_protocols.rs` (#108) recopie cette liste,
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

/// Valmet DNA : UDP 2517 (messages) et 4516, 4517 (balise), les ports
/// observes sur un reseau de process ; aucun n'est enregistre au nom du
/// protocole.
fn is_valmet_dna_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(2517 | 4516 | 4517))
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
mod tests;
