// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Sondes de contenu de la table de dispatch : leur identite ([`ProbeId`]),
//! leur execution ([`run_probe`]) et les verbes des protocoles texte.

use crate::checks::application::http::{may_start_request, may_start_response};
use crate::checks::application::quic::is_plausible_short_header;
use crate::parse::application::protocols::ams::AmsPacket;
use crate::parse::application::protocols::asterix::AsterixPacket;
use crate::parse::application::protocols::bacnet::BacnetPacket;
use crate::parse::application::protocols::bitcoin::BitcoinPacket;
use crate::parse::application::protocols::dhcp::DhcpPacket;
use crate::parse::application::protocols::dhcpv6::Dhcpv6Packet;
use crate::parse::application::protocols::dis::DisPacket;
use crate::parse::application::protocols::dnp3::Dnp3Packet;
use crate::parse::application::protocols::dns::DnsPacket;
use crate::parse::application::protocols::ethernet_ip::EtherNetIpPacket;
use crate::parse::application::protocols::ftp::FtpMessage;
use crate::parse::application::protocols::giop::GiopPacket;
use crate::parse::application::protocols::http::{HttpRequest, HttpResponse};
use crate::parse::application::protocols::iec104::Iec104Packet;
use crate::parse::application::protocols::ike::{IkePacket, UdpEncapsulation};
use crate::parse::application::protocols::modbus_tcp::ModbusTcpPacket;
use crate::parse::application::protocols::mqtt::MqttPacket;
use crate::parse::application::protocols::netbios::{NbnsPacket, NbssPacket};
use crate::parse::application::protocols::nntp::NntpMessage;
use crate::parse::application::protocols::ntp::NtpPacket;
use crate::parse::application::protocols::opcua::OpcuaPacket;
use crate::parse::application::protocols::openvpn::OpenVpnPacket;
use crate::parse::application::protocols::postgresql::{
    is_likely_postgresql_payload, is_plausible_postgresql_payload,
};
use crate::parse::application::protocols::ptp::PtpPacket;
use crate::parse::application::protocols::quic::QuicPacket;
use crate::parse::application::protocols::radius::RadiusPacket;
use crate::parse::application::protocols::rdp::RdpPacket;
use crate::parse::application::protocols::rtps::RtpsPacket;
use crate::parse::application::protocols::s7comm::S7CommPacket;
use crate::parse::application::protocols::smtp::SmtpMessage;
use crate::parse::application::protocols::snmp::SnmpPacket;
use crate::parse::application::protocols::srvloc::SrvlocPacket;
use crate::parse::application::protocols::ssdp::SsdpPacket;
use crate::parse::application::protocols::ssh::SshPacket;
use crate::parse::application::protocols::stanag5066::SisPdu;
use crate::parse::application::protocols::tls::TlsPacket;
use crate::parse::application::protocols::umas::UmasPacket;
use crate::parse::application::protocols::valmet_dna::ValmetDnaPacket;
use crate::parse::application::protocols::wireguard::WireGuardPacket;
use crate::parse::cotp_from_tpkt;
use crate::parse::transport::protocols::esp::EspPacket;
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
pub(super) const PROBE_CAP: usize = 18 * 1024;

/// Masque de memoisation de [`classify`](super::classify) : un bit par [`ProbeId`].
pub(super) type ProbeMask = u128;

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
pub(super) enum ProbeId {
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
    pub(super) const LAST: Self = Self::ValmetDnaBlind;
    /// Nombre d'identifiants ; les discriminants vont de 0 a `COUNT - 1`.
    pub(super) const COUNT: u32 = Self::LAST as u32 + 1;

    /// Le bit de cette sonde dans le masque de memoisation.
    pub(super) const fn bit(self) -> ProbeMask {
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
pub(super) fn run_probe(probe: ProbeId, payload: &[u8]) -> bool {
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
        // prefixe est la tete. Chaque decodeur est precede de sa garde a cout
        // constant (#249) : sans elle, tout segment TCP non reconnu payait
        // deux parcours du prefixe avant d'etre refuse sur sa premiere ligne.
        ProbeId::Http => {
            (may_start_request(text) && HttpRequest::try_from(text).is_ok())
                || (may_start_response(text) && HttpResponse::try_from(text).is_ok())
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

/// Verbes que seul FTP definit (RFC 959/2428). RETR figure dans la liste de
/// l'issue #66 bien que POP3 le partage : la crate ne classe pas POP3, et le
/// verbe est valide avec la syntaxe FTP. POST est exclu du set NNTP (HTTP).
///
/// L'oracle de `fuzz/oracles/text_protocols.rs` (#108) recopie cette liste,
/// les ports de [`is_text_protocol_port`](super::ports::is_text_protocol_port) et [`is_ftp_tcp_port`](super::ports::is_ftp_tcp_port), et
/// [`PROBE_CAP`] : toute modification s'y reporte. Elargir la detection sans
/// lui fait echouer le fuzzing nocturne sur un comportement voulu ; la
/// restreindre le relache en silence.
pub(super) const FTP_ONLY_VERBS: [&str; 11] = [
    "RETR", "STOR", "PASV", "APPE", "RNFR", "RNTO", "MKD", "CDUP", "EPSV", "EPRT", "NLST",
];
pub(super) const SMTP_ONLY_VERBS: [&str; 4] = ["EHLO", "HELO", "MAIL", "RCPT"];
pub(super) const NNTP_ONLY_VERBS: [&str; 7] = [
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
pub(super) fn starts_with_one_of(payload: &[u8], verbs: &[&str]) -> bool {
    verbs.iter().any(|verb| {
        let verb = verb.as_bytes();
        payload.len() > verb.len()
            && payload[..verb.len()].eq_ignore_ascii_case(verb)
            && matches!(payload[verb.len()], b' ' | b'\t' | b'\r')
    })
}

/// Une commande complete (syntaxe et arite validees par le parseur du
/// protocole) dont le verbe n'existe que dans ce protocole.
pub(super) fn is_unambiguous_ftp_command(payload: &[u8]) -> bool {
    starts_with_one_of(payload, &FTP_ONLY_VERBS)
        && matches!(
            FtpMessage::try_from(payload),
            Ok(FtpMessage::Command { verb, .. })
                if FTP_ONLY_VERBS.iter().any(|only| only.eq_ignore_ascii_case(verb))
        )
}

pub(super) fn is_unambiguous_smtp_command(payload: &[u8]) -> bool {
    starts_with_one_of(payload, &SMTP_ONLY_VERBS)
        && matches!(
            SmtpMessage::try_from(payload),
            Ok(SmtpMessage::Command { verb, .. })
                if SMTP_ONLY_VERBS.iter().any(|only| only.eq_ignore_ascii_case(verb))
        )
}

pub(super) fn is_unambiguous_nntp_command(payload: &[u8]) -> bool {
    starts_with_one_of(payload, &NNTP_ONLY_VERBS)
        && matches!(
            NntpMessage::try_from(payload),
            Ok(NntpMessage::Command { verb, .. })
                if NNTP_ONLY_VERBS.iter().any(|only| only.eq_ignore_ascii_case(verb))
        )
}
