// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! La table de dispatch : [`RULES`], ses regles ([`Rule`]) et leur garde
//! de transport ([`Guard`]). L'ordre de la table est la priorite (voir
//! [`super`]).

use super::ports::*;
use super::probes::ProbeId;
use crate::parse::application::protocol::ApplicationProtocol;
use crate::parse::transport::Transport;
use crate::parse::transport::protocols::TransportProtocol;

/// Transport requis par une regle.
#[derive(Clone, Copy)]
pub(super) enum Guard {
    Tcp,
    Udp,
    /// Sonde de contenu valable quel que soit le transport.
    Any,
}

impl Guard {
    pub(super) const fn admits(self, protocol: TransportProtocol) -> bool {
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
pub(super) struct Rule {
    pub(super) label: ApplicationProtocol,
    pub(super) guard: Guard,
    pub(super) ports: Option<fn(Option<u16>) -> bool>,
    /// Ports qui interdisent la regle : sur les ports standards de la
    /// famille des protocoles textuels, un verbe distinctif est souvent du
    /// *contenu* (corps SMTP DATA, article NNTP) — le port l'emporte.
    pub(super) ports_veto: Option<fn(Option<u16>) -> bool>,
    pub(super) probe: ProbeId,
    /// Regle terminale : si son port matche, le verdict est definitif meme
    /// quand la sonde echoue (mDNS : le port 5353 est reserve, RFC 6762 —
    /// la sonde DNS generique ne doit pas re-etiqueter ces octets).
    pub(super) terminal_on_port: bool,
}

pub(super) const fn rule(label: ApplicationProtocol, guard: Guard, probe: ProbeId) -> Rule {
    Rule {
        label,
        guard,
        ports: None,
        ports_veto: None,
        probe,
        terminal_on_port: false,
    }
}

pub(super) const fn port_rule(
    label: ApplicationProtocol,
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
/// sondes aveugles dans leur ordre historique, celui de la cascade sans
/// transport que portait `Application::try_from` jusqu'a la 11.x (#219) —
/// cet ordre est porteur de semantique (S7Comm avant COTP, DHCP avant
/// SRVLOC, MQTT en dernier) et verrouille par le snapshot
/// `tests/golden_pcaps.rs`.
pub(super) static RULES: &[Rule] = &[
    port_rule(
        ApplicationProtocol::Snmp,
        Guard::Udp,
        is_snmp_udp_port,
        ProbeId::Snmp,
    ),
    port_rule(
        ApplicationProtocol::Dhcpv6,
        Guard::Udp,
        is_dhcpv6_udp_port,
        ProbeId::Dhcpv6,
    ),
    // DHCP et SRVLOC sur leurs ports, avant les sondes aveugles de DIS et
    // de RADIUS (#294) : un DHCP dont `secs` egale la longueur du
    // datagramme est aussi un en-tete DIS valide, et un SrvTypeRqst SLPv1
    // de 20 octets un Access-Request RADIUS sans attribut. Leurs regles
    // aveugles restent plus bas, a leur rang.
    port_rule(
        ApplicationProtocol::Dhcp,
        Guard::Udp,
        is_dhcp_udp_port,
        ProbeId::Dhcp,
    ),
    // SLP circule sur UDP et TCP 427 : une regle par transport, comme
    // l'exige `port_rules_carry_a_transport_guard`.
    port_rule(
        ApplicationProtocol::Srvloc,
        Guard::Udp,
        is_srvloc_port,
        ProbeId::Srvloc,
    ),
    port_rule(
        ApplicationProtocol::Srvloc,
        Guard::Tcp,
        is_srvloc_port,
        ProbeId::Srvloc,
    ),
    // Signature assez forte pour le probing aveugle sur TCP, et doit gagner
    // sur l'etiquette COTP generique, y compris sur le port 102.
    rule(ApplicationProtocol::S7Comm, Guard::Tcp, ProbeId::S7Comm),
    port_rule(
        ApplicationProtocol::Cotp,
        Guard::Tcp,
        is_iso_tsap_tcp_port,
        ProbeId::CotpTpkt,
    ),
    // FTP, SMTP et NNTP partagent la meme forme de reponse ("code SP texte
    // CRLF") et plusieurs commandes : strictement gardes par port.
    port_rule(
        ApplicationProtocol::Ftp,
        Guard::Tcp,
        is_ftp_tcp_port,
        ProbeId::Ftp,
    ),
    port_rule(
        ApplicationProtocol::Smtp,
        Guard::Tcp,
        is_smtp_tcp_port,
        ProbeId::Smtp,
    ),
    port_rule(
        ApplicationProtocol::Nntp,
        Guard::Tcp,
        is_nntp_tcp_port,
        ProbeId::Nntp,
    ),
    // Detection hors port standard (issue #66) : certains verbes
    // n'appartiennent qu'a un seul des trois protocoles textuels — eux seuls
    // sont detectes par contenu, les verbes partages (QUIT, LIST, MODE...)
    // et les reponses (formes octet pour octet identiques) restent gardes
    // par port ci-dessus.
    Rule {
        label: ApplicationProtocol::Ftp,
        guard: Guard::Tcp,
        ports: None,
        ports_veto: Some(is_text_protocol_port),
        probe: ProbeId::FtpUnambiguous,
        terminal_on_port: false,
    },
    Rule {
        label: ApplicationProtocol::Smtp,
        guard: Guard::Tcp,
        ports: None,
        ports_veto: Some(is_text_protocol_port),
        probe: ProbeId::SmtpUnambiguous,
        terminal_on_port: false,
    },
    Rule {
        label: ApplicationProtocol::Nntp,
        guard: Guard::Tcp,
        ports: None,
        ports_veto: Some(is_text_protocol_port),
        probe: ProbeId::NntpUnambiguous,
        terminal_on_port: false,
    },
    // mDNS reprend le format DNS mais ses reponses omettent souvent la
    // question (RFC 6762 §6) : validateur dedie, et port terminal.
    Rule {
        label: ApplicationProtocol::Mdns,
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
        label: ApplicationProtocol::Llmnr,
        guard: Guard::Udp,
        ports: Some(is_llmnr_udp_port),
        ports_veto: None,
        probe: ProbeId::Llmnr,
        terminal_on_port: true,
    },
    // SSDP est du HTTPU sur le port multicast reserve 1900.
    port_rule(
        ApplicationProtocol::Ssdp,
        Guard::Udp,
        is_ssdp_udp_port,
        ProbeId::Ssdp,
    ),
    // NetBIOS : name service sur UDP 137, session service sur TCP 139 et
    // TCP 445 (SMB direct hosting, meme framing a 4 octets).
    port_rule(
        ApplicationProtocol::Nbns,
        Guard::Udp,
        is_nbns_udp_port,
        ProbeId::Nbns,
    ),
    port_rule(
        ApplicationProtocol::Nbss,
        Guard::Tcp,
        is_nbss_tcp_port,
        ProbeId::Nbss,
    ),
    // OpenVPN : datagramme nu sur UDP 1194, prefixe de longueur sur TCP.
    port_rule(
        ApplicationProtocol::OpenVpn,
        Guard::Udp,
        is_openvpn_port,
        ProbeId::OpenVpnUdp,
    ),
    port_rule(
        ApplicationProtocol::OpenVpn,
        Guard::Tcp,
        is_openvpn_port,
        ProbeId::OpenVpnTcp,
    ),
    // AMS : sur TCP, chaque message est precede de l'en-tete AMS/TCP de
    // 6 octets (#290). La regle UDP lit l'en-tete AMS nu ; Wireshark
    // n'enregistre aucun dissecteur AMS sur UDP 48899.
    port_rule(
        ApplicationProtocol::Ams,
        Guard::Tcp,
        is_ams_tcp_port,
        ProbeId::AmsTcp,
    ),
    port_rule(
        ApplicationProtocol::Ams,
        Guard::Udp,
        is_ams_udp_port,
        ProbeId::Ams,
    ),
    // QUIC 1-RTT (Short Header) : en-tete volontairement opaque (RFC 9000
    // §17.3), une heuristique gardee par le port est le maximum stateless.
    port_rule(
        ApplicationProtocol::Quic,
        Guard::Udp,
        is_quic_udp_port,
        ProbeId::QuicShortHeader,
    ),
    // QUIC a en-tete long sur UDP 443 (#299) : la v1 et le Version
    // Negotiation lus en entier, toute autre version par ses invariants
    // (RFC 8999 §5.1). La regle aveugle ne prend que la v1.
    port_rule(
        ApplicationProtocol::Quic,
        Guard::Udp,
        is_quic_udp_port,
        ProbeId::QuicLongHeaderPort,
    ),
    // Priorites de port sur sondes par ailleurs aveugles : le port ne suffit
    // jamais, mais il fait passer la sonde avant le reste de la cascade.
    port_rule(
        ApplicationProtocol::OpcUa,
        Guard::Tcp,
        is_opcua_tcp_port,
        ProbeId::Opcua,
    ),
    // DNS : la forme datagramme n'existe que sur UDP, et TCP prefixe chaque
    // message de sa longueur (RFC 1035 §4.2). Sonder la forme datagramme sur
    // du TCP etiquetait "DNS" des fragments de reassemblage (trame 6 de
    // dns_axfr.pcapng) : chaque transport n'a que sa forme.
    port_rule(
        ApplicationProtocol::Dns,
        Guard::Tcp,
        is_dns_port,
        ProbeId::DnsTcp,
    ),
    port_rule(
        ApplicationProtocol::Dns,
        Guard::Udp,
        is_dns_port,
        ProbeId::Dns,
    ),
    // PTP (IEEE 1588) : UDP 319 et 320 (annexes D et E). Garde par port : un
    // Delay_Req a exactement la forme d'un en-tete SLPv1 (#117), et le
    // seul messageType ne distingue pas PTP d'un payload quelconque. En
    // couche 2 (EtherType 0x88F7), PTP est decode par la couche internet.
    port_rule(
        ApplicationProtocol::Ptp,
        Guard::Udp,
        is_ptp_port,
        ProbeId::Ptp,
    ),
    // DIS (IEEE 1278.1) : pas de port IANA, 3000 par usage. Sur ce port, la
    // lecture tolere une longueur declaree plus courte que le datagramme
    // (trois PDU reels du corpus) ; ailleurs, la sonde aveugle ci-dessous
    // exige que les PDU pavent exactement le datagramme (#123).
    port_rule(
        ApplicationProtocol::Dis,
        Guard::Udp,
        is_dis_udp_port,
        ProbeId::DisLenient,
    ),
    // RADIUS (RFC 2865) sur ses ports : 1812/1813, les anciens 1645/1646,
    // 3799 (RFC 5176). La meme sonde revient a l'aveugle plus bas (#101).
    port_rule(
        ApplicationProtocol::Radius,
        Guard::Udp,
        is_radius_udp_port,
        ProbeId::Radius,
    ),
    // BACnet/IP (ASHRAE 135, annexe J) sur ses ports 47808 a 47823 ; la
    // meme sonde revient a l'aveugle plus bas (#102).
    port_rule(
        ApplicationProtocol::BacnetIp,
        Guard::Udp,
        is_bacnet_udp_port,
        ProbeId::Bacnet,
    ),
    // Valmet DNA (reseau de process Metso/Valmet, proprietaire) : UDP 2517
    // pour les messages `AB 01`, 4516 -> 4517 pour la balise — les ports
    // observes, le protocole n'en a pas d'enregistre a son nom. Sur ces
    // ports, une famille de message inconnue est acceptee avec son corps en
    // octets ; ailleurs, la sonde aveugle plus bas n'accepte que les deux
    // familles connues.
    port_rule(
        ApplicationProtocol::ValmetDna,
        Guard::Udp,
        is_valmet_dna_udp_port,
        ProbeId::ValmetDna,
    ),
    // RDP (MS-RDPBCGR) : TCP 3389. Garde par port : TPKT, COTP et MCS sont
    // aussi la pile de T.120 et d'ISO sur TCP, un autre port se declare par
    // Decode As. Apres une negociation TLS ou CredSSP, les segments
    // suivants sont du TLS et etiquetes TLS (#100).
    port_rule(
        ApplicationProtocol::Rdp,
        Guard::Tcp,
        is_rdp_tcp_port,
        ProbeId::Rdp,
    ),
    // IEC 60870-5-104 : TCP 2404. Garde par port : `0x68` et une longueur
    // sont deux octets, trop peu pour sonder tout segment TCP ; un autre
    // port se declare par Decode As (#102).
    port_rule(
        ApplicationProtocol::Iec104,
        Guard::Tcp,
        is_iec104_tcp_port,
        ProbeId::Iec104,
    ),
    // Java RMI (JRMP) : TCP 1099, le registre (IANA `rmiregistry`). Sur ce
    // port, tout message JRMP : les messages d'un octet (Ping, PingAck,
    // ProtocolNotSupported), le DgcAck et le ProtocolAck compris. Ailleurs,
    // la sonde aveugle plus bas ne retient que l'en-tete de flux, le Call et
    // le Return. Les objets exportes et les connecteurs JMX ecoutent sur le
    // port que choisit l'application : il se declare par Decode As (#313).
    port_rule(
        ApplicationProtocol::JavaRmi,
        Guard::Tcp,
        is_java_rmi_tcp_port,
        ProbeId::JavaRmi,
    ),
    // PostgreSQL sur son port : decodage et forme compatible suffisent — un
    // Terminate, un ReadyForQuery ou un mot de passe seuls dans leur
    // segment, la reponse d'un octet a SSLRequest (S ou N) — la ou la sonde
    // aveugle ci-dessous exige une preuve forte. Mesure sur le corpus Zeek :
    // aucun faux positif sur HTTP et MySQL rejoues sur 5432 (#98).
    port_rule(
        ApplicationProtocol::PostgreSql,
        Guard::Tcp,
        is_postgresql_tcp_port,
        ProbeId::PostgresqlPort,
    ),
    // IKE (RFC 7296, RFC 2408) : UDP 500, et UDP 4500 derriere le marqueur
    // non-ESP de la RFC 3948. Garde par port : un en-tete de vingt-huit
    // octets a version et longueur plausibles n'est pas une signature
    // suffisante pour sonder tout datagramme (#124).
    port_rule(
        ApplicationProtocol::Ike,
        Guard::Udp,
        is_ike_udp_port,
        ProbeId::Ike,
    ),
    // ESP dans UDP 4500 (RFC 3948 §2.1) : SPI non nul en tete, la suite ne
    // se decoupe qu'avec l'association de securite ; puis le NAT-keepalive
    // d'un octet (§2.3). ESP natif (protocole IP 50) est decode par la couche
    // transport.
    port_rule(
        ApplicationProtocol::Esp,
        Guard::Udp,
        is_nat_t_udp_port,
        ProbeId::EspNatT,
    ),
    port_rule(
        ApplicationProtocol::NatKeepalive,
        Guard::Udp,
        is_nat_t_udp_port,
        ProbeId::NatKeepalive,
    ),
    // STANAG 5066 SIS : TCP 5066 (port IANA). Garde par port : le preambule
    // `90 EB 00`, un type et une taille sont trois octets fixes et deux
    // contraintes — trop peu pour une sonde aveugle sur tout segment TCP ;
    // un autre port se declare par Decode As (#122).
    port_rule(
        ApplicationProtocol::Stanag5066,
        Guard::Tcp,
        is_stanag5066_tcp_port,
        ProbeId::Stanag5066,
    ),
    // Modbus/TCP sur TCP 502 (IANA `mbap`) : l'enveloppe MBAP suffit quand le
    // port confirme, UMAS d'abord, protocole le plus specifique ; ailleurs,
    // la sonde aveugle stricte plus bas (#167).
    port_rule(
        ApplicationProtocol::Umas,
        Guard::Tcp,
        is_modbus_tcp_port,
        ProbeId::Umas,
    ),
    port_rule(
        ApplicationProtocol::ModbusTcp,
        Guard::Tcp,
        is_modbus_tcp_port,
        ProbeId::ModbusTcp,
    ),
    // Modbus sur UDP 502 (#257) : hors de la specification « Modbus
    // Messaging on TCP/IP », mais present sur le terrain avec la meme
    // enveloppe MBAP, et decode par tshark (`mbudp`). Le meme decodeur
    // tolerant que sur TCP 502, sous sa propre etiquette. Pas de regle sans
    // port : sur l'Ultimate PCAP, 106 datagrammes CLDAP (UDP 389) ont la
    // forme d'une enveloppe MBAP. UMAS n'y est pas distingue, faute de
    // capture.
    port_rule(
        ApplicationProtocol::ModbusUdp,
        Guard::Udp,
        is_modbus_udp_port,
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
        ApplicationProtocol::WireGuard,
        Guard::Udp,
        is_wireguard_udp_port,
        ProbeId::WireGuardPort,
    ),
    // NTP (RFC 5905) : UDP 123, en derniere regle de port — la place
    // qu'avait la sonde aveugle, si bien que rien ne change sur ce port :
    // le decodeur tolerant suffit quand le port confirme (#164).
    port_rule(
        ApplicationProtocol::Ntp,
        Guard::Udp,
        is_ntp_udp_port,
        ProbeId::Ntp,
    ),
    // --- cascade aveugle, dans son ordre historique,
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
    rule(ApplicationProtocol::Ntp, Guard::Udp, ProbeId::NtpBlind),
    // RTPS (DDS) : magic `RTPS` puis des sous-messages qui pavent exactement
    // le datagramme. Sonde aveugle sur UDP : Cyclone DDS et Connext Micro
    // emploient des ports unicast aleatoires (#120).
    rule(ApplicationProtocol::Rtps, Guard::Udp, ProbeId::Rtps),
    // Valmet DNA : magie `AB 01`, longueur egale au datagramme moins deux et
    // une famille connue a sa taille exacte — plus de 64 bits de contrainte,
    // assez pour se passer du port.
    rule(
        ApplicationProtocol::ValmetDna,
        Guard::Udp,
        ProbeId::ValmetDnaBlind,
    ),
    // ASTERIX (surveillance aerienne) circule en UDP, le plus souvent en
    // multicast et sans port fixe : sonde structurelle (tous les data
    // blocks d'une categorie connue, records decoupes exactement selon
    // l'UAP). Avant DNS, dont la forme datagramme est moins contrainte.
    rule(ApplicationProtocol::Asterix, Guard::Udp, ProbeId::Asterix),
    // DIS : en-tete de douze octets (version 1 a 7, type 1 a 72, famille de
    // la norme) et pavage exact du datagramme par ses PDU.
    rule(ApplicationProtocol::Dis, Guard::Udp, ProbeId::Dis),
    // DNP3 (IEEE 1815) : `05 64`, un CRC-16/DNP sur l'en-tete et sur chaque
    // bloc de seize octets — une signature qui se passe du port 20000, sur
    // TCP comme sur UDP (#99).
    rule(ApplicationProtocol::Dnp3, Guard::Any, ProbeId::Dnp3),
    // RADIUS : code connu, longueur egale au datagramme, attributs qui le
    // pavent — assez contraint pour se passer du port (#101).
    rule(ApplicationProtocol::Radius, Guard::Udp, ProbeId::Radius),
    // BACnet/IP : `0x81`, une fonction BVLC, une longueur egale au
    // datagramme, un NPDU de version 1 — assez contraint pour se passer du
    // port (#102).
    rule(ApplicationProtocol::BacnetIp, Guard::Udp, ProbeId::Bacnet),
    rule(ApplicationProtocol::Bitcoin, Guard::Tcp, ProbeId::Bitcoin),
    // OPC UA hors port : chunks qui pavent le segment, partiel de taille
    // plausible (#296).
    rule(ApplicationProtocol::OpcUa, Guard::Tcp, ProbeId::OpcuaBlind),
    // EtherNet/IP est reellement bi-transport (TCP 44818, UDP 2222). Sur
    // TCP, plusieurs messages peuvent partager un segment (#288) ; sur UDP,
    // un datagramme porte un seul message.
    rule(
        ApplicationProtocol::EthernetIp,
        Guard::Tcp,
        ProbeId::EthernetIpTcp,
    ),
    rule(
        ApplicationProtocol::EthernetIp,
        Guard::Udp,
        ProbeId::EthernetIp,
    ),
    // PostgreSQL ne circule que sur TCP : la garde manquait et la sonde
    // s'executait deux fois (issue #29).
    rule(
        ApplicationProtocol::PostgreSql,
        Guard::Tcp,
        ProbeId::Postgresql,
    ),
    // Forme datagramme : UDP uniquement (RFC 1035 §4.2.1) — sur TCP elle ne
    // peut matcher que des fragments, la forme prefixee est port-guardee.
    // Hors port 53, sonde stricte : sections consommant tout le datagramme
    // et au moins un enregistrement (issue #118).
    rule(ApplicationProtocol::Dns, Guard::Udp, ProbeId::DnsBlind),
    // SNMP sur TCP existe (RFC 3430) meme s'il est rare : bi-transport.
    rule(ApplicationProtocol::Snmp, Guard::Any, ProbeId::Snmp),
    rule(ApplicationProtocol::Tls, Guard::Tcp, ProbeId::Tls),
    // SSH avant HTTP : prefixe litteral `SSH-` + version exacte, aucun
    // recouvrement avec les methodes HTTP.
    rule(ApplicationProtocol::Ssh, Guard::Tcp, ProbeId::Ssh),
    // SIP (RFC 3261, #342) : la version `SIP/2.0`, une methode du registre
    // IANA, Via, From, To, Call-ID et CSeq, dont la methode est celle de la
    // requete. Reellement bi-transport (UDP et TCP, §18) et sans port : 5060
    // est une convention, et 5061 porte du TLS. Disjoint de HTTP, dont la
    // sonde exige `HTTP/x.y`, et de SSDP (`* HTTP/1.1`).
    rule(ApplicationProtocol::Sip, Guard::Any, ProbeId::Sip),
    rule(ApplicationProtocol::Http, Guard::Tcp, ProbeId::Http),
    // La banniere SSH apres les lignes qu'un serveur peut envoyer avant elle
    // (RFC 4253 §4.2, #307) : apres HTTP, dont un corps peut citer une
    // banniere.
    rule(ApplicationProtocol::Ssh, Guard::Tcp, ProbeId::SshAfterLines),
    // GIOP/IIOP est transporte par TCP.
    rule(ApplicationProtocol::Giop, Guard::Tcp, ProbeId::Giop),
    // Java RMI (JRMP) hors de 1099 : `JRMI` suivi d'une version et d'un
    // protocole connus, ou un Call ou un Return, dont l'octet de type est
    // suivi de la magie `AC ED 00 05` du flux de serialisation et d'un bloc
    // assez long pour leur en-tete — au moins 48 bits fixes (#313).
    rule(
        ApplicationProtocol::JavaRmi,
        Guard::Tcp,
        ProbeId::JavaRmiBlind,
    ),
    // DHCP avant SRVLOC : un BOOTP mimait un en-tete SLP (issue #3).
    rule(ApplicationProtocol::Dhcp, Guard::Udp, ProbeId::Dhcp),
    // SLP accepte TCP et UDP (RFC 2608 §6.1) : bi-transport.
    rule(ApplicationProtocol::Srvloc, Guard::Any, ProbeId::Srvloc),
    // UMAS avant ModbusTCP : il est porte par une enveloppe Modbus valide,
    // donc la sonde Modbus reconnaitrait aussi ses trames. Le protocole le
    // plus specifique gagne l'etiquette, comme S7Comm devant COTP.
    rule(ApplicationProtocol::Umas, Guard::Tcp, ProbeId::Umas),
    // Modbus/TCP hors du port 502 : l'enveloppe MBAP (identifiant de
    // protocole nul, longueur qui pave le segment) est aussi celle de tout
    // message prefixe de deux octets et d'une longueur sur quatre — LDAP,
    // DICOM, Elasticsearch ; chaque PDU doit en plus porter un code fonction
    // courant et la taille qu'il impose (#167).
    rule(
        ApplicationProtocol::ModbusTcp,
        Guard::Tcp,
        ProbeId::ModbusTcpBlind,
    ),
    rule(
        ApplicationProtocol::Quic,
        Guard::Udp,
        ProbeId::QuicLongHeader,
    ),
    // WireGuard hors de 51820 : un octet de type, trois octets reserves nuls,
    // une taille fixe ou, pour les donnees, un compteur sous 2^60 et un
    // paquet clair complete a seize octets ou arrete a la MTU. Derniere sonde
    // UDP : un Transport Data n'a pour lui que `04 00 00 00` et ces
    // contraintes (#103).
    rule(
        ApplicationProtocol::WireGuard,
        Guard::Udp,
        ProbeId::WireGuardBlind,
    ),
    // CAPWAP (RFC 5415, #355) sur UDP 5246 et 5247 : ce que le tunnel n'a
    // pas decapsule (controle, DTLS, keep-alive, fragments, trames 802.11
    // de gestion). Regle a port placee apres toutes les sondes UDP a
    // signature : un port CAPWAP pris comme port ephemere par un autre
    // protocole garde son etiquette, et CAPWAP ne nomme que ce qui restait
    // `Unknown`.
    port_rule(
        ApplicationProtocol::Capwap,
        Guard::Udp,
        is_capwap_udp_port,
        ProbeId::Capwap,
    ),
    // RTCP (RFC 3550 §6, #354), derniere sonde UDP : des paquets de type 200 a
    // 207 dont les longueurs pavent exactement le datagramme, ouverts par
    // un SR ou un RR, ou un message de retour seul (RFC 5506).
    rule(ApplicationProtocol::Rtcp, Guard::Udp, ProbeId::RtcpBlind),
    // NMF ([MC-NMF], #352), sans port : un preambule (Version 1.0, Mode,
    // Via et son URI) ou une enveloppe a taille qui s'ouvre comme
    // [MC-NBFSE], soit au moins six octets fixes. Placee apres toutes les
    // sondes TCP a signature, avant MQTT.
    rule(ApplicationProtocol::Nmf, Guard::Tcp, ProbeId::NmfBlind),
    // DCE/RPC oriente connexion (C706 §12.6, #356), sans port fixe : version
    // 5.0 ou 5.1, type de PDU connu, representation des donnees dont deux
    // octets sont nuls, longueurs coherentes. Apres toutes les sondes TCP a
    // signature, avant MQTT.
    rule(ApplicationProtocol::DceRpc, Guard::Tcp, ProbeId::DceRpc),
    // MQTT (TCP) en dernier : en-tete fixe peu discriminant.
    rule(ApplicationProtocol::Mqtt, Guard::Tcp, ProbeId::Mqtt),
];

/// Un des deux ports touche-t-il une regle terminale de la table (port
/// reserve par RFC) ? Source unique : la table elle-meme.
pub(super) fn matches_terminal_reserved_port(transport: &Transport<'_>) -> bool {
    RULES.iter().any(|rule| {
        rule.terminal_on_port
            && rule.guard.admits(transport.protocol)
            && rule.ports.is_some_and(|ports| {
                ports(transport.source_port) || ports(transport.destination_port)
            })
    })
}
