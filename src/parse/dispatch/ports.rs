// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Predicats de port de la table de dispatch : un par famille de ports
//! standards. Le port ne decide jamais seul, la sonde de contenu confirme
//! (voir [`super`]).

/// Ports standards de la famille texte FTP/SMTP/NNTP : les regles de port
/// ci-dessus y ont deja tranche, et un verbe distinctif y est probablement
/// du contenu en transit (corps DATA, article) — jamais reclasse.
///
/// Recopie par l'oracle FTP du fuzz : voir [`FTP_ONLY_VERBS`](super::probes::FTP_ONLY_VERBS).
pub(super) fn is_text_protocol_port(port: Option<u16>) -> bool {
    matches!(port, Some(21 | 25 | 587 | 119))
}

pub(super) fn is_snmp_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(161 | 162))
}

pub(super) fn is_dhcpv6_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(546 | 547))
}

/// Modbus/TCP : TCP 502 (IANA `mbap`).
pub(super) fn is_modbus_tcp_port(port: Option<u16>) -> bool {
    matches!(port, Some(502))
}

/// ISO-TSAP (TPKT/COTP, notamment S7comm).
pub(super) fn is_iso_tsap_tcp_port(port: Option<u16>) -> bool {
    matches!(port, Some(102))
}

/// Beckhoff AMS/ADS sur TCP.
pub(super) fn is_ams_tcp_port(port: Option<u16>) -> bool {
    matches!(port, Some(48898))
}

/// Beckhoff AMS/ADS discovery sur UDP.
pub(super) fn is_ams_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(48899))
}

/// NTP : UDP 123 (IANA `ntp`), source d'un serveur, destination d'un
/// client, les deux en mode symetrique.
pub(super) fn is_ntp_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(123))
}

/// QUIC (HTTP/3) : UDP 443.
pub(super) fn is_quic_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(443))
}

/// WireGuard : UDP 51820, le port des exemples de `wg(8)` et `wg-quick(8)`
/// (aucun port IANA ; sans `ListenPort`, wg choisit un port au hasard).
pub(super) fn is_wireguard_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(51820))
}

/// DIS : UDP 3000, le port d'usage que Wireshark enregistre par defaut.
pub(super) fn is_dis_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(3000))
}

/// PostgreSQL : TCP 5432 (IANA `postgresql`).
pub(super) fn is_postgresql_tcp_port(port: Option<u16>) -> bool {
    matches!(port, Some(5432))
}

/// IEC 60870-5-104 : TCP 2404 (IANA `iec-104`).
pub(super) fn is_iec104_tcp_port(port: Option<u16>) -> bool {
    matches!(port, Some(2404))
}

/// RDP : TCP 3389 (IANA `ms-wbt-server`).
pub(super) fn is_rdp_tcp_port(port: Option<u16>) -> bool {
    matches!(port, Some(3389))
}

/// BACnet/IP : UDP 47808 (0xBAC0, IANA `bacnet`) et les quinze ports
/// suivants que l'annexe J laisse aux reseaux multiples.
pub(super) fn is_bacnet_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(47808..=47823))
}

/// RADIUS : UDP 1812/1813 (IANA), 1645/1646 (historiques), 3799 (RFC 5176).
pub(super) fn is_radius_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(1812 | 1813 | 1645 | 1646 | 3799))
}

/// Valmet DNA : UDP 2517 (messages) et 4516, 4517 (balise), les ports
/// observes sur un reseau de process ; aucun n'est enregistre au nom du
/// protocole.
pub(super) fn is_valmet_dna_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(2517 | 4516 | 4517))
}

/// IKE : UDP 500 (IANA `isakmp`) et 4500 (IANA `ipsec-nat-t`).
pub(super) fn is_ike_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(500 | 4500))
}

/// ESP encapsule et NAT-keepalive : UDP 4500 seulement (RFC 3948).
pub(super) fn is_nat_t_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(4500))
}

/// STANAG 5066 SIS : TCP 5066 (IANA `stanag-5066`).
pub(super) fn is_stanag5066_tcp_port(port: Option<u16>) -> bool {
    matches!(port, Some(5066))
}

/// FTP control channel : TCP 21.
///
/// Recopie par l'oracle FTP du fuzz : voir [`FTP_ONLY_VERBS`](super::probes::FTP_ONLY_VERBS).
pub(super) fn is_ftp_tcp_port(port: Option<u16>) -> bool {
    matches!(port, Some(21))
}

/// SMTP en clair ou avec STARTTLS : TCP 25 (relais) et 587 (soumission).
/// Le port 465 transporte du TLS implicite et ne peut pas contenir
/// directement une commande SMTP dans le payload inspecte ici.
pub(super) fn is_smtp_tcp_port(port: Option<u16>) -> bool {
    matches!(port, Some(25 | 587))
}

/// NNTP en clair ou avec STARTTLS : TCP 119. Le port 563 transporte du TLS
/// implicite et ne peut pas contenir directement une commande NNTP ici.
pub(super) fn is_nntp_tcp_port(port: Option<u16>) -> bool {
    matches!(port, Some(119))
}

/// LLMNR : UDP 5355 (port reserve, RFC 4795).
pub(super) fn is_llmnr_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(5355))
}

/// SSDP : UDP 1900 (UPnP Device Architecture).
pub(super) fn is_ssdp_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(1900))
}

/// NetBIOS Name Service : UDP 137 (RFC 1002).
pub(super) fn is_nbns_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(137))
}

/// NetBIOS Session Service : TCP 139, et TCP 445 (SMB direct hosting).
pub(super) fn is_nbss_tcp_port(port: Option<u16>) -> bool {
    matches!(port, Some(139 | 445))
}

/// OpenVPN : port officiel 1194 (TCP et UDP).
pub(super) fn is_openvpn_port(port: Option<u16>) -> bool {
    matches!(port, Some(1194))
}

/// mDNS : UDP 5353 (port reserve, RFC 6762).
pub(super) fn is_mdns_udp_port(port: Option<u16>) -> bool {
    matches!(port, Some(5353))
}

pub(super) fn is_opcua_tcp_port(port: Option<u16>) -> bool {
    matches!(port, Some(4840 | 12001))
}

/// PTP : 319 (messages d'evenement) et 320 (messages generaux).
pub(super) fn is_ptp_port(port: Option<u16>) -> bool {
    matches!(port, Some(319 | 320))
}

/// DNS classique : 53, sur UDP comme sur TCP.
pub(super) fn is_dns_port(port: Option<u16>) -> bool {
    matches!(port, Some(53))
}
