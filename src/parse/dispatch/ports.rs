// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Ports de la table de dispatch : une constante par famille de ports
//! standards. Le port ne decide jamais seul, la sonde de contenu confirme
//! (voir [`super`]).
//!
//! Les familles sont des donnees, pas des fonctions : l'index de la table
//! ([`super::index`]) en derive a la compilation, pour chaque port, les
//! regles qu'il ouvre et celles qu'il interdit.

/// Les ports d'une famille : ceux qu'une garde de port ou un veto de port
/// de la table reconnait.
#[derive(Clone, Copy)]
pub(super) enum Ports {
    /// Des ports isoles.
    Among(&'static [u16]),
    /// Une plage, bornes comprises.
    Range(u16, u16),
}

impl Ports {
    /// `port` est-il de la famille ?
    pub(super) const fn contains(self, port: u16) -> bool {
        match self {
            Self::Among(ports) => {
                let mut index = 0;
                while index < ports.len() {
                    if ports[index] == port {
                        return true;
                    }
                    index += 1;
                }
                false
            }
            Self::Range(first, last) => first <= port && port <= last,
        }
    }

    /// Le plus petit port de la famille qui ne soit pas sous `floor`.
    pub(super) const fn first_from(self, floor: u16) -> Option<u16> {
        match self {
            Self::Among(ports) => {
                let mut first = None;
                let mut index = 0;
                while index < ports.len() {
                    let port = ports[index];
                    if port >= floor
                        && match first {
                            Some(first) => port < first,
                            None => true,
                        }
                    {
                        first = Some(port);
                    }
                    index += 1;
                }
                first
            }
            Self::Range(first, last) => {
                if first > last || floor > last {
                    None
                } else if floor > first {
                    Some(floor)
                } else {
                    Some(first)
                }
            }
        }
    }
}

/// Ports standards de la famille texte FTP/SMTP/NNTP : les regles de port
/// ci-dessus y ont deja tranche, et un verbe distinctif y est probablement
/// du contenu en transit (corps DATA, article) — jamais reclasse.
///
/// Recopie par l'oracle FTP du fuzz : voir [`FTP_ONLY_VERBS`](super::probes::FTP_ONLY_VERBS).
pub(super) const TEXT_PROTOCOL_PORTS: Ports = Ports::Among(&[21, 25, 587, 119]);

pub(super) const SNMP_UDP_PORTS: Ports = Ports::Among(&[161, 162]);

pub(super) const DHCPV6_UDP_PORTS: Ports = Ports::Among(&[546, 547]);

/// DHCP et BOOTP : UDP 67 (serveur) et 68 (client), RFC 2131 §4.1 (#294).
pub(super) const DHCP_UDP_PORTS: Ports = Ports::Among(&[67, 68]);

/// SRVLOC : 427 sur UDP et TCP, RFC 2608 §6.1 et RFC 2165 §2 (#294).
pub(super) const SRVLOC_PORTS: Ports = Ports::Among(&[427]);

/// Modbus/TCP : TCP 502 (IANA `mbap`).
pub(super) const MODBUS_TCP_PORTS: Ports = Ports::Among(&[502]);

/// Modbus sur UDP : UDP 502, le port du dissecteur `mbudp` de Wireshark.
pub(super) const MODBUS_UDP_PORTS: Ports = Ports::Among(&[502]);

/// ISO-TSAP (TPKT/COTP, notamment S7comm).
pub(super) const ISO_TSAP_TCP_PORTS: Ports = Ports::Among(&[102]);

/// Beckhoff AMS/ADS sur TCP.
pub(super) const AMS_TCP_PORTS: Ports = Ports::Among(&[48898]);

/// Beckhoff AMS/ADS discovery sur UDP.
pub(super) const AMS_UDP_PORTS: Ports = Ports::Among(&[48899]);

/// NTP : UDP 123 (IANA `ntp`), source d'un serveur, destination d'un
/// client, les deux en mode symetrique.
pub(super) const NTP_UDP_PORTS: Ports = Ports::Among(&[123]);

/// QUIC (HTTP/3) : UDP 443.
pub(super) const QUIC_UDP_PORTS: Ports = Ports::Among(&[443]);

/// WireGuard : UDP 51820, le port des exemples de `wg(8)` et `wg-quick(8)`
/// (aucun port IANA ; sans `ListenPort`, wg choisit un port au hasard).
pub(super) const WIREGUARD_UDP_PORTS: Ports = Ports::Among(&[51820]);

/// DIS : UDP 3000, le port d'usage que Wireshark enregistre par defaut.
pub(super) const DIS_UDP_PORTS: Ports = Ports::Among(&[3000]);

/// PostgreSQL : TCP 5432 (IANA `postgresql`).
pub(super) const POSTGRESQL_TCP_PORTS: Ports = Ports::Among(&[5432]);

/// IEC 60870-5-104 : TCP 2404 (IANA `iec-104`).
pub(super) const IEC104_TCP_PORTS: Ports = Ports::Among(&[2404]);

/// Java RMI : TCP 1099 (IANA `rmiregistry`).
pub(super) const JAVA_RMI_TCP_PORTS: Ports = Ports::Among(&[1099]);

/// RDP : TCP 3389 (IANA `ms-wbt-server`).
pub(super) const RDP_TCP_PORTS: Ports = Ports::Among(&[3389]);

/// BACnet/IP : UDP 47808 (0xBAC0, IANA `bacnet`) et les quinze ports
/// suivants que l'annexe J laisse aux reseaux multiples.
pub(super) const BACNET_UDP_PORTS: Ports = Ports::Range(47808, 47823);

/// CAPWAP : UDP 5246 (controle) et 5247 (donnees), RFC 5415 §3.1.
pub(super) const CAPWAP_UDP_PORTS: Ports = Ports::Among(&[5246, 5247]);

/// RADIUS : UDP 1812/1813 (IANA), 1645/1646 (historiques), 3799 (RFC 5176).
pub(super) const RADIUS_UDP_PORTS: Ports = Ports::Among(&[1812, 1813, 1645, 1646, 3799]);

/// Valmet DNA : UDP 2517 (messages) et 4516, 4517 (balise), les ports
/// observes sur un reseau de process ; aucun n'est enregistre au nom du
/// protocole.
pub(super) const VALMET_DNA_UDP_PORTS: Ports = Ports::Among(&[2517, 4516, 4517]);

/// IKE : UDP 500 (IANA `isakmp`) et 4500 (IANA `ipsec-nat-t`).
pub(super) const IKE_UDP_PORTS: Ports = Ports::Among(&[500, 4500]);

/// ESP encapsule et NAT-keepalive : UDP 4500 seulement (RFC 3948).
pub(super) const NAT_T_UDP_PORTS: Ports = Ports::Among(&[4500]);

/// STANAG 5066 SIS : TCP 5066 (IANA `stanag-5066`).
pub(super) const STANAG5066_TCP_PORTS: Ports = Ports::Among(&[5066]);

/// FTP control channel : TCP 21.
///
/// Recopie par l'oracle FTP du fuzz : voir [`FTP_ONLY_VERBS`](super::probes::FTP_ONLY_VERBS).
pub(super) const FTP_TCP_PORTS: Ports = Ports::Among(&[21]);

/// SMTP en clair ou avec STARTTLS : TCP 25 (relais) et 587 (soumission).
/// Le port 465 transporte du TLS implicite et ne peut pas contenir
/// directement une commande SMTP dans le payload inspecte ici.
pub(super) const SMTP_TCP_PORTS: Ports = Ports::Among(&[25, 587]);

/// NNTP en clair ou avec STARTTLS : TCP 119. Le port 563 transporte du TLS
/// implicite et ne peut pas contenir directement une commande NNTP ici.
pub(super) const NNTP_TCP_PORTS: Ports = Ports::Among(&[119]);

/// LLMNR : UDP 5355 (port reserve, RFC 4795).
pub(super) const LLMNR_UDP_PORTS: Ports = Ports::Among(&[5355]);

/// SSDP : UDP 1900 (UPnP Device Architecture).
pub(super) const SSDP_UDP_PORTS: Ports = Ports::Among(&[1900]);

/// NetBIOS Name Service : UDP 137 (RFC 1002).
pub(super) const NBNS_UDP_PORTS: Ports = Ports::Among(&[137]);

/// NetBIOS Datagram Service : UDP 138 (IANA `netbios-dgm`) (#377).
pub(super) const NBDS_UDP_PORTS: Ports = Ports::Among(&[138]);

/// NetBIOS Session Service : TCP 139, et TCP 445 (SMB direct hosting).
pub(super) const NBSS_TCP_PORTS: Ports = Ports::Among(&[139, 445]);

/// OpenVPN : port officiel 1194 (TCP et UDP).
pub(super) const OPENVPN_PORTS: Ports = Ports::Among(&[1194]);

/// mDNS : UDP 5353 (port reserve, RFC 6762).
pub(super) const MDNS_UDP_PORTS: Ports = Ports::Among(&[5353]);

pub(super) const OPCUA_TCP_PORTS: Ports = Ports::Among(&[4840, 12001]);

/// PTP : 319 (messages d'evenement) et 320 (messages generaux).
pub(super) const PTP_PORTS: Ports = Ports::Among(&[319, 320]);

/// DNS classique : 53, sur UDP comme sur TCP.
pub(super) const DNS_PORTS: Ports = Ports::Among(&[53]);

/// Skinny (SCCP) : TCP 2000 (IANA `cisco-sccp`), le port ou les postes
/// joignent leur serveur d'appel (#370).
pub(super) const SKINNY_TCP_PORTS: Ports = Ports::Among(&[2000]);

/// LDAP : TCP 389 (IANA `ldap`) et TCP 3268 (IANA `msft-gc`), le catalogue
/// global d'un domaine Active Directory (#372).
pub(super) const LDAP_TCP_PORTS: Ports = Ports::Among(&[389, 3268]);

/// CLDAP : UDP 389, la recherche LDAP sans connexion (#372).
pub(super) const LDAP_UDP_PORTS: Ports = Ports::Among(&[389]);

/// Kerberos V5 : UDP 88 et TCP 88 (IANA `kerberos`, RFC 4120 §7.2) (#379).
pub(super) const KERBEROS_PORTS: Ports = Ports::Among(&[88]);

/// ONC RPC : 111 (IANA `sunrpc`, le portmapper) et 2049 (IANA `nfs`), en
/// UDP et en TCP (#381).
pub(super) const ONCRPC_PORTS: Ports = Ports::Among(&[111, 2049]);

/// Syslog : UDP 514 (IANA `syslog`, RFC 5426) (#374).
pub(super) const SYSLOG_UDP_PORTS: Ports = Ports::Among(&[514]);

/// Syslog sur TCP (RFC 6587) : 514, le port le plus courant bien que l'IANA
/// le donne a `shell` (rsh), et 601 (IANA `syslog-conn`) (#374).
pub(super) const SYSLOG_TCP_PORTS: Ports = Ports::Among(&[514, 601]);
