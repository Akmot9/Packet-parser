// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Premier octet des payloads que chaque sonde peut accepter : la
//! declaration dont [`classify`](super::classify) tire son prefiltre.
//!
//! La plupart des decodeurs refusent un payload sur son premier octet : une
//! version, une magie, un type de message. [`first_bytes`] declare, sonde
//! par sonde, l'ensemble des valeurs hors duquel la sonde rend `false`
//! **pour tout payload** de moins de [`PROVEN_BELOW`] octets. L'index en
//! derive, par transport et par premier octet, les regles qui valent une
//! visite ([`RuleList::worth_visiting`](super::index::RuleList::worth_visiting)).
//! Sur un payload que rien ne reconnait, il reste a tenter, en moyenne sur
//! les 256 valeurs du premier octet, 3,2 des 23 sondes sans port de TCP et
//! 2,1 des 17 d'UDP.
//!
//! Un ensemble trop large coute quelques instructions ; un ensemble trop
//! etroit change une etiquette en silence. Une sonde n'est donc restreinte
//! que si **chaque** chemin par lequel elle rend `true` contraint le premier
//! octet, et la preuve, lue dans le decodeur, est ecrite a cote de
//! l'ensemble : la fonction et le controle, par leur nom. Dans le doute,
//! [`FirstBytes::ANY`]. Quand le decodeur expose sa constante, l'ensemble en
//! derive ; sinon le litteral est recopie, et la preuve le dit.
//!
//! Trois filets gardent ces preuves :
//! - en build de debug, [`classify`](super::classify) rejoue la sonde de
//!   chaque regle du transport que le premier octet ecarte et verifie
//!   qu'elle refuse : les tests, le corpus de reference et chaque cible de
//!   fuzz en sont l'oracle continu ;
//! - `first_byte_sets_hold_on_accepted_payloads` substitue les 256 valeurs
//!   au premier octet des payloads que chaque sonde accepte ;
//! - `classify_agrees_with_a_scan_of_the_table` compare le verdict a celui
//!   d'un parcours de la table sans prefiltre.

use super::probes::{FTP_ONLY_VERBS, NNTP_ONLY_VERBS, ProbeId, SMTP_ONLY_VERBS};
use crate::checks::application::bacnet::BVLC_TYPE_BACNET_IP;
use crate::checks::application::dis::DIS_VERSION_2012;
use crate::checks::application::dnp3::DNP3_START_BYTES;
use crate::checks::application::iec104::IEC104_START_BYTE;
use crate::checks::application::ike::NAT_KEEPALIVE;
use crate::checks::application::java_rmi::{
    MESSAGE_CALL, MESSAGE_DGC_ACK, MESSAGE_HEADER, MESSAGE_PING, MESSAGE_PING_ACK,
    MESSAGE_PROTOCOL_ACK, MESSAGE_PROTOCOL_NOT_SUPPORTED, MESSAGE_RETURN,
};
use crate::checks::application::rdp::TPKT_VERSION;
use crate::checks::application::sip::{SIP_METHODS, SIP_VERSION};
use crate::checks::application::snmp::ASN1_SEQUENCE_TAG;
use crate::checks::application::ssh::SSH_PREFIX;
use crate::checks::application::stanag5066::SIS_SYNC_PREAMBLE;
use crate::checks::application::valmet_dna::VALMET_DNA_MAGIC;
use crate::parse::application::protocols::asterix::uap::SUPPORTED_CATEGORIES;
use crate::parse::application::protocols::rtcp::RTCP_VERSION;

/// Taille de payload sous laquelle les ensembles sont prouves ; au-dela,
/// [`classify`](super::classify) ne filtre pas. Un message qui s'ouvre par
/// sa longueur sur quatre octets gros-boutistes (le StartupMessage de
/// PostgreSQL) commence par un octet nul tant qu'il fait moins de 16 Mio :
/// la borne fait de cet octet une preuve.
pub(super) const PROVEN_BELOW: usize = 1 << 24;

/// Un ensemble de valeurs d'octet : le bit `n` du mot `n / 64` est la valeur
/// `n`.
#[derive(Clone, Copy)]
pub(super) struct FirstBytes([u64; 4]);

impl FirstBytes {
    /// Aucune preuve : la sonde est toujours tentee.
    pub(super) const ANY: Self = Self([u64::MAX; 4]);
    const NONE: Self = Self([0; 4]);

    pub(super) const fn contains(self, byte: u8) -> bool {
        self.0[(byte >> 6) as usize] >> (byte & 63) & 1 != 0
    }

    const fn with(mut self, byte: u8) -> Self {
        self.0[(byte >> 6) as usize] |= 1 << (byte & 63);
        self
    }

    /// Les valeurs de `bytes`.
    const fn only(bytes: &[u8]) -> Self {
        let mut set = Self::NONE;
        let mut index = 0;
        while index < bytes.len() {
            set = set.with(bytes[index]);
            index += 1;
        }
        set
    }

    /// Les valeurs de `first` a `last`, bornes comprises.
    const fn range(first: u8, last: u8) -> Self {
        let mut set = Self::NONE;
        let mut byte = first;
        while byte <= last {
            set = set.with(byte);
            if byte == u8::MAX {
                break;
            }
            byte += 1;
        }
        set
    }

    /// Le premier octet de chaque mot, tel qu'il est ecrit.
    const fn initials(words: &[&str]) -> Self {
        let mut set = Self::NONE;
        let mut index = 0;
        while index < words.len() {
            if let [first, ..] = words[index].as_bytes() {
                set = set.with(*first);
            }
            index += 1;
        }
        set
    }

    const fn or(self, other: Self) -> Self {
        Self([
            self.0[0] | other.0[0],
            self.0[1] | other.0[1],
            self.0[2] | other.0[2],
            self.0[3] | other.0[3],
        ])
    }

    /// L'ensemble, plus l'autre casse de chacune de ses lettres ASCII : pour
    /// un decodeur qui compare sans egard a la casse.
    const fn in_both_cases(self) -> Self {
        let mut set = self;
        let mut byte = u8::MIN;
        loop {
            if self.contains(byte) {
                set = set
                    .with(byte.to_ascii_lowercase())
                    .with(byte.to_ascii_uppercase());
            }
            if byte == u8::MAX {
                break;
            }
            byte += 1;
        }
        set
    }
}

/// Les premiers octets que `probe` peut accepter : hors de cet ensemble, la
/// sonde rend `false` pour tout payload de moins de [`PROVEN_BELOW`]
/// octets. Chaque bras porte sa preuve ; une sonde ajoutee a [`ProbeId`]
/// doit y prendre place, sous [`FirstBytes::ANY`] tant que rien n'est
/// prouve.
///
/// Les sondes des protocoles texte lisent `text`, le payload coupe a
/// `PROBE_CAP` octets : son premier octet est celui du payload.
pub(super) const fn first_bytes(probe: ProbeId) -> FirstBytes {
    match probe {
        // --- Les sondes des regles sans port de TCP, tentees sur tout
        // segment, et celles qui lisent le meme decodeur. ---

        // TPKT (RFC 1006), version 3. S7Comm : `extract_tpkt_header` passe
        // l'octet 0 a `validate_tpkt_version`, qui exige 0x03. COTP :
        // `cotp_from_tpkt` refuse d'emblee `payload[0] != 3` (litteraux
        // recopies).
        ProbeId::S7Comm | ProbeId::CotpTpkt => FirstBytes::only(&[0x03]),

        // `starts_with_one_of` exige en tete un verbe de la liste, casse
        // ignoree : sa premiere lettre, dans l'une ou l'autre casse.
        ProbeId::FtpUnambiguous => FirstBytes::initials(&FTP_ONLY_VERBS).in_both_cases(),
        ProbeId::SmtpUnambiguous => FirstBytes::initials(&SMTP_ONLY_VERBS).in_both_cases(),
        ProbeId::NntpUnambiguous => FirstBytes::initials(&NNTP_ONLY_VERBS).in_both_cases(),

        // `Dnp3Packet::try_from` lit d'abord une trame de liaison :
        // `parse_link_frame` exige `DNP3_START_BYTES` en tete
        // (`validate_start_bytes`).
        ProbeId::Dnp3 => FirstBytes::only(&[DNP3_START_BYTES[0]]),

        // `BitcoinPacket::is_tcp_match` commence par `check_magic_number` :
        // les quatre premiers octets sont un des `VALID_MAGIC_NUMBERS`, dont
        // voici les premiers octets sur le fil (constante privee, litteraux
        // recopies) : mainnet, testnet3, testnet4, regtest, signet.
        ProbeId::Bitcoin => FirstBytes::only(&[0xF9, 0x0B, 0x1C, 0xFA, 0x0A]),

        // `OpcuaPacket::try_from` et `is_blind_tcp_match` decodent d'abord le
        // chunk de tete : `next_chunk` lit `OpcuaTcpHeader`, dont
        // `extract_message_type` n'admet que HEL, ACK, ERR, RHE, OPN, MSG et
        // CLO (litteraux recopies). Le reste court de `validate_chunk_start`
        // ne se lit qu'apres un premier chunk.
        ProbeId::Opcua | ProbeId::OpcuaBlind => FirstBytes::only(b"HAEROMC"),

        // `EtherNetIpPacket::try_from` lit la commande, u16 petit-boutiste,
        // aux octets 0 et 1 (`extract_command`) : l'octet 0 est l'octet
        // faible d'une des dix commandes de `EtherNetIpCommand::try_from`,
        // toutes sous 0x0100 (litteraux recopies). `is_tcp_match` passe
        // d'abord a ce decodeur le message de tete du segment.
        ProbeId::EthernetIp | ProbeId::EthernetIpTcp => {
            FirstBytes::only(&[0x00, 0x04, 0x63, 0x64, 0x65, 0x66, 0x6F, 0x70, 0x72, 0x73])
        }

        // `PostgreSqlPacket::try_from` n'a que trois issues favorables. La
        // reponse d'un octet a SSLRequest : `S` ou `N`. Des messages types :
        // `parse_typed_messages` passe l'octet 0 a `extract_message_type`,
        // qui n'admet que ces trente lettres et chiffres (litteraux
        // recopies, `S` et `N` en sont). Un message sans type :
        // `extract_untyped_frame` exige que les quatre premiers octets,
        // gros-boutistes, valent la taille du payload, donc un octet 0 nul
        // sous `PROVEN_BELOW`. Les deux sondes passent par ce decodeur.
        ProbeId::Postgresql | ProbeId::PostgresqlPort => {
            FirstBytes::only(b"RKB2C3WdcfGDIEHFVnNAtSP1sQZTXp").with(0x00)
        }

        // `SnmpPacket::try_from` lit le TLV de tete (`read_tlv`, etiquette a
        // l'octet 0) et exige `ASN1_SEQUENCE_TAG` (`validate_tag`).
        ProbeId::Snmp => FirstBytes::only(&[ASN1_SEQUENCE_TAG]),

        // `TlsPacket::try_from` : `extract_content_type` passe l'octet 0 a
        // `TlsContentType::try_from`, qui n'admet que 20 a 24 (litteraux
        // recopies).
        ProbeId::Tls => FirstBytes::range(20, 24),

        // Le bras de la sonde exige `payload.starts_with(SSH_PREFIX)`.
        ProbeId::Ssh => FirstBytes::only(&[SSH_PREFIX[0]]),

        // `locate_ssh_identification` : le segment s'ouvre par `SSH_PREFIX`
        // (un `S`, dans la plage imprimable ci-dessous) ou par une ligne de
        // preambule. `prelude_line_length` refuse tout octet de controle
        // ASCII hors TAB, et CR ailleurs que devant LF : l'octet 0 est TAB,
        // le CR d'une ligne vide, ou le premier octet d'une ligne validee
        // en UTF-8, donc hors controle un octet de 0x20 a 0x7E ou l'octet de
        // tete d'une sequence, de 0xC2 a 0xF4.
        ProbeId::SshAfterLines => FirstBytes::only(b"\t\r")
            .or(FirstBytes::range(0x20, 0x7E))
            .or(FirstBytes::range(0xC2, 0xF4)),

        // Le bras de la sonde exige `may_start_sip` : `SIP_VERSION` en tete,
        // casse ignoree, ou une des `SIP_METHODS`, casse exacte.
        ProbeId::Sip => FirstBytes::initials(&[SIP_VERSION])
            .in_both_cases()
            .or(FirstBytes::initials(&SIP_METHODS)),

        // Le bras de la sonde exige `may_start_response`, donc `HTTP/` en
        // tete, ou `may_start_request` : une des neuf methodes (GET, HEAD,
        // POST, PUT, DELETE, CONNECT, OPTIONS, TRACE, PATCH ; constante
        // privee, initiales recopiees) apres les blancs que saute
        // `skip_leading_whitespace`, dont le premier octet est de TAB a CR,
        // une espace, ou l'octet de tete 0xC2, 0xE1, 0xE2 ou 0xE3 d'un blanc
        // Unicode.
        ProbeId::Http => FirstBytes::only(b"GHPDCOT")
            .or(FirstBytes::range(b'\t', b'\r'))
            .or(FirstBytes::only(&[b' ', 0xC2, 0xE1, 0xE2, 0xE3])),

        // Le bras de la sonde exige `payload.starts_with(b"GIOP")`.
        ProbeId::Giop => FirstBytes::only(b"G"),

        // `JavaRmiPacket::try_from` aiguille sur l'octet 0 : hors des huit
        // types de message, `UnknownMessageType`. A l'aveugle, seuls
        // l'en-tete de flux, le Call et le Return passent
        // (`is_self_identifying`), que seuls leurs trois types produisent.
        // Sur le port, `is_port_match` decode d'abord le message de tete.
        ProbeId::JavaRmiBlind => FirstBytes::only(&[MESSAGE_HEADER, MESSAGE_CALL, MESSAGE_RETURN]),
        ProbeId::JavaRmi => FirstBytes::only(&[
            MESSAGE_HEADER,
            MESSAGE_PROTOCOL_ACK,
            MESSAGE_PROTOCOL_NOT_SUPPORTED,
            MESSAGE_CALL,
            MESSAGE_RETURN,
            MESSAGE_PING,
            MESSAGE_PING_ACK,
            MESSAGE_DGC_ACK,
        ]),

        // `SrvlocPacket::try_from` aiguille sur la version, l'octet 0
        // (`extract_version`) : 1 ou 2, sinon `UnsupportedVersion`
        // (litteraux recopies).
        ProbeId::Srvloc => FirstBytes::only(&[1, 2]),

        // `NmfSegment::is_blind_match` exige en tete un enregistrement
        // Version ou SizedEnvelope, que `checks::record` ne produit que pour
        // les types 0x00 et 0x06 (litteraux recopies).
        ProbeId::NmfBlind => FirstBytes::only(&[0x00, 0x06]),

        // `DceRpcPdu::try_from` : `checks::version` exige la version majeure
        // 5 a l'octet 0 (litteral recopie).
        ProbeId::DceRpc => FirstBytes::only(&[5]),

        // `MqttPacket::try_from` lit d'abord un paquet : `parse_one` passe
        // l'octet 0 a `parse_packet_type`, qui refuse le type 0, puis a
        // `validate_fixed_header_flags` : drapeaux nuls, sauf 0b0010 pour
        // PUBREL, SUBSCRIBE et UNSUBSCRIBE, et tout sauf QoS 3 pour PUBLISH
        // (litteraux recopies).
        ProbeId::Mqtt => FirstBytes::only(&[
            0x10, 0x20, 0x40, 0x50, 0x62, 0x70, 0x82, 0x90, 0xA2, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0,
        ])
        .or(FirstBytes::range(0x30, 0x35))
        .or(FirstBytes::range(0x38, 0x3D)),

        // --- Les sondes des regles sans port d'UDP, tentees sur tout
        // datagramme, et celles qui lisent le meme decodeur. ---

        // `NtpPacket::try_from`, que les deux sondes appellent : l'octet 0
        // passe par `extract_flags`, qui exige une version de 1 a 4 (bits 3
        // a 5) et un mode de 1 a 5 (bits 0 a 2) ; l'indicateur de saut
        // (bits 6 et 7) est libre (litteraux recopies).
        ProbeId::Ntp | ProbeId::NtpBlind => {
            let mut set = FirstBytes::NONE;
            let mut leap = 0;
            while leap < 4 {
                let mut version = 1;
                while version <= 4 {
                    let mut mode = 1;
                    while mode <= 5 {
                        set = set.with(leap << 6 | version << 3 | mode);
                        mode += 1;
                    }
                    version += 1;
                }
                leap += 1;
            }
            set
        }

        // Le bras de la sonde exige `RTPS` ou `RTPX` en tete.
        ProbeId::Rtps => FirstBytes::only(b"R"),

        // `ValmetDnaPacket::try_from` exige `VALMET_DNA_MAGIC` aux octets 0
        // et 1 (`validate_magic`). Sur ses ports s'ajoute la balise :
        // `validate_beacon_frame` exige quatre octets nuls en tete (litteral
        // recopie).
        ProbeId::ValmetDnaBlind => FirstBytes::only(&[VALMET_DNA_MAGIC.to_be_bytes()[0]]),
        ProbeId::ValmetDna => FirstBytes::only(&[VALMET_DNA_MAGIC.to_be_bytes()[0], 0x00]),

        // `walk_datagram` lit d'abord l'en-tete du bloc de tete
        // (`read_block_header`, categorie a l'octet 0) et exige une
        // categorie dont l'UAP est connu (`uap_for`) : celles de
        // `SUPPORTED_CATEGORIES`, que
        // `test_every_supported_category_has_a_uap_and_vice_versa` tient
        // egales.
        ProbeId::Asterix => FirstBytes::only(&SUPPORTED_CATEGORIES),

        // `DisPacket::parse`, strict ou tolerant, lit d'abord un PDU :
        // `parse_pdu` passe l'octet 0 a `extract_version`, qui exige une
        // version de 1 a `DIS_VERSION_2012`.
        ProbeId::Dis | ProbeId::DisLenient => FirstBytes::range(1, DIS_VERSION_2012),

        // `RadiusPacket::try_from` passe l'octet 0 a `validate_code` : 1 a
        // 5, 11 a 13, 40 a 45 (litteraux recopies).
        ProbeId::Radius => FirstBytes::range(1, 5)
            .or(FirstBytes::range(11, 13))
            .or(FirstBytes::range(40, 45)),

        // `BacnetPacket::try_from` passe l'octet 0 a `validate_bvlc_type`,
        // qui exige `BVLC_TYPE_BACNET_IP`.
        ProbeId::Bacnet => FirstBytes::only(&[BVLC_TYPE_BACNET_IP]),

        // `parse_dhcp_packet` passe l'octet 0 a `extract_operation` :
        // BOOTREQUEST ou BOOTREPLY (`validate_operation`, litteraux
        // recopies).
        ProbeId::Dhcp => FirstBytes::only(&[1, 2]),

        // `QuicPacket::try_from` n'a que deux issues : un Version
        // Negotiation, bit de forme a 1, et un en-tete long v1, que
        // `extract_first_byte` n'admet qu'avec le bit de forme et le Fixed
        // Bit. A l'aveugle la version doit etre la v1, ce qu'un Version
        // Negotiation n'est pas : les deux bits. Sur le port,
        // `is_port_match` passe par ce decodeur ou par
        // `is_invariant_long_header`, qui exige le bit de forme. L'en-tete
        // court : `is_plausible_short_header` exige `0b01` aux deux bits de
        // tete (litteraux recopies).
        ProbeId::QuicLongHeader => FirstBytes::range(0xC0, 0xFF),
        ProbeId::QuicLongHeaderPort => FirstBytes::range(0x80, 0xFF),
        ProbeId::QuicShortHeader => FirstBytes::range(0x40, 0x7F),

        // `WireGuardPacket::try_from`, que les deux sondes appellent, passe
        // l'octet 0 a `validate_message_length` : types 1 a 4, sinon
        // `UnknownMessageType` (litteraux recopies).
        ProbeId::WireGuardBlind | ProbeId::WireGuardPort => FirstBytes::range(1, 4),

        // `RtcpCompound::try_from` lit d'abord un paquet : `checks::packet`
        // exige `RTCP_VERSION` aux deux bits de tete de l'octet 0.
        ProbeId::RtcpBlind => FirstBytes::range(RTCP_VERSION << 6, RTCP_VERSION << 6 | 0x3F),

        // --- Les autres sondes de regles a port, tentees sur leurs ports
        // seulement. ---

        // `RdpPacket::try_from` lit d'abord un TPKT : `validate_tpkt_header`
        // exige `TPKT_VERSION` a l'octet 0.
        ProbeId::Rdp => FirstBytes::only(&[TPKT_VERSION]),

        // `Dhcpv6Packet::try_from` passe l'octet 0 a
        // `validate_dhcpv6_message_type` : 1 a 13 (litteraux recopies).
        ProbeId::Dhcpv6 => FirstBytes::range(1, 13),

        // `Iec104Packet::try_from` lit d'abord un APDU : `validate_start_byte`
        // exige `IEC104_START_BYTE` a l'octet 0.
        ProbeId::Iec104 => FirstBytes::only(&[IEC104_START_BYTE]),

        // `SisPdu::try_from` exige `SIS_SYNC_PREAMBLE` aux octets 0 et 1
        // (`validate_preamble`).
        ProbeId::Stanag5066 => FirstBytes::only(&[SIS_SYNC_PREAMBLE[0]]),

        // `NbssPacket::try_from` passe l'octet 0 a
        // `extract_nbss_message_type` : 0x00, ou 0x81 a 0x85 (litteraux
        // recopies).
        ProbeId::Nbss => FirstBytes::range(0x81, 0x85).with(0x00),

        // `NbdsPacket::try_from` passe l'octet 0 a
        // `extract_nbds_message_type` : 0x10 a 0x16 (litteraux recopies).
        ProbeId::Nbds => FirstBytes::range(0x10, 0x16),

        // `SyslogMessage::try_from` : `extract_priority` exige `<` en tete.
        // Sur TCP, `SyslogFrame::try_from` lit la trame de tete :
        // `extract_octet_count` prend un chiffre pour un comptage d'octets,
        // et sinon le message commence a l'octet 0 (litteraux recopies).
        ProbeId::Syslog => FirstBytes::only(b"<"),
        ProbeId::SyslogTcp => FirstBytes::range(b'0', b'9').with(b'<'),

        // Le bras de la sonde exige que `UdpEncapsulation::classify` rende
        // `Keepalive`, donc que le payload soit `NAT_KEEPALIVE`.
        ProbeId::NatKeepalive => FirstBytes::only(&[NAT_KEEPALIVE[0]]),

        // --- Sans preuve : la sonde est toujours tentee. ---

        // Un identifiant libre aux deux premiers octets : la transaction de
        // MBAP (Modbus, UMAS), l'identifiant de DNS et de ses derives (mDNS,
        // LLMNR, NBNS), le `xid` d'ONC RPC en datagramme.
        ProbeId::Umas
        | ProbeId::ModbusTcp
        | ProbeId::ModbusTcpBlind
        | ProbeId::Dns
        | ProbeId::DnsBlind
        | ProbeId::Mdns
        | ProbeId::Llmnr
        | ProbeId::Nbns
        | ProbeId::OncRpc => FirstBytes::ANY,

        // Une longueur sur deux octets ou petit-boutiste en tete, dont
        // l'octet 0 est libre : DNS et OpenVPN sur TCP, Skinny. Un SPI libre
        // : IKE, ESP dans UDP.
        ProbeId::DnsTcp
        | ProbeId::OpenVpnTcp
        | ProbeId::Skinny
        | ProbeId::Ike
        | ProbeId::EspNatT => FirstBytes::ANY,

        // Regles a port dont le decodeur admet plusieurs formes en tete
        // (commandes et reponses texte, versions, enveloppes) : rien n'est
        // prouve, et le gain serait limite a leurs ports.
        ProbeId::Ftp
        | ProbeId::Smtp
        | ProbeId::Nntp
        | ProbeId::Ssdp
        | ProbeId::OpenVpnUdp
        | ProbeId::Ams
        | ProbeId::AmsTcp
        | ProbeId::Ptp
        | ProbeId::Capwap
        | ProbeId::Ldap
        | ProbeId::Kerberos
        | ProbeId::KerberosTcp
        | ProbeId::OncRpcTcp => FirstBytes::ANY,

        // Sondes de Decode As seulement : elles ne passent pas par le
        // prefiltre.
        ProbeId::WireGuard | ProbeId::Rtp | ProbeId::Nmf | ProbeId::Rtcp => FirstBytes::ANY,
    }
}
