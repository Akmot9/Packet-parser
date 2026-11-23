// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Comparaison L2-L4 de `packet_parser` avec `etherparse` et `pnet_packet`
//! (#375).
//!
//! Deux niveaux, pour comparer ce qui se compare :
//! - **decoupage** : les en-tetes sont localises, leurs champs ne sont pas
//!   lus (`etherparse::SlicedPacket`, vues `pnet_packet`) ;
//! - **decodage** : tous les champs d'Ethernet a la couche 4 sont lus et
//!   rendus dans une valeur (`etherparse::PacketHeaders`, accesseurs
//!   `pnet_packet`). `packet_parser::parse` n'a que ce niveau, et il lit en
//!   plus la couche 7.
//!
//! Chaque fonction mesuree a ici sa [`Key`] : ce qu'elle a lu de la trame.
//! Le bench ne garde que les trames ou les trois crates rendent la meme
//! cle, et le dit : une crate qui lirait autre chose, ou rien, ne gagnerait
//! pas de temps a ne pas faire le travail.

use std::net::IpAddr;

pub mod corpus;

/// Protocole de couche 4 que les trois crates decodent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum L4 {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
}

/// Ce qu'une crate a lu d'une trame : assez pour dire que deux crates ont
/// decode la meme chose, de la couche 3 a la couche 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Key {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub l4: L4,
    /// Ports TCP ou UDP ; type et code pour ICMP et ICMPv6.
    pub source_port: u16,
    pub destination_port: u16,
    /// Octets apres l'en-tete TCP ou UDP ; zero pour ICMP, dont les trois
    /// crates ne decoupent pas le message au meme endroit.
    pub payload_len: usize,
}

/// `packet_parser`.
pub mod pp {
    use super::{Key, L4};
    use packet_parser::parse::PacketFlow;
    use packet_parser::parse::transport::TransportDetails;
    use packet_parser::parse::transport::protocols::TransportProtocol;
    use packet_parser::{LinkType, parse};

    /// Le seul niveau de la crate : toutes les couches, la 7 comprise.
    #[inline]
    pub fn full(frame: &[u8]) -> Option<PacketFlow<'_>> {
        parse(LinkType::ETHERNET, frame).ok()
    }

    pub fn key(flow: &PacketFlow<'_>) -> Option<Key> {
        if flow.corrupted.is_some() {
            return None;
        }
        let internet = flow.internet.as_ref()?;
        let transport = flow.transport.as_ref()?;
        let l4 = match transport.protocol {
            TransportProtocol::Tcp => L4::Tcp,
            TransportProtocol::Udp => L4::Udp,
            TransportProtocol::Icmp => L4::Icmp,
            TransportProtocol::Ipv6Icmp => L4::Icmpv6,
            _ => return None,
        };
        let (source_port, destination_port, payload_len) = match transport.details.as_ref()? {
            TransportDetails::Icmp(icmp) => (icmp.message_type.into(), icmp.code.into(), 0),
            TransportDetails::Icmpv6(icmp) => (icmp.message_type.into(), icmp.code.into(), 0),
            _ => (
                transport.source_port?,
                transport.destination_port?,
                transport.payload.map_or(0, <[u8]>::len),
            ),
        };
        Some(Key {
            source: internet.source?,
            destination: internet.destination?,
            l4,
            source_port,
            destination_port,
            payload_len,
        })
    }
}

/// `etherparse`.
pub mod ep {
    use super::{Key, L4};
    use etherparse::{
        Ethernet2Header, Ipv4Header, Ipv6Header, LinkExtSlice, LinkSlice, NetHeaders, NetSlice,
        PacketHeaders, SingleVlanHeader, SlicedPacket, TransportHeader, TransportSlice,
    };
    use std::net::IpAddr;

    /// Decoupage : `SlicedPacket` verifie les longueurs et rend des vues.
    #[inline]
    pub fn slice(frame: &[u8]) -> Option<SlicedPacket<'_>> {
        SlicedPacket::from_ethernet(frame).ok()
    }

    /// Decodage : `PacketHeaders` copie chaque en-tete dans une structure.
    #[inline]
    pub fn full(frame: &[u8]) -> Option<PacketHeaders<'_>> {
        PacketHeaders::from_ethernet_slice(frame).ok()
    }

    /// Les en-tetes lus par les vues : ce que rend `to_header` sur chacune.
    pub struct Headers<'a> {
        pub link: Option<Ethernet2Header>,
        pub vlans: [Option<SingleVlanHeader>; SlicedPacket::LINK_EXTS_CAP],
        pub net: Net,
        pub transport: TransportHeader,
        pub payload: &'a [u8],
    }

    pub enum Net {
        Ipv4(Ipv4Header),
        /// L'en-tete fixe et les octets qu'occupent ses extensions.
        Ipv6(Ipv6Header, usize),
    }

    /// Decodage par les vues : `SlicedPacket`, puis `to_header` sur chaque
    /// vue. C'est la facon de lire tous les champs sans passer par
    /// `PacketHeaders`, dont la valeur pese 9,5 ko.
    #[inline]
    pub fn full_from_slices(frame: &[u8]) -> Option<Headers<'_>> {
        let packet = SlicedPacket::from_ethernet(frame).ok()?;
        let link = match packet.link.as_ref()? {
            LinkSlice::Ethernet2(ethernet) => Some(ethernet.to_header()),
            _ => None,
        };
        let mut vlans = [None, None, None];
        for (slot, ext) in vlans.iter_mut().zip(&packet.link_exts) {
            if let LinkExtSlice::Vlan(vlan) = ext {
                *slot = Some(vlan.to_header());
            }
        }
        let net = match packet.net.as_ref()? {
            NetSlice::Ipv4(ip) => Net::Ipv4(ip.header().to_header()),
            NetSlice::Ipv6(ip) => Net::Ipv6(ip.header().to_header(), ip.extensions().slice().len()),
            NetSlice::Arp(_) => return None,
        };
        let (transport, payload) = match packet.transport.as_ref()? {
            TransportSlice::Tcp(tcp) => (TransportHeader::Tcp(tcp.to_header()), tcp.payload()),
            TransportSlice::Udp(udp) => (TransportHeader::Udp(udp.to_header()), udp.payload()),
            TransportSlice::Icmpv4(icmp) => {
                (TransportHeader::Icmpv4(icmp.header()), icmp.payload())
            }
            TransportSlice::Icmpv6(icmp) => {
                (TransportHeader::Icmpv6(icmp.header()), icmp.payload())
            }
            TransportSlice::Igmp(_) => return None,
        };
        Some(Headers {
            link,
            vlans,
            net,
            transport,
            payload,
        })
    }

    pub fn headers_key(headers: &Headers<'_>) -> Option<Key> {
        let (source, destination): (IpAddr, IpAddr) = match &headers.net {
            Net::Ipv4(ip) => (ip.source.into(), ip.destination.into()),
            Net::Ipv6(ip, _) => (ip.source.into(), ip.destination.into()),
        };
        let rest = headers.payload.len();
        let (l4, source_port, destination_port, payload_len) = match &headers.transport {
            TransportHeader::Tcp(tcp) => (L4::Tcp, tcp.source_port, tcp.destination_port, rest),
            TransportHeader::Udp(udp) => (L4::Udp, udp.source_port, udp.destination_port, rest),
            TransportHeader::Icmpv4(icmp) => {
                let bytes = icmp.to_bytes();
                (L4::Icmp, bytes[0].into(), bytes[1].into(), 0)
            }
            TransportHeader::Icmpv6(icmp) => {
                let bytes = icmp.to_bytes();
                (L4::Icmpv6, bytes[0].into(), bytes[1].into(), 0)
            }
            TransportHeader::Igmp(_) => return None,
        };
        Some(Key {
            source,
            destination,
            l4,
            source_port,
            destination_port,
            payload_len,
        })
    }

    pub fn slice_key(packet: &SlicedPacket<'_>) -> Option<Key> {
        let (source, destination): (IpAddr, IpAddr) = match packet.net.as_ref()? {
            NetSlice::Ipv4(ip) => (
                ip.header().source_addr().into(),
                ip.header().destination_addr().into(),
            ),
            NetSlice::Ipv6(ip) => (
                ip.header().source_addr().into(),
                ip.header().destination_addr().into(),
            ),
            NetSlice::Arp(_) => return None,
        };
        let (l4, source_port, destination_port, payload_len) = match packet.transport.as_ref()? {
            TransportSlice::Tcp(tcp) => (
                L4::Tcp,
                tcp.source_port(),
                tcp.destination_port(),
                tcp.payload().len(),
            ),
            TransportSlice::Udp(udp) => (
                L4::Udp,
                udp.source_port(),
                udp.destination_port(),
                udp.payload().len(),
            ),
            TransportSlice::Icmpv4(icmp) => {
                (L4::Icmp, icmp.type_u8().into(), icmp.code_u8().into(), 0)
            }
            TransportSlice::Icmpv6(icmp) => {
                (L4::Icmpv6, icmp.type_u8().into(), icmp.code_u8().into(), 0)
            }
            TransportSlice::Igmp(_) => return None,
        };
        Some(Key {
            source,
            destination,
            l4,
            source_port,
            destination_port,
            payload_len,
        })
    }

    pub fn full_key(packet: &PacketHeaders<'_>) -> Option<Key> {
        let (source, destination): (IpAddr, IpAddr) = match packet.net.as_ref()? {
            NetHeaders::Ipv4(ip, _) => (ip.source.into(), ip.destination.into()),
            NetHeaders::Ipv6(ip, _) => (ip.source.into(), ip.destination.into()),
            NetHeaders::Arp(_) => return None,
        };
        let rest = packet.payload.slice().len();
        let (l4, source_port, destination_port, payload_len) = match packet.transport.as_ref()? {
            TransportHeader::Tcp(tcp) => (L4::Tcp, tcp.source_port, tcp.destination_port, rest),
            TransportHeader::Udp(udp) => (L4::Udp, udp.source_port, udp.destination_port, rest),
            TransportHeader::Icmpv4(icmp) => {
                let bytes = icmp.to_bytes();
                (L4::Icmp, bytes[0].into(), bytes[1].into(), 0)
            }
            TransportHeader::Icmpv6(icmp) => {
                let bytes = icmp.to_bytes();
                (L4::Icmpv6, bytes[0].into(), bytes[1].into(), 0)
            }
            TransportHeader::Igmp(_) => return None,
        };
        Some(Key {
            source,
            destination,
            l4,
            source_port,
            destination_port,
            payload_len,
        })
    }
}

/// `pnet_packet`.
///
/// La crate ne fournit que des vues par en-tete : pas de fonction qui
/// descende d'Ethernet a la couche 4, ni de verification des longueurs.
/// Le parcours ci-dessous est celui qu'ecrit tout utilisateur de pnet, avec
/// les seuls controles qui evitent de lire hors de la trame.
pub mod pn {
    use super::{Key, L4};
    use pnet_packet::Packet;
    use pnet_packet::ethernet::{EtherTypes, EthernetPacket};
    use pnet_packet::icmp::IcmpPacket;
    use pnet_packet::icmpv6::Icmpv6Packet;
    use pnet_packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
    use pnet_packet::ipv4::Ipv4Packet;
    use pnet_packet::ipv6::{ExtensionPacket, FragmentPacket, Ipv6Packet};
    use pnet_packet::tcp::TcpPacket;
    use pnet_packet::udp::UdpPacket;
    use pnet_packet::vlan::VlanPacket;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// Les octets d'IP et le nombre d'etiquettes VLAN qui les precedent.
    enum Network<'a> {
        V4(&'a [u8]),
        V6(&'a [u8]),
    }

    const MAX_VLAN: usize = 3;

    /// Ethernet II et jusqu'a trois etiquettes 802.1Q ou 802.1ad.
    #[inline]
    fn network<'a>(
        ethernet: &EthernetPacket<'a>,
        frame: &'a [u8],
        mut tag: impl FnMut(&VlanPacket<'a>),
    ) -> Option<Network<'a>> {
        let mut ethertype = ethernet.get_ethertype();
        let mut rest = frame.get(14..)?;
        for _ in 0..MAX_VLAN {
            if ethertype != EtherTypes::Vlan && ethertype != EtherTypes::QinQ {
                break;
            }
            let vlan = VlanPacket::new(rest)?;
            tag(&vlan);
            ethertype = vlan.get_ethertype();
            rest = rest.get(4..)?;
        }
        if ethertype == EtherTypes::Ipv4 {
            Some(Network::V4(rest))
        } else if ethertype == EtherTypes::Ipv6 {
            Some(Network::V6(rest))
        } else {
            None
        }
    }

    /// En-tete IPv4 et ses octets de couche 4, bornes par la longueur totale.
    #[inline]
    fn ipv4(bytes: &[u8]) -> Option<(Ipv4Packet<'_>, &[u8])> {
        let ip = Ipv4Packet::new(bytes)?;
        let header_len = usize::from(ip.get_header_length()) * 4;
        let total_len = usize::from(ip.get_total_length());
        if ip.get_version() != 4 || header_len < 20 || total_len < header_len {
            return None;
        }
        let payload = bytes.get(header_len..total_len)?;
        Some((ip, payload))
    }

    /// En-tete IPv6, puis ses extensions jusqu'au protocole de couche 4.
    #[inline]
    fn ipv6<'a>(
        bytes: &'a [u8],
        mut extension: impl FnMut(IpNextHeaderProtocol, &'a [u8]),
    ) -> Option<(Ipv6Packet<'a>, IpNextHeaderProtocol, &'a [u8], bool)> {
        let ip = Ipv6Packet::new(bytes)?;
        if ip.get_version() != 6 {
            return None;
        }
        let mut rest = bytes.get(40..40 + usize::from(ip.get_payload_length()))?;
        let mut next = ip.get_next_header();
        let mut fragmented = false;
        for _ in 0..8 {
            let len = if next == IpNextHeaderProtocols::Hopopt
                || next == IpNextHeaderProtocols::Ipv6Route
                || next == IpNextHeaderProtocols::Ipv6Opts
            {
                let ext = ExtensionPacket::new(rest)?;
                let len = usize::from(ext.get_hdr_ext_len()) * 8 + 8;
                extension(next, rest.get(..len)?);
                next = ext.get_next_header();
                len
            } else if next == IpNextHeaderProtocols::Ipv6Frag {
                let ext = FragmentPacket::new(rest)?;
                extension(next, rest.get(..8)?);
                // Decalage non nul ou « d'autres fragments » : le datagramme
                // n'est pas entier, sa couche 4 ne se lit pas.
                fragmented |= ext.get_fragment_offset_with_flags() & 0xfff9 != 0;
                next = ext.get_next_header();
                8
            } else {
                break;
            };
            rest = rest.get(len..)?;
        }
        Some((ip, next, rest, fragmented))
    }

    /// Ce que le decoupage rend : ou sont les en-tetes, rien de leurs champs.
    pub struct Sliced<'a> {
        pub ethernet: EthernetPacket<'a>,
        pub network: SlicedNetwork<'a>,
        pub transport: SlicedTransport<'a>,
    }

    pub enum SlicedNetwork<'a> {
        V4(Ipv4Packet<'a>),
        V6(Ipv6Packet<'a>),
    }

    pub enum SlicedTransport<'a> {
        Tcp(TcpPacket<'a>, &'a [u8]),
        Udp(UdpPacket<'a>, &'a [u8]),
        Icmp(IcmpPacket<'a>, &'a [u8]),
        Icmpv6(Icmpv6Packet<'a>, &'a [u8]),
    }

    #[inline]
    fn transport<'a>(
        protocol: IpNextHeaderProtocol,
        bytes: &'a [u8],
        v6: bool,
    ) -> Option<SlicedTransport<'a>> {
        if protocol == IpNextHeaderProtocols::Tcp {
            let tcp = TcpPacket::new(bytes)?;
            let header_len = usize::from(tcp.get_data_offset()) * 4;
            if header_len < 20 {
                return None;
            }
            let payload = bytes.get(header_len..)?;
            Some(SlicedTransport::Tcp(tcp, payload))
        } else if protocol == IpNextHeaderProtocols::Udp {
            let udp = UdpPacket::new(bytes)?;
            let length = usize::from(udp.get_length());
            // Longueur nulle : le datagramme va jusqu'au bout d'IP (RFC 2675).
            let payload = if length == 0 {
                bytes.get(8..)?
            } else {
                bytes.get(8..length)?
            };
            Some(SlicedTransport::Udp(udp, payload))
        } else if protocol == IpNextHeaderProtocols::Icmp && !v6 {
            Some(SlicedTransport::Icmp(IcmpPacket::new(bytes)?, bytes))
        } else if protocol == IpNextHeaderProtocols::Icmpv6 && v6 {
            Some(SlicedTransport::Icmpv6(Icmpv6Packet::new(bytes)?, bytes))
        } else {
            None
        }
    }

    /// Decoupage : les vues, sans lire d'autre champ que ceux du parcours.
    #[inline]
    pub fn slice(frame: &[u8]) -> Option<Sliced<'_>> {
        let ethernet = EthernetPacket::new(frame)?;
        match network(&ethernet, frame, |_| {})? {
            Network::V4(bytes) => {
                let (ip, payload) = ipv4(bytes)?;
                // Fragment : la couche 4 ne se lit pas sans reassemblage.
                if ip.get_fragment_offset() != 0 || ip.get_flags() & 1 != 0 {
                    return None;
                }
                let transport = transport(ip.get_next_level_protocol(), payload, false)?;
                Some(Sliced {
                    ethernet,
                    network: SlicedNetwork::V4(ip),
                    transport,
                })
            }
            Network::V6(bytes) => {
                let (ip, next, payload, fragmented) = ipv6(bytes, |_, _| {})?;
                if fragmented {
                    return None;
                }
                let transport = transport(next, payload, true)?;
                Some(Sliced {
                    ethernet,
                    network: SlicedNetwork::V6(ip),
                    transport,
                })
            }
        }
    }

    pub fn slice_key(sliced: &Sliced<'_>) -> Key {
        let (source, destination): (IpAddr, IpAddr) = match &sliced.network {
            SlicedNetwork::V4(ip) => (ip.get_source().into(), ip.get_destination().into()),
            SlicedNetwork::V6(ip) => (ip.get_source().into(), ip.get_destination().into()),
        };
        let (l4, source_port, destination_port, payload_len) = match &sliced.transport {
            SlicedTransport::Tcp(tcp, payload) => (
                L4::Tcp,
                tcp.get_source(),
                tcp.get_destination(),
                payload.len(),
            ),
            SlicedTransport::Udp(udp, payload) => (
                L4::Udp,
                udp.get_source(),
                udp.get_destination(),
                payload.len(),
            ),
            SlicedTransport::Icmp(icmp, _) => (
                L4::Icmp,
                icmp.get_icmp_type().0.into(),
                icmp.get_icmp_code().0.into(),
                0,
            ),
            SlicedTransport::Icmpv6(icmp, _) => (
                L4::Icmpv6,
                icmp.get_icmpv6_type().0.into(),
                icmp.get_icmpv6_code().0.into(),
                0,
            ),
        };
        Key {
            source,
            destination,
            l4,
            source_port,
            destination_port,
            payload_len,
        }
    }

    /// Octets d'options, copies comme le fait `etherparse` : sans allocation.
    #[derive(Clone, Copy)]
    pub struct Options {
        pub bytes: [u8; 40],
        pub len: u8,
    }

    impl Options {
        #[inline]
        fn new(raw: &[u8]) -> Self {
            let mut bytes = [0u8; 40];
            let len = raw.len().min(40);
            bytes[..len].copy_from_slice(&raw[..len]);
            Self {
                bytes,
                len: len as u8,
            }
        }
    }

    /// Tous les champs lus, d'Ethernet a la couche 4.
    pub struct Decoded<'a> {
        pub destination_mac: [u8; 6],
        pub source_mac: [u8; 6],
        pub ethertype: u16,
        /// PCP, DEI et VID de chaque etiquette, et son EtherType.
        pub vlans: [(u8, u8, u16, u16); MAX_VLAN],
        pub vlan_count: u8,
        pub network: DecodedNetwork,
        pub transport: DecodedTransport,
        pub payload: &'a [u8],
    }

    pub enum DecodedNetwork {
        V4 {
            version: u8,
            header_length: u8,
            dscp: u8,
            ecn: u8,
            total_length: u16,
            identification: u16,
            flags: u8,
            fragment_offset: u16,
            ttl: u8,
            protocol: u8,
            checksum: u16,
            source: Ipv4Addr,
            destination: Ipv4Addr,
            options: Options,
        },
        V6 {
            version: u8,
            traffic_class: u8,
            flow_label: u32,
            payload_length: u16,
            next_header: u8,
            hop_limit: u8,
            source: Ipv6Addr,
            destination: Ipv6Addr,
            /// Nombre d'extensions et octets qu'elles occupent.
            extensions: (u8, u16),
        },
    }

    pub enum DecodedTransport {
        Tcp {
            source: u16,
            destination: u16,
            sequence: u32,
            acknowledgement: u32,
            data_offset: u8,
            reserved: u8,
            flags: u8,
            window: u16,
            checksum: u16,
            urgent: u16,
            options: Options,
        },
        Udp {
            source: u16,
            destination: u16,
            length: u16,
            checksum: u16,
        },
        Icmp {
            kind: u8,
            code: u8,
            checksum: u16,
        },
        Icmpv6 {
            kind: u8,
            code: u8,
            checksum: u16,
        },
    }

    #[inline]
    fn decode_transport<'a>(sliced: SlicedTransport<'a>) -> (DecodedTransport, &'a [u8]) {
        match sliced {
            SlicedTransport::Tcp(tcp, payload) => {
                let header_len = usize::from(tcp.get_data_offset()) * 4;
                let options = Options::new(&tcp.packet()[20..header_len]);
                (
                    DecodedTransport::Tcp {
                        source: tcp.get_source(),
                        destination: tcp.get_destination(),
                        sequence: tcp.get_sequence(),
                        acknowledgement: tcp.get_acknowledgement(),
                        data_offset: tcp.get_data_offset(),
                        reserved: tcp.get_reserved(),
                        flags: tcp.get_flags(),
                        window: tcp.get_window(),
                        checksum: tcp.get_checksum(),
                        urgent: tcp.get_urgent_ptr(),
                        options,
                    },
                    payload,
                )
            }
            SlicedTransport::Udp(udp, payload) => (
                DecodedTransport::Udp {
                    source: udp.get_source(),
                    destination: udp.get_destination(),
                    length: udp.get_length(),
                    checksum: udp.get_checksum(),
                },
                payload,
            ),
            SlicedTransport::Icmp(icmp, bytes) => (
                DecodedTransport::Icmp {
                    kind: icmp.get_icmp_type().0,
                    code: icmp.get_icmp_code().0,
                    checksum: icmp.get_checksum(),
                },
                bytes,
            ),
            SlicedTransport::Icmpv6(icmp, bytes) => (
                DecodedTransport::Icmpv6 {
                    kind: icmp.get_icmpv6_type().0,
                    code: icmp.get_icmpv6_code().0,
                    checksum: icmp.get_checksum(),
                },
                bytes,
            ),
        }
    }

    /// Decodage : chaque champ est lu par son accesseur.
    #[inline]
    pub fn full(frame: &[u8]) -> Option<Decoded<'_>> {
        let ethernet = EthernetPacket::new(frame)?;
        let mut vlans = [(0u8, 0u8, 0u16, 0u16); MAX_VLAN];
        let mut vlan_count = 0u8;
        let network = network(&ethernet, frame, |vlan| {
            vlans[usize::from(vlan_count)] = (
                vlan.get_priority_code_point().0,
                vlan.get_drop_eligible_indicator(),
                vlan.get_vlan_identifier(),
                vlan.get_ethertype().0,
            );
            vlan_count += 1;
        })?;
        let (network, transport) = match network {
            Network::V4(bytes) => {
                let (ip, payload) = ipv4(bytes)?;
                if ip.get_fragment_offset() != 0 || ip.get_flags() & 1 != 0 {
                    return None;
                }
                let protocol = ip.get_next_level_protocol();
                let header_len = usize::from(ip.get_header_length()) * 4;
                let decoded = DecodedNetwork::V4 {
                    version: ip.get_version(),
                    header_length: ip.get_header_length(),
                    dscp: ip.get_dscp(),
                    ecn: ip.get_ecn(),
                    total_length: ip.get_total_length(),
                    identification: ip.get_identification(),
                    flags: ip.get_flags(),
                    fragment_offset: ip.get_fragment_offset(),
                    ttl: ip.get_ttl(),
                    protocol: protocol.0,
                    checksum: ip.get_checksum(),
                    source: ip.get_source(),
                    destination: ip.get_destination(),
                    options: Options::new(&bytes[20..header_len]),
                };
                (decoded, transport(protocol, payload, false)?)
            }
            Network::V6(bytes) => {
                let mut extensions = (0u8, 0u16);
                let (ip, next, payload, fragmented) = ipv6(bytes, |_, ext| {
                    extensions.0 += 1;
                    extensions.1 += ext.len() as u16;
                })?;
                if fragmented {
                    return None;
                }
                let decoded = DecodedNetwork::V6 {
                    version: ip.get_version(),
                    traffic_class: ip.get_traffic_class(),
                    flow_label: ip.get_flow_label(),
                    payload_length: ip.get_payload_length(),
                    next_header: ip.get_next_header().0,
                    hop_limit: ip.get_hop_limit(),
                    source: ip.get_source(),
                    destination: ip.get_destination(),
                    extensions,
                };
                (decoded, transport(next, payload, true)?)
            }
        };
        let (transport, payload) = decode_transport(transport);
        Some(Decoded {
            destination_mac: ethernet.get_destination().octets(),
            source_mac: ethernet.get_source().octets(),
            ethertype: ethernet.get_ethertype().0,
            vlans,
            vlan_count,
            network,
            transport,
            payload,
        })
    }

    pub fn full_key(decoded: &Decoded<'_>) -> Key {
        let (source, destination): (IpAddr, IpAddr) = match &decoded.network {
            DecodedNetwork::V4 {
                source,
                destination,
                ..
            } => ((*source).into(), (*destination).into()),
            DecodedNetwork::V6 {
                source,
                destination,
                ..
            } => ((*source).into(), (*destination).into()),
        };
        let payload_len = decoded.payload.len();
        let (l4, source_port, destination_port, payload_len) = match &decoded.transport {
            DecodedTransport::Tcp {
                source,
                destination,
                ..
            } => (L4::Tcp, *source, *destination, payload_len),
            DecodedTransport::Udp {
                source,
                destination,
                ..
            } => (L4::Udp, *source, *destination, payload_len),
            DecodedTransport::Icmp { kind, code, .. } => {
                (L4::Icmp, (*kind).into(), (*code).into(), 0)
            }
            DecodedTransport::Icmpv6 { kind, code, .. } => {
                (L4::Icmpv6, (*kind).into(), (*code).into(), 0)
            }
        };
        Key {
            source,
            destination,
            l4,
            source_port,
            destination_port,
            payload_len,
        }
    }
}
