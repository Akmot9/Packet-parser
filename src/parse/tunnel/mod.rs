// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Tunnel / encapsulation detection and peeling.
//!
//! Some packets carry a **whole other packet** inside their payload
//! (encapsulation). The base parser is layered and single-level, so without
//! help it only sees the *outer* flow and misses the real conversation nested
//! inside the tunnel.
//!
//! This module recognizes a tunnel from the transport layer, peels its
//! headers, exposes an honest inner IEEE 802.11 link layer and lets [`PacketFlow`] re-parse the
//! encapsulated packet recursively. One wire packet then yields several flow
//! levels (outer tunnel + inner conversation(s)).
//!
//! Currently supported:
//! - **CAPWAP-Data** (RFC 5415) carrying **IEEE 802.11** → **LLC/SNAP** → L3 ;
//! - **GRE** (RFC 2784/2890, version 0) carrying IPv4, IPv6 or Ethernet
//!   (0x6558) — ERSPAN and version 1 (PPTP) are refused, not guessed ;
//! - **IP-in-IP** (protocoles IP 4 et 41) carrying a bare IPv4/IPv6 packet ;
//! - **VXLAN** (RFC 7348, UDP 4789) carrying a full Ethernet frame — the
//!   GBP/GPE flag extensions are refused, not guessed ;
//! - **Geneve** (RFC 8926, UDP 6081) carrying Ethernet (0x6558) or bare IP,
//!   variable-length options skipped — OAM control messages are refused ;
//! - **GTP-U** (3GPP TS 29.281, UDP 2152) carrying a bare IP packet, with the
//!   optional fields and the chained extension headers walked — only G-PDU
//!   messages are peeled, everything else refused. Alone among these, it
//!   announces nothing about what it carries, so it is also the only one to
//!   require that its inner packet parse cleanly before the label is set.

use super::PacketFlow;
use super::data_link::DataLink;
use super::data_link::ethertype::Ethertype;
use super::data_link::mac_addres::MacAddress;
use super::internet::Internet;
use super::link::{DecodedLink, RawIpDecoder};
use super::link_layer::{Ieee80211Link, LinkLayer};
use super::transport::Transport;
use super::transport::protocols::TransportProtocol;
use crate::LinkType;

/// Maximum tunnel nesting depth (anti-loop guard against malformed traffic that
/// could claim endless encapsulation). The outer flow is depth 0.
pub(crate) const MAX_TUNNEL_DEPTH: u8 = 4;

/// UDP port of the CAPWAP data plane (RFC 5415).
const CAPWAP_DATA_PORT: u16 = 5247;

/// UDP port assigned to VXLAN (RFC 7348).
const VXLAN_PORT: u16 = 4789;

/// UDP port of the GTP-U user plane (3GPP TS 29.281).
const GTP_U_PORT: u16 = 2152;

/// UDP port assigned to Geneve (RFC 8926).
const GENEVE_PORT: u16 = 6081;

/// Detects an encapsulation on the transport layer. On success returns
/// `(tunnel_name, inner_flow)`: the name is meant for the *outer* flow's
/// application-protocol field, and `inner_flow` is the fully re-parsed
/// encapsulated packet.
///
/// Returns `None` (graceful degradation, never an error) when there is no
/// tunnel, the payload is encrypted (e.g. CAPWAP/DTLS), truncated, or uses a
/// shape we don't decode yet.
pub(crate) fn detect_inner<'a>(
    transport: &Transport<'a>,
    depth: u8,
    decode_as: &[(u16, crate::parse::DecodeAsProtocol)],
) -> Option<(&'static str, PacketFlow<'a>)> {
    if depth + 1 >= MAX_TUNNEL_DEPTH {
        return None;
    }

    let payload = transport.payload?;

    // --- CAPWAP-Data over UDP 5247 → 802.11 → LLC/SNAP → L3 ---
    if transport.protocol == TransportProtocol::Udp
        && (transport.source_port == Some(CAPWAP_DATA_PORT)
            || transport.destination_port == Some(CAPWAP_DATA_PORT))
        && let Some(inner_link) = peel_capwap_ieee80211(payload)
        && let Ok(inner) =
            PacketFlow::parse_decoded_with(DecodedLink::new(inner_link), depth + 1, decode_as)
    {
        return Some(("CAPWAP", inner));
    }

    // --- VXLAN over UDP 4789 → trame Ethernet interne complete ---
    if transport.protocol == TransportProtocol::Udp
        && (transport.source_port == Some(VXLAN_PORT)
            || transport.destination_port == Some(VXLAN_PORT))
        && let Some(inner_link) = peel_vxlan(payload)
        && let Ok(inner) = PacketFlow::parse_decoded_with(inner_link, depth + 1, decode_as)
    {
        return Some(("VXLAN", inner));
    }

    // --- Geneve over UDP 6081 → Ethernet (0x6558) ou IP brute interne ---
    if transport.protocol == TransportProtocol::Udp
        && (transport.source_port == Some(GENEVE_PORT)
            || transport.destination_port == Some(GENEVE_PORT))
        && let Some(inner_link) = peel_geneve(payload)
        && let Ok(inner) = PacketFlow::parse_decoded_with(inner_link, depth + 1, decode_as)
    {
        return Some(("Geneve", inner));
    }

    // --- GTP-U over UDP 2152 → paquet IP interne, sans couche 2 ---
    //
    // Seul tunnel du module a exiger que son interne se decode **sans
    // corruption**, et c'est delibere : les autres declarent ce qu'ils
    // portent — EtherType pour GRE et Geneve, protocole IP externe pour
    // IP-in-IP, Ethernet par construction pour VXLAN — et gardent donc une
    // preuve independante du contenu. GTP-U ne declare rien : son paquet
    // interne est sa seule preuve. L'etiqueter alors qu'on vient d'echouer a
    // le lire reviendrait a affirmer ce qu'on n'a pas su verifier.
    if transport.protocol == TransportProtocol::Udp
        && (transport.source_port == Some(GTP_U_PORT)
            || transport.destination_port == Some(GTP_U_PORT))
        && let Some(inner_link) = peel_gtp_u(payload)
        && let Ok(inner) = PacketFlow::parse_decoded_with(inner_link, depth + 1, decode_as)
        && inner.corrupted.is_none()
    {
        return Some(("GTP-U", inner));
    }

    None
}

/// Detecte un tunnel au niveau IP (issue #15) : GRE (protocole 47) et
/// IP-in-IP (protocoles 4 et 41). Independant de la couche transport — ces
/// protocoles n'en ont pas, et le peeling ne doit pas dependre du Transport
/// creux que la branche fourre-tout de `try_from_parts` fabrique pour eux.
pub(crate) fn detect_inner_l3<'a>(
    internet: &Internet<'a>,
    depth: u8,
    decode_as: &[(u16, crate::parse::DecodeAsProtocol)],
) -> Option<(&'static str, PacketFlow<'a>)> {
    if depth + 1 >= MAX_TUNNEL_DEPTH {
        return None;
    }

    let (label, inner_link) = match internet.payload_protocol {
        Some(TransportProtocol::Gre) => ("GRE", peel_gre(internet.payload)?),
        // Le protocole IP externe ANNONCE la version interne (4 = IPv4-in-IP,
        // 41 = IPv6-in-IP) : le decodeur raw-IP la verifie contre le quartet
        // de version du paquet interne — refus si les deux ne concordent pas.
        Some(TransportProtocol::Ipv4) => (
            "IP-in-IP",
            RawIpDecoder::decode_as(LinkType::IPV4, internet.payload).ok()?,
        ),
        Some(TransportProtocol::Ipv6) => (
            "IP-in-IP",
            RawIpDecoder::decode_as(LinkType::IPV6, internet.payload).ok()?,
        ),
        _ => return None,
    };

    PacketFlow::parse_decoded_with(inner_link, depth + 1, decode_as)
        .ok()
        .map(|inner| (label, inner))
}

/// Pele un en-tete GRE version 0 (RFC 2784, extensions RFC 2890 : checksum,
/// cle, sequence) et rend la vue liaison du paquet interne. Les bits de
/// routage (RFC 1701), la version 1 (PPTP) et les protocoles non transportes
/// par la crate (ERSPAN 0x22eb/0x88be, keepalive proto 0) sont refuses avec
/// None : frontiere nommee, pas de decodage approximatif.
fn peel_gre(payload: &[u8]) -> Option<DecodedLink<'_>> {
    const FLAG_CHECKSUM: u8 = 0x80;
    const FLAG_ROUTING: u8 = 0x40;
    const FLAG_KEY: u8 = 0x20;
    const FLAG_SEQUENCE: u8 = 0x10;

    if payload.len() < 4 {
        return None;
    }
    let flags = payload[0];
    let version = payload[1] & 0x07;
    if version != 0 || flags & FLAG_ROUTING != 0 {
        return None;
    }

    let mut header = 4usize;
    // Le champ checksum (et son reserved1) est present si C est pose.
    if flags & FLAG_CHECKSUM != 0 {
        header += 4;
    }
    if flags & FLAG_KEY != 0 {
        header += 4;
    }
    if flags & FLAG_SEQUENCE != 0 {
        header += 4;
    }
    let inner = payload.get(header..)?;

    match u16::from_be_bytes([payload[2], payload[3]]) {
        // L'EtherType GRE annonce la version : verifiee par le decodeur.
        0x0800 => RawIpDecoder::decode_as(LinkType::IPV4, inner).ok(),
        0x86dd => RawIpDecoder::decode_as(LinkType::IPV6, inner).ok(),
        // Transparent Ethernet bridging (NVGRE, gretap) : trame complete.
        0x6558 => DataLink::try_from(inner)
            .ok()
            .map(|frame| DecodedLink::new(LinkLayer::ethernet_as(LinkType::ETHERNET, frame))),
        _ => None,
    }
}

/// Pele un en-tete VXLAN (RFC 7348) : 8 octets fixes — flags, 3 octets
/// reserves, VNI sur 3 octets, 1 octet reserve — puis une trame Ethernet
/// interne complete. Seul le bit I (VNI valide) doit etre pose : les
/// extensions qui posent d'autres flags (VXLAN-GBP 0x80, VXLAN-GPE) changent
/// le sens des champs reserves et sont refusees — frontiere nommee, pas de
/// decodage approximatif.
fn peel_vxlan(payload: &[u8]) -> Option<DecodedLink<'_>> {
    const FLAG_VNI_VALID: u8 = 0x08;

    if payload.len() < 8 || payload[0] != FLAG_VNI_VALID {
        return None;
    }
    DataLink::try_from(&payload[8..])
        .ok()
        .map(|frame| DecodedLink::new(LinkLayer::ethernet_as(LinkType::ETHERNET, frame)))
}

/// Pele un en-tete Geneve (RFC 8926) : 8 octets fixes — version/Opt Len,
/// flags O/C, protocol type, VNI — puis les options TLV, sautees en bloc
/// (Opt Len en mots de 4 octets : elles ne font que deplacer la charge
/// utile). La version doit valoir 0, et les messages de controle OAM
/// (bit O) sont refuses : ils ne portent pas une trame utilisateur. Le
/// protocol type annonce l'interne — Ethernet (0x6558) ou IP brute, dont la
/// version est verifiee par le decodeur raw-IP.
fn peel_geneve(payload: &[u8]) -> Option<DecodedLink<'_>> {
    const FLAG_OAM: u8 = 0x80;

    if payload.len() < 8 {
        return None;
    }
    let version = payload[0] >> 6;
    let options = usize::from(payload[0] & 0x3f) * 4;
    if version != 0 || payload[1] & FLAG_OAM != 0 {
        return None;
    }
    let inner = payload.get(8 + options..)?;

    match u16::from_be_bytes([payload[2], payload[3]]) {
        0x0800 => RawIpDecoder::decode_as(LinkType::IPV4, inner).ok(),
        0x86dd => RawIpDecoder::decode_as(LinkType::IPV6, inner).ok(),
        0x6558 => DataLink::try_from(inner)
            .ok()
            .map(|frame| DecodedLink::new(LinkLayer::ethernet_as(LinkType::ETHERNET, frame))),
        _ => None,
    }
}

/// Pele un GTP-U (3GPP TS 29.281) et rend le paquet IP encapsule.
///
/// L'en-tete fait huit octets, suivis de quatre octets optionnels — numero
/// de sequence, N-PDU, type de l'extension suivante — presents des qu'un des
/// trois flags E/S/PN est pose. Vient ensuite, si E est pose, une **chaine**
/// d'extension headers : chacun donne sa longueur en mots de quatre octets et
/// se termine par le type du suivant, zero fermant la chaine. C'est le seul
/// tunnel du module dont l'en-tete se parcourt plutot qu'il ne se saute.
///
/// Deux refus, pas deux devinettes :
/// - la version doit valoir 1 et le bit PT doit etre pose. GTP' (PT = 0) est
///   un protocole de facturation, pas un tunnel ;
/// - le message type doit valoir 255 (G-PDU). Les Echo, les notifications et
///   tout le plan de controle circulent sur le meme port sans porter le
///   moindre paquet utilisateur.
///
/// Contrairement a VXLAN (toujours Ethernet) et a Geneve (qui annonce son
/// interne par un EtherType), **rien dans l'en-tete GTP-U ne dit ce qui
/// suit** : la version se lit sur le quartet de tete du paquet encapsule,
/// et `RawIpDecoder` la verifie ensuite.
///
/// Le champ de longueur borne le message, et tout ce qui suit se lit dans
/// cette borne. Sans elle, n'importe quel datagramme sur 2152 dont les
/// octets 8 et suivants ressemblent a de l'IP passerait pour un tunnel : la
/// lecture du quartet de version est une confirmation, pas un filtre.
///
/// La fragmentation ne peut pas la mettre en defaut, contrairement a ce
/// qu'on pourrait craindre — un premier fragment annonce bien la longueur du
/// datagramme entier, mais il n'arrive jamais ici : `validate_udp_length`
/// exige l'egalite stricte entre la longueur UDP declaree et les octets
/// presents, donc un datagramme fragmente n'expose aucune couche transport.
fn peel_gtp_u(payload: &[u8]) -> Option<DecodedLink<'_>> {
    /// Numero de version de GTPv1, sur les trois bits de poids fort.
    const VERSION_1: u8 = 1;
    /// Bit PT : 1 = GTP, 0 = GTP' (facturation).
    const PROTOCOL_TYPE_GTP: u8 = 0x10;
    /// Bit E : un ou plusieurs extension headers suivent.
    const FLAG_EXTENSION: u8 = 0x04;
    /// Bits E, S et PN : l'un d'eux suffit a rendre les quatre octets
    /// optionnels presents — tous les trois, pas seulement celui qui est pose.
    const OPTIONAL_FIELDS: u8 = 0x07;
    /// Message type d'un G-PDU : le seul qui porte un paquet.
    const G_PDU: u8 = 0xff;
    const HEADER_LEN: usize = 8;
    const OPTIONAL_LEN: usize = 4;

    let flags = *payload.first()?;
    if payload.len() < HEADER_LEN
        || flags >> 5 != VERSION_1
        || flags & PROTOCOL_TYPE_GTP == 0
        || payload[1] != G_PDU
    {
        return None;
    }

    // Le champ porte la longueur de tout ce qui suit les huit premiers
    // octets, et un datagramme UDP porte un message GTP-U et un seul. La
    // longueur annoncee doit donc valoir la charge utile exactement : ni
    // moins, ce qui laisserait un reliquat non declare derriere le message,
    // ni plus, ce qui reclamerait des octets absents.
    let announced = usize::from(u16::from_be_bytes([payload[2], payload[3]]));
    if payload.len() != HEADER_LEN + announced {
        return None;
    }

    let mut offset = HEADER_LEN;
    if flags & OPTIONAL_FIELDS != 0 {
        offset += OPTIONAL_LEN;

        if flags & FLAG_EXTENSION != 0 {
            // Le type de la premiere extension occupe le dernier des quatre
            // octets optionnels ; chaque extension nomme ensuite la suivante.
            let mut next = *payload.get(HEADER_LEN + OPTIONAL_LEN - 1)?;
            while next != 0 {
                let length = usize::from(*payload.get(offset)?);
                // Une longueur nulle ne progresse pas : la chaine boucle.
                offset = offset.checked_add(length.checked_mul(4).filter(|n| *n > 0)?)?;
                next = *payload.get(offset - 1)?;
            }
        }
    }

    let inner = payload.get(offset..)?;
    match inner.first()? >> 4 {
        4 => RawIpDecoder::decode_as(LinkType::IPV4, inner).ok(),
        6 => RawIpDecoder::decode_as(LinkType::IPV6, inner).ok(),
        _ => None,
    }
}

/// Peels CAPWAP-Data → IEEE 802.11 → LLC/SNAP and returns the inner data-link
/// layer (802.11 MAC addresses + SNAP EtherType + L3 payload).
fn peel_capwap_ieee80211(payload: &[u8]) -> Option<LinkLayer<'_>> {
    // --- CAPWAP header (RFC 5415) ---
    // Byte 0: preamble = version(4 bits) | type(4 bits). Type 0 = plaintext,
    // type 1 = DTLS (encrypted) → we can't recurse into it.
    if payload.len() < 8 || payload[0] & 0x0f != 0 {
        return None;
    }
    // HLEN (5 bits, top of byte 1) = header length in 4-byte words.
    let capwap_header = ((payload[1] >> 3) & 0x1f) as usize * 4;
    if capwap_header < 8 || payload.len() < capwap_header {
        return None;
    }

    peel_ieee80211(&payload[capwap_header..])
}

/// Peels an IEEE 802.11 **data** frame and its LLC/SNAP header into an inner
/// data-link layer. Handles ToDS/FromDS addressing, the optional Address4
/// (WDS) and the optional QoS control field.
fn peel_ieee80211(frame: &[u8]) -> Option<LinkLayer<'_>> {
    if frame.len() < 24 {
        return None;
    }
    // Frame Control is 2 octets: one carries version/type/subtype, the other the
    // flags. Cisco CAPWAP captures sometimes byte-swap them (Wireshark shows
    // "(Swapped)"). The version bits (low 2 bits of the type octet) are 0 for
    // real frames, so we use that to tell which octet is which.
    let (fc_type, fc_flags) = if frame[0] & 0x03 == 0 {
        (frame[0], frame[1])
    } else if frame[1] & 0x03 == 0 {
        (frame[1], frame[0])
    } else {
        return None;
    };

    // Only data frames (type 2) carry an upper-layer payload we can recurse on.
    if (fc_type >> 2) & 0x03 != 2 {
        return None;
    }
    let subtype = (fc_type >> 4) & 0x0f;
    let to_ds = fc_flags & 0x01 != 0;
    let from_ds = fc_flags & 0x02 != 0;

    // Header length: base 24 (+6 for Address4 in WDS, +2 for QoS control).
    let mut header = 24usize;
    if to_ds && from_ds {
        header += 6;
    }
    if subtype & 0x08 != 0 {
        header += 2; // QoS data subtypes (>= 8)
    }
    if frame.len() < header {
        return None;
    }

    // Real source/destination depend on ToDS/FromDS (802.11 address mapping).
    let a1 = &frame[4..10];
    let a2 = &frame[10..16];
    let a3 = &frame[16..22];
    let (dst, src): (&[u8], &[u8]) = match (to_ds, from_ds) {
        (false, false) => (a1, a2),           // IBSS: DA=A1, SA=A2
        (false, true) => (a1, a3),            // from AP: DA=A1, SA=A3
        (true, false) => (a3, a2),            // to AP: DA=A3, SA=A2
        (true, true) => (a3, &frame[24..30]), // WDS: DA=A3, SA=A4
    };

    let (ethertype, l3) = peel_llc_snap(&frame[header..])?;

    Some(LinkLayer::ieee80211(Ieee80211Link::new(
        MacAddress(dst.try_into().ok()?),
        MacAddress(src.try_into().ok()?),
        Ethertype(ethertype),
        l3,
    )))
}

/// Peels an LLC/SNAP header (DSAP=SSAP=0xAA, control=0x03, OUI=00:00:00) and
/// returns the encapsulated EtherType and the remaining L3 payload. Only the
/// SNAP form (which carries an EtherType) is handled.
fn peel_llc_snap(llc: &[u8]) -> Option<(u16, &[u8])> {
    if llc.len() < 8 {
        return None;
    }
    if llc[0] != 0xAA || llc[1] != 0xAA || llc[2] != 0x03 {
        return None;
    }
    if llc[3] != 0x00 || llc[4] != 0x00 || llc[5] != 0x00 {
        return None;
    }
    let ethertype = u16::from_be_bytes([llc[6], llc[7]]);
    Some((ethertype, &llc[8..]))
}

#[cfg(test)]
mod tests {
    /// Octets reels : le debut de la charge UDP de la trame 1 de
    /// `pcaps_exemple/tunnels/gtp_u/gtp_ext_header.pcap`, tronquee apres le
    /// debut du TCP interne. C'est le seul en-tete d'extension GTP-U du
    /// corpus, et son datagramme est fragmente — la couche transport se
    /// retire donc avant GTP, et aucun golden de bout en bout ne peut
    /// l'atteindre. Le peleur, lui, se teste directement.
    ///
    /// `36` = version 1, PT=1, flags E et S ; `ff` = G-PDU ; puis le type de
    /// la premiere extension (`c0`, PDCP PDU number) et la chaine elle-meme,
    /// `01 09 04 00` : longueur 1 mot de quatre octets, contenu `09 04`,
    /// suivant `00` qui la ferme. L'IPv4 interne commence a l'octet 16.
    ///
    /// **Un seul champ differe de la capture** : la longueur annoncee, aux
    /// octets 2 et 3, ramenee de `0x05e4` (1508) a `0x0024` (36) pour valoir
    /// cet extrait et non le datagramme entier. La trame d'origine etant un
    /// premier fragment, sa longueur declaree parle du tout ; la garder
    /// reviendrait a tester la chaine d'extension sur un message que le
    /// peleur doit precisement refuser.
    const REAL_GTP_EXTENSION_HEADER: &[u8] = &[
        0x36, 0xff, 0x00, 0x24, 0x00, 0x10, 0x06, 0x57, 0x00, 0x05, 0x00, 0xc0, 0x01, 0x09, 0x04,
        0x00, 0x45, 0x00, 0x05, 0xdc, 0xdc, 0xfa, 0x40, 0x00, 0x3f, 0x06, 0xd2, 0xe7, 0x0a, 0x9b,
        0xb6, 0xca, 0x0a, 0x9b, 0xba, 0x39, 0xa2, 0x27, 0x17, 0x75, 0x96, 0x12, 0xe6, 0x03,
    ];

    #[test]
    fn gtp_u_walks_the_extension_header_chain_to_find_the_inner_packet() {
        let (layer, _, _) = peel_gtp_u(REAL_GTP_EXTENSION_HEADER)
            .expect("la chaine d'extension est franchie")
            .into_parts();
        // L'interne est un paquet IP nu : aucune couche 2 a exposer.
        assert!(layer.as_ethernet().is_none());
        assert_eq!(layer.link_type(), LinkType::IPV4);
    }

    /// Une longueur d'extension nulle ne fait avancer aucun offset : la
    /// chaine bouclerait indefiniment. Le peleur doit s'arreter.
    #[test]
    fn a_zero_length_extension_header_is_refused_rather_than_looped_on() {
        let mut bytes = REAL_GTP_EXTENSION_HEADER.to_vec();
        bytes[12] = 0x00;
        assert!(peel_gtp_u(&bytes).is_none());
    }

    /// Octets reels : la charge UDP complete de la trame 3 de
    /// `gtp1_gn_normal_incl_fragmentation.pcap`. Datagramme entier, non
    /// fragmente — `30` = version 1, PT=1, aucun flag ; `ff` = G-PDU ;
    /// longueur `0x0028` = 40, soit exactement les 48 octets de charge moins
    /// les 8 de l'en-tete. Interne : TCP 1923 -> 80.
    const REAL_GTP_G_PDU: &[u8] = &[
        0x30, 0xff, 0x00, 0x28, 0x8c, 0x61, 0xbe, 0x36, 0x45, 0x00, 0x00, 0x28, 0x52, 0x66, 0x40,
        0x00, 0x80, 0x06, 0xb0, 0x3b, 0x0a, 0x83, 0x2f, 0xb9, 0x4f, 0x65, 0x6e, 0x8d, 0x07, 0x83,
        0x00, 0x50, 0xcd, 0x6c, 0x69, 0xb8, 0x6f, 0xc3, 0x54, 0x94, 0x50, 0x10, 0xfd, 0xca, 0xb6,
        0x8b, 0x00, 0x00,
    ];

    /// La longueur annoncee borne le message. Sans elle, n'importe quel
    /// datagramme sur 2152 dont les octets 8 et suivants ressemblent a de
    /// l'IP serait etiquete GTP-U — la lecture du quartet de version ne
    /// suffit pas a s'en premunir.
    ///
    /// Le champ est fiable : sur les 34 G-PDU reels du corpus, il vaut
    /// exactement la charge utile moins huit octets, sans une exception. Et
    /// il ne peut pas etre mis en defaut par la fragmentation, puisque UDP
    /// exige deja l'egalite entre sa longueur declaree et les octets
    /// presents — un datagramme fragmente n'expose aucune couche transport,
    /// donc n'arrive jamais ici.
    #[test]
    fn the_announced_length_bounds_the_message() {
        assert!(
            peel_gtp_u(REAL_GTP_G_PDU).is_some(),
            "la trame reelle passe"
        );

        // Longueur nulle : le message ne couvre meme pas son propre en-tete.
        let mut empty = REAL_GTP_G_PDU.to_vec();
        empty[2] = 0x00;
        empty[3] = 0x00;
        assert!(peel_gtp_u(&empty).is_none(), "longueur nulle refusee");

        // Longueur qui deborde de la charge utile.
        let mut beyond = REAL_GTP_G_PDU.to_vec();
        beyond[3] = 0xff;
        assert!(peel_gtp_u(&beyond).is_none(), "longueur debordante refusee");

        // Et l'inverse : des octets que la longueur ne declare pas. Un
        // datagramme UDP porte un message GTP-U et un seul ; un reliquat
        // derriere lui ne peut pas etre du GTP-U bien forme, et l'accepter
        // reviendrait a etiqueter la trame sur son seul prefixe.
        let mut trailing = REAL_GTP_G_PDU.to_vec();
        trailing.extend_from_slice(&[0u8; 4]);
        assert!(
            peel_gtp_u(&trailing).is_none(),
            "octets non declares refuses"
        );
    }

    /// Le paquet interne **est** la seule preuve qu'on tient un GTP-U.
    ///
    /// Les cinq autres tunnels du module declarent ce qu'ils portent : GRE
    /// et Geneve par un EtherType, IP-in-IP par le protocole IP externe,
    /// VXLAN par construction. GTP-U ne declare rien — `RawIpDecoder` ne
    /// verifie qu'un quartet de version, et `0x40` le satisfait tout en
    /// etant un IPv4 impossible (IHL nul). Sans autre garde, un datagramme
    /// sur 2152 dont le T-PDU commence par un 4 ou un 6 serait etiquete
    /// GTP-U alors qu'on vient d'echouer a le decoder.
    ///
    /// Octets fabriques, et non une capture : c'est un test de robustesse
    /// sur une forme qu'aucune trame reelle du corpus ne presente. Il faut
    /// bien construire ce qu'on veut voir refuse.
    #[test]
    fn a_tunnel_is_not_labelled_when_its_inner_packet_does_not_parse() {
        let bytes = hex::decode(concat!(
            "00000c07ace888e0f3c8bff008004500004c000000003d111dacef729b6f3f5e",
            "95b50868086800380b4230ff00288c61be364000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000"
        ))
        .expect("fixture hex");

        let flow = crate::parse(LinkType::ETHERNET, bytes.as_slice()).expect("la trame decode");
        assert!(
            flow.inner.is_none(),
            "rien n'est pele quand l'interne ne se decode pas"
        );
        assert_ne!(
            flow.application
                .as_ref()
                .map(|application| application.application_protocol),
            Some("GTP-U"),
            "l'etiquette ne peut pas etre plus sure que le paquet qui la porte"
        );
    }

    /// Seul un G-PDU porte un paquet utilisateur. Le plan de controle et les
    /// Echo circulent sur le meme port, et rien n'empeche leur charge utile
    /// de commencer par un quartet 4 ou 6 : la verification du message type
    /// ne peut pas etre deleguee a la lecture de la version interne.
    ///
    /// La trame reelle, avec son seul message type change — le corpus n'a pas
    /// de non-G-PDU dont la charge ressemble a de l'IP.
    #[test]
    fn a_non_g_pdu_is_refused_even_when_its_payload_looks_like_ip() {
        let mut echo_request = REAL_GTP_EXTENSION_HEADER.to_vec();
        echo_request[1] = 0x01;
        assert!(peel_gtp_u(&echo_request).is_none());
    }

    /// GTPv0 (version 0) et GTP' (bit PT a zero) circulent sur le meme port
    /// sans avoir la meme en-tete. Le corpus porte 12 trames en 0x1e, soit
    /// une version 0 : les refuser, pas les peler de travers.
    #[test]
    fn only_version_1_with_the_protocol_type_bit_is_peeled() {
        let mut v0 = REAL_GTP_EXTENSION_HEADER.to_vec();
        v0[0] = 0x1e;
        assert!(peel_gtp_u(&v0).is_none(), "GTPv0 refuse");

        let mut gtp_prime = REAL_GTP_EXTENSION_HEADER.to_vec();
        gtp_prime[0] = 0x26; // version 1, PT = 0
        assert!(peel_gtp_u(&gtp_prime).is_none(), "GTP' refuse");
    }

    use super::*;
    use crate::{LinkType, parse};

    /// Trame 1 de `pcaps_exemple/capwap-only.pcap` : Ethernet -> IPv4 ->
    /// UDP 35981 -> 5247 -> CAPWAP-Data (version 0, type 0 = plaintext,
    /// HLEN = 8) encapsulant une trame IEEE 802.11 **de management**
    /// (Association Request, SSID "Prova"), et non une trame de donnees.
    const CAPWAP_MANAGEMENT_FRAME_HEX: &str = concat!(
        "0000000000000000000000000800450000570000400040113c947f0000017f00",
        "00018c8d147f00430000001043000000000000003a0102000000000002000000",
        "0100020000000000c01921040500000550726f7661010802040b160c12182432",
        "043048606c"
    );

    fn capwap_management_frame() -> Vec<u8> {
        let bytes = hex::decode(CAPWAP_MANAGEMENT_FRAME_HEX).expect("invalid test hex fixture");
        assert_eq!(bytes.len(), 101, "fixture length must match capture");
        bytes
    }

    /// L'en-tete CAPWAP de la capture est valide (version 0, type 0, HLEN 8) :
    /// le peeling franchit CAPWAP, puis s'arrete plus haut faute de charge
    /// utile exploitable.
    ///
    /// NB : cette trame porte une Association Request, dont le corps n'est ni
    /// du 802.11 data ni du LLC/SNAP. Elle est donc refusee **deux fois** —
    /// par le controle de type 802.11 et par celui du SNAP — et ne peut pas
    /// isoler l'un des deux. Elle fige le verdict, pas son motif.
    #[test]
    fn capwap_header_is_accepted_but_management_payload_is_not_peeled() {
        let frame = capwap_management_frame();
        // UDP payload = CAPWAP : 14 (Ethernet) + 20 (IPv4) + 8 (UDP).
        let capwap = &frame[42..];
        assert_eq!(capwap[0] & 0x0f, 0, "type 0 = plaintext, pas de DTLS");
        assert_eq!(((capwap[1] >> 3) & 0x1f) as usize * 4, 8, "HLEN = 8 octets");

        let ieee80211 = &capwap[8..];
        assert_eq!(
            (ieee80211[0] >> 2) & 0x03,
            0,
            "type 0 = management (seul le type 2, data, est pele)"
        );

        assert!(
            peel_capwap_ieee80211(capwap).is_none(),
            "une trame 802.11 de management ne doit pas produire de couche interne"
        );
    }

    /// Bout-en-bout : la trame se parse, et n'expose aucun flux interne.
    #[test]
    fn capwap_management_frame_yields_no_inner_flow() {
        let frame = capwap_management_frame();
        let flow = parse(LinkType::ETHERNET, frame.as_slice()).expect("captured frame decodes");

        let transport = flow.transport.as_ref().expect("UDP est decode");
        assert_eq!(transport.protocol, TransportProtocol::Udp);
        assert_eq!(transport.destination_port, Some(CAPWAP_DATA_PORT));

        assert!(flow.inner.is_none(), "aucun paquet interne n'est extrait");
        assert_eq!(flow.flatten().len(), 1, "un seul niveau de flux");
    }

    /// Un en-tete CAPWAP annoncant DTLS (type 1) est refuse : le contenu est
    /// chiffre, il n'y a rien a peler. On mute le seul nibble de type sur la
    /// trame reelle, tout le reste est inchange.
    ///
    /// Meme reserve que ci-dessus : la trame etant deja refusee au LLC/SNAP,
    /// ce test ne prouve pas que la garde DTLS est ce qui rejette. Neutraliser
    /// `payload[0] & 0x0f != 0` le laisse passer. Couvrir reellement cette
    /// garde demande une capture CAPWAP-Data portant du 802.11 **data** —
    /// absente du corpus (issue #23).
    #[test]
    fn peel_capwap_refuses_dtls_encrypted_payload() {
        let mut frame = capwap_management_frame();
        frame[42] |= 0x01; // preambule : version | type, type 1 = DTLS

        assert!(peel_capwap_ieee80211(&frame[42..]).is_none());
    }

    // -----------------------------------------------------------------------
    // Trames fabriquees : le corpus ne contient aucune trame CAPWAP-Data
    // portant du 802.11 *data* (c'est le trou documente par l'issue #23), et
    // la borne de recursion ne peut de toute facon s'exercer que sur des
    // encapsulations imbriquees artificiellement. La regle « trames reelles
    // obligatoires » vaut pour les golden tests, pas pour ces tests de garde.
    // -----------------------------------------------------------------------

    /// En-tete 802.11 data (24 octets, ToDS=FromDS=0, sans QoS) + LLC/SNAP.
    fn ieee80211_data_with_snap(ethertype: u16, l3: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0x08, 0x00]); // FC : version 0, type 2 (data)
        frame.extend_from_slice(&[0, 0]); // duration
        frame.extend_from_slice(&[0x02; 6]); // A1 = DA
        frame.extend_from_slice(&[0x04; 6]); // A2 = SA
        frame.extend_from_slice(&[0x06; 6]); // A3 = BSSID
        frame.extend_from_slice(&[0, 0]); // sequence control
        frame.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00]);
        frame.extend_from_slice(&ethertype.to_be_bytes());
        frame.extend_from_slice(l3);
        frame
    }

    /// En-tete CAPWAP-Data minimal (version 0, type 0, HLEN = 2 mots).
    fn capwap_data_header() -> [u8; 8] {
        let mut header = [0u8; 8];
        header[1] = 2 << 3;
        header
    }

    /// Emballe un paquet IPv4 dans un niveau CAPWAP complet :
    /// IPv4 / UDP 5247 / CAPWAP / 802.11 data / LLC-SNAP(IPv4) / `inner`.
    fn capwap_level(inner_ipv4: &[u8]) -> Vec<u8> {
        let mut udp_payload = capwap_data_header().to_vec();
        udp_payload.extend_from_slice(&ieee80211_data_with_snap(0x0800, inner_ipv4));

        let udp_len = 8 + udp_payload.len();
        let mut packet = Vec::new();
        packet.extend_from_slice(&[0x45, 0x00]);
        packet.extend_from_slice(&((20 + udp_len) as u16).to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0x40, 0x00, 64, 17, 0, 0]);
        packet.extend_from_slice(&[10, 0, 0, 1]);
        packet.extend_from_slice(&[10, 0, 0, 2]);
        packet.extend_from_slice(&CAPWAP_DATA_PORT.to_be_bytes());
        packet.extend_from_slice(&CAPWAP_DATA_PORT.to_be_bytes());
        packet.extend_from_slice(&(udp_len as u16).to_be_bytes());
        packet.extend_from_slice(&[0, 0]);
        packet.extend_from_slice(&udp_payload);
        packet
    }

    /// Paquet IPv4/UDP quelconque servant de charge utile la plus profonde.
    fn innermost_ipv4() -> Vec<u8> {
        let payload = b"x";
        let udp_len = 8 + payload.len();
        let mut packet = Vec::new();
        packet.extend_from_slice(&[0x45, 0x00]);
        packet.extend_from_slice(&((20 + udp_len) as u16).to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0x40, 0x00, 64, 17, 0, 0]);
        packet.extend_from_slice(&[192, 168, 1, 1]);
        packet.extend_from_slice(&[192, 168, 1, 2]);
        packet.extend_from_slice(&40000_u16.to_be_bytes());
        packet.extend_from_slice(&40001_u16.to_be_bytes());
        packet.extend_from_slice(&(udp_len as u16).to_be_bytes());
        packet.extend_from_slice(&[0, 0]);
        packet.extend_from_slice(payload);
        packet
    }

    /// La seule protection anti-DoS recursif de la crate : six niveaux CAPWAP
    /// imbriques ne produisent que MAX_TUNNEL_DEPTH flux, et le plus profond
    /// s'arrete proprement (inner = None) au lieu de recurser.
    #[test]
    fn nested_capwap_recursion_stops_at_max_tunnel_depth() {
        let mut ipv4 = innermost_ipv4();
        for _ in 0..6 {
            ipv4 = capwap_level(&ipv4);
        }
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0x02; 6]);
        frame.extend_from_slice(&[0x04; 6]);
        frame.extend_from_slice(&0x0800_u16.to_be_bytes());
        frame.extend_from_slice(&ipv4);

        let flow = parse(LinkType::ETHERNET, frame.as_slice()).expect("fabricated frame decodes");
        let flows = flow.flatten();

        assert_eq!(
            flows.len(),
            usize::from(MAX_TUNNEL_DEPTH),
            "la recursion doit s'arreter a MAX_TUNNEL_DEPTH niveaux"
        );
        for outer in &flows[..flows.len() - 1] {
            assert_eq!(
                outer
                    .application
                    .as_ref()
                    .map(|application| application.application_protocol),
                Some("CAPWAP"),
                "chaque niveau pele est etiquete comme tunnel"
            );
            assert!(outer.inner.is_some());
        }
        assert!(
            flows.last().unwrap().inner.is_none(),
            "le flux le plus profond ne recurse pas au-dela de la borne"
        );
    }

    /// Une trame 802.11 *data* est reellement pelee : ce cas positif isole
    /// enfin les gardes que les tests sur trame de management ne peuvent pas
    /// separer (cf. reserves ci-dessus).
    #[test]
    fn capwap_data_frame_is_peeled_to_its_snap_ethertype() {
        let mut capwap = capwap_data_header().to_vec();
        capwap.extend_from_slice(&ieee80211_data_with_snap(0x0800, &innermost_ipv4()));

        let link = peel_capwap_ieee80211(&capwap).expect("802.11 data + SNAP se pele");
        let ieee80211 = link.as_ieee80211().expect("vue 802.11");
        assert_eq!(ieee80211.destination_mac.0, [0x02; 6]);
        assert_eq!(ieee80211.source_mac.0, [0x04; 6]);
        assert_eq!(ieee80211.snap_protocol.0, 0x0800);

        // La meme trame, en DTLS (type 1) : c'est bien la garde DTLS qui
        // refuse, tout le reste etant identique et pelable.
        let mut dtls = capwap.clone();
        dtls[0] |= 0x01;
        assert!(peel_capwap_ieee80211(&dtls).is_none());
    }

    /// HLEN hors bornes : 0 (en-tete plus court que le minimum de 8 octets)
    /// et 31 mots (124 octets, au-dela de la charge utile) sont refuses.
    #[test]
    fn capwap_hlen_out_of_bounds_is_refused() {
        let mut capwap = capwap_data_header().to_vec();
        capwap.extend_from_slice(&ieee80211_data_with_snap(0x0800, &innermost_ipv4()));

        let mut hlen_zero = capwap.clone();
        hlen_zero[1] = 0;
        assert!(peel_capwap_ieee80211(&hlen_zero).is_none());

        let mut hlen_beyond = capwap.clone();
        hlen_beyond[1] = 0x1f << 3;
        assert!(
            hlen_beyond.len() < 31 * 4 + 24 + 8,
            "le HLEN choisi depasse bien la trame"
        );
        assert!(peel_capwap_ieee80211(&hlen_beyond).is_none());
    }

    /// Options GRE (RFC 2890) absentes du corpus : l'en-tete s'allonge de
    /// 4 octets par option posee (checksum, cle, sequence). Fabrique, comme
    /// les gardes de profondeur.
    #[test]
    fn gre_optional_fields_shift_the_inner_packet() {
        let inner = innermost_ipv4();

        // Sans option : en-tete de 4 octets.
        let mut plain = vec![0x00, 0x00, 0x08, 0x00];
        plain.extend_from_slice(&inner);
        let (layer, _, payload) = peel_gre(&plain).expect("GRE nu").into_parts();
        assert_eq!(payload, inner.as_slice());
        assert!(layer.as_raw_ip().is_some());

        // C + K + S : 4 + 12 octets.
        let mut optioned = vec![0xb0, 0x00, 0x08, 0x00];
        optioned.extend_from_slice(&[0u8; 12]);
        optioned.extend_from_slice(&inner);
        let (_, _, payload) = peel_gre(&optioned).expect("GRE avec options").into_parts();
        assert_eq!(payload, inner.as_slice());

        // Version 1 (PPTP), bits de routage, proto inconnu : refus.
        assert!(peel_gre(&[0x00, 0x01, 0x08, 0x00, 0x45]).is_none());
        assert!(peel_gre(&[0x40, 0x00, 0x08, 0x00, 0x45]).is_none());
        assert!(peel_gre(&[0x00, 0x00, 0x22, 0xeb, 0x45]).is_none());
        // Options annoncees mais tronquees : refus sans panique.
        assert!(peel_gre(&[0xb0, 0x00, 0x08, 0x00, 0x00, 0x00]).is_none());
    }

    /// Trame Ethernet minimale portant `payload` sous `ethertype`.
    fn ethernet_frame(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0x02; 6]);
        frame.extend_from_slice(&[0x04; 6]);
        frame.extend_from_slice(&ethertype.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    /// Le pelage VXLAN n'accepte que la forme RFC 7348 stricte : bit I seul.
    /// Les extensions GBP/GPE (autres flags poses), l'absence de VNI valide
    /// et l'en-tete tronque sont refuses. Formes absentes du corpus :
    /// fabriquees, comme les gardes de profondeur.
    #[test]
    fn vxlan_flags_other_than_vni_valid_are_refused() {
        let inner = ethernet_frame(0x0800, &innermost_ipv4());
        let mut vxlan = vec![0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x00];
        vxlan.extend_from_slice(&inner);

        let (layer, _, _) = peel_vxlan(&vxlan).expect("VXLAN RFC 7348").into_parts();
        assert!(layer.as_ethernet().is_some());

        let mut gbp = vxlan.clone();
        gbp[0] = 0x88; // bit G (VXLAN-GBP) en plus du bit I
        assert!(peel_vxlan(&gbp).is_none());

        let mut no_vni = vxlan.clone();
        no_vni[0] = 0x00;
        assert!(peel_vxlan(&no_vni).is_none());

        assert!(peel_vxlan(&vxlan[..7]).is_none(), "en-tete tronque");
    }

    /// Les options Geneve ne font que deplacer la charge utile (Opt Len en
    /// mots de 4) et le protocol type choisit la forme interne. Version
    /// inconnue, message de controle OAM, options au-dela de la charge et
    /// protocol type inconnu sont refuses. Formes absentes du corpus (la
    /// capture kernel n'emet ni option ni OAM) : fabriquees.
    #[test]
    fn geneve_options_shift_the_inner_frame_and_control_forms_are_refused() {
        let inner = ethernet_frame(0x0800, &innermost_ipv4());

        // Sans option : en-tete de 8 octets, interne Ethernet (0x6558).
        let mut plain = vec![0x00, 0x00, 0x65, 0x58, 0x00, 0x00, 0x2a, 0x00];
        plain.extend_from_slice(&inner);
        let (layer, _, _) = peel_geneve(&plain).expect("Geneve nu").into_parts();
        assert!(layer.as_ethernet().is_some());

        // Opt Len = 2 mots : 8 octets d'options sautes sans etre interpretes.
        let mut optioned = vec![0x02, 0x00, 0x65, 0x58, 0x00, 0x00, 0x2a, 0x00];
        optioned.extend_from_slice(&[0u8; 8]);
        optioned.extend_from_slice(&inner);
        let (layer, _, _) = peel_geneve(&optioned)
            .expect("Geneve avec options")
            .into_parts();
        assert!(layer.as_ethernet().is_some());

        // Protocol type 0x0800 : l'interne est de l'IP brute, sans L2.
        let mut raw_ip = vec![0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x2a, 0x00];
        raw_ip.extend_from_slice(&innermost_ipv4());
        let (layer, _, _) = peel_geneve(&raw_ip).expect("Geneve IP brute").into_parts();
        assert!(layer.as_raw_ip().is_some());

        // Version non nulle, OAM, options au-dela, protocol type inconnu.
        let mut bad_version = plain.clone();
        bad_version[0] |= 0x40;
        assert!(peel_geneve(&bad_version).is_none());

        let mut oam = plain.clone();
        oam[1] |= 0x80;
        assert!(peel_geneve(&oam).is_none());

        let mut beyond = plain.clone();
        beyond[0] = 0x3f; // 252 octets d'options annonces, charge plus courte
        assert!(peel_geneve(&beyond).is_none());

        let mut unknown = plain.clone();
        unknown[2] = 0x22;
        unknown[3] = 0xeb;
        assert!(peel_geneve(&unknown).is_none());
    }

    /// L'en-tete LLC/SNAP n'est accepte que sous sa forme SNAP stricte
    /// (DSAP = SSAP = 0xAA, control = 0x03, OUI = 00:00:00).
    #[test]
    fn peel_llc_snap_requires_the_snap_form() {
        // Forme SNAP valide portant IPv4.
        let snap = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00];
        assert_eq!(peel_llc_snap(&snap), Some((0x0800, &snap[8..])));

        // DSAP/SSAP non-SNAP.
        assert_eq!(
            peel_llc_snap(&[0x42, 0x42, 0x03, 0, 0, 0, 0x08, 0x00]),
            None
        );
        // OUI non nul (encapsulation non-EtherType).
        assert_eq!(
            peel_llc_snap(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x08, 0x00]),
            None
        );
        // Trop court pour porter un EtherType.
        assert_eq!(
            peel_llc_snap(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08]),
            None
        );
    }
}
