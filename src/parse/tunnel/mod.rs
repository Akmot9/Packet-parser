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
//! - **CAPWAP-Data** (RFC 5415) carrying **IEEE 802.11** → **LLC/SNAP** → L3.
//!
//! Designed to grow: IP/UDP tunnels (VXLAN, GRE, GTP-U, IP-in-IP) plug into
//! [`detect_inner`] the same way.

use super::PacketFlow;
use super::data_link::ethertype::Ethertype;
use super::data_link::mac_addres::MacAddress;
use super::link::DecodedLink;
use super::link_layer::{Ieee80211Link, LinkLayer};
use super::transport::Transport;
use super::transport::protocols::TransportProtocol;

/// Maximum tunnel nesting depth (anti-loop guard against malformed traffic that
/// could claim endless encapsulation). The outer flow is depth 0.
pub(crate) const MAX_TUNNEL_DEPTH: u8 = 4;

/// UDP port of the CAPWAP data plane (RFC 5415).
const CAPWAP_DATA_PORT: u16 = 5247;

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
        && let Ok(inner) = PacketFlow::parse_decoded(DecodedLink::new(inner_link), depth + 1)
    {
        return Some(("CAPWAP", inner));
    }

    None
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
