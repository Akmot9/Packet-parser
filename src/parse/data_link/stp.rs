// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Parseur des BPDU Spanning Tree (STP / RSTP / MSTP, IEEE 802.1D / 802.1Q).
//!
//! STP n'est pas un protocole applicatif : les BPDU circulent en trames
//! IEEE 802.3 (le champ apres les MAC est une longueur <= 0x05DC, pas un
//! EtherType), suivies d'un en-tete LLC DSAP 0x42 / SSAP 0x42 / controle UI
//! 0x03, vers l'adresse de groupe bridge 01:80:c2:00:00:00.
//!
//! Le pipeline actuel (`DataLink::try_from`) lit ce champ longueur comme un
//! EtherType inconnu et ne route pas les trames LLC. Ce module est donc
//! autonome : [`stp_llc_payload`] detecte une trame BPDU complete et retourne
//! la slice BPDU (apres 14 octets Ethernet + 3 octets LLC), et
//! [`BpduPacket::try_from`] decode cette slice. Le cablage dans le pipeline
//! est decide separement.

use std::convert::TryFrom;

use crate::{
    checks::data_link::stp::{
        BPDU_HEADER_LEN, BRIDGE_GROUP_ADDRESS, LLC_STP_HEADER, MAX_IEEE_802_3_LENGTH,
        extract_bpdu_type, extract_bridge_id, extract_protocol_identifier, extract_stp_version,
        extract_version_1_length, extract_version_3_extension, validate_bpdu_header_length,
        validate_configuration_length, validate_rst_length, validate_version_type_coherence,
    },
    errors::data_link::stp::StpError,
    parse::data_link::mac_addres::MacAddress,
};

const ETHERNET_HEADER_LEN: usize = 14;
const LLC_HEADER_LEN: usize = 3;

/// Version de protocole annoncee par le BPDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StpVersion {
    /// Spanning Tree classique (802.1D), version 0.
    Stp,
    /// Rapid Spanning Tree (802.1w), version 2.
    Rstp,
    /// Multiple Spanning Tree (802.1s / 802.1Q), version 3.
    Mstp,
}

impl StpVersion {
    /// Valeur de la version sur le fil.
    pub const fn wire_value(self) -> u8 {
        match self {
            Self::Stp => 0,
            Self::Rstp => 2,
            Self::Mstp => 3,
        }
    }
}

/// Type de BPDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpduType {
    /// Configuration BPDU (0x00), STP classique.
    Configuration,
    /// Topology Change Notification (0x80), sans corps.
    TopologyChangeNotification,
    /// Rapid/Multiple Spanning Tree BPDU (0x02).
    RapidSpanningTree,
}

impl BpduType {
    /// Valeur du type sur le fil.
    pub const fn wire_value(self) -> u8 {
        match self {
            Self::Configuration => 0x00,
            Self::TopologyChangeNotification => 0x80,
            Self::RapidSpanningTree => 0x02,
        }
    }
}

/// Identifiant de bridge : 4 bits de priorite, 12 bits d'extension
/// d'identifiant systeme (VLAN pour PVST), 6 octets de MAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BridgeId {
    /// Les 16 bits bruts priorite + extension, tels que sur le fil.
    pub raw_priority: u16,
    /// MAC du bridge.
    pub mac: MacAddress,
}

impl BridgeId {
    /// Priorite du bridge, multiple de 4096 (4 bits de poids fort).
    pub const fn priority(&self) -> u16 {
        self.raw_priority & 0xF000
    }

    /// Extension d'identifiant systeme (12 bits de poids faible).
    pub const fn system_id_extension(&self) -> u16 {
        self.raw_priority & 0x0FFF
    }
}

/// Corps partage par les Configuration BPDU (STP) et les RST/MST BPDU.
///
/// Les ages et delais sont des `u16` en 1/256 de seconde (802.1D-2004
/// §9.2.8) : 20 s s'ecrit 0x1400.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigurationBpdu<'a> {
    /// Flags : topology change, proposal/agreement et role de port (RST).
    pub flags: u8,
    /// Bridge racine annonce.
    pub root_identifier: BridgeId,
    /// Cout du chemin vers la racine.
    pub root_path_cost: u32,
    /// Bridge emetteur.
    pub bridge_identifier: BridgeId,
    /// Identifiant du port emetteur.
    pub port_identifier: u16,
    /// Age du message, en 1/256 s.
    pub message_age: u16,
    /// Age maximal, en 1/256 s.
    pub max_age: u16,
    /// Periode hello, en 1/256 s.
    pub hello_time: u16,
    /// Delai de passage en forwarding, en 1/256 s.
    pub forward_delay: u16,
    /// RST/MST seulement : longueur version 1, toujours 0.
    pub version_1_length: Option<u8>,
    /// MST seulement : partie etendue (MST configuration id, CIST, MSTI
    /// records), gardee brute et bornee par la longueur version 3 annoncee.
    pub mst_extension: Option<&'a [u8]>,
}

/// Corps du BPDU selon son type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpduBody<'a> {
    /// TCN : aucun corps apres l'en-tete de 4 octets.
    TopologyChangeNotification,
    /// Configuration STP ou RST/MST.
    Configuration(ConfigurationBpdu<'a>),
}

#[cfg_attr(all(doc, feature = "doc-diagrams"), aquamarine::aquamarine)]
/// BPDU Spanning Tree (IEEE 802.1D-2004 §9.3, 802.1Q pour MSTP).
///
/// La slice attendue commence apres l'en-tete LLC (offset 14 Ethernet +
/// 3 LLC dans la trame). Les octets de bourrage Ethernet au-dela du BPDU
/// sont toleres : le champ longueur 802.3 n'est plus visible a ce niveau.
///
/// ```mermaid
/// ---
/// title: BpduPacket
/// ---
/// packet-beta
/// 0-15: "Protocol Identifier u16 (0x0000)"
/// 16-23: "Version u8 (0/2/3)"
/// 24-31: "BPDU Type u8 (0x00/0x80/0x02)"
/// 32-39: "Flags u8"
/// 40-103: "Root Identifier (u16 priorite + MAC)"
/// 104-135: "Root Path Cost u32"
/// 136-199: "Bridge Identifier (u16 priorite + MAC)"
/// 200-215: "Port Identifier u16"
/// 216-231: "Message Age u16 (1/256 s)"
/// 232-247: "Max Age u16 (1/256 s)"
/// 248-263: "Hello Time u16 (1/256 s)"
/// 264-279: "Forward Delay u16 (1/256 s)"
/// 280-287: "Version 1 Length u8 (RST/MST)"
/// 288-303: "Version 3 Length u16 (MST)"
/// 304-319: "MST extension variable (MST)"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpduPacket<'a> {
    /// Toujours 0x0000.
    pub protocol_identifier: u16,
    /// Version annoncee : 0 STP, 2 RSTP, 3 MSTP.
    pub version: StpVersion,
    /// Type de BPDU : 0x00 config, 0x80 TCN, 0x02 RST/MST.
    pub bpdu_type: BpduType,
    /// Corps decode selon le type.
    pub body: BpduBody<'a>,
}

impl<'a> TryFrom<&'a [u8]> for BpduPacket<'a> {
    type Error = StpError;

    fn try_from(payload: &'a [u8]) -> Result<Self, Self::Error> {
        validate_bpdu_header_length(payload)?;

        let protocol_identifier = extract_protocol_identifier(payload)?;
        let version = extract_stp_version(payload[2])?;
        let bpdu_type = extract_bpdu_type(payload[3])?;
        validate_version_type_coherence(version, bpdu_type)?;

        let body = match bpdu_type {
            BpduType::TopologyChangeNotification => BpduBody::TopologyChangeNotification,
            BpduType::Configuration => {
                validate_configuration_length(payload)?;
                BpduBody::Configuration(parse_configuration_body(payload, version, bpdu_type)?)
            }
            BpduType::RapidSpanningTree => {
                validate_rst_length(payload)?;
                BpduBody::Configuration(parse_configuration_body(payload, version, bpdu_type)?)
            }
        };

        Ok(BpduPacket {
            protocol_identifier,
            version,
            bpdu_type,
            body,
        })
    }
}

/// Decode le corps commun config/RST. Les longueurs minimales ont deja ete
/// validees par type ; les champs sans contrainte sont lus directement.
fn parse_configuration_body<'a>(
    payload: &'a [u8],
    version: StpVersion,
    bpdu_type: BpduType,
) -> Result<ConfigurationBpdu<'a>, StpError> {
    let flags = payload[4];
    let root_identifier = extract_bridge_id(&payload[5..13])?;
    let root_path_cost = u32::from_be_bytes([payload[13], payload[14], payload[15], payload[16]]);
    let bridge_identifier = extract_bridge_id(&payload[17..25])?;
    let port_identifier = u16::from_be_bytes([payload[25], payload[26]]);
    let message_age = u16::from_be_bytes([payload[27], payload[28]]);
    let max_age = u16::from_be_bytes([payload[29], payload[30]]);
    let hello_time = u16::from_be_bytes([payload[31], payload[32]]);
    let forward_delay = u16::from_be_bytes([payload[33], payload[34]]);

    // L'octet version 1 length n'existe que dans les RST/MST BPDU ;
    // validate_rst_length garantit payload[35].
    let version_1_length = match bpdu_type {
        BpduType::RapidSpanningTree => Some(extract_version_1_length(payload[35])?),
        BpduType::Configuration | BpduType::TopologyChangeNotification => None,
    };

    // La partie MST n'existe qu'en version 3 (coherence deja validee :
    // version 3 implique le type RST).
    let mst_extension = match version {
        StpVersion::Mstp => Some(extract_version_3_extension(payload)?),
        StpVersion::Stp | StpVersion::Rstp => None,
    };

    Ok(ConfigurationBpdu {
        flags,
        root_identifier,
        root_path_cost,
        bridge_identifier,
        port_identifier,
        message_age,
        max_age,
        hello_time,
        forward_delay,
        version_1_length,
        mst_extension,
    })
}

/// Detecte une trame Ethernet 802.3 + LLC portant un BPDU Spanning Tree et
/// retourne la slice BPDU, delimitee par le champ longueur 802.3.
///
/// Criteres : destination 01:80:c2:00:00:00, champ longueur <= 0x05DC,
/// en-tete LLC 0x42/0x42/0x03. Le bourrage Ethernet au-dela de la longueur
/// annoncee est exclu de la slice. Retourne `None` si la trame est d'un
/// autre type (EtherType, PVST+ en SNAP...) ou tronquee par la capture.
pub fn stp_llc_payload(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < ETHERNET_HEADER_LEN + LLC_HEADER_LEN + BPDU_HEADER_LEN {
        return None;
    }
    if frame[0..6] != BRIDGE_GROUP_ADDRESS {
        return None;
    }

    let length = u16::from_be_bytes([frame[12], frame[13]]);
    if length > MAX_IEEE_802_3_LENGTH {
        // Un EtherType, pas une longueur 802.3 : pas une trame LLC.
        return None;
    }
    let length = length as usize;
    if length < LLC_HEADER_LEN + BPDU_HEADER_LEN {
        return None;
    }

    if frame[ETHERNET_HEADER_LEN..ETHERNET_HEADER_LEN + LLC_HEADER_LEN] != LLC_STP_HEADER {
        return None;
    }

    let end = ETHERNET_HEADER_LEN + length;
    if end > frame.len() {
        // Longueur annoncee au-dela de la capture : trame tronquee.
        return None;
    }
    Some(&frame[ETHERNET_HEADER_LEN + LLC_HEADER_LEN..end])
}

/// Indique si la trame est une trame 802.3 + LLC 42-42-03 vers l'adresse de
/// groupe bridge, c'est-a-dire un BPDU Spanning Tree detectable.
pub fn is_stp_frame(frame: &[u8]) -> bool {
    stp_llc_payload(frame).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trame 2173 : RST BPDU LLC 42-42-03 vers 01:80:c2:00:00:00, emis par
    /// 00:0a:8a:a1:5a:9a (pcaps_exemple/The-Ultimate-PCAP.pcapng). Slice
    /// BPDU seule, apres 14 octets Ethernet + 3 octets LLC.
    const RST_BPDU_FRAME_2173: [u8; 36] = [
        0x00, 0x00, // protocol identifier
        0x02, // version 2 : RSTP
        0x02, // type RST
        0x3c, // flags : forwarding, learning, port designated
        0x80, 0x01, 0x00, 0x0a, 0x8a, 0xa1, 0x5a, 0x80, // root id 32768/1
        0x00, 0x00, 0x00, 0x00, // root path cost
        0x80, 0x01, 0x00, 0x0a, 0x8a, 0xa1, 0x5a, 0x80, // bridge id 32768/1
        0x80, 0x42, // port id
        0x00, 0x00, // message age 0
        0x14, 0x00, // max age 20 s
        0x02, 0x00, // hello time 2 s
        0x0f, 0x00, // forward delay 15 s
        0x00, // version 1 length
    ];

    /// Trame 15 : Configuration BPDU STP classique emise par
    /// fc:fb:fb:f8:cc:01 (pcaps_exemple/vlan0--packet-capture CAPWAP a
    /// partir de ligne 520  (Ap = 192_168.0.104 ) + radius _ partir de la
    /// ligne 33003 .cap). Slice BPDU de 35 octets, sans le bourrage.
    const CONFIG_BPDU_FRAME_15: [u8; 35] = [
        0x00, 0x00, // protocol identifier
        0x00, // version 0 : STP
        0x00, // type configuration
        0x00, // flags
        0x80, 0x0a, 0xfc, 0xfb, 0xfb, 0xf8, 0xcc, 0x00, // root id 32768/10
        0x00, 0x00, 0x00, 0x00, // root path cost
        0x80, 0x0a, 0xfc, 0xfb, 0xfb, 0xf8, 0xcc, 0x00, // bridge id 32768/10
        0x80, 0x01, // port id
        0x00, 0x00, // message age 0
        0x14, 0x00, // max age 20 s
        0x02, 0x00, // hello time 2 s
        0x0f, 0x00, // forward delay 15 s
    ];

    #[test]
    fn parses_captured_rst_bpdu() {
        let bpdu = BpduPacket::try_from(RST_BPDU_FRAME_2173.as_ref()).expect("captured RST BPDU");

        assert_eq!(bpdu.protocol_identifier, 0x0000);
        assert_eq!(bpdu.version, StpVersion::Rstp);
        assert_eq!(bpdu.bpdu_type, BpduType::RapidSpanningTree);

        let BpduBody::Configuration(body) = bpdu.body else {
            panic!("RST BPDU exposes a configuration body");
        };
        assert_eq!(body.flags, 0x3c);
        assert_eq!(body.root_identifier.priority(), 32768);
        assert_eq!(body.root_identifier.system_id_extension(), 1);
        assert_eq!(
            body.root_identifier.mac,
            MacAddress([0x00, 0x0a, 0x8a, 0xa1, 0x5a, 0x80])
        );
        assert_eq!(body.root_path_cost, 0);
        assert_eq!(body.bridge_identifier, body.root_identifier);
        assert_eq!(body.port_identifier, 0x8042);
        assert_eq!(body.message_age, 0);
        assert_eq!(body.max_age, 20 * 256);
        assert_eq!(body.hello_time, 2 * 256);
        assert_eq!(body.forward_delay, 15 * 256);
        assert_eq!(body.version_1_length, Some(0));
        assert_eq!(body.mst_extension, None);
    }

    #[test]
    fn parses_captured_configuration_bpdu() {
        let bpdu =
            BpduPacket::try_from(CONFIG_BPDU_FRAME_15.as_ref()).expect("captured config BPDU");

        assert_eq!(bpdu.version, StpVersion::Stp);
        assert_eq!(bpdu.bpdu_type, BpduType::Configuration);

        let BpduBody::Configuration(body) = bpdu.body else {
            panic!("configuration BPDU exposes a configuration body");
        };
        assert_eq!(body.root_identifier.priority(), 32768);
        assert_eq!(body.root_identifier.system_id_extension(), 10);
        assert_eq!(body.port_identifier, 0x8001);
        assert_eq!(body.version_1_length, None);
        assert_eq!(body.mst_extension, None);
    }

    /// Synthetique : TCN minimal (4 octets), absent du corpus de captures.
    #[test]
    fn parses_synthetic_tcn_bpdu() {
        let payload = [0x00, 0x00, 0x00, 0x80];
        let bpdu = BpduPacket::try_from(payload.as_ref()).expect("TCN BPDU");

        assert_eq!(bpdu.version, StpVersion::Stp);
        assert_eq!(bpdu.bpdu_type, BpduType::TopologyChangeNotification);
        assert_eq!(bpdu.body, BpduBody::TopologyChangeNotification);
    }

    /// Synthetique : MST BPDU minimal, corps RST reel (trame 2173) prolonge
    /// d'une version 3 length et d'une extension MST brute de 4 octets.
    #[test]
    fn parses_synthetic_mst_bpdu_with_bounded_extension() {
        let mut payload = Vec::from(RST_BPDU_FRAME_2173);
        payload[2] = 0x03; // version 3 : MSTP
        payload.extend_from_slice(&[0x00, 0x04]); // version 3 length
        payload.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

        let bpdu = BpduPacket::try_from(payload.as_slice()).expect("MST BPDU");

        assert_eq!(bpdu.version, StpVersion::Mstp);
        let BpduBody::Configuration(body) = bpdu.body else {
            panic!("MST BPDU exposes a configuration body");
        };
        assert_eq!(body.mst_extension, Some([0xde, 0xad, 0xbe, 0xef].as_ref()));
    }

    /// Synthetique : version 3 length annoncant plus que les octets restants.
    #[test]
    fn rejects_mst_extension_longer_than_payload() {
        let mut payload = Vec::from(RST_BPDU_FRAME_2173);
        payload[2] = 0x03;
        payload.extend_from_slice(&[0x00, 0x40]); // 64 octets annonces, 0 disponible

        assert_eq!(
            BpduPacket::try_from(payload.as_slice()),
            Err(StpError::InvalidVersion3Length {
                announced: 64,
                available: 0,
            })
        );
    }

    /// Synthetique : troncatures aux differents seuils.
    #[test]
    fn rejects_truncated_bpdus() {
        assert!(matches!(
            BpduPacket::try_from(&RST_BPDU_FRAME_2173[..3]),
            Err(StpError::InvalidLength {
                expected: 4,
                actual: 3,
            })
        ));
        assert!(matches!(
            BpduPacket::try_from(&RST_BPDU_FRAME_2173[..35]),
            Err(StpError::InvalidLength {
                expected: 36,
                actual: 35,
            })
        ));
        assert!(matches!(
            BpduPacket::try_from(&CONFIG_BPDU_FRAME_15[..20]),
            Err(StpError::InvalidLength {
                expected: 35,
                actual: 20,
            })
        ));
    }

    /// Synthetique : identifiant de protocole non nul.
    #[test]
    fn rejects_invalid_protocol_identifier() {
        let mut payload = RST_BPDU_FRAME_2173;
        payload[0] = 0x01;

        assert_eq!(
            BpduPacket::try_from(payload.as_ref()),
            Err(StpError::InvalidProtocolIdentifier(0x0100))
        );
    }

    /// Synthetique : version inconnue.
    #[test]
    fn rejects_invalid_version() {
        let mut payload = RST_BPDU_FRAME_2173;
        payload[2] = 0x01;

        assert_eq!(
            BpduPacket::try_from(payload.as_ref()),
            Err(StpError::InvalidVersion(1))
        );
    }

    /// Synthetique : type de BPDU inconnu.
    #[test]
    fn rejects_invalid_bpdu_type() {
        let mut payload = RST_BPDU_FRAME_2173;
        payload[3] = 0x05;

        assert_eq!(
            BpduPacket::try_from(payload.as_ref()),
            Err(StpError::InvalidBpduType(0x05))
        );
    }

    /// Synthetique : combinaisons version/type non definies ensemble.
    #[test]
    fn rejects_incoherent_version_type_combinations() {
        // Version 2 avec un type configuration.
        let mut payload = CONFIG_BPDU_FRAME_15;
        payload[2] = 0x02;
        assert_eq!(
            BpduPacket::try_from(payload.as_ref()),
            Err(StpError::IncoherentVersionType {
                version: 2,
                bpdu_type: 0x00,
            })
        );

        // Version 0 avec un type RST.
        let mut payload = RST_BPDU_FRAME_2173;
        payload[2] = 0x00;
        assert_eq!(
            BpduPacket::try_from(payload.as_ref()),
            Err(StpError::IncoherentVersionType {
                version: 0,
                bpdu_type: 0x02,
            })
        );
    }

    /// Synthetique : longueur version 1 non nulle dans un RST BPDU.
    #[test]
    fn rejects_nonzero_version_1_length() {
        let mut payload = RST_BPDU_FRAME_2173;
        payload[35] = 0x07;

        assert_eq!(
            BpduPacket::try_from(payload.as_ref()),
            Err(StpError::InvalidVersion1Length(7))
        );
    }

    /// Le bourrage Ethernet apres le BPDU est tolere : au niveau de la slice
    /// BPDU, le champ longueur 802.3 n'est plus visible. Base reelle
    /// (trame 15) + bourrage nul observe dans la capture.
    #[test]
    fn tolerates_ethernet_padding_after_bpdu() {
        let mut payload = Vec::from(CONFIG_BPDU_FRAME_15);
        payload.extend_from_slice(&[0x00; 8]);

        let bpdu = BpduPacket::try_from(payload.as_slice()).expect("padded BPDU");
        assert_eq!(bpdu.bpdu_type, BpduType::Configuration);
    }

    /// Synthetique : trame complete construite autour d'un BPDU reel
    /// (trame 2173) pour les cas negatifs de detection.
    fn synthetic_frame(dst: [u8; 6], length: u16, llc: [u8; 3]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&dst);
        frame.extend_from_slice(&[0x00, 0x0a, 0x8a, 0xa1, 0x5a, 0x9a]);
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(&llc);
        frame.extend_from_slice(&RST_BPDU_FRAME_2173);
        frame
    }

    #[test]
    fn detection_accepts_a_well_formed_llc_frame() {
        let frame = synthetic_frame(BRIDGE_GROUP_ADDRESS, 39, LLC_STP_HEADER);

        assert_eq!(stp_llc_payload(&frame), Some(RST_BPDU_FRAME_2173.as_ref()));
        assert!(is_stp_frame(&frame));
    }

    #[test]
    fn detection_rejects_non_bridge_group_destination() {
        let frame = synthetic_frame([0xff; 6], 39, LLC_STP_HEADER);
        assert_eq!(stp_llc_payload(&frame), None);
    }

    #[test]
    fn detection_rejects_ethertype_frames() {
        // 0x0800 > 0x05DC : EtherType IPv4, pas une longueur 802.3.
        let frame = synthetic_frame(BRIDGE_GROUP_ADDRESS, 0x0800, LLC_STP_HEADER);
        assert_eq!(stp_llc_payload(&frame), None);
    }

    #[test]
    fn detection_rejects_snap_llc_header() {
        // PVST+ circule en SNAP : DSAP/SSAP 0xAA.
        let frame = synthetic_frame(BRIDGE_GROUP_ADDRESS, 39, [0xaa, 0xaa, 0x03]);
        assert_eq!(stp_llc_payload(&frame), None);
    }

    #[test]
    fn detection_rejects_truncated_frames() {
        // Longueur annoncee au-dela des octets captures.
        let frame = synthetic_frame(BRIDGE_GROUP_ADDRESS, 200, LLC_STP_HEADER);
        assert_eq!(stp_llc_payload(&frame), None);

        // Trame plus courte que le minimum Ethernet + LLC + en-tete BPDU.
        assert_eq!(stp_llc_payload(&frame[..18]), None);
    }
}
