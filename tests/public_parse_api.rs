use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use packet_parser::parse::transport::protocols::TransportProtocol;
use packet_parser::{
    CorruptedLayerKind, LinkLayerError, LinkType, NetworkProtocol, PacketFlow, ParseError,
    ParsedPacketError, is_supported, parse,
};

/// Packet #1 extracted from Sonar's `test_files/raw_ip.pcapng` fixture.
const RAW_IPV4_ICMP_FIXTURE: [u8; 28] = [
    0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01, 0x7c, 0xde, 0x0a, 0xc8, 0x00, 0x01,
    0x0a, 0xc8, 0x00, 0x02, 0x08, 0x00, 0xf7, 0xff, 0x00, 0x01, 0x00, 0x01,
];

fn ethernet_frame_with_unknown_ethertype() -> [u8; 14] {
    [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // destination MAC
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // source MAC
        0xab, 0xcd, // unknown EtherType, valid Ethernet frame
    ]
}

fn ethernet_ipv4_udp() -> Vec<u8> {
    vec![
        0, 1, 2, 3, 4, 5, // destination MAC
        6, 7, 8, 9, 10, 11, // source MAC
        0x08, 0x00, // IPv4
        0x45, 0x00, 0x00, 0x1c, 0x12, 0x34, 0x00, 0x00, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100,
        2, // IPv4 header
        0x04, 0xd2, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00, // UDP header
    ]
}

fn ethernet_ipv6_udp() -> Vec<u8> {
    let mut frame = vec![
        0, 1, 2, 3, 4, 5, // destination MAC
        6, 7, 8, 9, 10, 11, // source MAC
        0x86, 0xdd, // IPv6
        0x60, 0, 0, 0, 0, 8, 17, 64, // IPv6 fixed header prefix
    ];
    frame.extend_from_slice(&[0; 15]);
    frame.push(1); // 0000::1
    frame.extend_from_slice(&[0; 15]);
    frame.push(2); // 0000::2
    frame.extend_from_slice(&[0x04, 0xd2, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00]);
    frame
}

fn vlan_ipv4_udp() -> Vec<u8> {
    let ethernet = ethernet_ipv4_udp();
    let mut frame = ethernet[..12].to_vec();
    frame.extend_from_slice(&[0x81, 0x00, 0x00, 0x0a, 0x08, 0x00]);
    frame.extend_from_slice(&ethernet[14..]);
    frame
}

fn raw_ipv6_udp() -> Vec<u8> {
    ethernet_ipv6_udp()[14..].to_vec()
}

fn assert_raw_link<'a>(
    bytes: &'a [u8],
    expected_protocol: NetworkProtocol,
    expected_version: u8,
) -> PacketFlow<'a> {
    let flow = parse(LinkType::RAW, bytes).unwrap();
    let raw = flow.data_link.as_raw_ip().expect("RAW IP view");

    assert_eq!(flow.data_link.link_type(), LinkType::RAW);
    assert_eq!(flow.data_link.network_protocol(), expected_protocol);
    assert_eq!(flow.data_link.network_payload(), bytes);
    assert_eq!(flow.data_link.network_payload().as_ptr(), bytes.as_ptr());
    assert_eq!(raw.ip_version, expected_version);
    assert_eq!(raw.payload, bytes);
    assert_eq!(raw.payload.as_ptr(), bytes.as_ptr());
    assert!(flow.data_link.as_ethernet().is_none());
    assert!(flow.data_link.as_ieee80211().is_none());

    flow
}

fn assert_raw_l3_corruption(
    bytes: &[u8],
    expected_protocol: NetworkProtocol,
    expected_version: u8,
) {
    let flow = assert_raw_link(bytes, expected_protocol, expected_version);

    assert!(flow.internet.is_none());
    assert!(flow.transport.is_none());
    assert!(flow.application.is_none());
    let corrupted = flow.corrupted.expect("recognized but corrupt IP header");
    assert_eq!(corrupted.layer, CorruptedLayerKind::Internet);
    assert!(!corrupted.error.is_empty());
}

fn assert_ethernet_apis_match(bytes: &[u8]) {
    let explicit = parse(LinkType::ETHERNET, bytes).unwrap();
    let legacy = parse_through_legacy_api(bytes).unwrap();

    assert_eq!(explicit, legacy);
    assert_eq!(explicit.data_link.link_type(), LinkType::ETHERNET);
    assert!(explicit.data_link.as_ethernet().is_some());
}

fn parse_through_legacy_api(bytes: &[u8]) -> Result<PacketFlow<'_>, ParsedPacketError> {
    PacketFlow::try_from(bytes)
}

#[test]
fn explicit_ethernet_entry_matches_legacy_try_from() {
    let bytes = ethernet_frame_with_unknown_ethertype();

    let explicit = parse(LinkType::ETHERNET, bytes.as_slice()).unwrap();
    let legacy = parse_through_legacy_api(bytes.as_slice()).unwrap();

    assert_eq!(explicit, legacy);
}

#[test]
fn explicit_ethernet_matches_legacy_for_l3_and_vlan_paths() {
    assert_ethernet_apis_match(&ethernet_ipv4_udp());
    assert_ethernet_apis_match(&ethernet_ipv6_udp());
    assert_ethernet_apis_match(&vlan_ipv4_udp());

    let mut corrupt_l3 = ethernet_ipv4_udp()[..14].to_vec();
    corrupt_l3.extend_from_slice(&[0xff; 6]);
    assert_ethernet_apis_match(&corrupt_l3);

    let mut corrupt_l4 = ethernet_ipv4_udp();
    corrupt_l4[23] = 6; // IPv4 protocol = TCP
    corrupt_l4.truncate(14 + 20 + 4);
    corrupt_l4[16] = 0;
    corrupt_l4[17] = 24; // IPv4 total length = 24
    assert_ethernet_apis_match(&corrupt_l4);
}

#[test]
fn borrowed_and_owned_link_layers_share_the_same_schema() {
    let bytes = ethernet_frame_with_unknown_ethertype();
    let flow = parse(LinkType::ETHERNET, bytes.as_slice()).unwrap();
    let borrowed = serde_json::to_value(&flow.data_link).unwrap();
    let owned = serde_json::to_value(&flow.to_owned().data_link).unwrap();

    assert_eq!(borrowed, owned);
    assert_eq!(
        borrowed,
        serde_json::json!({
            "link_type": 1,
            "network_protocol": { "kind": "other", "value": 0xabcd },
            "link_kind": "ethernet",
            "link_details": {
                "destination_mac": "00:11:22:33:44:55",
                "source_mac": "66:77:88:99:aa:bb",
                "ethertype": "Unknown (0xABCD)"
            }
        })
    );
}

#[test]
fn borrowed_and_owned_vlan_link_layers_share_the_same_schema() {
    let bytes = vlan_ipv4_udp();
    let flow = parse(LinkType::ETHERNET, bytes.as_slice()).unwrap();
    let borrowed = serde_json::to_value(&flow.data_link).unwrap();
    let owned = serde_json::to_value(&flow.to_owned().data_link).unwrap();

    assert_eq!(borrowed, owned);
    assert_eq!(borrowed["network_protocol"]["kind"], "ipv4");
    assert_eq!(borrowed["link_details"]["ethertype"], "IPv4");
    assert_eq!(
        borrowed["link_details"]["vlan"],
        serde_json::json!({ "id": 10, "pcp": 0, "dei": false })
    );
}

#[test]
fn raw_ipv4_fixture_and_raw_ipv6_use_the_shared_network_pipeline() {
    let ipv4 = assert_raw_link(&RAW_IPV4_ICMP_FIXTURE, NetworkProtocol::Ipv4, 4);
    let ipv4_internet = ipv4.internet.as_ref().unwrap();
    assert_eq!(ipv4_internet.protocol_name, "IPv4");
    assert_eq!(
        ipv4_internet.source,
        Some(IpAddr::V4(Ipv4Addr::new(10, 200, 0, 1)))
    );
    assert_eq!(
        ipv4_internet.destination,
        Some(IpAddr::V4(Ipv4Addr::new(10, 200, 0, 2)))
    );
    assert_eq!(
        ipv4.transport.as_ref().unwrap().protocol,
        TransportProtocol::Icmp
    );
    assert!(ipv4.corrupted.is_none());

    let ipv6_bytes = raw_ipv6_udp();
    let ipv6 = assert_raw_link(&ipv6_bytes, NetworkProtocol::Ipv6, 6);
    let ipv6_internet = ipv6.internet.as_ref().unwrap();
    assert_eq!(ipv6_internet.protocol_name, "IPv6");
    assert_eq!(ipv6_internet.source, Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    assert_eq!(
        ipv6_internet.destination,
        Some(IpAddr::V6(Ipv6Addr::from(2_u128)))
    );
    let ipv6_transport = ipv6.transport.as_ref().unwrap();
    assert_eq!(ipv6_transport.protocol, TransportProtocol::Udp);
    assert_eq!(ipv6_transport.source_port, Some(1234));
    assert_eq!(ipv6_transport.destination_port, Some(53));
    assert!(ipv6.corrupted.is_none());
}

#[test]
fn raw_borrowed_and_owned_models_share_a_schema_without_ethernet_fields() {
    let ipv6 = raw_ipv6_udp();
    for (bytes, protocol, version, protocol_kind) in [
        (
            RAW_IPV4_ICMP_FIXTURE.as_slice(),
            NetworkProtocol::Ipv4,
            4,
            "ipv4",
        ),
        (ipv6.as_slice(), NetworkProtocol::Ipv6, 6, "ipv6"),
    ] {
        let flow = assert_raw_link(bytes, protocol, version);
        let borrowed = serde_json::to_value(&flow.data_link).unwrap();
        let owned_link = flow.to_owned().data_link;
        let owned = serde_json::to_value(&owned_link).unwrap();

        assert_eq!(borrowed, owned);
        assert!(owned_link.as_raw_ip().is_some());
        assert!(owned_link.as_ethernet().is_none());
        assert_eq!(
            borrowed,
            serde_json::json!({
                "link_type": 101,
                "network_protocol": { "kind": protocol_kind },
                "link_kind": "raw_ip",
                "link_details": { "ip_version": version }
            })
        );
    }
}

#[test]
fn raw_empty_and_invalid_version_are_structured_link_errors() {
    assert!(matches!(
        parse(LinkType::RAW, &[]),
        Err(ParseError::InvalidLinkLayer(LinkLayerError::Truncated {
            link_type: LinkType::RAW,
            required: 1,
            actual: 0,
        }))
    ));

    assert!(matches!(
        parse(LinkType::RAW, &[0x70]),
        Err(ParseError::InvalidLinkLayer(
            LinkLayerError::InvalidIpVersion {
                link_type: LinkType::RAW,
                version: 7,
            }
        ))
    ));
}

#[test]
fn recognized_but_truncated_raw_ip_headers_degrade_at_l3() {
    for len in 1..20 {
        let mut bytes = vec![0; len];
        bytes[0] = 0x45;
        assert_raw_l3_corruption(&bytes, NetworkProtocol::Ipv4, 4);
    }

    let mut invalid_ihl = vec![0; 20];
    invalid_ihl[0] = 0x40;
    assert_raw_l3_corruption(&invalid_ihl, NetworkProtocol::Ipv4, 4);

    for len in 1..40 {
        let mut bytes = vec![0; len];
        bytes[0] = 0x60;
        assert_raw_l3_corruption(&bytes, NetworkProtocol::Ipv6, 6);
    }

    let mut missing_ipv6_payload = vec![0; 40];
    missing_ipv6_payload[0] = 0x60;
    missing_ipv6_payload[5] = 1;
    assert_raw_l3_corruption(&missing_ipv6_payload, NetworkProtocol::Ipv6, 6);
}

#[test]
fn unsupported_link_type_preserves_its_numeric_value() {
    let unsupported = LinkType(0xdead_beef);

    let error = parse(unsupported, &[]).unwrap_err();

    assert!(matches!(
        error,
        ParseError::UnsupportedLinkType(actual) if actual == unsupported
    ));
}

#[test]
fn unsupported_link_type_never_falls_back_to_ethernet() {
    let bytes = ethernet_frame_with_unknown_ethertype();
    let error = parse(LinkType::LINUX_SLL, bytes.as_slice()).unwrap_err();

    assert!(matches!(
        error,
        ParseError::UnsupportedLinkType(actual) if actual == LinkType::LINUX_SLL
    ));
}

#[test]
fn ethernet_bytes_labelled_as_raw_never_fall_back_to_ethernet() {
    let bytes = ethernet_frame_with_unknown_ethertype();

    assert!(matches!(
        parse(LinkType::RAW, bytes.as_slice()),
        Err(ParseError::InvalidLinkLayer(
            LinkLayerError::InvalidIpVersion {
                link_type: LinkType::RAW,
                version: 0,
            }
        ))
    ));
}

#[test]
fn support_preflight_matches_the_decoder_catalogue() {
    assert!(is_supported(LinkType::ETHERNET));
    assert!(is_supported(LinkType::RAW));
    assert!(!is_supported(LinkType::IEEE802_11));
    assert!(!is_supported(LinkType::LINUX_SLL));
    assert!(!is_supported(LinkType::LINUX_SLL2));
    assert!(!is_supported(LinkType::BLUETOOTH_HCI_H4_WITH_PHDR));
    assert!(!is_supported(LinkType(u32::MAX)));
}

#[test]
fn explicit_ethernet_errors_match_the_legacy_api() {
    for len in 0..14 {
        let bytes = vec![0_u8; len];
        let explicit = parse(LinkType::ETHERNET, bytes.as_slice()).unwrap_err();
        let legacy = parse_through_legacy_api(bytes.as_slice()).unwrap_err();

        assert!(matches!(&explicit, ParseError::InvalidDataLink(_)));
        assert!(matches!(&legacy, ParseError::InvalidDataLink(_)));
        assert_eq!(explicit.to_string(), legacy.to_string());
    }
}

#[test]
fn truncated_vlan_errors_match_the_legacy_api() {
    let mut bytes = ethernet_frame_with_unknown_ethertype().to_vec();
    bytes[12..14].copy_from_slice(&[0x81, 0x00]);

    for len in 14..18 {
        bytes.resize(len, 0);
        let explicit = parse(LinkType::ETHERNET, bytes.as_slice()).unwrap_err();
        let legacy = parse_through_legacy_api(bytes.as_slice()).unwrap_err();

        assert_eq!(explicit.to_string(), legacy.to_string());
    }
}

#[cfg(feature = "parse_timing")]
#[test]
fn explicit_timed_api_matches_normal_dispatch() {
    use packet_parser::{parse_timed, timing::ParseTiming};

    let bytes = ethernet_frame_with_unknown_ethertype();
    let normal = parse(LinkType::ETHERNET, bytes.as_slice()).unwrap();
    let mut timing = ParseTiming::default();
    let timed = parse_timed(LinkType::ETHERNET, bytes.as_slice(), &mut timing).unwrap();

    assert_eq!(normal, timed);
    assert!(timing.total_ns >= timing.l2_ns);
}

#[cfg(feature = "parse_timing")]
#[test]
fn explicit_timed_raw_api_matches_success_and_l3_corruption() {
    use packet_parser::{parse_timed, timing::ParseTiming};

    let ipv6 = raw_ipv6_udp();
    for bytes in [
        RAW_IPV4_ICMP_FIXTURE.as_slice(),
        ipv6.as_slice(),
        &[0x45][..],
        &[0x60][..],
    ] {
        let normal = parse(LinkType::RAW, bytes).unwrap();
        let mut timing = ParseTiming::default();
        let timed = parse_timed(LinkType::RAW, bytes, &mut timing).unwrap();

        assert_eq!(normal, timed);
        assert!(timing.total_ns >= timing.l2_ns);
        assert!(timing.total_ns >= timing.l3_ns);
        assert!(timing.total_ns >= timing.l4_ns);
        assert!(timing.total_ns >= timing.l7_ns);
    }
}

#[cfg(feature = "parse_timing")]
#[test]
fn explicit_timed_raw_errors_match_normal_errors() {
    use packet_parser::{parse_timed, timing::ParseTiming};

    for bytes in [&[][..], &[0x70][..]] {
        let normal = parse(LinkType::RAW, bytes).unwrap_err();
        let mut timing = ParseTiming {
            l2_ns: 1,
            l3_ns: 1,
            l4_ns: 1,
            l7_ns: 1,
            total_ns: 1,
        };
        let timed = parse_timed(LinkType::RAW, bytes, &mut timing).unwrap_err();

        assert_eq!(normal.to_string(), timed.to_string());
        assert_eq!(timing.l3_ns, 0);
        assert_eq!(timing.l4_ns, 0);
        assert_eq!(timing.l7_ns, 0);
        assert!(timing.total_ns >= timing.l2_ns);
    }
}

#[cfg(feature = "parse_timing")]
#[test]
fn timed_api_rejects_unsupported_link_type_before_decoding() {
    use packet_parser::{parse_timed, timing::ParseTiming};

    let bytes = ethernet_frame_with_unknown_ethertype();
    let mut timing = ParseTiming {
        l2_ns: 1,
        l3_ns: 1,
        l4_ns: 1,
        l7_ns: 1,
        total_ns: 1,
    };
    let error = parse_timed(LinkType::LINUX_SLL, bytes.as_slice(), &mut timing).unwrap_err();

    assert!(matches!(
        error,
        ParseError::UnsupportedLinkType(actual) if actual == LinkType::LINUX_SLL
    ));
    assert_eq!(timing.l2_ns, 0);
    assert_eq!(timing.l3_ns, 0);
    assert_eq!(timing.l4_ns, 0);
    assert_eq!(timing.l7_ns, 0);
}
