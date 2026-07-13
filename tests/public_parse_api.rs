use packet_parser::{LinkType, PacketFlow, ParseError, ParsedPacketError, is_supported, parse};

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
    let error = parse(LinkType::RAW, bytes.as_slice()).unwrap_err();

    assert!(matches!(
        error,
        ParseError::UnsupportedLinkType(actual) if actual == LinkType::RAW
    ));
}

#[test]
fn support_preflight_matches_the_decoder_catalogue() {
    assert!(is_supported(LinkType::ETHERNET));
    assert!(!is_supported(LinkType::RAW));
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
    assert!(timing.total_ns > 0);
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
    let error = parse_timed(LinkType::RAW, bytes.as_slice(), &mut timing).unwrap_err();

    assert!(matches!(
        error,
        ParseError::UnsupportedLinkType(actual) if actual == LinkType::RAW
    ));
    assert_eq!(timing.l2_ns, 0);
    assert_eq!(timing.l3_ns, 0);
    assert_eq!(timing.l4_ns, 0);
    assert_eq!(timing.l7_ns, 0);
}
