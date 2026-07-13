use packet_parser::{LinkType, PacketFlow, ParseError, ParsedPacketError, is_supported, parse};

fn ethernet_frame_with_unknown_ethertype() -> [u8; 14] {
    [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // destination MAC
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // source MAC
        0xab, 0xcd, // unknown EtherType, valid Ethernet frame
    ]
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
