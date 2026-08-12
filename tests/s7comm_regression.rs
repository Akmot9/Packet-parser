// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use std::{fs::File, path::Path};

use packet_parser::{
    LinkType, parse,
    parse::{
        application::protocols::s7comm::S7CommPacket, transport::protocols::TransportProtocol,
    },
};
use pcap::Capture;
use pcap_file::pcap::PcapReader;

// Real TCP payloads extracted from the repository's S7Comm fixtures. The
// expected fields and frame numbers were cross-checked with Wireshark 4.6.6:
// - Setup Communication: frames 9 (JOB) and 10 (ACK-Data) of
//   s7comm_varservice_libnodavedemo.pcap;
// - Read Var: frames 11 (JOB) and 12 (ACK-Data) of that same capture;
// - Userdata: frames 10 (request) and 11 (response) of
//   s7comm_program_blocklist_onlineview.pcap.
/// Frame 11: Read Var JOB (`s7comm_varservice_libnodavedemo.pcap`).
const READ_VAR_REQUEST: &str = "0300001f02f080320100000000000e00000401120a10020040000184000000";
/// Frame 12: Read Var ACK-Data (`s7comm_varservice_libnodavedemo.pcap`).
const READ_VAR_ACK_DATA: &str = concat!(
    "0300005902f0803203000000000002004400000401",
    "ff0402000000000000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000"
);
/// Frame 9: Setup Communication JOB (`s7comm_varservice_libnodavedemo.pcap`).
const SETUP_COMM_REQUEST: &str = "0300001902f08032010000ffff00080000f000000100010780";
/// Frame 10: Setup Communication ACK-Data (`s7comm_varservice_libnodavedemo.pcap`).
const SETUP_COMM_ACK_DATA: &str = "0300001b02f08032030000ffff000800000000f0000001000100f0";
/// Frame 10: Userdata request (`s7comm_program_blocklist_onlineview.pcap`).
const USERDATA_REQUEST: &str = "0300002102f080320700000300000800080001120411440100ff09000401320004";
/// Frame 11: Userdata response (`s7comm_program_blocklist_onlineview.pcap`).
const USERDATA_RESPONSE: &str = concat!(
    "0300005102f080320700000300000c0034000112081284010100000000",
    "ff090030013200040028000100040001000000010002000000005656bc04a3d58401d6b202",
    "000000000000000000000000000000"
);

fn decode(hex_payload: &str) -> Vec<u8> {
    hex::decode(hex_payload).expect("valid regression fixture")
}

#[test]
fn real_read_var_request_and_ack_data_response_parse() {
    let request_bytes = decode(READ_VAR_REQUEST);
    let request = S7CommPacket::try_from(request_bytes.as_slice()).expect("real Read Var request");

    assert_eq!(request.tpkt.length, request_bytes.len() as u16);
    assert_eq!(request.cotp.length, 2);
    assert_eq!(request.cotp.pdu_type, 0xf0);
    assert!(request.cotp.last_data_unit);
    assert_eq!(request.s7_header.protocol_id, 0x32);
    assert_eq!(request.s7_header.rosctr, 0x01);
    assert_eq!(request.s7_header.parameter_length, 14);
    assert_eq!(request.s7_header.data_length, 0);
    assert_eq!(request.parameter.function, 0x04);
    assert_eq!(request.parameter.item_count, Some(1));
    assert_eq!(request.parameter.raw, &request_bytes[17..31]);
    assert_eq!(request.parameter.items.len(), 1);
    assert_eq!(request.parameter.items[0].count, 64);
    assert_eq!(request.parameter.items[0].db_number, 1);
    assert_eq!(request.parameter.items[0].area, 0x84);
    assert_eq!(request.parameter.items[0].address, 0);
    assert!(request.payload.is_none());

    let response_bytes = decode(READ_VAR_ACK_DATA);
    let response =
        S7CommPacket::try_from(response_bytes.as_slice()).expect("real Read Var ACK-Data response");

    assert_eq!(response.tpkt.length, response_bytes.len() as u16);
    assert_eq!(response.s7_header.rosctr, 0x03);
    assert_eq!(response.s7_header.parameter_length, 2);
    assert_eq!(response.s7_header.data_length, 68);
    assert_eq!(response.s7_header.error_class, Some(0));
    assert_eq!(response.s7_header.error_code, Some(0));
    assert_eq!(response.parameter.function, 0x04);
    assert_eq!(response.parameter.item_count, Some(1));
    assert_eq!(response.parameter.raw, &response_bytes[19..21]);
    // In an ACK-Data, byte 1 is the number of data results, not a count of
    // S7ANY parameter descriptors. The result values live in the data area.
    assert!(response.parameter.items.is_empty());
    assert_eq!(response.payload.expect("Read Var result data").len(), 68);
}

#[test]
fn real_setup_communication_and_userdata_frames_parse() {
    let setup_request_bytes = decode(SETUP_COMM_REQUEST);
    let setup_request = S7CommPacket::try_from(setup_request_bytes.as_slice())
        .expect("real Setup Communication request");
    assert_eq!(setup_request.s7_header.rosctr, 0x01);
    assert_eq!(setup_request.s7_header.parameter_length, 8);
    assert_eq!(setup_request.parameter.function, 0xf0);
    assert_eq!(setup_request.parameter.item_count, None);
    assert_eq!(setup_request.parameter.raw, &setup_request_bytes[17..25]);
    assert!(setup_request.parameter.items.is_empty());

    let setup_response_bytes = decode(SETUP_COMM_ACK_DATA);
    let setup_response = S7CommPacket::try_from(setup_response_bytes.as_slice())
        .expect("real Setup Communication response");
    assert_eq!(setup_response.s7_header.rosctr, 0x03);
    assert_eq!(setup_response.s7_header.parameter_length, 8);
    assert_eq!(setup_response.parameter.function, 0xf0);
    assert_eq!(setup_response.parameter.item_count, None);
    assert_eq!(setup_response.parameter.raw, &setup_response_bytes[19..27]);
    assert!(setup_response.parameter.items.is_empty());

    let userdata_request_bytes = decode(USERDATA_REQUEST);
    let userdata_request =
        S7CommPacket::try_from(userdata_request_bytes.as_slice()).expect("real Userdata request");
    assert_eq!(userdata_request.s7_header.rosctr, 0x07);
    assert_eq!(userdata_request.s7_header.parameter_length, 8);
    assert_eq!(userdata_request.s7_header.data_length, 8);
    assert_eq!(userdata_request.parameter.item_count, None);
    assert_eq!(
        userdata_request.parameter.raw,
        &userdata_request_bytes[17..25]
    );
    assert_eq!(
        userdata_request
            .payload
            .expect("Userdata request data")
            .len(),
        8
    );

    let userdata_response_bytes = decode(USERDATA_RESPONSE);
    let userdata_response =
        S7CommPacket::try_from(userdata_response_bytes.as_slice()).expect("real Userdata response");
    assert_eq!(userdata_response.s7_header.rosctr, 0x07);
    assert_eq!(userdata_response.s7_header.parameter_length, 12);
    assert_eq!(userdata_response.s7_header.data_length, 52);
    assert_eq!(userdata_response.parameter.item_count, None);
    assert_eq!(
        userdata_response.parameter.raw,
        &userdata_response_bytes[17..29]
    );
    assert_eq!(
        userdata_response
            .payload
            .expect("Userdata response data")
            .len(),
        52
    );
}

#[test]
fn invalid_tpkt_cotp_and_s7_signatures_are_rejected() {
    let valid = decode(READ_VAR_REQUEST);
    assert_eq!(valid.len(), 31);

    let mut mutations = Vec::new();

    let mut non_zero_tpkt_reserved = valid.clone();
    non_zero_tpkt_reserved[1] = 0x01;
    mutations.push(("TPKT reserved byte is non-zero", non_zero_tpkt_reserved));

    let mut tpkt_too_short = valid.clone();
    tpkt_too_short[2..4].copy_from_slice(&30_u16.to_be_bytes());
    mutations.push(("TPKT length shorter than its S7 sections", tpkt_too_short));

    let mut tpkt_too_long = valid.clone();
    tpkt_too_long[2..4].copy_from_slice(&32_u16.to_be_bytes());
    mutations.push(("TPKT length longer than the input", tpkt_too_long));

    let mut wrong_cotp_length = valid.clone();
    wrong_cotp_length[4] = 0x03;
    mutations.push(("COTP DT length indicator is not 2", wrong_cotp_length));

    let mut wrong_cotp_type = valid.clone();
    wrong_cotp_type[5] = 0xe0;
    mutations.push(("COTP is not a DT TPDU", wrong_cotp_type));

    let mut missing_eot = valid.clone();
    missing_eot[6] = 0x00;
    mutations.push(("COTP DT does not end its TSDU", missing_eot));

    let mut non_zero_tpdu_number = valid.clone();
    non_zero_tpdu_number[6] = 0xff;
    mutations.push(("COTP DT carries TPDU-NR 0x7f", non_zero_tpdu_number));

    let mut wrong_protocol_id = valid.clone();
    wrong_protocol_id[7] = 0x33;
    mutations.push(("S7 protocol ID is not 0x32", wrong_protocol_id));

    let mut non_zero_s7_reserved = valid.clone();
    non_zero_s7_reserved[9] = 0x01;
    mutations.push(("S7 reserved field is non-zero", non_zero_s7_reserved));

    let mut invalid_specification_type = valid.clone();
    invalid_specification_type[19] = 0x11;
    mutations.push((
        "Read Var item is not a variable specification",
        invalid_specification_type,
    ));

    let mut unknown_rosctr = valid;
    unknown_rosctr[8] = 0x99;
    mutations.push(("unknown S7 ROSCTR", unknown_rosctr));

    for (name, bytes) in mutations {
        assert!(
            S7CommPacket::try_from(bytes.as_slice()).is_err(),
            "accepted invalid signature: {name}"
        );
    }
}

#[test]
fn coalesced_tpkts_are_bounded_to_the_first_declared_frame() {
    let first = decode(READ_VAR_REQUEST);
    let second = decode(SETUP_COMM_REQUEST);
    let first_length = first.len();
    let mut coalesced = first.clone();
    coalesced.extend_from_slice(second.as_slice());

    let parsed = S7CommPacket::try_from(coalesced.as_slice()).expect("first complete TPKT");
    assert_eq!(usize::from(parsed.tpkt.length), first_length);
    let item_raw = parsed.parameter.items[0].raw.expect("S7ANY raw descriptor");
    let raw_start = item_raw.as_ptr() as usize - coalesced.as_ptr() as usize;
    assert!(raw_start + item_raw.len() <= first_length);

    // The same physical buffer must not let a truncated first TPKT borrow its
    // missing final byte from the following, otherwise the section-length
    // validation silently crosses an RFC 1006 frame boundary.
    let mut truncated_first = first;
    truncated_first.pop();
    let truncated_length = truncated_first.len() as u16;
    truncated_first[2..4].copy_from_slice(&truncated_length.to_be_bytes());
    truncated_first.extend_from_slice(second.as_slice());
    assert!(S7CommPacket::try_from(truncated_first.as_slice()).is_err());
}

#[test]
fn ack_data_requires_both_error_bytes() {
    // TPKT + COTP-DT + the complete 12-byte ACK-Data header, with no
    // parameter or data section.
    let complete = decode("0300001302f080320300000001000000000000");
    assert_eq!(complete.len(), 19);
    let parsed = S7CommPacket::try_from(complete.as_slice()).expect("complete ACK-Data header");
    assert_eq!(parsed.s7_header.error_class, Some(0));
    assert_eq!(parsed.s7_header.error_code, Some(0));
    assert_eq!(parsed.parameter.item_count, None);
    assert!(parsed.parameter.raw.is_empty());

    let mut missing_error_code = complete;
    missing_error_code.pop();
    let truncated_length = missing_error_code.len() as u16;
    missing_error_code[2..4].copy_from_slice(&truncated_length.to_be_bytes());
    assert!(S7CommPacket::try_from(missing_error_code.as_slice()).is_err());
}

fn ethernet_ipv4_tcp(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
    let ip_total_length = 20 + 20 + payload.len();
    let mut frame = vec![
        0,
        1,
        2,
        3,
        4,
        5, // destination MAC
        6,
        7,
        8,
        9,
        10,
        11, // source MAC
        0x08,
        0x00, // IPv4
        0x45,
        0x00, // version/IHL, DSCP/ECN
        (ip_total_length >> 8) as u8,
        ip_total_length as u8,
        0x00,
        0x01, // identification
        0x40,
        0x00, // don't fragment
        64,
        6, // TTL, TCP
        0,
        0, // checksum (not validated by the parser)
        192,
        0,
        2,
        1, // TEST-NET-1
        198,
        51,
        100,
        2, // TEST-NET-2
    ];
    frame.extend_from_slice(&source_port.to_be_bytes());
    frame.extend_from_slice(&destination_port.to_be_bytes());
    frame.extend_from_slice(&[
        0, 0, 0, 1, // sequence number
        0, 0, 0, 1, // acknowledgement number
        0x50, 0x18, // data offset, PSH+ACK
        0x20, 0x00, // window
        0, 0, // checksum
        0, 0, // urgent pointer
    ]);
    frame.extend_from_slice(payload);
    frame
}

fn ethernet_ipv4_udp(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
    let udp_length = 8 + payload.len();
    let ip_total_length = 20 + udp_length;
    let mut frame = vec![
        0,
        1,
        2,
        3,
        4,
        5, // destination MAC
        6,
        7,
        8,
        9,
        10,
        11, // source MAC
        0x08,
        0x00, // IPv4
        0x45,
        0x00, // version/IHL, DSCP/ECN
        (ip_total_length >> 8) as u8,
        ip_total_length as u8,
        0x00,
        0x01, // identification
        0x40,
        0x00, // don't fragment
        64,
        17, // TTL, UDP
        0,
        0, // checksum (not validated by the parser)
        192,
        0,
        2,
        1, // TEST-NET-1
        198,
        51,
        100,
        2, // TEST-NET-2
    ];
    frame.extend_from_slice(&source_port.to_be_bytes());
    frame.extend_from_slice(&destination_port.to_be_bytes());
    frame.extend_from_slice(&(udp_length as u16).to_be_bytes());
    frame.extend_from_slice(&[0, 0]); // checksum
    frame.extend_from_slice(payload);
    frame
}

fn application_label(frame: &[u8]) -> Option<&'static str> {
    parse(LinkType::ETHERNET, frame)
        .expect("synthetic Ethernet frame")
        .application
        .map(|application| application.application_protocol)
}

#[test]
fn packetflow_requires_tcp_for_s7_but_allows_a_non_standard_port() {
    let payload = decode(READ_VAR_REQUEST);

    let standard_port = ethernet_ipv4_tcp(40_000, 102, payload.as_slice());
    assert_eq!(application_label(standard_port.as_slice()), Some("S7Comm"));

    // A complete, strictly signed S7 envelope remains recognizable when an
    // installation deliberately exposes it away from TCP/102.
    let non_standard_port = ethernet_ipv4_tcp(40_000, 40_001, payload.as_slice());
    let flow = parse(LinkType::ETHERNET, non_standard_port.as_slice()).unwrap();
    assert_eq!(
        flow.application
            .as_ref()
            .map(|application| application.application_protocol),
        Some("S7Comm")
    );
    assert_eq!(
        flow.transport.as_ref().expect("S7 transport").protocol,
        TransportProtocol::Tcp
    );

    let udp = ethernet_ipv4_udp(40_000, 102, payload.as_slice());
    assert_ne!(application_label(udp.as_slice()), Some("S7Comm"));
}

#[test]
fn packetflow_decodes_tpkt_before_cotp_on_tcp_102() {
    // Frames 7 and 8 of s7comm_varservice_libnodavedemo.pcap.
    let connection_request = decode("0300001611e00000000100c1020100c2020102c00109");
    let connection_confirm = decode("0300001611d00001000300c00109c1020100c2020102");

    for payload in [connection_request, connection_confirm] {
        let frame = ethernet_ipv4_tcp(42_258, 102, payload.as_slice());
        assert_eq!(application_label(frame.as_slice()), Some("COTP"));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FrameOracle {
    count: usize,
    frame_digest: u64,
}

fn update_frame_digest(digest: &mut u64, frame_number: usize) {
    // FNV-1a over fixed-width little-endian frame numbers. Counts are checked
    // separately, so both a missing/replaced frame and a reordered sequence
    // change the oracle.
    for byte in (frame_number as u64).to_le_bytes() {
        *digest ^= u64::from(byte);
        *digest = digest.wrapping_mul(1_099_511_628_211);
    }
}

fn count_fixture_protocols(path: &Path) -> (FrameOracle, FrameOracle) {
    let file = File::open(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let mut reader =
        PcapReader::new(file).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let link_type = LinkType::from(u32::from(reader.header().datalink));
    let mut s7comm = 0;
    let mut cotp = 0;
    let mut s7comm_digest = 14_695_981_039_346_656_037;
    let mut cotp_digest = 14_695_981_039_346_656_037;
    let mut frame_number = 0;

    while let Some(packet) = reader.next_packet() {
        frame_number += 1;
        let packet = packet.unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        let flow = parse(link_type, packet.data.as_ref())
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        let innermost = flow.flatten().into_iter().last().unwrap();
        match innermost
            .application
            .as_ref()
            .map(|application| application.application_protocol)
        {
            Some("S7Comm") => {
                s7comm += 1;
                update_frame_digest(&mut s7comm_digest, frame_number);
            }
            Some("COTP") => {
                cotp += 1;
                update_frame_digest(&mut cotp_digest, frame_number);
            }
            _ => {}
        }
    }

    (
        FrameOracle {
            count: s7comm,
            frame_digest: s7comm_digest,
        },
        FrameOracle {
            count: cotp,
            frame_digest: cotp_digest,
        },
    )
}

#[test]
fn repository_pcaps_keep_the_complete_s7_and_cotp_corpus() {
    // These counts and FNV-1a digests were generated independently from
    // `tshark -Y s7comm` and `tshark -Y 'cotp && !s7comm'`, using the ordered
    // `frame.number` fields. The test itself only uses the pure-Rust pcap
    // reader and PacketFlow: no external executable is needed at runtime.
    let fixtures = [
        (
            "s7comm_program_blocklist_onlineview.pcap",
            FrameOracle {
                count: 70,
                frame_digest: 0xdb90_4d1c_981a_bb26,
            },
            FrameOracle {
                count: 45,
                frame_digest: 0xce71_aa49_3749_cf50,
            },
        ),
        (
            "s7comm_downloading_block_db1.pcap",
            FrameOracle {
                count: 48,
                frame_digest: 0x47ad_cd73_de51_b389,
            },
            FrameOracle {
                count: 30,
                frame_digest: 0x8508_dfd0_9144_e650,
            },
        ),
        (
            "s7comm_varservice_libnodavedemo.pcap",
            FrameOracle {
                count: 16,
                frame_digest: 0x8e12_f725_f282_f135,
            },
            FrameOracle {
                count: 2,
                frame_digest: 0x92fc_16a9_7f3a_6caa,
            },
        ),
        (
            "s7comm_varservice_libnodavedemo_bench.pcap",
            FrameOracle {
                count: 10_006,
                frame_digest: 0x02f5_39b8_8cb2_5ec9,
            },
            FrameOracle {
                count: 2,
                frame_digest: 0xa918_1db4_3578_e1c4,
            },
        ),
        (
            "s7comm_reading_setting_plc_time.pcap",
            FrameOracle {
                count: 26,
                frame_digest: 0xd431_dc2f_bba2_6baf,
            },
            FrameOracle {
                count: 15,
                frame_digest: 0x545a_b00a_90b1_9612,
            },
        ),
        (
            "s7comm_reading_plc_status.pcap",
            FrameOracle {
                count: 144,
                frame_digest: 0xf86d_29db_88ab_0025,
            },
            FrameOracle {
                count: 74,
                frame_digest: 0x29a7_1408_07db_e910,
            },
        ),
    ];
    let fixture_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("pcaps_exemple")
        .join("protocols")
        .join("s7comm");
    let mut total = (0, 0);

    for (name, expected_s7comm, expected_cotp) in fixtures {
        let counts = count_fixture_protocols(fixture_dir.join(name).as_path());
        assert_eq!(
            counts,
            (expected_s7comm, expected_cotp),
            "protocol counts changed for {name}"
        );
        total.0 += counts.0.count;
        total.1 += counts.1.count;
    }

    assert_eq!(total, (10_310, 168));
}

fn collect_capture_files(path: &Path, captures: &mut Vec<std::path::PathBuf>) {
    if path.is_dir() {
        if path.file_name().is_some_and(|name| name == "s7comm") {
            return;
        }

        let mut entries: Vec<_> = std::fs::read_dir(path)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
            .map(|entry| entry.expect("readable directory entry").path())
            .collect();
        entries.sort();
        for entry in entries {
            collect_capture_files(entry.as_path(), captures);
        }
        return;
    }

    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "pcap" | "pcapng" | "cap"
            )
        })
    {
        captures.push(path.to_path_buf());
    }
}

#[test]
fn non_s7_protocol_corpus_has_no_s7comm_or_cotp_false_positive() {
    // The protocol-specific negative corpus deliberately excludes the six
    // S7Comm captures. Do not broaden this to all of pcaps_exemple: the large
    // 4SICS capture contains genuine S7 traffic outside the protocol folder.
    let protocol_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("pcaps_exemple")
        .join("protocols");
    let mut captures = Vec::new();
    collect_capture_files(protocol_dir.as_path(), &mut captures);
    captures.sort();

    let mut opened_files = 0;
    let mut frame_count = 0;
    let mut parsed_flows = 0;
    let mut link_errors = 0;
    let mut skipped_files = Vec::new();
    let mut read_errors = Vec::new();
    let mut s7comm_frames = Vec::new();
    let mut cotp_frames = Vec::new();

    for path in &captures {
        let mut capture = match Capture::from_file(path) {
            Ok(capture) => capture,
            Err(_) => {
                skipped_files.push(
                    path.strip_prefix(protocol_dir.as_path())
                        .unwrap()
                        .display()
                        .to_string(),
                );
                continue;
            }
        };
        opened_files += 1;
        let link_type = LinkType::from(capture.get_datalink().0 as u32);
        let mut file_frame = 0;

        loop {
            let packet = match capture.next_packet() {
                Ok(packet) => packet,
                Err(pcap::Error::NoMorePackets) => break,
                Err(_) => {
                    read_errors.push((
                        path.strip_prefix(protocol_dir.as_path())
                            .unwrap()
                            .display()
                            .to_string(),
                        file_frame,
                    ));
                    break;
                }
            };
            file_frame += 1;
            frame_count += 1;
            let Ok(flow) = parse(link_type, packet.data) else {
                link_errors += 1;
                continue;
            };
            parsed_flows += 1;

            for flattened in flow.flatten() {
                let label = flattened
                    .application
                    .as_ref()
                    .map(|application| application.application_protocol);
                let frames = match label {
                    Some("S7Comm") => &mut s7comm_frames,
                    Some("COTP") => &mut cotp_frames,
                    _ => continue,
                };
                frames.push(format!(
                    "{}:{file_frame}",
                    path.strip_prefix(protocol_dir.as_path()).unwrap().display()
                ));
            }
        }
    }

    // Coverage oracle: a green test must prove it actually walked the corpus.
    assert_eq!(captures.len(), 58);
    assert_eq!(opened_files, 57);
    assert_eq!(frame_count, 2_880);
    // +17 / -17 depuis le support de LINKTYPE_IPV4 (228) : les 17 trames de
    // protocols/tls/tls12-dsb.pcapng echouaient toutes en L2 faute de decodeur.
    // +3 depuis l'ajout de protocols/icmp/icmp_destination_unreachable.pcapng.
    assert_eq!(parsed_flows, 2_838);
    assert_eq!(link_errors, 42);
    assert_eq!(
        skipped_files,
        ["mqtt/mqtt_packets_Windows.cap"],
        "only the legacy NetXRay capture is unsupported by libpcap"
    );
    assert_eq!(
        read_errors,
        [("mqtt/mqtt_packets_RedHat61_tcpdump.pcap".to_string(), 1)],
        "the legacy RedHat capture has a malformed second pcap record"
    );
    assert!(
        s7comm_frames.is_empty(),
        "false-positive S7Comm labels: {s7comm_frames:?}"
    );
    assert!(
        cotp_frames.is_empty(),
        "false-positive COTP labels: {cotp_frames:?}"
    );
}
