// Fuzz cible du decodeur S7Comm : outre l'absence de panic, tout paquet
// accepte doit respecter les invariants discriminants TPKT + COTP-DT + S7.
#![no_main]

use libfuzzer_sys::fuzz_target;
use packet_parser::parse::application::protocols::s7comm::S7CommPacket;

const READ_VAR_REQUEST: [u8; 31] = [
    0x03, 0x00, 0x00, 0x1f, 0x02, 0xf0, 0x80, 0x32, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00,
    0x00, 0x04, 0x01, 0x12, 0x0a, 0x10, 0x02, 0x00, 0x40, 0x00, 0x01, 0x84, 0x00, 0x00, 0x00,
];

fn exercise(data: &[u8]) {
    if let Ok(packet) = S7CommPacket::try_from(data) {
        assert_eq!(packet.tpkt.version, 0x03);
        assert_eq!(packet.tpkt.reserved, 0x00);
        let tpkt_length = usize::from(packet.tpkt.length);
        // A TCP segment may coalesce several TPKTs. The decoder parses the
        // first declared frame, but must never borrow its sections from bytes
        // beyond that boundary.
        assert!(tpkt_length <= data.len());

        assert_eq!(packet.cotp.length, 2);
        assert_eq!(packet.cotp.pdu_type, 0xf0);
        assert!(packet.cotp.last_data_unit);
        assert_eq!(data[6] & 0x7f, 0, "S7 class-0 DT requires TPDU-NR zero");

        assert_eq!(packet.s7_header.protocol_id, 0x32);
        assert!(matches!(packet.s7_header.rosctr, 0x01 | 0x02 | 0x03 | 0x07));
        assert_eq!(packet.s7_header.reserved, 0);

        let s7_header_length = if matches!(packet.s7_header.rosctr, 0x02 | 0x03) {
            assert!(packet.s7_header.error_class.is_some());
            assert!(packet.s7_header.error_code.is_some());
            12
        } else {
            assert!(packet.s7_header.error_class.is_none());
            assert!(packet.s7_header.error_code.is_none());
            10
        };
        let expected_length = 4
            + 1
            + usize::from(packet.cotp.length)
            + s7_header_length
            + usize::from(packet.s7_header.parameter_length)
            + usize::from(packet.s7_header.data_length);
        assert_eq!(expected_length, tpkt_length);
    }
}

fuzz_target!(|data: &[u8]| {
    exercise(data);

    // Keep the fuzzer close to a real, deep S7ANY path even when starting
    // without an external seed corpus. Input bytes XOR a known-good Read Var
    // request; longer inputs continue to exercise the raw parser above.
    let mut seeded = READ_VAR_REQUEST;
    for (byte, mutation) in seeded.iter_mut().zip(data) {
        *byte ^= mutation;
    }
    exercise(&seeded);
});
