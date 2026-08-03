// Fuzz du decodeur COTP public : absence de panic, determinisme entre les
// deux points d'entree et coherence entre LI, type de TPDU et champs exposes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use packet_parser::parse::application::protocols::copt::{
    CotpHeader, CotpNumberFormat, CotpParameter, CotpPduType,
};

// CR/CC/DT reels : payloads COTP des frames 7/8/9 de
// pcaps_exemple/protocols/s7comm/s7comm_varservice_libnodavedemo.pcap.
const CR_REAL: &[u8] = &[
    0x11, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xc1, 0x02, 0x01, 0x00, 0xc2, 0x02, 0x01, 0x02, 0xc0,
    0x01, 0x09,
];
const CC_REAL: &[u8] = &[
    0x11, 0xd0, 0x00, 0x01, 0x00, 0x03, 0x00, 0xc0, 0x01, 0x09, 0xc1, 0x02, 0x01, 0x00, 0xc2, 0x02,
    0x01, 0x02,
];
const DT_REAL: &[u8] = &[0x02, 0xf0, 0x80];

// Trames synthetiques minimales, identifiees comme telles faute de captures de
// reference dans le depot. Elles couvrent les parties fixes RFC 905 qui ne
// figurent pas dans les trois trames reelles ci-dessus.
const DR_SYNTHETIC: &[u8] = &[0x06, 0x80, 0x00, 0x01, 0x00, 0x02, 0x80];
const DC_SYNTHETIC: &[u8] = &[0x05, 0xc0, 0x00, 0x01, 0x00, 0x02];
const ER_SYNTHETIC: &[u8] = &[0x04, 0x70, 0x00, 0x01, 0x00];
const ED_NORMAL_SYNTHETIC: &[u8] = &[0x04, 0x10, 0x00, 0x01, 0x80, 0xaa];
const EA_NORMAL_SYNTHETIC: &[u8] = &[0x04, 0x20, 0x00, 0x01, 0x01];
const AK_NORMAL_SYNTHETIC: &[u8] = &[0x04, 0x60, 0x00, 0x01, 0x01];
const RJ_NORMAL_SYNTHETIC: &[u8] = &[0x04, 0x50, 0x00, 0x01, 0x01];

// DT en numerotation etendue, EOT positionne, suivi de l'unique parametre
// checksum autorise pour LI=11. Ce chemin combine les deux formats optionnels.
const DT_EXTENDED_CHECKSUM_SYNTHETIC: &[u8] = &[
    0x0b, 0xf0, 0x00, 0x01, 0x80, 0x00, 0x00, 0x01, 0xc3, 0x02, 0x12, 0x34,
];
const DT_EXTENDED_ATN_CHECKSUM32_SYNTHETIC: &[u8] = &[
    0x0d, 0xf0, 0x00, 0x01, 0x80, 0x00, 0x00, 0x01, 0x08, 0x04, 0x12, 0x34, 0x56, 0x78,
];
const EA_NORMAL_ATN_CHECKSUM16_SYNTHETIC: &[u8] =
    &[0x08, 0x20, 0x00, 0x01, 0x01, 0x09, 0x02, 0x12, 0x34];

const SEEDS: &[&[u8]] = &[
    CR_REAL,
    CC_REAL,
    DT_REAL,
    DR_SYNTHETIC,
    DC_SYNTHETIC,
    ER_SYNTHETIC,
    ED_NORMAL_SYNTHETIC,
    EA_NORMAL_SYNTHETIC,
    AK_NORMAL_SYNTHETIC,
    RJ_NORMAL_SYNTHETIC,
    DT_EXTENDED_CHECKSUM_SYNTHETIC,
    DT_EXTENDED_ATN_CHECKSUM32_SYNTHETIC,
    EA_NORMAL_ATN_CHECKSUM16_SYNTHETIC,
];

fn assert_borrowed_within(data: &[u8], borrowed: &[u8], maximum_end: usize) {
    let base = data.as_ptr() as usize;
    let start = (borrowed.as_ptr() as usize)
        .checked_sub(base)
        .expect("COTP zero-copy slice must borrow from its input");
    assert!(start <= maximum_end);
    assert!(borrowed.len() <= maximum_end - start);
}

fn exercise(data: &[u8]) -> bool {
    let parsed = CotpHeader::from_bytes(data);
    let via_try_from = CotpHeader::try_from(data);

    let (header, consumed) = match (parsed, via_try_from) {
        (Ok((header, consumed)), Ok(via_try_from)) => {
            assert_eq!(header, via_try_from, "public COTP entry points diverged");
            (header, consumed)
        }
        (Err(_), Err(_)) => return false,
        _ => panic!("public COTP entry points disagree on validity"),
    };

    assert!(consumed <= data.len());
    let declared_end = usize::from(header.length) + 1;
    assert_eq!(consumed, declared_end, "consumed bytes must follow COTP LI");
    assert_eq!(header.length, data[0]);
    assert_eq!(header.pdu_type, CotpPduType::from(data[1]));

    assert_borrowed_within(data, header.raw_fixed_part, declared_end);
    assert_borrowed_within(data, header.user_data, data.len());
    let user_data_start = header.user_data.as_ptr() as usize - data.as_ptr() as usize;
    assert!(user_data_start >= declared_end);

    for parameter in &header.parameters {
        match parameter {
            CotpParameter::DisconnectAdditionalInfo(bytes)
            | CotpParameter::InvalidTpdu(bytes)
            | CotpParameter::Other(_, bytes) => {
                assert_borrowed_within(data, bytes, declared_end);
            }
            CotpParameter::TpduNumber(number) => assert!(*number <= 0x7f),
            CotpParameter::TpduNumberExtended(number) => assert!(*number <= 0x7fff_ffff),
            CotpParameter::Checksum(_)
            | CotpParameter::AtnExtendedChecksum32(_)
            | CotpParameter::AtnExtendedChecksum16(_) => {
                assert!(!matches!(header.pdu_type, CotpPduType::Reject));
            }
            CotpParameter::Eot(_) => assert!(matches!(
                header.pdu_type,
                CotpPduType::Data | CotpPduType::ExpeditedData
            )),
            _ => {}
        }
    }

    assert_eq!(
        header.disconnect_reason.is_some(),
        matches!(header.pdu_type, CotpPduType::DisconnectRequest)
    );
    assert_eq!(
        header.reject_cause.is_some(),
        matches!(header.pdu_type, CotpPduType::TpduError)
    );

    match header.pdu_type {
        CotpPduType::ConnectionRequest => {
            assert_eq!(header.dst_ref, 0);
            assert_ne!(header.src_ref, 0);
            assert_eq!(header.credit, Some(u16::from(data[1] & 0x0f)));
        }
        CotpPduType::ConnectionConfirm => {
            assert_ne!(header.dst_ref, 0);
            assert_ne!(header.src_ref, 0);
            assert_eq!(header.credit, Some(u16::from(data[1] & 0x0f)));
        }
        CotpPduType::Data if header.length == 2 => {
            assert_eq!(header.dst_ref, 0);
            assert_eq!(header.src_ref, 0);
            assert_eq!(header.number_format, Some(CotpNumberFormat::Class01Normal));
            assert!(matches!(
                header.parameters.first(),
                Some(CotpParameter::TpduNumber(number)) if *number == data[2] & 0x7f
            ));
            assert!(matches!(
                header.parameters.get(1),
                Some(CotpParameter::Eot(eot)) if *eot == (data[2] & 0x80 != 0)
            ));
        }
        CotpPduType::DisconnectRequest => {
            assert_eq!(header.disconnect_reason, Some(data[6]));
        }
        CotpPduType::DisconnectConfirm => assert_eq!(header.raw_fixed_part.len(), 4),
        CotpPduType::TpduError => assert_eq!(header.reject_cause, Some(data[4])),
        _ => {}
    }

    // Exerce aussi le rendu public, notamment les codes TPDU-size hostiles.
    let _ = header.to_string();
    true
}

fuzz_target!(|data: &[u8]| {
    let _ = exercise(data);

    // Toutes les formes passent exactement a chaque iteration. Deux octets de
    // fuzz choisissent ensuite une position et une mutation XOR sur une graine
    // selectionnee, ce qui conserve des chemins wire profonds des le depart.
    for seed in SEEDS {
        assert!(exercise(seed), "la graine COTP valide doit rester acceptee");
    }

    let seed_index = usize::from(data.first().copied().unwrap_or(0)) % SEEDS.len();
    let mut seeded = SEEDS[seed_index].to_vec();
    for mutation in data.get(1..).unwrap_or_default().chunks_exact(2) {
        let offset = usize::from(mutation[0]) % seeded.len();
        seeded[offset] ^= mutation[1];
    }
    let _ = exercise(seeded.as_slice());
});
