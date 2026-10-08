// Fuzz du decodeur PTP (IEEE 1588) : en-tete commun v2, corps des dix types
// de message, zone TLV parcourue a la demande, en-tete v1. Ni panic ni
// boucle infinie ; quand le decodage reussit, message, TLV et octets de fin
// pavent exactement l'entree, chaque TLV pointe dans le buffer d'origine, et
// la variante UDP n'accepte qu'un sous-ensemble de ce qu'accepte la forme
// couche 2.
#![no_main]

use libfuzzer_sys::fuzz_target;
use packet_parser::parse::application::protocols::ptp::PtpPacket;

fuzz_target!(|data: &[u8]| {
    let udp = PtpPacket::try_from_udp(data);
    let Ok(packet) = PtpPacket::try_from(data) else {
        assert!(udp.is_err());
        return;
    };
    match &packet {
        PtpPacket::V2(message) => {
            let length = usize::from(message.header.message_length);
            assert_eq!(length + message.trailing.len(), data.len());
            let tlvs = message.tlvs.as_bytes();
            assert!(data[..length].ends_with(tlvs));
            let mut covered = 0;
            for tlv in message.tlvs {
                let Ok(tlv) = tlv else {
                    break;
                };
                assert!(data.as_ptr_range().contains(&tlv.value.as_ptr()) || tlv.value.is_empty());
                covered += 4 + tlv.value.len();
            }
            assert!(covered <= tlvs.len());
            if udp.is_ok() {
                assert!(message.trailing.len() == 0 || message.trailing.len() == 2);
            }
        }
        PtpPacket::V1(message) => {
            assert_eq!(40 + message.body.len(), data.len());
            assert!(udp.is_ok());
        }
        _ => unreachable!("PTPv1 ou PTPv2"),
    }
});
