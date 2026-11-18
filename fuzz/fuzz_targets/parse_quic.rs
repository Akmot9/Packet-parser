// Fuzz du parseur QUIC Long Header : varints RFC 9000, Connection IDs et
// champ Length ne doivent jamais paniquer ni lire hors bornes sur des
// octets hostiles.
#![no_main]

use libfuzzer_sys::fuzz_target;
use packet_parser::parse::application::protocols::quic::QuicPacket;

fuzz_target!(|data: &[u8]| {
    let Ok(packet) = QuicPacket::try_from(data) else {
        return;
    };
    match &packet {
        // Un Version Negotiation (#299) : version 0, des blocs de 4 octets
        // jusqu'a la fin du datagramme.
        QuicPacket::VersionNegotiation {
            dcid,
            scid,
            versions,
            ..
        } => {
            assert_eq!(packet.version(), 0);
            assert_eq!(versions.len() % 4, 0);
            assert_eq!(
                7 + dcid.bytes.len() + scid.bytes.len() + versions.len(),
                data.len()
            );
            assert_eq!(
                packet.supported_versions().map(Iterator::count),
                Some(versions.len() / 4)
            );
        }
        // Sinon, de la v1 : 20 octets de Connection ID au plus, et pas de
        // liste de versions.
        QuicPacket::Initial { header, .. }
        | QuicPacket::Handshake { header, .. }
        | QuicPacket::OtherLong { header, .. } => {
            assert_eq!(packet.version(), 1);
            assert!(header.dcid.bytes.len() <= 20 && header.scid.bytes.len() <= 20);
            assert!(packet.supported_versions().is_none());
        }
        _ => panic!("variante inattendue : {packet:?}"),
    }
});
