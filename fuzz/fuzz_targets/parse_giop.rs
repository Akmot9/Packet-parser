// Fuzz du parseur GIOP : curseur CDR (alignements, longueurs declarees),
// IOR et profils IIOP, iteration sur les messages d'un payload et
// resynchronisation. Ni panic ni boucle infinie, et un message ne couvre
// jamais plus d'octets que le buffer n'en contient.
#![no_main]

use libfuzzer_sys::fuzz_target;
use packet_parser::parse::application::protocols::giop::{
    GiopLocateReplyDetail, GiopMessage, GiopReplyDetail, TargetAddress, find_giop_message,
    giop_messages,
};

fuzz_target!(|data: &[u8]| {
    let start = find_giop_message(data).unwrap_or(0);
    let mut covered = 0;
    for packet in giop_messages(&data[start..]) {
        assert!(packet.wire_len() >= 12);
        covered += packet.wire_len();
        assert!(covered <= data.len() - start);

        let ior = match &packet.payload {
            GiopMessage::Reply(reply) => match &reply.detail {
                GiopReplyDetail::LocationForward(ior) => Some(ior),
                _ => None,
            },
            GiopMessage::LocateReply(reply) => match &reply.detail {
                GiopLocateReplyDetail::ObjectForward(ior) => Some(ior),
                _ => None,
            },
            GiopMessage::Request(request) => match &request.target {
                TargetAddress::ReferenceAddr { ior, .. } => Some(ior),
                TargetAddress::ProfileAddr(profile) => {
                    let _ = profile.iiop();
                    None
                }
                _ => None,
            },
            _ => None,
        };
        if let Some(ior) = ior {
            let _ = ior.iiop();
        }
    }
});
