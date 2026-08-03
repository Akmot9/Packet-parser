// Fuzz du point d'entrée principal : aucun octet hostile ne doit provoquer
// de panic, seulement Ok(_) ou Err(_).
#![no_main]

use libfuzzer_sys::fuzz_target;
use packet_parser::{PacketFlow, parse::transport::protocols::TransportProtocol};

fuzz_target!(|data: &[u8]| {
    if let Ok(flow) = PacketFlow::try_from(data) {
        // FTP est volontairement garde par TCP/21 : le fuzzer doit aussi
        // proteger cet invariant semantique, pas seulement l'absence de panic.
        for parsed_flow in flow.flatten() {
            if parsed_flow
                .application
                .as_ref()
                .is_some_and(|application| application.application_protocol == "FTP")
            {
                let transport = parsed_flow
                    .transport
                    .as_ref()
                    .expect("FTP doit toujours posseder une couche transport");
                assert_eq!(transport.protocol, TransportProtocol::Tcp);
                assert!(
                    transport.source_port == Some(21) || transport.destination_port == Some(21),
                    "FTP ne doit jamais etre detecte hors de TCP/21"
                );
            }
        }

        // Exerce aussi les chemins de conversion et d'aplatissement.
        let _ = flow.to_owned();
        let _ = flow.flatten();
    }
});
