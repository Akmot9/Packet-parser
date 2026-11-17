// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Regles TOML (#325). Un texte quelconque est lu comme fichier de regles :
//! refuse ou accepte, jamais une panique ; accepte, ses regles passent sur
//! ses propres octets. Puis les octets passent comme charge TCP et UDP par
//! les regles de l'exemple, champs compris.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use packet_parser::{
    ApplicationProtocol, ParseConfig, PayloadContext, RuleSet, TransportProtocol,
    classify_payload_with,
};

const EXAMPLE: &str = include_str!("../../examples/acme_rules.toml");

fn example() -> &'static ParseConfig {
    static CONFIG: OnceLock<ParseConfig> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let rules = RuleSet::from_toml(EXAMPLE).expect("exemple valide");
        ParseConfig::new().with_rules(&rules).expect("etiquettes libres")
    })
}

/// Le payload sous chaque transport et quelques ports, champs compris.
fn run(config: &ParseConfig, payload: &[u8]) {
    for transport in [TransportProtocol::Tcp, TransportProtocol::Udp] {
        for port in [47_000, 9_000] {
            let Some(application) =
                classify_payload_with(transport, Some(40_000), Some(port), payload, config)
            else {
                continue;
            };
            if let ApplicationProtocol::Custom(label) = application.protocol {
                let parser = config.parser(label).expect("etiquette enregistree");
                let context = PayloadContext::new(transport, Some(40_000), Some(port));
                let _ = parser.fields(payload, &context);
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data)
        && let Ok(rules) = RuleSet::from_toml(text)
        && let Ok(config) = ParseConfig::new().with_rules(&rules)
    {
        run(&config, data);
    }
    run(example(), data);
});
