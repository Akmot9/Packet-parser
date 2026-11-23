// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Regles TOML (#325) : lecture, refus a leur ligne, reconnaissance et
//! champs. ACME et DEMO sont inventes.

use super::*;
use crate::parse::application::custom::{CustomTransports, PayloadContext};
use crate::parse::transport::protocols::TransportProtocol::{self, Tcp, Udp};

const EXAMPLE: &str = include_str!("../../../../examples/acme_rules.toml");

fn context(transport: TransportProtocol, destination: u16) -> PayloadContext {
    PayloadContext::new(transport, Some(40_000), Some(destination))
}

/// Le parseur de l'etiquette `label`.
fn parser<'a>(rules: &'a RuleSet, label: &str) -> &'a RuleParser {
    rules
        .parsers
        .iter()
        .find(|parser| parser.label == label)
        .expect("etiquette du fichier")
}

/// La ligne et le message du refus de `text`.
fn refused(text: &str) -> (Option<usize>, String) {
    let error = RuleSet::from_toml(text).expect_err("fichier refuse");
    (error.line(), error.message().to_string())
}

/// Une regle minimale valide, a completer.
fn rule(extra: &str) -> String {
    format!(
        "version = 1\n[[rule]]\nlabel = \"QQTOP\"\n[[rule.pattern]]\noffset = 0\nbytes = \"51 51\"\n{extra}"
    )
}

#[test]
fn the_example_file_is_valid() {
    let rules = RuleSet::from_toml(EXAMPLE).expect("exemple valide");
    assert_eq!(rules.labels().collect::<Vec<_>>(), ["ACME", "DEMO"]);
    assert_eq!(rules.len(), 2);
    assert!(!rules.is_empty());
    assert!(
        RuleSet::from_toml("version = 1\n")
            .expect("vide")
            .is_empty()
    );
}

#[test]
fn acme_is_recognized_and_its_fields_decoded() {
    let rules = RuleSet::from_toml(EXAMPLE).expect("exemple valide");
    let acme = parser(&rules, "ACME");
    assert_eq!(acme.transports(), CustomTransports::Udp);
    assert_eq!(acme.ports(), [47_000]);

    let payload = b"ACME\x31\x02\x00\x2a\xde\xad\xbe\xef trailing";
    assert!(acme.matches(payload, &context(Udp, 47_000)));
    assert_eq!(
        acme.fields(payload, &context(Udp, 47_000)),
        [
            ("version".to_string(), "1".to_string()),
            ("type".to_string(), "response (2)".to_string()),
            ("length".to_string(), "42".to_string()),
            ("id".to_string(), "DE AD BE EF".to_string()),
        ]
    );
    // 0x7F est nomme en hexadecimal ; une valeur sans nom reste un nombre.
    let error = b"ACME\x01\x7f\x00\x00\x00\x00\x00\x00";
    assert_eq!(
        acme.fields(error, &context(Udp, 47_000))[1].1,
        "error (127)"
    );
    let other = b"ACME\x01\x05\x00\x00\x00\x00\x00\x00";
    assert_eq!(acme.fields(other, &context(Udp, 47_000))[1].1, "5");

    // Le masque du motif : seul le quartet bas de l'octet 4 compte.
    assert!(!acme.matches(
        b"ACME\x02\x02\x00\x00\x00\x00\x00\x00",
        &context(Udp, 47_000)
    ));
    // Les gardes : transport, port, longueur minimale.
    assert!(!acme.matches(payload, &context(Tcp, 47_000)));
    assert!(!acme.matches(payload, &context(Udp, 47_001)));
    assert!(!acme.matches(b"ACME\x01\x02\x00\x00\x00", &context(Udp, 47_000)));
    // Une charge non reconnue n'a pas de champ.
    assert!(
        acme.fields(b"OTHER PAYLOAD!", &context(Udp, 47_000))
            .is_empty()
    );
}

#[test]
fn variants_of_one_label_share_it_and_keep_their_fields() {
    let rules = RuleSet::from_toml(EXAMPLE).expect("exemple valide");
    let demo = parser(&rules, "DEMO");
    assert_eq!(demo.transports(), CustomTransports::Tcp);
    assert!(demo.ports().is_empty());

    let request = b"DEMO?ST-0042\0\0";
    let response = b"DEMO!\x01\x00";
    assert!(demo.matches(request, &context(Tcp, 9_000)));
    assert!(demo.matches(response, &context(Tcp, 9_000)));
    assert_eq!(
        demo.fields(request, &context(Tcp, 9_000)),
        [
            ("kind".to_string(), "?".to_string()),
            ("station".to_string(), "ST-0042".to_string()),
        ]
    );
    assert_eq!(
        demo.fields(response, &context(Tcp, 9_000)),
        [
            ("kind".to_string(), "!".to_string()),
            ("status".to_string(), "busy (1)".to_string()),
        ]
    );
    // Un champ qui deborde n'est pas affiche.
    assert_eq!(
        demo.fields(b"DEMO?ST", &context(Tcp, 9_000)),
        [("kind".to_string(), "?".to_string())]
    );
}

#[test]
fn the_union_of_the_variants_guards_the_parser() {
    let rules = RuleSet::from_toml(
        "version = 1\n\
         [[rule]]\nlabel = \"QQ\"\ntransport = \"tcp\"\nports = [2, 1, 2]\n[[rule.pattern]]\noffset = 0\nbytes = \"51 51\"\n\
         [[rule]]\nlabel = \"QQ\"\ntransport = \"udp\"\nports = [3]\n[[rule.pattern]]\noffset = 0\nbytes = \"51 52\"\n",
    )
    .expect("valide");
    let zz = parser(&rules, "QQ");
    assert_eq!(zz.transports(), CustomTransports::TcpAndUdp);
    assert_eq!(zz.ports(), [1, 2, 3]);
    // Chaque variante garde ses propres gardes.
    assert!(zz.matches(b"QQ", &context(Tcp, 1)));
    assert!(!zz.matches(b"QQ", &context(Udp, 1)));
    assert!(zz.matches(b"QR", &context(Udp, 3)));
    assert!(!zz.matches(b"QR", &context(Tcp, 3)));

    let any_port = RuleSet::from_toml(&format!(
        "{}[[rule]]\nlabel = \"QQTOP\"\nports = [7]\n[[rule.pattern]]\noffset = 0\nbytes = \"51 52\"\n",
        rule("")
    ))
    .expect("valide");
    assert!(parser(&any_port, "QQTOP").ports().is_empty());
}

#[test]
fn integer_fields_read_every_width_and_order() {
    let rules = RuleSet::from_toml(&rule(
        "[[rule.field]]\nname = \"a\"\noffset = 2\ntype = \"u16le\"\n\
         [[rule.field]]\nname = \"b\"\noffset = 2\ntype = \"u32be\"\n\
         [[rule.field]]\nname = \"c\"\noffset = 2\ntype = \"u32le\"\n\
         [[rule.field]]\nname = \"d\"\noffset = 2\ntype = \"u64be\"\n\
         [[rule.field]]\nname = \"e\"\noffset = 2\ntype = \"u64le\"\n\
         [[rule.field]]\nname = \"f\"\noffset = 2\ntype = \"u16be\"\nmask = \"0F F0\"\n\
         [[rule.field]]\nname = \"g\"\noffset = 2\ntype = \"u64be\"\nmask = \"FF FF FF FF FF FF FF FF\"\n",
    ))
    .expect("valide");
    let payload = [0x51, 0x51, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
    let fields = parser(&rules, "QQTOP").fields(&payload, &context(Udp, 1));
    let value = |name: &str| {
        fields
            .iter()
            .find(|(field, _)| field == name)
            .map(|(_, value)| value.clone())
    };
    assert_eq!(value("a"), Some(0x3412_u64.to_string()));
    assert_eq!(value("b"), Some(0x1234_5678_u64.to_string()));
    assert_eq!(value("c"), Some(0x7856_3412_u64.to_string()));
    assert_eq!(value("d"), Some(0x1234_5678_9ABC_DEF0_u64.to_string()));
    assert_eq!(value("e"), Some(0xF0DE_BC9A_7856_3412_u64.to_string()));
    assert_eq!(value("f"), Some(0x23_u64.to_string()));
    assert_eq!(value("g"), Some(0x1234_5678_9ABC_DEF0_u64.to_string()));
}

#[test]
fn text_is_escaped_and_stops_at_nul() {
    let rules = RuleSet::from_toml(&rule(
        "[[rule.field]]\nname = \"t\"\noffset = 2\ntype = \"text\"\nlength = 8\n",
    ))
    .expect("valide");
    let payload = b"QQ\x01A\\B~\x7f\0rest";
    assert_eq!(
        parser(&rules, "QQTOP").fields(payload, &context(Udp, 1)),
        [("t".to_string(), "\\x01A\\\\B~\\x7F".to_string())]
    );
}

#[test]
fn max_length_bounds_the_payload() {
    let rules = RuleSet::from_toml(
        "version = 1\n[[rule]]\nlabel = \"QQTOP\"\nmin_length = 3\nmax_length = 4\n[[rule.pattern]]\noffset = 0\nbytes = \"51 51\"\n",
    )
    .expect("valide");
    let zz = parser(&rules, "QQTOP");
    assert!(!zz.matches(b"QQ", &context(Udp, 1)));
    assert!(zz.matches(b"QQ.", &context(Udp, 1)));
    assert!(zz.matches(b"QQ..", &context(Udp, 1)));
    assert!(!zz.matches(b"QQ...", &context(Udp, 1)));
}

#[test]
fn each_mistake_is_refused_at_its_line() {
    let cases: Vec<(String, usize, &str)> = vec![
        // TOML et cles.
        ("version = 1\n[[rule]\n".into(), 2, ""),
        (
            rule("").replace("[[rule.pattern]]", "port = [1]\n[[rule.pattern]]"),
            4,
            "port",
        ),
        ("version = 2\n".into(), 1, "version de format 2"),
        (
            rule("").replace("\"51 51\"", "\"51 5\""),
            6,
            "hexadecimal invalide",
        ),
        (
            rule("").replace("\"51 51\"", "\"51 QQ\""),
            6,
            "hexadecimal invalide",
        ),
        (rule("mask = \"FF\"\n"), 7, "mask a 1 octets"),
        (rule("mask = \"FF 0F\"\n"), 6, "bits hors de son masque"),
        (
            rule("").replace("\"51 51\"", "\"51\""),
            2,
            "signature trop faible : 8 bits",
        ),
        (
            rule("")
                .replace("bytes = \"51 51\"", "bytes = \"51 51\"\nmask = \"0F 0F\"")
                .replace("\"51 51\"", "\"0A 0A\""),
            2,
            "signature trop faible : 8 bits",
        ),
        // Le meme octet verifie deux fois ne fait pas seize bits (#383) ; ni
        // deux motifs qui se recouvrent sur leurs quatre bits communs.
        (
            rule("").replace("\"51 51\"", "\"51\"")
                + "[[rule.pattern]]\noffset = 0\nbytes = \"51\"\n",
            2,
            "signature trop faible : 8 bits",
        ),
        (
            rule("").replace("bytes = \"51 51\"", "bytes = \"50\"\nmask = \"FC\"")
                + "[[rule.pattern]]\noffset = 0\nbytes = \"01\"\nmask = \"0F\"\n",
            2,
            "signature trop faible : 8 bits",
        ),
        (
            rule("[[rule.pattern]]\noffset = 2\nbytes = \"00\"\nmask = \"00\"\n"),
            7,
            "masque est nul",
        ),
        (
            "version = 1\n[[rule]]\nlabel = \"QQTOP\"\n".into(),
            2,
            "au moins un motif",
        ),
        (
            rule("").replace("offset = 0", "offset = 65536"),
            5,
            "depasse la borne 65535",
        ),
        (
            rule("").replace("label = \"QQTOP\"", "label = \"QQTOP\"\nmin_length = 1"),
            4,
            "sous la fin du dernier motif (2)",
        ),
        (
            rule("").replace("label = \"QQTOP\"", "label = \"QQTOP\"\nmax_length = 1"),
            4,
            "sous la longueur minimale (2)",
        ),
        (
            rule("").replace(
                "label = \"QQTOP\"",
                "label = \"QQTOP\"\ntransport = \"sctp\"",
            ),
            4,
            "transport \"sctp\" inconnu",
        ),
        (
            rule("").replace("label = \"QQTOP\"", "label = \"QQTOP\"\nports = [70000]"),
            4,
            "",
        ),
        // Etiquettes.
        (
            rule("").replace("\"QQTOP\"", "\" QQTOP\""),
            3,
            "etiquette de parseur invalide",
        ),
        (
            rule("").replace("\"QQTOP\"", "\"\""),
            3,
            "etiquette de parseur invalide",
        ),
        (
            rule("").replace("\"QQTOP\"", "\"dns\""),
            3,
            "etiquette d'un protocole de la crate",
        ),
        (
            format!(
                "{}[[rule]]\nlabel = \"qqtop\"\n[[rule.pattern]]\noffset = 0\nbytes = \"51 51\"\n",
                rule("")
            ),
            8,
            "que par la casse",
        ),
        // Champs.
        (
            rule("[[rule.field]]\nname = \"x\"\noffset = 0\ntype = \"u24\"\n"),
            10,
            "type de champ \"u24\" inconnu",
        ),
        (
            rule("[[rule.field]]\nname = \"x\"\noffset = 0\ntype = \"u8\"\nlength = 1\n"),
            11,
            "length ne s'applique",
        ),
        (
            rule("[[rule.field]]\nname = \"x\"\noffset = 0\ntype = \"hex\"\n"),
            10,
            "demande length",
        ),
        (
            rule("[[rule.field]]\nname = \"x\"\noffset = 0\ntype = \"hex\"\nlength = 0\n"),
            11,
            "length = 0",
        ),
        (
            rule("[[rule.field]]\nname = \"x\"\noffset = 0\ntype = \"text\"\nlength = 257\n"),
            11,
            "depasse la borne 256",
        ),
        (
            rule(
                "[[rule.field]]\nname = \"x\"\noffset = 0\ntype = \"hex\"\nlength = 2\nmask = \"FF\"\n",
            ),
            12,
            "mask ne s'applique qu'aux champs entiers",
        ),
        (
            rule(
                "[[rule.field]]\nname = \"x\"\noffset = 0\ntype = \"text\"\nlength = 2\nvalues = { 1 = \"a\" }\n",
            ),
            12,
            "values ne s'applique",
        ),
        (
            rule("[[rule.field]]\nname = \"x\"\noffset = 0\ntype = \"u16be\"\nmask = \"FF\"\n"),
            11,
            "le type u16be en a 2",
        ),
        (
            rule("[[rule.field]]\nname = \"x\"\noffset = 0\ntype = \"u8\"\nmask = \"00\"\n"),
            11,
            "mask nul",
        ),
        (
            rule(
                "[[rule.field]]\nname = \"x\"\noffset = 0\ntype = \"u8\"\nvalues = { a = \"b\" }\n",
            ),
            11,
            "cle de values \"a\"",
        ),
        (
            rule(
                "[[rule.field]]\nname = \"x\"\noffset = 0\ntype = \"u8\"\nvalues = { 256 = \"b\" }\n",
            ),
            11,
            "depasse la valeur maximale du champ (255)",
        ),
        (
            rule(
                "[[rule.field]]\nname = \"x\"\noffset = 0\ntype = \"u8\"\nmask = \"0F\"\nvalues = { 16 = \"b\" }\n",
            ),
            12,
            "(15)",
        ),
        (
            rule(
                "[[rule.field]]\nname = \"x\"\noffset = 0\ntype = \"u8\"\nvalues = { 1 = \"a\", 0x01 = \"b\" }\n",
            ),
            11,
            "nommee deux fois",
        ),
        (
            rule(
                "[[rule.field]]\nname = \"x\"\noffset = 0\ntype = \"u8\"\nvalues = { 1 = \"\" }\n",
            ),
            11,
            "nom de valeur",
        ),
        (
            rule("[[rule.field]]\nname = \"\"\noffset = 0\ntype = \"u8\"\n"),
            8,
            "nom de champ",
        ),
        (
            rule(
                "[[rule.field]]\nname = \"x\"\noffset = 0\ntype = \"u8\"\n[[rule.field]]\nname = \"x\"\noffset = 1\ntype = \"u8\"\n",
            ),
            12,
            "declare deux fois",
        ),
    ];
    for (text, line, message) in &cases {
        let (found_line, found_message) = refused(text);
        assert_eq!(
            found_line,
            Some(*line),
            "{message:?} dans\n{text}\n-> {found_message}"
        );
        assert!(
            found_message.contains(message),
            "{found_message:?} devrait contenir {message:?}"
        );
    }
}

#[test]
fn the_bounds_are_enforced() {
    let mut text = String::from("version = 1\n");
    for index in 0..=MAX_RULES {
        text.push_str(&format!(
            "[[rule]]\nlabel = \"R{index}\"\n[[rule.pattern]]\noffset = 0\nbytes = \"51 51\"\n"
        ));
    }
    let (line, message) = refused(&text);
    assert!(message.contains("plus de 256 regles"), "{message}");
    assert_eq!(line, Some(2 + 5 * MAX_RULES));

    let ports: Vec<String> = (0..=MAX_PORTS).map(|port| port.to_string()).collect();
    let (_, message) = refused(&rule("").replace(
        "label = \"QQTOP\"",
        &format!("label = \"QQTOP\"\nports = [{}]", ports.join(", ")),
    ));
    assert!(message.contains("plus de 256 ports"), "{message}");

    let (_, message) = refused(&rule("").replace(
        "\"51 51\"",
        &format!("\"{}\"", "51 ".repeat(MAX_PATTERN_LENGTH + 1)),
    ));
    assert!(message.contains("motif de 65 octets"), "{message}");

    let patterns: String = (0..MAX_PATTERNS)
        .map(|index| format!("[[rule.pattern]]\noffset = {}\nbytes = \"51\"\n", index + 2))
        .collect();
    let (line, message) = refused(&rule(&patterns));
    assert!(message.contains("plus de 64 motifs"), "{message}");
    assert_eq!(line, Some(4 + 3 * MAX_PATTERNS));
    // Soixante-quatre motifs passent.
    let (allowed, _) = patterns
        .rsplit_once("[[rule.pattern]]")
        .expect("un motif de moins");
    assert!(RuleSet::from_toml(&rule(allowed)).is_ok());

    let fields: String = (0..=MAX_FIELDS)
        .map(|index| format!("[[rule.field]]\nname = \"f{index}\"\noffset = 0\ntype = \"u8\"\n"))
        .collect();
    let (_, message) = refused(&rule(&fields));
    assert!(message.contains("plus de 64 champs"), "{message}");

    let values: Vec<String> = (0..=MAX_VALUES)
        .map(|value| format!("{value} = \"v{value}\""))
        .collect();
    let (_, message) = refused(&rule(&format!(
        "[[rule.field]]\nname = \"x\"\noffset = 0\ntype = \"u16be\"\nvalues = {{ {} }}\n",
        values.join(", ")
    )));
    assert!(message.contains("plus de 256 valeurs"), "{message}");
}

#[test]
fn the_error_reads_with_its_place() {
    let error = RuleSet::from_toml("version = 1\n[[rule]]\nlabel = \"QQTOP\"\nport = [1]\n")
        .expect_err("cle inconnue");
    assert_eq!(error.line(), Some(4));
    assert_eq!(error.column(), Some(1));
    assert!(
        error.to_string().starts_with("ligne 4, colonne 1 : "),
        "{error}"
    );
}

#[test]
fn a_label_is_leaked_once() {
    let first = RuleSet::from_toml(&rule("")).expect("valide");
    let second = RuleSet::from_toml(&rule("")).expect("valide");
    let label = |rules: &RuleSet| rules.labels().next().expect("une etiquette");
    assert!(std::ptr::eq(label(&first), label(&second)));
    assert!(std::ptr::eq(intern("QQTOP"), label(&first)));
}
