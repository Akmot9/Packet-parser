# classify_payload (#219) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Une fonction publique rend, pour un transport, deux ports et un payload, l'étiquette que `parse` met dans `PacketFlow::application` ; puis, sur `release/12.0.0`, `impl TryFrom<&[u8]> for Application` disparaît.

**Architecture:** L'étape L7 d'un flux à couche transport sort de `parse_l7_and_inner` dans une fonction du moteur que `parse` et `classify_payload` appellent toutes deux : même réponse par construction, tunnels compris. Deux PR : la fonction vers `main` (sans rupture), le retrait vers la branche d'intégration `release/12.0.0`.

**Tech Stack:** Rust 2024, MSRV 1.88, `pcap-file` pour lire le corpus, `cargo-fuzz` (nightly), `cargo-semver-checks` 0.50.

**Spec:** `docs/superpowers/specs/2026-11-14-classify-payload-219-design.md`

## Global Constraints

- Aucune rupture sur `main` : `cargo semver-checks check-release --baseline-version 11.8.2 --release-type minor` vert.
- L'histogramme golden et les oracles ne bougent pas ; aucun test existant n'est affaibli.
- Tests golden sur trames réelles ; tout octet synthétique le dit dans son commentaire.
- Commentaires du code et CHANGELOG en français sans accents ; rustdoc des entrées publiques en anglais, comme `parse` ; `MIGRATION-12.md` en français accentué, comme `MIGRATION-11.md`.
- Commits : `type(scope): resume (#219)`, sans accents, terminés par `Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>`.
- Gates avant chaque push : `cargo fmt --all -- --check` ; `cargo +stable clippy --workspace --all-targets --all-features --locked -- -D warnings` (après `rustup update stable`) ; `cargo +1.88.0 check -p packet_parser --all-features --all-targets --locked` ; `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features` ; `cargo test --workspace --all-features --locked` ; semver-checks ; `cargo bench --manifest-path benches/Cargo.toml --no-run`.
- Chemin chaud : la fonction extraite du moteur est `#[inline(always)]` ; CodSpeed ne doit signaler aucune régression sur la PR.
- Tag, publication, Sonar : hors plan.

## Review Focus

Entrées que la spec implique et qu'un appelant rencontrera ; chacune a son test dans la tâche 1 (`tests/classify_payload_parity.rs`).

1. Ports inconnus (`None`, `None`) sur un payload que seul le port identifie : `Unknown`, jamais l'étiquette d'un autre transport (`mms_without_ports_is_unknown_not_radius`).
2. Protocole autre que TCP/UDP (SCTP, ICMP, ESP) avec un payload reconnaissable : `None` (`other_transports_are_never_probed`).
3. Payload vide, tous transports : `None` (même test).
4. Port réservé (UDP 5353) avec un contenu qui n'est pas mDNS : `None`, pas `Unknown` (`reserved_mdns_port_with_other_content_is_none`).
5. Segment TCP anormal (SYN+FIN) : `parse` ne sonde pas, la fonction classe ; la différence est figée, pas subie (`anomalous_tcp_is_the_documented_difference`).

---

## PR 1 — `feat/classify-payload-219` vers `main`

### Task 1: `classify_payload` et `classify_payload_with`

**Files:**
- Create: `tests/classify_payload_parity.rs`
- Modify: `src/parse/engine.rs` (extraction de l'étape L7 à transport), `src/parse/mod.rs` (les deux fonctions publiques), `src/lib.rs` (réexportations)

**Interfaces:**
- Produces:
  - `packet_parser::classify_payload(protocol: TransportProtocol, source_port: Option<u16>, destination_port: Option<u16>, payload: &[u8]) -> Option<Application>`
  - `packet_parser::classify_payload_with(protocol, source_port, destination_port, payload, config: &ParseConfig) -> Option<Application>`
  - `packet_parser::TransportProtocol` (réexportation de `parse::transport::protocols::TransportProtocol`)
  - interne : `PacketFlow::application_and_inner(transport: &Transport<'a>, depth: u8, decode_as: &[(u16, DecodeAsProtocol)]) -> (Option<Application>, Option<Box<PacketFlow<'a>>>)`, `#[inline(always)]`, `pub(super)`

- [ ] **Step 1: Écrire le test de parité et les tests ciblés (ils ne compilent pas encore)**

`tests/classify_payload_parity.rs`, avec `mod common;` pour `read_capture`, et un collecteur récursif local sur tout `pcaps_exemple/` (celui de `common` saute `s7comm/`).

```rust
/// pcaps_exemple/protocols/goose/iti_Sample_File_MMS_and_GOOSE.pcap, trame
/// 126, TCP 102 -> 1345 : MMS confirmed-ErrorPDU sous TPKT/COTP.
const MMS_OVER_COTP: &str =
    "0300002202f0800100010061153013020103a00ea20c800304a273a205a003870102";
/// pcaps_exemple/capture_sll2.pcap, trame 722, UDP 47715 -> 53 : requete
/// AAAA avec EDNS, 48 octets.
const DNS_QUERY_WITH_EDNS: &str = "0d060100000100000000000108756e6167692d657506616d617a6f6e03636f6d00001c000100002905ac000000000000";

fn label(application: Option<Application>) -> Option<&'static str>; // .map(|a| a.application_protocol)

#[test] fn classify_payload_answers_like_parse_on_the_whole_corpus()
// pour chaque flux aplati a transport TCP/UDP et payload Some, non anormal :
//   assert_eq!(classify_payload(t.protocol, t.source_port, t.destination_port, payload), flow.application)
// (comparaison des Option<Application> : PartialEq sur l'etiquette)
// message d'echec : capture, numero de trame, profondeur, ports, les deux etiquettes
// puis : assert!(compared >= 350_000) ; assert!(tunnels >= 93) (flux dont l'etiquette est VXLAN, Geneve ou GTP-U)

#[test] fn classify_payload_with_answers_like_parse_with_on_a_declared_port()
// The-Ultimate-PCAP.pcapng, ParseConfig::new().decode_as(3911, DecodeAsProtocol::Ssdp)
// meme egalite avec parse_with / classify_payload_with ;
// assert_eq!(flux ou classify_payload_with rend "SSDP" et classify_payload "Unknown", 5)

#[test] fn mms_on_iso_tsap_is_cotp()
// (Tcp, Some(102), Some(1345)) -> Some("COTP")
#[test] fn mms_without_ports_is_unknown_not_radius()
// (Tcp, None, None) -> Some("Unknown")
#[test] fn dns_query_on_port_53_is_dns()
// (Udp, Some(47715), Some(53)) -> Some("DNS")
#[test] fn other_transports_are_never_probed()
// Sctp, Icmp, Esp avec MMS_OVER_COTP -> None ; payload vide en Tcp et en Udp -> None
#[test] fn reserved_mdns_port_with_other_content_is_none()
// (Udp, Some(5353), Some(5353), MMS_OVER_COTP) -> None
#[test] fn anomalous_tcp_is_the_documented_difference()
// trame Ethernet/IPv4/TCP synthetique (le dit), drapeaux SYN|FIN (0x03), ports 102 -> 1345,
// payload MMS_OVER_COTP : parse(...).application est None et corrupted.layer == Transport ;
// classify_payload(Tcp, Some(102), Some(1345), payload) -> Some("COTP")
```

- [ ] **Step 2: Vérifier l'échec**

Run: `cargo test --test classify_payload_parity`
Expected: erreur de compilation, `classify_payload` introuvable dans `packet_parser`.

- [ ] **Step 3: Première implémentation, la table seule**

Dans `src/parse/mod.rs`, les deux fonctions publiques appellent `dispatch::classify` sur un `Transport { source_port, destination_port, protocol, payload: Some(payload), details: None }`, après le refus de tout protocole autre que `Tcp` et `Udp`. Réexportations dans `src/lib.rs`.

- [ ] **Step 4: Vérifier que la parité échoue sur les tunnels**

Run: `cargo test --test classify_payload_parity`
Expected: `classify_payload_answers_like_parse_on_the_whole_corpus` échoue sur un flux `VXLAN`, `Geneve` ou `GTP-U` (attendu par `parse`, `Unknown` rendu) ; les tests ciblés passent. C'est la preuve que le test de parité mord.

- [ ] **Step 5: Passer par le chemin du moteur**

Dans `src/parse/engine.rs`, extraire de `parse_l7_and_inner` la branche `Some(transport)` dans `application_and_inner` (signature ci-dessus) ; `parse_l7_and_inner` l'appelle. Les fonctions publiques appellent `PacketFlow::application_and_inner(&transport, 0, decode_as).0`.

- [ ] **Step 6: Vérifier le vert**

Run: `cargo test --test classify_payload_parity && cargo test --all-features --locked golden_pcaps`
Expected: 8 tests passent ; l'histogramme golden est inchangé.

- [ ] **Step 7: Rustdoc des deux fonctions, en anglais, avec doctest**

Contenu imposé : ce que rend la fonction (la valeur de `PacketFlow::application`), les trois cas `None`, `Some("Unknown")`, les noms de tunnel, le port inconnu passé `None`, la différence TCP anormal. Doctest sur `MMS_OVER_COTP` : `Some("COTP")` en TCP 102, `Some("Unknown")` sans port.

Run: `cargo test --doc classify_payload && RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features`
Expected: PASS, aucune alerte.

- [ ] **Step 8: Commit**

```bash
git add docs/superpowers tests/classify_payload_parity.rs src/parse/engine.rs src/parse/mod.rs src/lib.rs
git commit -m "feat(dispatch): classify_payload, la classification L7 sans trame (#219)"
```

### Task 2: Basculer les appelants du dépôt

**Files:**
- Modify: `src/parse/application/mod.rs` (tests), `tests/ssh_golden.rs:88-108`, `examples/decortique.rs`, `examples/pars_quic.rs`, `fuzz/fuzz_targets/parse_application.rs`, `fuzz/fuzz_targets/parse_valmet_dna.rs`, `fuzz/fuzz_targets/parse_wireguard.rs`

**Interfaces:**
- Consumes: `classify_payload`, `TransportProtocol` (tâche 1) ; `frames::ethernet_ipv4_payload(TransportProtocol, u16, u16, &[u8]) -> Vec<u8>` de `fuzz/oracles/frames.rs`.

- [ ] **Step 1: Tests unitaires de `src/parse/application/mod.rs`**

Chaque test passe à `classify_payload(<transport>, None, None, payload)` sous le transport de sa règle : `Udp` pour NTP, DHCP, QUIC, Valmet DNA, SNMP, SRVLOC ; `Tcp` pour PostgreSQL, GIOP, HTTP, MQTT ; les deux pour `test_unknown_payload_falls_through`. Mêmes étiquettes attendues. Deux tests restent sur `Application::try_from`, sous un commentaire « impl conservee jusqu'a la 12.0 (#219) » : `test_empty_packet_is_an_error` et `test_blind_try_from_still_answers` (le télégramme Valmet DNA réel, `"Valmet DNA"`).

Run: `cargo test --lib parse::application::tests`
Expected: PASS, même nombre de tests plus un.

- [ ] **Step 2: `tests/ssh_golden.rs`, exemples**

`text_that_merely_starts_with_ssh_is_not_detected` : `classify_payload(Tcp, None, None, payload)`. `examples/decortique.rs` : `classify_payload(t.protocol, t.source_port, t.destination_port, p)`. `examples/pars_quic.rs` : `classify_payload(Udp, None, None, …)`.

Run: `cargo test --test ssh_golden && cargo build --examples`
Expected: PASS.

- [ ] **Step 3: Cibles de fuzz**

`parse_application` : `let [selector, sp_hi, sp_lo, dp_hi, dp_lo, payload @ ..] = data else { return };`
- `selector & 1` : `Tcp` (0) ou `Udp` (1) ;
- `selector & 2` : ports `None`, `None` — sans panic, rien d'autre ;
- `selector & 4` : `TransportProtocol::from_u8(sp_hi)` ; s'il n'est ni `Tcp` ni `Udp`, `assert!(…is_none())` ;
- sinon : `assert_eq!(classify_payload(protocol, Some(sp), Some(dp), payload), parse(LinkType::ETHERNET, &ethernet_ipv4_payload(protocol, sp, dp, payload)).expect("trame valide").application)`, pour `payload.len() <= 1400`.

`parse_valmet_dna`, `parse_wireguard` : `classify_payload(TransportProtocol::Udp, None, None, data)` ; les assertions gardent leur sens (`is_some_and(|a| a.application_protocol == "…")`).

Run: `cd fuzz && for t in parse_application parse_valmet_dna parse_wireguard; do cargo +nightly fuzz run $t -- -runs=20000 || break; done`
Expected: trois fins normales.

- [ ] **Step 4: Dix minutes par cible touchée (en fond, pendant la tâche 3)**

Run: `cargo +nightly fuzz run <cible> -- -max_total_time=600` pour les trois cibles.
Expected: aucun crash ; noter exécutions et couverture pour la PR.

- [ ] **Step 5: Vérifier qu'il ne reste que l'impl et ses deux tests**

Run: `grep -rn "Application::try_from" src tests examples fuzz/fuzz_targets benches`
Expected: `src/parse/application/mod.rs` (rustdoc, les deux tests), les commentaires de `src/parse/dispatch/` ; rien dans `fuzz/`, `examples/`, `tests/`.

- [ ] **Step 6: Commit**

```bash
git commit -am "test(dispatch): tests, exemples et cibles de fuzz passent a classify_payload (#219)"
```

### Task 3: Annonce et documentation

**Files:**
- Create: `MIGRATION-12.md`
- Modify: `src/parse/application/mod.rs` (rustdoc de `Application` et de l'impl), `src/parse/dispatch/mod.rs` (doc de `classify_blind`), `README.md:87-93`, `docs/reference.md:107-118`, `METHODE_AJOUT_PROTOCOLE.md` (voie 1), `ROADMAP.md` (ligne #209 du tableau), `CHANGELOG.md` (`[Non publie]`), `CONTRIBUTING.md` (liste « Where the rules live »)

- [ ] **Step 1: Rustdoc**

Sur `Application` et sur l'impl : « scheduled for removal in 12.0 (#219) », pourquoi (ni transport ni ports), lien vers `classify_payload`, et la raison de l'absence de `#[deprecated]` (rustc le refuse sur un impl de trait).

- [ ] **Step 2: `MIGRATION-12.md`**

En-tête : la 12.0 n'est pas publiée, pas avant mars 2027 ; une entrée par rupture, avant, après, raison. Première entrée, « `Application::try_from(&[u8])` est retiré » : avant/après en code (`Result` devient `Option` ; payload vide : `None` au lieu de `Err(EmptyPacket)`), quoi passer quand on n'a pas les ports (`None`), ce qui change dans les étiquettes (les chiffres du §1 de la spec), disponible dès la prochaine 11.x.

- [ ] **Step 3: Tables d'API, METHODE, ROADMAP, CHANGELOG, CONTRIBUTING**

README et `docs/reference.md` : une ligne « Classify a payload without its frame (transport and ports known) ». METHODE voie 1 : `Application::try_from` part en 12.0, les tests de sonde aveugle s'écrivent avec `classify_payload`. ROADMAP : `#219 … (classify_payload fait, non publie ; retrait sur release/12.0.0)`. CHANGELOG : `### Ajoute` (les deux fonctions, la parité mesurée, la réexportation) et `### Deprecie` (l'impl, sans attribut, et pourquoi). CONTRIBUTING : `MIGRATION-12.md` dans la liste.

- [ ] **Step 4: Vérifier**

Run: `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features && cargo test --test rustdoc_mermaid && cargo package --list --allow-dirty | grep -c MIGRATION-12`
Expected: doc sans alerte, test vert, `0` (le guide n'entre dans le paquet qu'avec la 12.0).

- [ ] **Step 5: Commit**

```bash
git commit -am "docs(dispatch): annonce du retrait de Application::try_from, MIGRATION-12.md (#219)"
```

### Task 4: Gates, PR 1, fusion

- [ ] **Step 1: Les gates de Global Constraints, dans l'ordre.** Expected: tout vert ; semver-checks « no semver update required » ou mineure.
- [ ] **Step 2: Résultats du fuzz de la tâche 2 étape 4.** Expected: aucun crash.
- [ ] **Step 3: `git push -u origin feat/classify-payload-219`, puis `gh pr create --base main`.** Corps : ce qui est livré, la mesure de parité, les choix marqués « mon choix » dans la spec, les sorties des gates. Référence `#219` sans `closes`.
- [ ] **Step 4: Attendre la CI.** Expected: les jobs GitHub Actions verts (les trois statuts FOSSA externes restent `pending`), CodSpeed sans régression.
- [ ] **Step 5: `gh pr merge <n> --merge --delete-branch`.**

---

## PR 2 — `feat/retrait-try-from-219` vers `release/12.0.0`

### Task 5: Ouvrir la branche d'intégration et retirer l'impl

**Files:**
- Modify: `Cargo.toml` (`version`, `include`), `Cargo.lock`, `fuzz/Cargo.lock`, `benches/Cargo.lock`, `tools/lab/Cargo.lock`, `src/parse/application/mod.rs`, `src/parse/dispatch/mod.rs`, `src/parse/dispatch/rules.rs` (commentaires), `src/parse/dispatch/tests.rs`, `METHODE_AJOUT_PROTOCOLE.md`, `MIGRATION-12.md`, `CHANGELOG.md`, `ROADMAP.md`

- [ ] **Step 1: Branches**

```bash
git switch main && git pull && git switch -c release/12.0.0 && git push -u origin release/12.0.0
git switch -c feat/retrait-try-from-219
```

- [ ] **Step 2: Le test qui échoue tant que l'impl existe**

Dans la rustdoc d'`Application`, un doctest `compile_fail` :

```rust
/// ```compile_fail
/// use packet_parser::Application;
/// let _ = Application::try_from(&b"GET / HTTP/1.1\r\n\r\n"[..]);
/// ```
```

Run: `cargo test --doc parse::application`
Expected: FAIL (« test compiled successfully »).

- [ ] **Step 3: `version = "12.0.0"`** dans `Cargo.toml`, puis `cargo update -p packet_parser` à la racine et avec `--manifest-path` pour `fuzz/`, `benches/`, `tools/lab/`. Expected: une seule ligne changée par fichier de lock.

- [ ] **Step 4: Retirer** `impl TryFrom<&[u8]> for Application`, `classify_blind`, les deux tests restés sur l'impl ; la rustdoc d'`Application` dit que la classification passe par `parse` ou `classify_payload`. `blind_rules_mirror_the_public_cascade_order` devient `blind_rules_order_is_frozen` (commentaire et message sans la cascade publique ; METHODE suit). Les commentaires de `rules.rs` et de `dispatch/mod.rs` ne citent plus `Application::try_from`.

- [ ] **Step 5: Vérifier**

Run: `cargo test --workspace --all-features --locked && grep -rn "Application::try_from\|classify_blind" src tests examples fuzz/fuzz_targets benches`
Expected: suite verte, doctest `compile_fail` vert ; le grep ne rend que le doctest.

- [ ] **Step 6: `MIGRATION-12.md`** (l'entrée passe de « à venir » à « fait sur `release/12.0.0` »), `/MIGRATION-12.md` dans `include`, CHANGELOG `### Rupture`, ROADMAP.

- [ ] **Step 7: Commit**

```bash
git commit -am "feat(dispatch)!: retrait de TryFrom<&[u8]> for Application (#219)"
```

### Task 6: `ApplicationError` et `ParseError::Application`, sans constructeur

**Files:**
- Modify: `src/errors/application/mod.rs`, `src/errors/mod.rs`, `MIGRATION-12.md`, `CHANGELOG.md`

- [ ] **Step 1: Vérifier qu'ils sont morts.** Run: `grep -rn "ApplicationError\|ParseError::Application" src tests examples fuzz/fuzz_targets benches tools`. Expected: leurs deux définitions seulement.
- [ ] **Step 2: Retirer** l'enum et la variante ; une entrée chacun dans `MIGRATION-12.md` et dans la section `Rupture`.
- [ ] **Step 3: Run:** `cargo test --workspace --all-features --locked`. Expected: PASS.
- [ ] **Step 4: Commit à part** : `refactor(errors)!: ApplicationError et ParseError::Application, sans constructeur (#219)`.

### Task 7: Preuve semver, PR 2, fusion dans la branche d'intégration

- [ ] **Step 1: Run:** `cargo semver-checks check-release -p packet_parser --baseline-version 11.8.2 --release-type minor`. Expected: échec, dont la liste est exactement celle de `MIGRATION-12.md` ; noter ce que l'outil ne voit pas (un impl de trait retiré). Puis sans `--release-type` : vert (12.0.0 déclarée).
- [ ] **Step 2: Les gates de Global Constraints.** `cargo package --list --allow-dirty | grep MIGRATION-12` : présent.
- [ ] **Step 3: Push, `gh pr create --base release/12.0.0`**, sortie de semver-checks dans le corps. CI verte, fusion.

---

## Suivi

### Task 8: Issues et mémoire

- [ ] **Step 1: #219** — corriger la piste (pas de `#[deprecated]` : rustdoc, CHANGELOG, `MIGRATION-12.md`), cocher les critères avec leur preuve (PR, test, grep), commentaire qui cite les deux PR. L'issue reste ouverte jusqu'à la fusion de `release/12.0.0` dans `main`.
- [ ] **Step 2: Livre** — tâche `Akmot9/packet-parser-book` : les dix pages qui citent `Application::try_from`, à faire après la publication qui contient `classify_payload` ; référence `Akmot9/Packet-parser#219`.
- [ ] **Step 3: Modbus/UDP** — issue sur `Akmot9/Packet-parser` : 38 trames réelles de `The-Ultimate-PCAP.pcapng` (UDP 502, tshark `mbudp`) que `parse` rend `Unknown` ; constat, piste, critères, au format maison.
- [ ] **Step 4: Mémoire** — la branche `release/12.0.0` existe, ce qu'elle porte, la règle de fusion de `main` (garder 12.0.0).
