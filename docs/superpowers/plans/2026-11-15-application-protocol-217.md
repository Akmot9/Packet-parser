# `ApplicationProtocol` (#217) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remplacer l'étiquette texte d'`Application` par un enum non exhaustif, sans changer un octet du JSON owned.

**Architecture:** Un nouveau module porte l'enum et ses conversions. Le champ d'`Application` change de nom et de type ; la table de dispatch, « Decode As », les tunnels et STP produisent l'enum. Les appelants du dépôt lisent `.protocol.label()`.

**Tech Stack:** Rust 2024, MSRV 1.88, serde.

**Spec:** `docs/superpowers/specs/2026-11-15-application-protocol-217-design.md`

## Global Constraints

- Branche `feat/application-protocol-217`, PR vers `release/12.0.0` (version 12.0.0 conservée).
- Aucune étiquette ne change de texte ; `tests/json_schema_parity.rs` et `tests/golden_pcaps.rs` passent sans modification de leurs attentes.
- Commentaires, commits, CHANGELOG en français sans accents ; `MIGRATION-12.md` et PR en français accentué.
- Avant de pousser : fmt, clippy stable `-D warnings`, `cargo +1.88 check --all-targets`, `cargo test`, `cargo doc --no-deps`, build du fuzz, de `tools/lab` et de `benches`.

## Review Focus

- Une étiquette inconnue passée à `FromStr` rend une erreur, pas `Unknown` (tâche 1).
- `FromStr` est sensible à la casse : `"mdns"` n'est pas `"mDNS"` (tâche 1).
- Le JSON emprunté d'`Application` garde la clé `application_protocol` (tâche 2).
- Une variante ajoutée sans entrée dans `ALL` est refusée par un test (tâche 1).
- `Display` d'`Application` garde son espace final (tâche 2).

---

### Task 1: l'enum et ses conversions

**Files:**
- Create: `src/parse/application/protocol.rs`
- Modify: `src/parse/application/mod.rs` (`pub mod protocol;`), `src/lib.rs` (réexport)

**Interfaces:**
- Produces: `ApplicationProtocol` (53 variantes), `pub const ALL: &'static [Self]`, `pub const fn label(self) -> &'static str`, `impl Display`, `impl FromStr<Err = UnknownApplicationLabel>`, `impl Serialize`, `pub struct UnknownApplicationLabel(pub String)`.

- [ ] **Step 1 :** écrire les tests dans le module : `every_label_round_trips`, `labels_are_unique`, `labels_are_frozen` (la liste triée des 53 chaînes en dur), `all_lists_every_variant` (un `match` exhaustif sans bras `_` qui compte), `unknown_label_is_an_error` (`"mdns"` et `"Modbus"` refusés), `serializes_as_its_label`.
- [ ] **Step 2 :** ils ne compilent pas.
- [ ] **Step 3 :** écrire l'enum par une macro `(Variante, "etiquette")`.
- [ ] **Step 4 :** `cargo test --lib application::protocol` vert.
- [ ] **Step 5 :** commit `feat(application): enum ApplicationProtocol (#217)`.

### Task 2: `Application.protocol` et les producteurs

**Files:**
- Modify: `src/parse/application/mod.rs`, `src/parse/dispatch/{mod,rules}.rs`, `src/parse/engine.rs`, `src/parse/tunnel/mod.rs`, `src/displays/application/mod.rs`, `src/owned/mod.rs`, tous les appelants (`src`, `tests`, `examples`, `fuzz`, `benches`, `tools/lab`)

**Interfaces:**
- Consumes: tâche 1.
- Produces: `Application { pub protocol: ApplicationProtocol }` avec `#[serde(rename = "application_protocol")]`.

- [ ] **Step 1 :** test `application_serializes_under_its_historical_key` dans `src/parse/application/mod.rs` : `{"application_protocol":"NTP"}`.
- [ ] **Step 2 :** il ne compile pas.
- [ ] **Step 3 :** changer le champ ; `Rule.label: ApplicationProtocol` ; `DecodeAsProtocol::rule` rend l'enum ; tunnels et STP aussi ; appelants en `.protocol.label()`.
- [ ] **Step 4 :** `cargo test` vert, sans toucher aux attentes des golden.
- [ ] **Step 5 :** commit `refactor(application)!: Application.protocol porte l'enum (#217)`.

### Task 3: documentation et PR

- [ ] **Step 1 :** `MIGRATION-12.md` (section #217, avant/après d'un `match`), CHANGELOG `Rupture`, ROADMAP, rustdoc de `lib.rs`, `docs/reference.md`, README si le champ y figure.
- [ ] **Step 2 :** toutes les vérifications des Global Constraints ; `cargo semver-checks --baseline-version 11.8.2 --release-type minor` comparé au guide.
- [ ] **Step 3 :** commit de doc, pousser, PR vers `release/12.0.0`, fusion quand la CI est verte ; mettre à jour #217.
