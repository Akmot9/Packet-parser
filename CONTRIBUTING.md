# Contributing to packet_parser

This page says where the rules are written, what to check before a pull
request, and how to release. It links to the sources instead of copying them.
Issues, commit messages and the changelog are written in French.

## Where the rules live

- [`METHODE_AJOUT_PROTOCOLE.md`](METHODE_AJOUT_PROTOCOLE.md) (French): how to
  write a decoder, and its [checklist](METHODE_AJOUT_PROTOCOLE.md#7-checklist-avant-commit).
- [The book](https://akmot9.github.io/packet-parser-book/): the design, layer by
  layer ([its repository](https://github.com/Akmot9/packet-parser-book)).
- [`ROADMAP.md`](ROADMAP.md): open epics, versions, and the
  [stability rules](ROADMAP.md#4-regles-de-la-fenetre-de-stabilite).
- [`CHANGELOG.md`](CHANGELOG.md): history, one section per release.
- [`MIGRATION-11.md`](MIGRATION-11.md): every breaking change of 11.0.0.
- [`pcaps_exemple/README.md`](pcaps_exemple/README.md): the capture corpus.

## Before you open a pull request

CI already runs these on every PR ([`ci.yml`](.github/workflows/ci.yml),
[`cargo-deny.yml`](.github/workflows/cargo-deny.yml)):

- `cargo fmt --all -- --check`, `cargo audit` and `cargo deny check`;
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`, on the latest stable;
- `cargo test --workspace --all-features --locked`, and the crate tests on macOS;
- `cargo check -p packet_parser --all-features --all-targets --locked` on 1.88, the MSRV;
- `cargo semver-checks` against the latest crates.io version (job `semver`, #213);
- every fuzz target is declared, builds, and runs once (`-runs=1`).

CI does not check these, so do them yourself:

```bash
rustup update stable   # CI runs clippy on the latest stable: match it
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
cargo doc-mermaid      # the docs with their mermaid diagrams drawn, as on docs.rs
cargo +nightly fuzz run <target> -- -max_total_time=600   # each target you touched
```

- An entry under `## [Non publie]` in `CHANGELOG.md`, and the task struck through
  in the `ROADMAP.md` table: `~~#N~~ ... (fait, non publie)`.
- For a decoder, the rest of the [METHODE checklist](METHODE_AJOUT_PROTOCOLE.md#7-checklist-avant-commit):
  golden test on real frames, negative corpus, protocol lists of both READMEs.
- The workspace members need libpcap: `sudo apt-get install libpcap-dev`.

## New enum variants go last

Add a variant at the end of its enum. Inserted higher, it shifts the
discriminant of every variant after it: that breaks the API, even for a
`#[non_exhaustive]` enum. The `semver` job rejects it (#213); see the
[METHODE checklist](METHODE_AJOUT_PROTOCOLE.md#7-checklist-avant-commit).

## Releasing a version

As done for 11.7.0 and 11.8.0 (#206, #229):

1. From an up-to-date `main`, create `chore/release-X.Y.Z`. Read `[Non publie]` to
   choose patch, minor or major. A major must be planned in the ROADMAP and come
   with a `MIGRATION-<N>.md`.
2. Set `version = "X.Y.Z"` in `Cargo.toml`, then run `cargo update -p packet_parser`
   and `cargo update -p packet_parser --manifest-path fuzz/Cargo.toml`. In
   `Cargo.lock` and `fuzz/Cargo.lock`, only the `packet_parser` line changes.
3. Change the install line `packet_parser = "X.Y.Z"` in `README.md` and `README-fr.md`.
4. In `CHANGELOG.md`, insert `## [X.Y.Z] - YYYY-MM-DD` right below `## [Non publie]` (now empty).
5. In `ROADMAP.md`, write a new `Etat au YYYY-MM-DD` paragraph at the top; the
   old one becomes `Etat anterieur (...)`.
6. Run the checklist above, then `cargo semver-checks check-release -p packet_parser`
   (it now checks the declared bump), `cargo publish --dry-run --locked`, and
   `cargo package --list` (no `pcaps_exemple/` file).
7. Commit `chore(release): prepare vX.Y.Z`, list the results in the PR, merge when CI is green.
8. Tag the merge commit on `main` and push the tag:
   `git switch main && git pull && git tag -a vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z`.
9. **Pushing the tag publishes the crate**, through [`publish.yml`](.github/workflows/publish.yml):
   tag checked against `Cargo.toml`, `cargo semver-checks check-release`, then
   `cargo publish`. **This cannot be undone**: crates.io can yank a version,
   never replace or delete it. Do not start the workflow by hand: that skips the tag check.
10. Check the run, crates.io and docs.rs. There is no GitHub release. Then move
    [the book](https://github.com/Akmot9/packet-parser-book) to the new version.

## Issues

- Titles start with `[Epic]`, `[Feature]` or `[Task]`. An epic groups features,
  a feature groups tasks. Examples: #207, #208, #212.
- A child starts with `Parent : #N`, then `Priorité : **P1**` (P1 to P3, P1 first).
  The parent lists its children as checkboxes under `### Sous-issues`.
- A task has `## Constat` (what was observed), `## Piste` (the proposed fix), a line
  `Semver : patch` (or `mineure`, `majeure`, `sans objet`), and
  `### Critères d'acceptation` as `- [ ]` checkboxes, ticked when done, with the proof.
- Labels (`gh api repos/Akmot9/Packet-parser/labels`): `epic`, `feature`, `task`,
  `bug`, `enhancement`, `documentation`; `sev:critique`, `sev:haute`,
  `sev:moyenne`, `sev:basse`; `effort:S` (under half a day), `effort:M` (one or
  two days), `effort:L` (more); `phase-12.0` for the breaks grouped in 12.0.
  The nightly fuzz workflow opens `fuzz-failure` issues itself.

## Commits and branches

- Subject in French, without accents: `type(scope): summary (#N)`.
- Types in use: `feat(<proto>)`, `fix(<proto>)`, `fix(dispatch)`, `test(<area>)`,
  `docs(<area>)` or `docs:`, `ci:`, `chore(release)`.
- Branches: `feat/<topic>-<N>`, `fix/<topic>-<N>`, `docs/...`, `ci/...`,
  `chore/release-X.Y.Z`. PRs are merged with a merge commit.

## Capture corpus

- Golden tests use real captured frames only. Synthetic bytes are for targeted
  unit tests and must say so ([rule](METHODE_AJOUT_PROTOCOLE.md#golden-tests-sur-trames-reelles)).
- Each capture folder in `pcaps_exemple/` has a `SOURCE.md`: where the capture
  comes from, what was anonymised or cut, and its licence, whose text goes in
  [`pcaps_exemple/LICENSES/`](pcaps_exemple/LICENSES/README.md) (#104).
  Example: [valmet_dna](pcaps_exemple/protocols/valmet_dna/SOURCE.md).
- No sensitive data: anonymise before you commit.
