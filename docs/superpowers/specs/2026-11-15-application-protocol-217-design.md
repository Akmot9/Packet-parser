# `ApplicationProtocol`, un enum à la place de l'étiquette texte (#217) : conception

Date : 2026-11-15. Issue : Akmot9/Packet-parser#217, feature #209.
Validée par Cyprien le 2026-11-15.

## Intention

`Application { application_protocol: &'static str }` oblige l'appelant à
comparer des chaînes : pas d'exhaustivité, une faute de frappe est
silencieuse, et un renommage d'étiquette est une rupture que
`cargo semver-checks` ne voit pas.

## Buts, non-buts, anti-buts

- **Buts.** Un enum `ApplicationProtocol` couvre toutes les étiquettes ; la
  table de dispatch, « Decode As », les tunnels et STP le portent.
- **Non-buts.** `ApplicationOwned.protocol` reste une `String`. Aucune
  étiquette ne change de texte.
- **Anti-buts.** Un octet du JSON owned qui bouge. Une étiquette produite
  quelque part sans variante.

## Approches

- **Retenue : remplacer le champ.** `Application.protocol:
  ApplicationProtocol` remplace `application_protocol`, directement sur
  `release/12.0.0`. Cyprien est le seul appelant de la crate : pas de
  transition en 11.x.
- **Écartée : garder le champ texte et ajouter `protocol()`.** Elle ne sert
  qu'à une transition dont personne n'a besoin, et laisse deux sources de
  vérité.

## Ce qui change

- `src/parse/application/protocol.rs` : `#[non_exhaustive] pub enum
  ApplicationProtocol`, `Debug, Clone, Copy, PartialEq, Eq, Hash`, une
  variante par étiquette (53), `Unknown` comprise. `label(&self) -> &'static
  str` rend la chaîne actuelle à l'octet près ; `ALL: &[Self]` ; `Display`
  écrit `label()` ; `FromStr` l'inverse, erreur `UnknownApplicationLabel` ;
  `Serialize` écrit `label()`.
- `Application { pub protocol: ApplicationProtocol }`, sérialisé sous la clé
  `application_protocol`. `PartialEq`, `Eq` et `Hash` dérivés.
- `ApplicationProtocol` est réexporté à la racine de la crate.
- `Rule.label`, `DecodeAsProtocol::rule`, les noms de tunnels et STP passent
  à l'enum.
- Les tests, exemples, cibles de fuzz, `benches` et `tools/lab` comparent
  `.protocol.label()` aux mêmes chaînes qu'avant.
- Tests nouveaux : aller-retour `label()` / `FromStr` sur `ALL`, unicité des
  étiquettes, liste des étiquettes figée, `ALL` complet.
- `MIGRATION-12.md` : la réécriture d'un `match` sur chaîne en `match` sur
  enum. CHANGELOG `Rupture`.

## Laissé à l'exécution

Les noms exacts des variantes (CamelCase du protocole : `ModbusTcp`,
`Iec104`, `OpcUa`, `GtpU`, `IpInIp`, `NatKeepalive`…).
