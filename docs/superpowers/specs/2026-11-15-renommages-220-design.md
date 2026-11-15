# Renommages groupés de la 12.0 (#220) : conception

Date : 2026-11-15. Issue : Akmot9/Packet-parser#220, feature #209.

## Intention

Des noms publics portent une faute (`copt`, `mac_addres`) ou un mauvais nom
(`NatDetection`, les types RADIUS 124 et 125). Chacun est une rupture
isolée ; groupés dans la 12.0, ils font une migration lisible, et aucune
13.0 ne s'ouvre pour une faute de frappe.

## Buts, non-buts, anti-buts

- **Buts.** Les bons noms sont utilisables dès la prochaine 11.x. Les anciens
  disparaissent en 12.0. `MIGRATION-12.md` a une ligne par symbole.
- **Non-buts.** Aucun changement de comportement, d'étiquette ou de JSON.
  Pas de publication, pas de tag.
- **Anti-buts.** Une rupture en 11.x. Un discriminant d'enum qui bouge. Un
  nom retiré en 12.0 sans entrée dans le guide.

## Contraintes

- Deux PR, comme #219 : la partie sans rupture sur `main`, le retrait sur
  `release/12.0.0` (qui garde `version = "12.0.0"`).
- `cargo semver-checks` : rien à signaler sur `main` ; sur la branche, il ne
  signale que ce que le guide liste.
- Clippy stable et MSRV 1.88 avant de pousser.

## Approches pour les deux modules

Mesuré sur rustc 1.88 et 1.100 : `#[deprecated] pub use cotp as copt;`
n'avertit pas un appelant externe, pas plus qu'un module déprécié qui
réexporte par `pub use super::cotp::*`. Seuls les éléments définis dans un
module déprécié avertissent.

- **A. Alias muet** : `pub use cotp as copt;`, annoncé par la rustdoc, le
  CHANGELOG et le guide. Une ligne, aucun risque.
- **B. Ancien module rempli d'alias de types dépréciés** : le compilateur
  avertit, mais un alias de type ne remplace pas le constructeur d'un tuple
  struct. `mac_addres::MacAddress(octets)` ne compilerait plus : une rupture
  en mineure.

**Retenu : A pour les deux modules** (choix de Cyprien, 2026-11-15).

## Ce qui change

### PR 1, sur `main` (mineure, sans rupture)

| Ancien nom, conservé | Nouveau nom |
|---|---|
| `parse::application::protocols::copt` | `parse::application::protocols::cotp` |
| `errors::application::copt` | `errors::application::cotp` |
| `parse::data_link::mac_addres` | `parse::data_link::mac_address` |
| `errors::data_link::mac_addres` | `errors::data_link::mac_address` |
| `ike::PayloadType::NatDetection` (dépréciée) | constante associée `PayloadType::NatDiscovery` |

- Les fichiers sont renommés (`git mv`) ; l'ancien chemin est un
  `pub use … as …;` avec une rustdoc qui annonce le retrait.
- `checks` et `displays` sont internes : renommés sans alias.
- `NatDiscovery` suit le modèle RADIUS de la 11.7.0 : constante associée,
  variante `#[deprecated]`, le code de la crate passe à la constante.
- Tout le dépôt (tests, exemples, fuzz, lab, doc) passe aux nouveaux noms.
- Un test fige les discriminants `as u8` de `NatDetection`,
  `MipHomeAgentAddress` et `MipHomeAgentHost`.
- `MIGRATION-12.md` : une section « Renommages », état « annoncé ».
- CHANGELOG `[Non publie]` : `Ajoute` et `Deprecie`.

### PR 2, sur `release/12.0.0` (rupture)

- Les quatre alias de modules sont retirés.
- Les variantes sont renommées sur place, à la même position :
  `NatDetection` → `NatDiscovery`, `MipHomeAgentAddress` →
  `Mip6FeatureVector`, `MipHomeAgentHost` → `Mip6HomeLinkPrefix`. Les
  constantes associées du même nom disparaissent ; les appelants qui les
  utilisaient ne changent rien.
- Le test de discriminants passe aux nouveaux noms, mêmes valeurs.
- Trois dépréciations sans issue partent aussi (mon choix, hors de l'issue) :
  `SrvlocHeaderV1::encoding`, `convert::hex_stream_to_bytes`,
  `S7CommPacket::MIN_SIZES`. Commit séparé, pour pouvoir le laisser tomber.
- `MIGRATION-12.md` passe à l'état « fait » ; CHANGELOG `Rupture`.
- Le guide note que `{:?}` rend le nouveau nom des variantes. Ces types ne
  sont pas sérialisés : le JSON owned ne bouge pas.

## Relecture des autres noms publics

Les mots des 2 351 identifiants publics (modules, types, fonctions,
constantes, champs) et des variantes d'enum ont été comparés au dictionnaire
anglais. Hors sigles et noms de protocoles, deux mots seulement sont
fautifs : `addres` et `copt`. Cette relecture voit les fautes de frappe, pas
un nom correct mais faux au regard d'une RFC, comme `NatDetection`.

## Laissé à l'exécution

- La forme exacte de la rustdoc des alias.
- Le découpage en commits de chaque PR.
- La preuve de la rupture pour chaque retrait (semver-checks, ou le
  compilateur là où il ne voit rien).
