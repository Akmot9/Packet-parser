# `classify_payload` — classer un payload sans sa trame, à la place de `TryFrom<&[u8]> for Application` (#219)

Date : 2026-11-14 — Statut : approche choisie par le mainteneur le
2026-11-14 (« retrait maintenant, sur `release/12.0.0` »). Les points marqués
**mon choix** n'ont pas été discutés : ils se corrigent à la relecture des PR.

## 1. But

Qu'il n'existe plus de classification L7 publique qui ignore le transport et
les ports. `Application::try_from(&[u8])` ne voit que les octets : elle saute
les règles à port de la table `RULES` et n'applique pas ses gardes de
transport (`classify_blind`, #216). C'est une seconde porte publique, qui ne
répond pas comme `parse`.

Mesure du 2026-11-14 sur tout `pcaps_exemple/` (210 captures, 387 123 trames,
254 107 flux TCP/UDP à payload non vide) : `try_from` et `parse` divergent sur
9 307 flux (3,7 %).

| Écart | Flux |
|---|---|
| `parse` reconnaît le protocole grâce au port, `try_from` rend `Unknown` | 8 004 |
| NBNS, mDNS, LLMNR rendus `DNS` (même format, seul le port les distingue) | 1 246 |
| Modbus/UDP sur 502 : `try_from` dit `ModbusTCP`, `parse` dit `Unknown` (trou de `parse`, hors sujet ici) | 38 |
| Autre protocole, faux : MMS sur TCP 102 rendu `RADIUS` (13), réponses SSDP rendues `HTTP` (5), requête DNS rendue `NTP` (1) | 19 |

Critère de succès : une fonction publique rend, pour un transport, deux ports
et un payload, l'étiquette que `parse` met dans `PacketFlow::application`,
flux pour flux sur tout le corpus ; sur `release/12.0.0`, l'impl `TryFrom`
n'existe plus et `cargo semver-checks` ne signale rien que
`MIGRATION-12.md` ne liste.

## 2. Contraintes trouvées dans le dépôt

- Le retrait est une rupture : pas sur `main` avant la 12.0, que le ROADMAP
  place en mars 2027 au plus tôt. D'où la branche d'intégration.
- `#[deprecated]` sur un impl de trait, ou sur sa méthode, est refusé par
  rustc (`useless_deprecated`, refusé par défaut, vérifié en 1.99.1 et en
  1.88). L'étape « 11.x : `#[deprecated]` » de l'issue est donc impossible :
  l'annonce passe par la rustdoc, le CHANGELOG et `MIGRATION-12.md`.
- `ApplicationProtocol` n'existe pas avant #217 : la fonction rend
  `Option<Application>`, le type même de `PacketFlow::application`. Quand
  #217 changera le champ, la signature ne bougera pas.
- La table seule ne rend pas l'étiquette de `parse` : VXLAN, Geneve, GTP-U et
  CAPWAP sont décidés avant elle, par `tunnel::detect_inner`.
- CI : « une majeure s'annonce dans `Cargo.toml` dès la première PR qui
  casse » (`ci.yml`, job `semver`). La branche d'intégration porte donc
  `version = "12.0.0"`.
- Le livre cite `Application::try_from` dans dix pages et épingle
  `=11.8.0` : il ne peut suivre qu'après une publication qui contient la
  fonction.

## 3. Approches

1. **Fonction libre, par le chemin du moteur** (retenue). `classify_payload`
   construit un `Transport` et appelle l'étape L7 que `parse` appelle. Même
   réponse par construction, tunnels compris ; rien à tenir d'accord.
2. **Fonction libre, la table seule** (`dispatch::classify`). Plus simple,
   mais les 93 flux de tunnel du corpus (GTP-U 34, Geneve 30, VXLAN 29)
   sortiraient `Unknown` au lieu de leur nom : une divergence avec `parse`,
   ce que l'issue supprime. Écartée.
3. **Méthode de `Transport`**. `Transport` est `#[non_exhaustive]` : seul
   `Transport::try_from_parts` le construit, à partir de l'en-tête L4. Qui a
   un flux TCP réassemblé ou un payload stocké sans en-tête ne peut pas
   l'appeler. Écartée.

Pour le retrait, deux calendriers ont été proposés au mainteneur : plus tard,
à l'ouverture de la branche 12.0 (ma recommandation), ou maintenant sur
`release/12.0.0`, comme `release/11.0.0` l'an dernier. **Il a choisi
maintenant.**

## 4. Design

### 4.1 Sur `main`, sans rupture (PR 1, `feat/classify-payload-219`)

```rust
pub fn classify_payload(
    protocol: TransportProtocol,
    source_port: Option<u16>,
    destination_port: Option<u16>,
    payload: &[u8],
) -> Option<Application>;

pub fn classify_payload_with(
    protocol: TransportProtocol,
    source_port: Option<u16>,
    destination_port: Option<u16>,
    payload: &[u8],
    config: &ParseConfig,
) -> Option<Application>;
```

- Dans `packet_parser::parse`, réexportées à la racine comme `parse` et
  `parse_with`. `TransportProtocol` gagne une réexportation à la racine
  (**mon choix**, pour que la signature se nomme sans chemin de quatre
  modules).
- Valeur de retour : celle de `PacketFlow::application`. `None` là où
  `parse` laisse la couche vide (payload vide ; port réservé à mDNS ou LLMNR
  dont le contenu n'en est pas) ; `Some("Unknown")` pour un payload sondé
  sans succès ; le nom du tunnel pour un datagramme VXLAN, Geneve, GTP-U ou
  CAPWAP.
- **Mon choix** : tout protocole autre que TCP et UDP rend `None`. `parse`
  ne sonde rien au-dessus d'ICMP, d'ESP ou d'un protocole sans décodeur
  (`Transport::payload` y reste `None`) ; la fonction ne doit pas rouvrir
  une porte que `parse` tient fermée.
- Un port inconnu se passe `None` : les règles à port ne s'appliquent pas,
  les sondes fortes restent, derrière leur garde de transport.
- **Mon choix** : `classify_payload_with`, pendant de `parse_with`. Sans
  elle, qui déclare un port (« Decode As », #65) n'aurait pas la même
  réponse des deux côtés.
- Implémentation : l'étape L7 d'un flux à couche transport sort de
  `parse_l7_and_inner` dans une fonction du moteur, `#[inline(always)]`,
  appelée par `parse` et par `classify_payload`. Le flux interne d'un tunnel
  est décodé puis jeté : c'est lui qui prouve le tunnel.
- Une différence avec `parse`, documentée : sans en-tête TCP, la fonction ne
  voit pas les drapeaux, donc pas l'anomalie (SYN+FIN, bits réservés) pour
  laquelle `parse` ne sonde pas le segment (#24).

Tests :

- `tests/classify_payload_parity.rs` : sur tout `pcaps_exemple/`, pour
  chaque flux (tunnels compris) à transport TCP ou UDP — 358 247 flux au
  2026-11-14, dont 104 140 à payload vide —, `classify_payload` rend
  exactement `flow.application`. Les segments TCP anormaux sont écartés (le
  corpus n'en contient aucun à ce jour). Seconde passe sur
  `The-Ultimate-PCAP.pcapng` avec le port 3911 déclaré SSDP, qui y change
  cinq étiquettes : `classify_payload_with` contre `parse_with`.
- Tests ciblés sur octets réels : le MMS que `try_from` appelait `RADIUS`
  sort `COTP` sur TCP 102 ; la requête DNS qu'il appelait `NTP` sort `DNS`
  sur le port 53 ; autre protocole que TCP/UDP et payload vide : `None` ;
  un segment SYN+FIN, que `parse` ne sonde pas, est classé (la différence
  documentée).
- Doctest sur la fonction, avec ce même payload MMS.
- **Mon choix** : les tests unitaires de `src/parse/application/mod.rs`
  passent à la nouvelle fonction dès `main`, chacun sous son transport.
  Ce fichier change à chaque protocole ajouté : s'il restait sur
  `try_from`, chaque fusion de `main` dans `release/12.0.0` ne compilerait
  plus. Deux tests restent sur l'impl tant qu'elle existe.

Fuzz :

- `parse_application` : cinq octets de tête choisissent le transport et les
  ports, le reste est le payload. Ni panic, et (**mon choix**) la même
  étiquette que `parse` sur la trame Ethernet/IPv4 bâtie autour du même
  payload : la parité du corpus, tenue aussi sous octets hostiles.
- `parse_valmet_dna`, `parse_wireguard` : `classify_payload(Udp, None,
  None, …)` à la place de la cascade aveugle.

Documentation : annonce du retrait dans la rustdoc d'`Application` et de
l'impl ; ligne dans les tables d'API du README et de `docs/reference.md` ;
METHODE (voie 1) ; ROADMAP ; CHANGELOG (`Ajoute`, `Deprecie`) ;
`MIGRATION-12.md` créé avec cette première entrée.

### 4.2 Sur `release/12.0.0`, la rupture (PR 2, `feat/retrait-try-from-219`)

`release/12.0.0` part de `main` une fois la PR 1 fusionnée.

- `version = "12.0.0"` dans `Cargo.toml` et les quatre fichiers de lock : la
  convention du job `semver`. À chaque fusion de `main` dans la branche,
  cette ligne se résout en gardant 12.0.0.
- Retrait de `impl TryFrom<&[u8]> for Application` et de `classify_blind`,
  qui ne servait qu'à lui.
- **Mon choix**, dans un commit à part pour qu'il se retire seul :
  `ApplicationError` et `ParseError::Application`. `EmptyPacket`, sa seule
  variante, n'a plus de constructeur une fois l'impl partie ; la 11.0.0
  avait purgé de la même façon les neuf variantes jamais construites (#32).
- Les deux derniers tests sur l'impl disparaissent ; le test qui fige la
  liste aveugle de la table perd la mention de la cascade publique.
- `MIGRATION-12.md` : l'entrée passe de « à venir » à « fait », et le fichier
  entre dans la liste `include` du paquet, comme `MIGRATION-11.md`.
  CHANGELOG : section `Rupture`.
- Preuve : `cargo semver-checks check-release --release-type minor` contre
  la 11.8.2, dont la liste d'échecs doit être celle du guide, ni plus ni
  moins ; la sortie va dans la PR.

## 5. Hors périmètre

- `ApplicationProtocol` (#217), `details` au L7 (#218), renommages (#220).
- Modbus/UDP, que `parse` ne reconnaît pas (38 trames réelles du corpus,
  tshark `mbudp`) : une issue à part.
- Le livre : une tâche ouverte dans `Akmot9/packet-parser-book`, à faire
  après la publication qui contiendra `classify_payload`.
- Tag, publication, montée de Sonar : sur demande explicite, comme pour la
  11.0.0. `classify_payload` attend sous `[Non publie]` la prochaine
  version (une mineure).

## 6. Livraison

1. PR 1 vers `main` : TDD, puis les gates de `CONTRIBUTING.md` (fmt, clippy
   stable du jour, 1.88, `cargo doc`, semver-checks, suite complète, bench,
   cibles de fuzz touchées lancées dix minutes).
2. `release/12.0.0` créée depuis `main` à jour ; PR 2 vers elle, mêmes
   gates.
3. #219 : la piste est corrigée (pas de `#[deprecated]`), les critères
   cochés avec leur preuve. L'issue reste ouverte jusqu'à la fusion de
   `release/12.0.0` dans `main`.

## 7. Écarts constatés à l'implémentation et à la relecture (2026-11-14)

- **Trois différences avec `parse`, pas une.** Le §4.1 n'en nommait qu'une,
  les drapeaux TCP anormaux. La relecture indépendante de la PR 1 en a
  montré deux autres, que la rustdoc affirmait ne pas exister : GRE et
  IP-in-IP, que `parse` nomme depuis l'en-tête IP et pour lesquels la
  fonction rend `None` ; et le dernier des quatre niveaux de flux que
  `parse` garde, où il ne cherche plus de tunnel alors que la fonction, sans
  profondeur, le nomme encore. Le comportement est gardé, la documentation
  corrigée, et chaque différence a son test
  (`anomalous_tcp_…`, `ip_level_tunnels_…`, `the_last_level_parse_keeps_…`).
  Le test de parité écarte explicitement le troisième cas au lieu d'échouer
  le jour où une capture le contiendrait.
- **« Port réservé à mDNS ou LLMNR » ne vaut que sur UDP.** Précisé partout.
- **`MIGRATION-12.md` entre dans le paquet dès `main`**, et non sur
  `release/12.0.0` comme l'écrivait le §4.2 : le CHANGELOG de la prochaine
  11.x y renvoie, et sans lui la référence serait morte sur crates.io. C'est
  la raison que `Cargo.toml` donne déjà pour `MIGRATION-11.md`.
- **Pas de doctest `compile_fail` pour figer le retrait** (plan, tâche 5) :
  un test qui affirme qu'un symbole retiré reste retiré ne détecte aucun
  bug. Le retrait est prouvé par le compilateur et par semver-checks.
- **Un appelant de plus** : `src/parse/tests.rs`
  (`packetflow_never_detects_s7comm_over_udp`), que le relevé initial avait
  manqué. Converti avec les autres.
- **L'oracle de fuzz borne le payload à 65 495 octets**, la limite de la
  longueur totale IPv4, et non à 1 400. En pratique libFuzzer ne dépasse pas
  4 096 octets sans `-max_len` : la parité au-delà de `PROBE_CAP` n'est tenue
  que par le corpus et par construction.
