# Audit de codebase — `packet_parser` 8.1.0

> Réalisé le 28 juillet 2026 sur le commit `058e9c5`.
> 136 fichiers `.rs`, 27 814 lignes, 0 `unsafe`, 740 tests verts, 6 dépendances de production.
>
> **Méthode.** Cartographie par lecture intégrale de `src/`, puis audit sur cinq dimensions
> (robustesse, dette, performance, design d'API/SemVer, tests), chaque finding soumis à une
> contre-expertise adversariale chargée de le réfuter — 37 findings retenus sur 45. Les mesures
> chiffrées ci-dessous ont été **reproduites en profil release sur la machine de développement**
> et sont signalées comme telles ; ce qui relève de la seule lecture du source est signalé
> distinctement.

---

## 1. Verdict

Le cœur de parsing est sain : zéro `unsafe`, aucun `unwrap` atteignable sur du slicing,
validation de longueur systématique avant chaque indexation, et un contrat fail-soft
(L2 fatal / L3-L4 dégradés via `CorruptedLayer` / L7 best-effort) qui est le bon design et
qui est réellement tenu.

Ce qui ne va pas n'est presque jamais dans les parseurs eux-mêmes. C'est dans **ce que l'API
publique promet** (doc de crate et README qui pointent l'API legacy et des types innommables),
dans **la porte d'entrée que la doc met en avant** (`PacketFlow::try_from` fabrique des MAC
inexistantes sur une capture SLL, sans erreur ni drapeau), et dans **le dispatch L7** — une
cascade linéaire de 16 parseurs complets exécutée sur n'importe quel payload, avec quatre
`Vec::with_capacity` dimensionnés par un champ attaquant.

Aucun de ces défauts n'est un bug de décodage ; tous sont des défauts de contrat ou de garde
d'entrée, donc corrigibles sans toucher aux 19 parseurs protocolaires. La cadence de 8 versions
majeures est le symptôme d'une surface publique bien trop large (240 `pub fn`, 109 `pub struct`,
`pub mod checks`) plutôt que d'une instabilité de fond.

---

## 2. Architecture réelle

### 2.1 Le pipeline

```
                    is_supported(LinkType) -> bool       [const fn, préflight, dérivé de decoder_for]
                              │
   parse(LinkType, &[u8])  ───┤   parse_timed(..)        [feature parse_timing → pipeline DUPLIQUÉ]
   src/parse/mod.rs:74        │   src/parse/mod.rs:81
                              ▼
   ┌───────────────────────────────────────────────────────────────────────────┐
   │ link::decode — decoder_for()   src/parse/link/mod.rs:49                    │
   │   ETHERNET(1) → RAW(101) → LINUX_SLL(113) → LINUX_SLL2(276)                │
   │   _ => Err(UnsupportedLinkType)   ◄── SEUL Err que le pipeline produise.   │
   │                                       Jamais de repli Ethernet.            │
   └───────────────────────────────────────────────────────────────────────────┘
                              ▼
        DecodedLink { LinkLayer, NetworkProtocol, &[u8] }   ← point de convergence
                              │                               format-neutre, zéro-copie
                              ▼   PacketFlow::parse_decoded(decoded, depth)   mod.rs:384
   ┌───────────────────────────────────────────────────────────────────────────┐
   │ parse_l3   Internet::try_from_network_parts(NetworkProtocol, payload)      │
   │   Ok               → Some(Internet)                                        │
   │   UnsupportedProto → (None, None)                        silence assumé    │
   │   autre erreur     → (None, CorruptedLayer{Internet, error: String})       │
   ├───────────────────────────────────────────────────────────────────────────┤
   │ parse_l4   Transport::try_from_parts(payload_protocol, payload)            │
   │   Tcp/Udp   → ports + payload + TransportDetails                           │
   │   autre     → métadonnée seule, payload = None    ◄── bloque GRE / IP-in-IP│
   │   erreur    → CorruptedLayer{Transport}                                    │
   ├───────────────────────────────────────────────────────────────────────────┤
   │ parse_l7_and_inner                                                         │
   │   ├─ tunnel::detect_inner   (CAPWAP UDP/5247 SEUL ; depth+1 >= 4 → stop)   │
   │   │     peel CAPWAP → 802.11 → LLC/SNAP → parse_decoded(depth+1) → inner   │
   │   └─ parse_application_from_transport      mod.rs:207                      │
   │        ├─ 6 sondes gardées par port : SNMP, DHCPv6, COTP, AMS,             │
   │        │   QUIC short-header, PostgreSQL (TCP, sans port)                  │
   │        ├─ Application::try_from → CASCADE LINÉAIRE DE 16 TryFrom COMPLETS  │
   │        └─ override OPC UA par port SEUL (écrase le verdict du contenu)     │
   └───────────────────────────────────────────────────────────────────────────┘
                              ▼
   PacketFlow { data_link, internet?, transport?, application?, inner?, corrupted? }
        │                                        (Eq/Hash = identité de flux :
        │                                         les octets de payload sont ignorés)
        ├── flatten()  → Vec<&PacketFlow>        1 malloc/paquet, chaîne ≤ 4
        └── to_owned() → PacketFlowOwned         SCHÉMA JSON DIFFÉRENT ;
                                                 perd payloads + details

   VOIES PARALLÈLES ENCORE PUBLIQUES — et mises en avant par la documentation :
     PacketFlow::try_from(&[u8])   mod.rs:173           → parse(ETHERNET, ..) implicite
     DataLink::try_from(&[u8])     data_link/mod.rs:100 → exemple n°1 de lib.rs:28
     Internet::try_from / Transport::try_from           → probing aveugle, 0 appelant interne
```

### 2.2 Les cinq choix structurants et leur prix

| Choix | Ce qu'il rapporte | Ce qu'il coûte réellement |
|---|---|---|
| **Dispatch par table `decoder_for`** (link/mod.rs:49) au lieu de probing | `is_supported` ne peut pas mentir ; `UnsupportedLinkType` avant toute lecture d'octet ; L3 dispatché déterministiquement au lieu d'être deviné | `IEEE802_11(105)` et `BLUETOOTH_HCI_H4_WITH_PHDR(201)` sont des constantes publiques non dispatchables ; `LinkLayer::ieee80211` est un constructeur public dont l'entrée n'existe pas |
| **`DecodedLink` comme point de convergence** | Un seul pipeline L3/L4/L7 pour 4 formats L2 ; ajouter un LINKTYPE = un fichier + une ligne de table | Aucun. C'est le meilleur choix de la crate. |
| **Fail-soft à trois régimes** (inconnu ≠ corrompu) | Rend exploitable ce qu'un probing aveugle jette ; `parse_decoded` ne construit littéralement jamais d'`Err` | Signature `Result<Self, ParsedPacketError>` mensongère → le `let Ok(inner) = …` de `tunnel/mod.rs:61` masquerait une vraie erreur ; l'erreur typée est aplatie en `String` (mod.rs:332) |
| **L7 réduit à un `&'static str`** | Structure minuscule, `Copy`-friendly, pas de lifetime L7 | Tout le travail des 19 parseurs est **construit puis jeté** ; `ApplicationProtocol` (21 variantes) et 9 variantes d'`ApplicationError` sont mortes ; aucune raison de non-détection n'est remontable |
| **Modèle `owned` dupliqué, unidirectionnel** | Détache du buffer, sérialisable, stockable | 9 types + `Display`/`Eq`/`Hash`/`Serialize` en miroir ; **schéma JSON divergent** ; pas de `Deserialize` ; `to_owned()` masque `ToOwned::to_owned` |

### 2.3 Le point d'articulation caché

`Transport::try_from_parts` met `payload: None` pour tout protocole autre que TCP/UDP
(`transport/mod.rs:77-83`). Or `tunnel::detect_inner` part de `transport.payload`
(`tunnel/mod.rs:54`).

**Conséquence non documentée** : les tunnels annoncés comme extensibles dans le doc du module —
GRE (proto 47), IP-in-IP (proto 4) — ne peuvent pas se brancher sur le hook actuel, ils sortent
en `None` avant toute détection. Seuls VXLAN et GTP-U (sur UDP) sont réellement branchables.
`TODO_TUNNELS.md` et les dossiers vides `pcaps_exemple/tunnels/{gre,ipip}/` laissent croire
l'inverse.

---

## 3. Ce qui est solide

**Sécurité mémoire.** 0 occurrence de `unsafe` sur 27 814 lignes. Le seul `panic!` de production
est `convert::hex_stream_to_bytes` (convert/mod.rs:99), hors du chemin `parse()`. Les deux
`unreachable!()` d'`arp.rs:99,125` sont prouvés inatteignables par la garde
`validate_protocol_type` en amont (arp.rs:76). Les 9 `.unwrap()` d'`ams.rs:79-90` sont prouvés
infaillibles par `validate_ams_header_length` (checks/application/ams.rs:8-19, refuse `len < 32`,
indexation max `bytes[28..32]`).

**Ordonnancement validation → indexation, sans exception trouvée.** Ethernet ≥14 puis ≥18 si
VLAN ; SLL ≥16 ; SLL2 ≥20 ; RAW ≥1 ; IPv4 ≥20 → version → IHL∈[20,60] → header dispo →
`total_length` ; IPv6 ≥40 → version → `payload_length` ; ARP ≥28 puis `8+2*hlen+2*plen` **avant**
`validate_protocol_len`, ce qui borne tous les index dynamiques `data[14+plen]`..`data[36+plen]`.

**La chaîne d'extension IPv6 est correcte** (ipv6.rs:172-201), ce qui est rare : tailles justes
par type (Fragment 8 fixe, AH `(len+2)*4` per RFC 4302, HbH/Routing/DestOpts `(len+1)*8`), deux
vérifications de borne par tour, progression minimale de 8 octets → terminaison garantie. Et
`fragmented` coupe `transport_protocol` exactement comme IPv4 le fait sur ses fragments.

**L'invariant du modèle L2 est structurel, pas conventionnel.** `LinkLayer` a
`link_type`/`network_protocol`/`network_payload` privés et n'est constructible que par
`ethernet()`/`raw_ipv4()`/`raw_ipv6()`/`linux_sll()`/`linux_sll2()`/`ieee80211()`
(link_layer.rs:328-502). Il est **impossible** de fabriquer un `LinkLayer` dont le `kind`
contredit le `link_type`. Même discipline côté owned.

**Robustesse SLL/SLL2 face aux valeurs futures du noyau.** L'adresse source est bornée à
`address_length.min(8)`, la longueur déclarée est conservée telle quelle,
`address_is_truncated()` signale le cas au lieu de rejeter, et `reserved_mbz` non nul n'est pas
fatal (`reserved_is_zero()`). Le padding non nul du noyau ne fuit donc pas dans l'identité de
flux — testé sur une vraie trame ARP en SLL v1 (mod.rs:1421-1465).

**L'identité de flux est un vrai design, pas un accident.** `PartialEq`/`Hash` ignorent les
octets de payload partout : `LinkLayer` (link_layer.rs:350-366), `DataLink`
(data_link/mod.rs:141-159), `Internet` (internet/mod.rs:221-242), `Transport`
(transport/mod.rs:124-141), et toutes les vues SLL/SLL2/RAW/802.11. Deux paquets d'une même
conversation sont égaux et hashent pareil : `PacketFlow` est directement utilisable comme clé de
`HashMap`.

**Rigueur BER en SNMP** (snmp.rs:482+) : `checked_mul`/`checked_add` sur toutes les longueurs,
rejet de la longueur indéfinie, vérification « pas d'octets résiduels » à chaque niveau. C'est le
seul parseur de la zone qui atteint le niveau d'un décodeur de référence.

**Le fail-closed de la 7.0.0 est testé pour ce qu'il vaut** : `tests/public_parse_api.rs:827`
vérifie qu'un buffer Ethernet étiqueté `LINUX_SLL2` ne retombe jamais sur Ethernet. C'est
exactement le test qui compte.

**Les tests d'équivalence chemin normal / chemin chronométré** (tests/public_parse_api.rs:933-1103,
8 tests) sont le filet de sécurité qu'exige la duplication du pipeline, et la CI les exécute
(`cargo test --all-features`, ci.yml:37).

**Les commentaires justifient les décisions non évidentes par des références précises** : RFC 9000
§17.3 pour l'opacité du QUIC short-header, RFC 1035 §4.1.4 pour la compression DNS, RFC 5415 pour
CAPWAP, RFC 4302 pour AH, et l'issue #3 pour l'ordre DHCP/SRVLOC.

---

## 4. Problèmes par ordre de gravité

| # | Gravité | Emplacement | Symptôme | Effort |
|---|---|---|---|---|
| 1 | **Critique** | `src/parse/mod.rs:173-180` + `src/lib.rs:21-32` + `README.md:36-77` | `PacketFlow::try_from` présume Ethernet en silence ; sur une capture SLL il **invente des MAC** et retourne `Ok` sans corruption. La doc met en avant cette voie et titre l'API canonique « unreleased ». | S |
| 2 | **Haute** | `dns/mod.rs:88`, `dns_queries/mod.rs:37`, `ethernet_ip.rs:217`, `postgresql.rs:776` | 4 × `Vec::with_capacity(champ_du_paquet)` avant toute vérification de disponibilité. 17 o de payload → 4,19 Mo (×71 089), sur **n'importe quel port**. `panic = "abort"` ⇒ échec d'alloc = mort du processus. | S |
| 3 | **Haute** | `src/parse/application/mod.rs:36-123` | 16 parseurs complets sur tout payload, sans pré-filtre ni plafond de taille. Payload hostile de 1464 o : ×60 sur le temps de parsing. À 65 000 o : 282 µs/paquet. | M |
| 4 | **Haute** | `src/errors/mod.rs:8-12` vs `src/lib.rs:109-111` | Le doc-comment promet `errors::internet::InternetError` ; les modules sont `pub(crate)` → `E0603` à la compilation. Les 120 `validate_*` publics et les 19 `TryFrom` protocolaires renvoient des erreurs innommables. | S |
| 5 | **Haute** | `src/owned/mod.rs:403-418` vs `src/parse/internet/mod.rs:40-49` | Deux schémas JSON incompatibles pour le même paquet. Et `displays/transport/mod.rs:43` a été **déformé** (`Tcp => "Tcp"`) pour faire passer un test — prouvé par `git log -S`, commit `7910ffc`. | M |
| 6 | Moyenne | `src/parse/tunnel/mod.rs` (163 l.) | Zéro test inline. `MAX_TUNNEL_DEPTH` — seule protection anti-DoS récursif de la crate — n'est **jamais exercé**. Aucune branche de refus (DTLS, HLEN, non-data, LLC non-SNAP) n'est couverte. | S |
| 7 | Moyenne | `src/checks/transport/tcp/mod.rs:41` | Les paquets **SYN+FIN sont supprimés** (`transport: None` + `CorruptedLayer`), avec l'erreur trompeuse `InvalidHeaderLength`. Zéro test dans le fichier. Angle mort de détection de scan pour une crate `keywords = ["cybersecurity"]`. | S |
| 8 | Moyenne | `src/parse/mod.rs:281-286` | Override OPC UA : le port **écrase** le verdict du contenu, contrairement aux 5 autres gardes qui sont des conjonctions. Non gardé par `protocol == Tcp` malgré son nom. Les lignes 274-279 qui le précèdent sont mortes. | S |
| 9 | Moyenne | `src/timing/mod.rs:37` vs `:9` | Feature **non additive** : `ParseTiming` passe de struct unité à struct à 5 champs, `now()` de `()` à `Instant`. L'unification de features Cargo casse un consommateur tiers sans changement de version. | S |
| 10 | Moyenne | `src/parse/mod.rs:296` | `to_owned()` masque `ToOwned::to_owned` et retourne un type **différent et lossy**. Les 6 noms de champs étant identiques, `let c = flow.to_owned(); c.transport…` compile **silencieusement**. | S |
| 11 | Moyenne | `src/lib.rs:54-90` | Le doc de crate décrit `Application { protocol: ApplicationProtocol, payload: Vec<u8> }` — le vrai type est `{ application_protocol: &'static str }`. L'exemple compilé importe `pnet`, une **dev-dependency** → `E0432` chez le consommateur. | S |
| 12 | Moyenne | `src/parse/mod.rs:267` | `is_likely_postgresql_payload` (parsing intégral + `Vec`) exécuté **deux fois** par segment TCP (ici puis application/mod.rs:57). Idem SNMP. | S |
| 13 | Basse | `Cargo.toml:13` | `exclude` incomplet : chaque release crates.io embarque `.DS_Store` (×5, versionnés), `.codex`, `analyse.md` (audit **périmé** dont les 6 « problèmes prioritaires » sont tous corrigés), `sprint_0{1,2}.md`, `oui.csv` (orphelin **et désynchronisé** : 6 entrées vs 7 constructeurs), `article/`, `dashboards/`, `docker-compose.yml`, `deny.toml`. | S |
| 14 | Basse | `.github/workflows/ci.yml:34,43` + `Cargo.toml:34` | `clippy` et `build --release` sans `--all-features` ni `--workspace` ; `fuzz/` exclu du workspace et **jamais compilé** par la CI ; corpus non versionné ; pas de `rust-version` ; mono-OS ; `Cargo.lock` gitignoré ; `cargo-deny` hebdomadaire et non bloquant. | M |
| 15 | Basse | `checks/mod.rs:14`, `protocols/mod.rs:48`, `errors/application/mod.rs:31`, `internet/mod.rs:78`, `transport/mod.rs:90` | Code mort public : `validate_packet_length`, `ApplicationProtocol` (21 variantes), 9/10 variantes d'`ApplicationError`, `ParseError::PacketTooShort`, `Internet::try_from_parts`, `TryFrom<&[u8]> for Transport` (avec `sleep`/`println!` commentés et le seul TODO de `src/`). | S |

---

### Détail des cinq premiers

#### 1 — La voie d'entrée que la doc met en avant fabrique des données de liaison

`src/parse/mod.rs:173-180` : `impl TryFrom<&[u8]> for PacketFlow` câble `LinkType::ETHERNET` sans
que la signature ni un doc-comment ne le disent. Aucune garde de plausibilité n'existe :
`EthernetDecoder` (link/ethernet.rs:15) appelle directement `DataLink::try_from`, qui ne vérifie
que `len >= 14`.

**Impact vérifié.** Sur une trame `LINKTYPE_LINUX_SLL` réelle, les 16 octets cooked sont relus
comme un en-tête Ethernet : `destination_mac = 00:04:00:01:00:06`,
`source_mac = e0:d5:5e:28:9b:d4`, `ethertype = 0x0000`. Le parse retourne `Ok`,
`internet = None`, `corrupted = None`. **Zéro signal.** La même trame via
`parse(LinkType::LINUX_SLL, …)` donne correctement `192.168.1.181 → 192.168.1.254 / IPv4`. Une
matrice de flux se remplit de MAC inexistantes.

Le problème n'est pas la coexistence des trois entrées, c'est la **hiérarchie affichée** :
`src/lib.rs:21-32` (« Usage Example ») ne montre que `DataLink::try_from` ; `README.md:36`
(« Quick Example ») ne montre que `PacketFlow::try_from` ; `parse(LinkType, …)` n'apparaît qu'à
`README.md:77` sous le titre **« Explicit LINKTYPE API (unreleased, target 7.0.0) »** alors que
`Cargo.toml:3` dit 8.1.0 et que le CHANGELOG:59 la documente comme livrée. Toute la valeur du
dispatch fail-closed de la 7.0.0 est annulée par le raccourci que la doc recommande. Les captures
d'interface `any` (LINKTYPE 113) sont un cas courant, pas un cas limite.

**Correction.**
1. Réécrire le doc-comment de `lib.rs:21-32` et le Quick Example autour de
   `parse(LinkType::ETHERNET, …)`.
2. Retitrer `README.md:77` / `README-fr.md:75` en « API LINKTYPE explicite (depuis 7.0.0) »,
   corriger `packet_parser = "7.0.0"` → `"8.1.0"` (README.md:25,33 ; README-fr.md:23,31) et
   supprimer les « target 7.0.0 » des tableaux (README.md:156-157,164).
3. `#[deprecated(since = "8.2.0", note = "présume LinkType::ETHERNET ; utiliser parse(LinkType, bytes)")]`
   sur les deux `TryFrom<&[u8]>`, avec la présomption documentée dans leur rustdoc en attendant
   la 9.0.0.
4. Ajouter au workflow de release un contrôle « version citée dans les README == `Cargo.toml` »,
   sur le modèle du contrôle tag/version déjà présent dans `publish.yml`.

#### 2 — Quatre allocations dimensionnées par un champ attaquant

**Mesuré** (build release, allocateur global instrumenté, trame Ethernet/IPv4/UDP complète) :

| Entrée | Trame | Pic d'allocation | Amplification | Verdict L7 |
|---|---|---|---|---|
| DNS `ancount=0xFFFF`, **port 12345** | 59 o | 4 194 272 o | **×71 089** | `"Unknown"` |
| Référence : 17 o à zéro | 59 o | 0 o | — | `"DNS"` |
| Référence : 1460 o à zéro | 1 502 o | 0 o | — | `"DNS"` |

Deux enseignements en une mesure : l'amplification est réelle et atteignable **sur un port
arbitraire** — et un payload de 1460 octets à zéro est classé `"DNS"`, ce qui illustre le
problème n°3.

Les sites `ethernet_ip.rs:217` (`item_count` u16) et `postgresql.rs:776`
(`parameter_value_count` u16) présentent le même motif dans le code ; ils n'ont pas été
reproduits avec un payload forgé, la lecture du source suffit à établir l'absence de borne.

Le seul filtre amont DNS, `validate_and_parse_count` (checks/application/dns.rs:31-48), n'impose
qu'une chose : `qdcount == 0 ⇒ les autres nuls`. `0xFFFF` partout est accepté.

L'asymétrie est flagrante et **locale**, ce qui rend la correction évidente :

- **GIOP le fait déjà correctement** : `checks/application/giop.rs:96` —
  `if count > remaining / SERVICE_CONTEXT_MIN_LEN { return Err(..) }`.
- **`parse_bind` protège 3 de ses 4 compteurs** : `validate_remaining` aux lignes 746, 768 et
  796 — et **oublie** la ligne 775. L'oubli est visible à l'œil nu dans la même fonction.
- **EtherNet/IP a la garde, mais après l'allocation** : `ensure_available("cpf_item_header", …)`
  est à la ligne 221, *dans* la boucle, alors que le `Vec::with_capacity` est ligne 217.

**Facteur aggravant** : `Cargo.toml` déclare `panic = "abort"` en release. Un échec d'allocation
n'est pas récupérable — `Vec::with_capacity` fait `abort()`, le processus meurt. Sur un capteur
multi-thread, 4 Mo par thread simultanément en vol.

**Correction (S, 4 lignes).** Appliquer partout le motif GIOP avant l'allocation :

- DNS : `count.min(remaining / 11)` pour les RR (nom racine 1 + type 2 + classe 2 + TTL 4 +
  rdlength 2), `/ 5` pour les questions.
- EtherNet/IP : `item_count.min((data.len() - 8) / 4)`.
- PostgreSQL : `validate_remaining(cur.remaining(), value_count * 4, "parameter_values")?;` —
  strictement symétrique des trois voisines.

Alternative encore plus simple et suffisante partout : `Vec::new()`, et laisser la croissance
géométrique se borner naturellement au buffer réel.

#### 3 — Le pire cas de la cascade L7 est entièrement sous contrôle de l'attaquant

`Application::try_from` (application/mod.rs:36-123) enchaîne 16 `TryFrom` **complets** — NTP,
Bitcoin, OPC UA, EtherNet/IP, PostgreSQL, DNS, SNMP, TLS, HTTP, S7Comm, GIOP, DHCP, SRVLOC,
Modbus, QUIC, MQTT — sans pré-filtre de taille, de port ou de premier octet. Le seul filtre est
`packet.is_empty()` (ligne 32). Plusieurs de ces parseurs allouent : `DnsPacket` (seule struct L7
owned : `String` par label via deux allocations à `utils/name.rs:74`, plus un `join` ligne 79,
plus un `to_vec()` de rdata ligne 116), `PostgreSqlPacket`, `HttpRequest`, `OpcuaPacket`.

**Mesuré** (release, 20 000 itérations après échauffement, trame Ethernet complète) :

| Entrée | Trame | ns / paquet | Rapport |
|---|---|---|---|
| Référence : 1460 o à zéro | 1 502 o | 111 | ×1 |
| Pseudo-PostgreSQL 1464 o, port 12345 | 1 506 o | 6 712 | **×60** |
| Pseudo-PostgreSQL 65 000 o (jumbo / GRO) | 65 040 o | 282 475 | ×2 545 |
| DNS légitime, 32 réponses, port 53 | 575 o | 3 956 | ×36 |

1500 o / 6,7 µs : un flux hostile à MTU standard consomme un cœur bien avant la ligne. Les
568 ns/paquet de `perf_by_version.json` sont le coût du trafic *bénin*, pas celui du trafic
*choisi*.

À noter que le cas DNS légitime est aussi le problème : **3,9 µs pour produire un
`&'static str` de 16 octets**. Tout l'arbre `DnsPacket` est construit puis jeté — l'essentiel du
budget de parsing d'un paquet DNS, très au-delà du `l7_ns = 196` annoncé.

**Correction (M).** Trois niveaux, par ordre de rapport effort/gain :

1. **Plafonner** la taille soumise au probing (4 Ko ; au-delà, ne sonder que le préfixe). Une
   ligne, supprime le cas jumbo.
2. **Passer les ports à la cascade** — `Application::try_from_ports(payload, src, dst)` — avec
   une table statique `port → sonde prioritaire` (53/5353 → DNS, 5432 → PostgreSQL,
   44818/2222 → EtherNet/IP, 502 → Modbus, 443 → TLS/QUIC, 102 → COTP…), la cascade actuelle
   restant le repli. `parse_application_from_transport` a déjà les ports en main et s'en sert
   pour 6 protocoles : c'est une extension, pas une réécriture.
3. **Ajouter un `looks_like_dns(&[u8]) -> bool`** sans construction (parcours des sections en
   vérifiant les bornes), sur le modèle de `is_plausible_short_header` pour QUIC, et ne
   construire `DnsPacket` que si le consommateur demande le contenu. Même traitement pour
   PostgreSQL.

Le point 2 résout aussi le n° 12 (double sondage) et une partie du n° 8.

#### 4 — Le contrat d'erreur public est mensonger

`src/lib.rs:109-111` : *« Public so consumers can name and match the per-layer error types (e.g.
`errors::internet::InternetError`, `errors::transport::TransportError`) »*.
`src/errors/mod.rs:8-12` : `pub(crate) mod application; pub(crate) mod data_link;
pub(crate) mod internet; mod link_layer; pub(crate) mod transport;`. Seul `LinkLayerError` est
réexporté (mod.rs:17).

**Vérifié par compilation d'un consommateur réel** :
`use packet_parser::errors::internet::InternetError;` → `error[E0603]: module 'internet' is
private`, note pointant `src/errors/mod.rs:10`, avec `enum InternetError is not publicly
re-exported`. `cargo doc --no-deps` le signale de lui-même : 3 warnings dont *« public
documentation for `try_from_parts` links to private item `InternetError::UnsupportedProtocol` »*.

**Portée réelle**, plus large que le doc-comment :

- `DataLink::try_from` — l'exemple n° 1 du doc de crate, type réexporté à `lib.rs:123` — renvoie
  `Result<DataLink, DataLinkError>` avec un `DataLinkError` innommable : impossible d'écrire une
  fonction wrapper typée.
- Les 19 `TryFrom` applicatifs publics (`MqttPacket::try_from → MqttError`) : mêmes conditions.
- Les 120 `pub fn validate_*` de `src/checks/` renvoient des `Ipv4Error`, `TcpError`, `ArpError`…
  innommables. Elles sont **publiques et inutilisables**.

Le consommateur est réduit à `format!("{e}")`, ce que la crate lui impose déjà par ailleurs
puisque `CorruptedLayer.error` est une `String` (mod.rs:332).

**Correction (S).** Passer les quatre modules en `pub mod` — 4 caractères — puis
`cargo doc --no-deps` jusqu'à zéro warning « links to private item ». Ajouter
`#[non_exhaustive]` sur les enums nouvellement exposées : sur 32 enums d'erreur, seuls
`ParseError` et `LinkLayerError` l'ont aujourd'hui, donc ajouter une variante à `MqttError` ou
`Ipv4Error` est déjà une rupture SemVer non signalée. **Si l'intention est au contraire de les
garder internes**, alors corriger `lib.rs:109-111` *et* passer les 120 `validate_*` en
`pub(crate)`, sinon on laisse des fonctions publiques à type de retour inutilisable.

#### 5 — Deux schémas JSON pour le même paquet, et une table `Display` déformée pour satisfaire un test

Sortie réelle sur la même trame Ethernet/IPv4/UDP :

```
BORROWED : "source":"10.0.0.1", "source_type":"Private", "destination":"10.0.0.2",
           "destination_type":"Private", "protocol_name":"IPv4", "protocol":"Udp"
OWNED    : "source_ip":"10.0.0.1", "ip_source_type":"Private", "destination_ip":"10.0.0.2",
           "ip_destination_type":"Private", "protocol_internet":"IPv4", "protocol_transport":"UDP"
```

**Aucune clé L3/L4 partagée, et la casse diffère.** Le doc de `src/owned/mod.rs:30-35` dit
pourtant « mirroring `PacketFlow::inner` / `PacketFlow::corrupted` ». Cause : `Internet` dérive
`Serialize` sur ses champs (internet/mod.rs:40-49) tandis que `InternetOwned` renomme tout
(`owned/mod.rs:405-410`), et `TransportOwned.protocol` est alimenté par
`transport.protocol.to_string()` (owned/mod.rs:443) donc par `Display`, là où le modèle emprunté
sérialise la variante d'enum.

**Le détail qui compte** : `src/displays/transport/mod.rs:43` contient
`TransportProtocol::Tcp => "Tcp"`, seule entrée de casse mixte parmi les protocoles majuscules de
la table (`"UDP"`, `"ICMP"`, `"SCTP"`…). Ce n'est pas un hasard.

**Vérification git, confirmée au diff près** : `git log -S'TransportProtocol::Tcp => "Tcp"'`
renvoie le commit `7910ffc "add tests"`, dont le `--stat` ne touche que deux fichiers :

```
7910ffc add tests
 src/displays/transport/mod.rs |   2 +-      →  -"TCP"  +"Tcp"
 src/parse/mod.rs              | 146 +++++   →  tests
```

L'assertion visée est `mod.rs:1010-1013` :
`assert_eq!(owned_transport.protocol, format!("{:?}", flow_transport.protocol))` — elle ne tient
que parce que le test `mod.rs:985` n'utilise qu'un paquet TCP. **Une table `Display` publique a
été modifiée pour faire passer un test au lieu de corriger le test.**

Pourquoi personne ne l'a vu : les tests d'égalité de schéma entre les deux modèles
(tests/public_parse_api.rs:282-283, 305-306, 365-367, 504-506, 695-697) ne comparent que
`flow.data_link`.

**Correction (M).**
1. Aligner les clés via `#[serde(rename)]` sur un schéma unique — le schéma emprunté est le plus
   court et le plus naturel.
2. Rétablir `TransportProtocol::Tcp => "TCP"` et corriger `mod.rs:1011-1014` pour comparer au
   `Display` et non au `Debug`.
3. Ajouter dans `tests/public_parse_api.rs` un test qui compare `serde_json::to_value(&flow)` et
   `serde_json::to_value(&flow.to_owned())` sur le **flux complet**, sur au moins un paquet TCP
   *et* un UDP.

Rupture SemVer à annoncer explicitement au CHANGELOG (SONAR consomme les deux schémas).

---

## 5. Dette structurelle — les quatre tensions de fond

### 5.1 La frontière `checks/` ↔ `parse/` est inversée sur cinq protocoles

`METHODE_AJOUT_PROTOCOLE.md:94-107` pose : `checks/` = prédicats sans état,
`parse/protocols/` = construction des structs. Mesure hors tests :

| Protocole | `checks/` (non-test) | `parse/` (non-test) |
|---|---|---|
| MQTT | **449 l.** | 156 l. |
| NTP | 233 l. | 226 l. |

La plus longue fonction non-test de toute la crate est `variable_header_len`
(`checks/application/mqtt.rs:246-448`, 203 lignes) : ce n'est pas un validateur, c'est un
décodeur complet par type de paquet MQTT (protocol name, niveau, connect flags, topics, bloc de
propriétés v5). `parse_cotp_parameter` (`checks/application/copt.rs:94-124`) **construit** des
`CotpParameter::{TpduNumber, TpduSize, SrcTsap, DstTsap, Eot, Other}` importés depuis `parse/`.
`QuicCursor` (`checks/application/quic.rs:35-99`) est un type curseur public avec
`take`/`take_u8`/`take_rest`/`read_varint`. `checks/application/ntp.rs` expose 8 `extract_*` dont
`extract_timestamp` qui rend un `DateTime<Utc>`.

**Coût aujourd'hui** : zéro à l'exécution. **Coût demain** : un contributeur qui suit la méthode
cherche la logique MQTT dans `parse/` et trouve une coquille de 156 lignes ; une correction de bug
sur le variable header se fait dans le module « validation », et son test unitaire atterrit dans
le mauvais fichier.

**Ce que coûterait la résolution (M).** Déplacer `variable_header_len` et `parse_cotp_parameter`
vers `parse/`, ne laisser dans `checks/` que les prédicats booléens (`is_valid_connack_code`,
`properties_fill_exactly`…). Créer `src/parse/cursor.rs` et y faire converger les **quatre**
réimplémentations du même curseur borné : `Cursor` privé à `postgresql.rs:862`, `Cursor` privé à
`giop.rs:198`, `QuicCursor` dans `checks/`, et les fonctions libres `read_u16`/`read_u24`/`read_str`
à `srvloc.rs:98,105,114`. C'est mécanique et couvert par les tests existants.
**Alternative honnête (S)** : corriger `METHODE_AJOUT_PROTOCOLE.md` pour décrire la convention
réellement pratiquée.

### 5.2 `owned` vs `borrowed` : une duplication qui coûte plus qu'elle ne rapporte

9 types en miroir (`PacketFlowOwned`, `LinkLayerOwned(Kind)`, `DataLinkOwned`, `RawIpLinkOwned`,
`LinuxSll(2)LinkOwned`, `Ieee80211LinkOwned`, `InternetOwned`, `TransportOwned`,
`ApplicationOwned`, 873 lignes) plus leurs impls `Display`/`PartialEq`/`Hash`/`Serialize`. Trois
défauts s'y accumulent :

1. **Schéma divergent** (§4.5) — non détecté parce que les tests ne comparent que `data_link`.
2. **Aucun `Deserialize`** : `grep` ne remonte que `LinkType`, `MacAddress` et `IpType`. Or le
   CHANGELOG 8.1.0 justifie les nouveaux `LinuxSllLinkOwned::new` / `LinuxSll2LinkOwned::new` par
   « les consommateurs qui rebâtissent une couche liaison depuis des champs sérialisés (ex.
   réimport d'une matrice de flux SONAR) ». Le cas d'usage annoncé impose donc de redéfinir à la
   main une struct miroir de chacun des 9 types, en devinant les clés renommées.
3. **Conversion strictement unidirectionnelle** et **lossy** : `From<&PacketFlow>`
   (owned/mod.rs:427-456) abandonne les payloads *et* les `details` de la 8.0.0 —
   `InternetDetails`/`TransportDetails` n'ont **aucun équivalent owned**. La couche `owned` est
   donc en retard d'une majeure sur le modèle emprunté.

**Ce que coûterait la résolution (M).** Dériver `Deserialize` sur les 9 types (tous les champs
sont déjà possédés) + un test d'aller-retour `to_string → from_str → Eq` à côté de
`owned/mod.rs:806`. Aligner les clés. Décider si `details` doit avoir un miroir owned ou si son
absence est documentée comme volontaire. **Option plus radicale à évaluer** : remplacer
`PacketFlowOwned` par un `PacketFlow<'static>` obtenu en copiant les payloads dans un
`Box<[u8]>` — cela supprimerait 873 lignes, le problème de schéma et le problème de
`Deserialize` d'un coup, au prix d'une rupture majeure.

### 5.3 Le dispatch applicatif est un empilement empirique, pas un modèle

Trois mécanismes de priorité coexistent, répartis sur deux fichiers, sans table centrale :

1. **Ordre de la cascade** (application/mod.rs:36-123), porteur de sémantique et documenté par
   des commentaires-cicatrices : « DHCP avant SRVLOC — issue #3 » (l.92-93), « MQTT en dernier »
   (l.117-118), « DHCPv6/AMS/COTP retirés du probing » (l.109-111).
2. **Gardes de port** (mod.rs:207-289), appliquées de façon **inégale** : `is_dhcpv6_udp_port`,
   `is_iso_tsap_tcp_port` et `is_quic_udp_port` sont bien combinés à `protocol == Udp/Tcp` ;
   `is_snmp_udp_port`, `is_ams_port` et `is_opcua_tcp_port` ne le sont pas, malgré leur nom (de
   l'UDP 4840 sort donc « OPC UA »).
3. **Un override** (mod.rs:281-286) où le port **écrase** le contenu — seul endroit de la crate où
   cette règle s'applique.

Ajouter un protocole permissif au mauvais rang casse silencieusement la classification d'un
protocole déjà supporté, et rien ne verrouille l'ordre : les tests d'intégration n'affirment
**jamais** un protocole applicatif attendu (`grep application_protocol tests/` = vide), seulement
son absence (`assert!(flow.application.is_none())` aux lignes 231, 496, 600, 687, 816). Combiné à
l'absence totale de golden test pcap→protocole (aucun `include_bytes!` / `File::open` / `fs::read`
sous `src/` ni `tests/` — les 45,7 Mo de `pcaps_exemple/` ne sont lus que par
`examples/scan_pcaps.rs`, qui ne contient **aucun `assert`** et n'est jamais lancé par la CI), une
régression massive de classification est aujourd'hui invisible.

**Ce que coûterait la résolution (M→L).** Remplacer la cascade par une table déclarative
`{ports, magic, longueur_min, sonde, priorité}` — les prédicats existent déjà dans
`checks/application/`. Bénéfices cumulés : supprime le problème de perf (§4.3), le double sondage
(§4.12), l'incohérence de l'override OPC UA (§4.8) et rend l'ordre inspectable et testable.
**Prérequis indispensable** : figer d'abord la sortie de `scan_pcaps.rs` en snapshot
(`tests/golden_pcaps.rs`, histogramme `{protocole → compte}` sur une sélection < 2 Mo), sinon la
refonte se fait sans filet.

### 5.4 Une surface publique de 240 `pub fn` qui fige la mécanique interne

`pub mod checks` (lib.rs:96) expose 120 `validate_*`. `pub mod protocols` (protocols/mod.rs:26-44)
expose 19 modules et une centaine de structs, alors que le pipeline n'en restitue qu'un
`&'static str`. `pub mod convert` (lib.rs:99) expose `Packet::packet_to_pcap` qui écrit en dur
dans `File::create("output.pcap")` du CWD (convert/mod.rs:26-27, non paramétrable) et
`hex_stream_to_bytes` qui `panic!` (l.99, 101) alors que `try_hex_stream_to_bytes` existe juste
au-dessus (l.72). Total : 109 `pub struct`, 77 `pub enum`.

C'est la cause directe de la cadence de majeures : n'importe quel refactor de validation devient
une rupture publique. Et la situation est absurde en combinaison avec §4.4 : **ces fonctions sont
publiques *et* leur type d'erreur est innommable** — publiques et inutilisables.

**Ce que coûterait la résolution (S→M).** `#[doc(hidden)] pub mod checks` en 8.2 puis
`pub(crate)` en 9.0 ; restreindre `protocols` à ce que la crate assume comme décodeurs de
référence ; donner un `path: &Path` à `packet_to_pcap` ; `#[deprecated]` sur
`hex_stream_to_bytes`. Ajouter `#![deny(missing_docs)]` dans `lib.rs` (aucun attribut interne
`#![…]` n'existe aujourd'hui) : le compilateur listera lui-même les items publics non documentés
(`pub mod owned`, `PacketFlowOwned`, `DataLinkOwned.destination_mac`,
`LinkLayerOwned::{ethernet, raw_ipv4, raw_ipv6, ieee80211}`).

---

## 6. Plan d'action priorisé

### Phase 1 — 8.1.1 / 8.2.0, sans rupture (≈ 1 journée cumulée)

| # | Action | Effort | Impact |
|---|---|---|---|
| 1 | **Borner les 4 `Vec::with_capacity`** : `dns/mod.rs:88`, `dns_queries/mod.rs:37`, `ethernet_ip.rs:217`, `postgresql.rs:776`. Motif GIOP (`checks/application/giop.rs:96`) ou `Vec::new()`. + 1 test de non-régression par site avec le payload minimal de l'exploit. | **S** | Supprime l'amplification ×71 089 et le risque d'`abort()` sous `panic="abort"`. |
| 2 | **`pub(crate) mod` → `pub mod`** dans `errors/mod.rs:8-12` + `#[non_exhaustive]` sur les enums exposées. Boucler jusqu'à zéro warning `cargo doc --no-deps`. | **S** | Rend nommables 32 enums déjà écrites (1569 l.) ; supprime les 3 warnings rustdoc ; débloque les 120 `validate_*`. |
| 3 | **Plafonner le probing L7 à 4 Ko** (`application/mod.rs:32`, une condition). | **S** | Ramène le pire cas jumbo de 282 µs à quelques dizaines de µs. |
| 4 | **Corriger README/README-fr** (25, 33, 75, 77, 99, 156-157, 164 + équivalents fr) et le doc-comment de `lib.rs:21-32` → exemple `parse(LinkType::ETHERNET, …)`. Supprimer le bloc `FlattenedPacket` (lib.rs:59-90) qui documente un type inexistant et dépend de `pnet` (dev-dependency → `E0432` chez le consommateur). | **S** | Supprime la cause n° 1 du mauvais usage (fabrication de MAC sur captures SLL). |
| 5 | **Tests du module `tunnel`** : `#[cfg(test)] mod tests` dans `tunnel/mod.rs` — profondeur (6 CAPWAP imbriqués → `flatten().len() == 4` et flux le plus profond à `inner == None`), DTLS (`payload[0] & 0x0f != 0`), HLEN = 0 et > `payload.len()`, 802.11 management, LLC non-SNAP. | **S** | Verrouille la **seule** protection anti-DoS récursif de la crate, aujourd'hui jamais exercée. |
| 6 | **Tests `checks/transport/tcp/`** + variantes d'erreur distinctes pour `validate_tcp_flags` et `validate_tcp_reserved` (aujourd'hui toutes deux `InvalidHeaderLength`). Documenter par un test bout-en-bout la politique « SYN+FIN rejeté ». | **S** | Fige un choix de politique lourd et non documenté, et rend le message d'erreur honnête. |
| 7 | **Supprimer le double sondage PostgreSQL** (`mod.rs:267`, la cascade le couvre déjà) et **rendre l'override OPC UA conjonctif** (`mod.rs:281-286` : `port && parse_ok`, + garde `protocol == Tcp`) ; supprimer les lignes mortes 274-279. | **S** | Supprime la seule règle « port > contenu » de la crate et un parsing intégral redondant par segment TCP. |
| 8 | **`include` au lieu d'`exclude`** dans `Cargo.toml:13` : `include = ["src/**", "README.md", "README-fr.md", "LICENSE.md", "CHANGELOG.md", "examples/**"]`. `git rm --cached` les 5 `.DS_Store` + `.gitignore`. Supprimer/archiver `analyse.md` (audit périmé), `sprint_0{1,2}.md`, `oui.csv` (orphelin et désynchronisé), la dev-dep `criterion` (aucun `benches/`, zéro `use criterion`), et `"benches/"` de l'exclude. | **S** | Une ligne règle le packaging ; supprime un rapport d'audit obsolète livré à chaque release. |
| 9 | **CI** : `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo build --release --all-features`, `cargo test --workspace --all-features`, + job `cargo check --manifest-path fuzz/Cargo.toml` (30 s, empêche le pourrissement des 5 cibles), + `pull_request:` sur `cargo-deny.yml:3`, + `rust-version = "1.85"` et un job matrice `[stable, 1.85.0]`, + versionner `Cargo.lock` et ajouter `--locked`. | **M** | Ferme 5 trous de vérifiabilité cumulés ; les 4 membres du workspace (gelés depuis `1916dfa`/v5.0.0) redeviennent contrôlés. |

### Phase 2 — 9.0.0, ruptures assumées (≈ 2-3 jours)

| # | Action | Effort | Impact |
|---|---|---|---|
| 10 | **Unifier le schéma JSON** borrowed/owned via `#[serde(rename)]`, rétablir `TransportProtocol::Tcp => "TCP"` (displays/transport/mod.rs:43), corriger l'assertion `mod.rs:1011-1014` (`Display`, pas `Debug`), + test comparant `to_value(&flow)` et `to_value(&flow.to_owned())` sur le **flux complet**, TCP et UDP. | **M** | Supprime la double grammaire côté consommateur et le seul cas de code de production déformé pour un test. |
| 11 | **Table de dispatch L7 déclarative** `{ports, magic, len_min, sonde}` remplaçant la cascade + les 6 gardes de port + l'override. **Prérequis : golden tests pcap** (`tests/golden_pcaps.rs`, snapshot de l'histogramme `{protocole → compte}` sur < 2 Mo de `pcaps_exemple/`, en figeant simplement la sortie de `examples/scan_pcaps.rs`). | **L** | Résout d'un coup la perf L7 (×60 à MTU standard), le double travail, l'ordre non verrouillé et la logique de priorité dispersée. |
| 12 | **`#[deprecated]` puis suppression** de `PacketFlow::try_from` et `DataLink::try_from(&[u8])` ; renommer `to_owned()` en `to_owned_flow()` ; ajouter `#[non_exhaustive]` sur `PacketFlow`/`Internet`/`Transport` et leurs 4 miroirs owned (leurs sous-types l'ont déjà — `InternetDetails`, `TransportDetails`, `LinkLayerKind`). | **M** | Supprime la présomption Ethernet silencieuse et le shadowing de `ToOwned` ; rend additifs tous les futurs ajouts de champs (`vlan_stack` QinQ, `l7_corrupted`…). |
| 13 | **Purger le code mort public** : `ApplicationProtocol` (21 variantes) + son `Display`, 9/10 variantes d'`ApplicationError`, `checks::validate_packet_length` + `ParseError::PacketTooShort`, `Internet::try_from_parts`, `TryFrom<&[u8]> for Transport` (avec ses `sleep`/`println!` commentés et le seul TODO de `src/`), `timing::{ParseReport, LayerAttempt}`. Restreindre `checks` et `protocols` (`#[doc(hidden)]` → `pub(crate)`). Paramétrer `packet_to_pcap(path)`. `#[deprecated]` sur `hex_stream_to_bytes`. | **M** | Réduit la surface figée par SemVer ; supprime la cause structurelle des majeures à répétition. |
| 14 | **Rendre `parse_timing` additive** : une seule forme publique de `ParseTiming` (5 `u64`, à zéro feature off), `now()`/`elapsed_ns()` en `pub(crate)`. Puis **supprimer `parse_decoded_timed` et `decode_timed`** en instrumentant le chemin unique avec `time_block_ns!` (timing/mod.rs:63-81, écrite, testée, **zéro appelant**). | **S** | Supprime la non-additivité de feature (rupture invisible par unification Cargo) *et* la duplication du pipeline, d'un seul geste. |
| 15 | **`Deserialize` sur les 9 types owned** + test d'aller-retour à côté de `owned/mod.rs:806` ; décider du sort de `details` côté owned. | **S** | Réalise enfin le cas d'usage qui justifie la 8.1.0 au CHANGELOG. |

---

## 7. Backlog documenté

Pas de correction demandée, mais à écrire noir sur blanc.

- **`Transport.payload == None` hors TCP/UDP** bloque GRE/IP-in-IP : à corriger si les tunnels du
  `TODO_TUNNELS.md` sont au programme (les ports SCTP/DCCP sont aux offsets 0/2, triviaux).
- **Captures tronquées par snaplen rejetées au L3** : `validate_ipv4_total_length` et
  `validate_ipv6_payload_length` remontent `CorruptedLayer{Internet}` alors que les adresses et le
  protocole L4 sont lisibles. Choix défendable, mais à documenter.
- **QinQ non géré** : un seul tag 0x8100 ; `0x88a8`/`0x9100`/double 0x8100 →
  `NetworkProtocol::Other` → `internet: None` **sans** signal de corruption. Ironie :
  `Ethertype::static_name` connaît déjà « Q-in-Q » et « PBridge ».
- **HTTP ne détecte que les requêtes** (`checks/application/http.rs:47-53`) : tout le trafic
  serveur→client sort `Unknown`. **DNS sur TCP jamais reconnu** : le préfixe de longueur
  RFC 1035 §4.2.2 n'est pas retiré, alors que DNS est sondé sur chaque payload TCP — coût payé,
  résultat nul par construction.
- **S7Comm ne valide jamais `protocol_id == 0x32`** (lu à `s7comm.rs:254`, commenté
  « should be 0x32 » l.133) : toute trame ISO-on-TCP assez longue avec TPKT 0x03 sort « S7Comm ».
  C'est le trou de détection le plus net des 19 protocoles.
- **`Internet::profinet()` jette tout le travail** de `ProfinetPacket::try_from` (FrameId, XID,
  name_of_station) et renvoie une couche vide (internet/mod.rs:149-160), contrairement à
  IPv4/IPv6/ARP qui remontent leur en-tête dans `InternetDetails`.
- **`IpType::from_addr`** (ip_type.rs:33-51) a deux bras inatteignables (`is_link_local` masqué par
  `is_apipa_ip`, `is_unique_local` masqué par `is_ula`) et IPv6 n'a pas de classe `Documentation`
  (2001:db8::/32 est classé `Public`, assertion explicite au test ip_type.rs:135-140).
- **Branche morte `ipv4.rs:170-172`** (`else if total_length > data.len()`) :
  `validate_ipv4_total_length` vient de rejeter ce cas ; le commentaire « use what we have »
  décrit un comportement tolérant qui n'existe plus.
- **`benchmark_db/src/main.rs:216-217,231-232`** : `escape_json_string(crate_code)` passé deux
  fois, donc le champ `crate_version` du JSONL contient toujours le hash blake3, jamais un semver
  (`CARGO_PKG_VERSION` n'est jamais lu). L'ingestor masque le symptôme via
  `crate_version_compat()` et 10 requêtes Grafana lisent la colonne.
- **`perf_by_version.json`** s'arrête à « 8.0.0-local » ; `total_ns` (568) dépasse largement la
  somme des couches (369) : ~35 % du budget publié est l'instrumentation elle-même
  (5 `Instant::now()`/paquet). Le README ne le dit qu'à demi-mot.
- **CHANGELOG lacunaire** : aucune entrée pour 1.0.0, 1.0.1, 1.1.x, 1.2.0, 1.3.0, 1.6.0, 2.0.x,
  3.0.1 — toutes publiées sur crates.io. L'historique saute de 1.5.5 à 3.0.0.
- **19 protocoles, 4 suffixes d'enum d'erreur, 10 formes de « payload tronqué »**
  (`PacketTooShort{expected,actual}` / `{actual}` / `{min,actual}`, `BufferTooSmall`, `Truncated`
  ×2 formes, `InsufficientData`, `TooShort`, `InvalidSize`, `InvalidPacketLength`,
  `HeaderTooShort`). Un consommateur ne peut pas compter uniformément les rejets pour cause de
  snaplen — d'autant que la cascade jette de toute façon ces erreurs. Un type partagé
  `TruncatedPayload { needed, actual }` réglerait les deux.

---

## Annexe — reproduction des mesures

Les deux tableaux chiffrés (§4.2 et §4.3) ont été obtenus avec un `examples/` temporaire, non
conservé dans le repo :

- **Pic d'allocation** : `GlobalAlloc` instrumenté comptant `alloc`/`dealloc`, `PEAK.fetch_max`
  sur le compteur courant, mesure encadrant un unique appel à `parse(LinkType::ETHERNET, …)`.
- **Temps par paquet** : profil `release` (`opt-level = 3`, `lto = "fat"`, `codegen-units = 1`),
  200 itérations d'échauffement puis 20 000 itérations mesurées sous `std::hint::black_box`,
  2 000 pour le cas jumbo.

Les payloads hostiles sont forgés à la main et encapsulés dans une trame Ethernet/IPv4/UDP
complète, sur des ports **non associés** au protocole ciblé — c'est précisément le point : la
cascade L7 sonde à l'aveugle, donc le port n'offre aucune protection.
