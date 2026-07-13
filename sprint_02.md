# Sprint 02 - Architecture de parsing multi-LINKTYPE extensible

> Statut : actif
>
> Date de cadrage : 2026-07-13
>
> Consommateur de reference : Sonar, fidelite du parsing et detection du DLT
> ([issue #150](https://github.com/Sonar-team/Sonar_desktop_app/issues/150)).

## Objectif

Faire evoluer `packet_parser` pour parser un paquet a partir de son type de
liaison explicite, sans supposer Ethernet et sans fabriquer de fausses donnees
de couche 2. L'architecture doit permettre d'ajouter un futur LINKTYPE en
ajoutant son decodeur, ses tests et sa documentation, sans modifier le pipeline
L3/L4/L7 ni les consommateurs.

Le resultat attendu de ce sprint n'est pas seulement un dispatcher. Le modele
retourne par la crate doit representer correctement Ethernet, RAW IP, Linux SLL
et Linux SLL2, y compris lorsque la couche de liaison ne possede pas deux
adresses MAC ou d'EtherType Ethernet.

## Frontiere de responsabilite

`packet_parser` recoit un paquet brut et un LINKTYPE canonique. La crate :

- selectionne le decodeur de liaison ;
- valide et decode l'en-tete de liaison ;
- expose les metadonnees de liaison reellement presentes ;
- transmet le protocole reseau et son payload au pipeline L3/L4/L7 commun ;
- retourne un `PacketFlow` ou une erreur structuree ;
- conserve un chemin zero-copy pour les payloads.

Le lecteur ou moteur de capture reste responsable de :

- lire les conteneurs PCAP/PCAPNG ;
- associer chaque paquet a son interface et a son LINKTYPE ;
- normaliser les valeurs `DLT_*` d'une capture live vers l'espace canonique
  `LINKTYPE_*` lorsque leurs valeurs different ;
- fournir `caplen`, `wirelen`, timestamps, snaplen et statistiques de pertes ;
- garantir l'atomicite d'un import et produire la comptabilite exhaustive.

`packet_parser` ne doit donc dependre ni de libpcap ni d'une crate de lecture
PCAP/PCAPNG.

## Decisions d'architecture

### Identifiant ouvert

`LinkType` reste un newtype numerique ouvert. Une valeur inconnue doit etre
preservee telle quelle et ne doit jamais etre convertie implicitement en
Ethernet.

L'espace numerique public de `LinkType` est celui des `LINKTYPE_*` stockes dans
les fichiers de capture. Les adaptateurs de capture live portent la
responsabilite de la normalisation depuis `DLT_*`.

### Sortie normalisee du decodeur

Un decodeur de liaison ne doit pas construire directement un `PacketFlow`
Ethernet. Il retourne une vue normalisee equivalente a :

```rust
pub(crate) struct DecodedLink<'a> {
    pub layer: LinkLayer<'a>,
    pub network_protocol: NetworkProtocol,
    pub network_payload: &'a [u8],
}
```

Le pipeline commun construit ensuite `PacketFlow` et execute le parsing
L3/L4/L7. Les noms exacts peuvent evoluer, mais cette separation est un
invariant du sprint.

### Modele public de liaison

Le modele emprunte et son equivalent owned doivent :

- exposer le `LinkType` effectivement utilise ;
- representer les adresses de liaison comme optionnelles et typees ;
- conserver les details propres au LINKTYPE sans inventer de MAC ;
- exposer le protocole reseau suivant sans imposer un EtherType Ethernet ;
- conserver le payload sous forme de slice dans le chemin emprunte ;
- utiliser des enums extensibles `#[non_exhaustive]` lorsque de futurs variants
  publics sont attendus ;
- definir et tester un schema de serialisation non ambigu.

Le type Ethernet existant peut rester disponible comme parseur specialise et
comme raccourci de compatibilite. Il ne doit plus etre le seul modele possible
dans `PacketFlow` et `PacketFlowOwned`.

### Catalogue des decodeurs

Un catalogue interne suffit pour ce sprint. Une ABI de plugins dynamiques est
hors perimetre. La crate expose toutefois une capacite de preflight equivalente
a :

```rust
pub fn is_supported(link_type: LinkType) -> bool;
pub fn decoder_info(link_type: LinkType) -> Option<DecoderInfo>;
```

Un consommateur doit pouvoir refuser un LINKTYPE non supporte meme si une
interface PCAPNG ne contient aucun paquet.

## Matrice de support cible

| LINKTYPE | Valeur | Attente de ce sprint |
| --- | ---: | --- |
| Ethernet | 1 | Support complet, sans regression de l'API historique |
| RAW IP | 101 | Support IPv4 et IPv6, sans adresses MAC inventees |
| Linux SLL v1 | 113 | Support complet des champs SLL utiles et du payload reseau |
| Linux SLL v2 | 276 | Support complet des champs SLL2 utiles et du payload reseau |
| Bluetooth H4 avec pseudo-header | 201 | Identifie mais refuse explicitement tant qu'aucun decodeur n'existe |
| Toute autre valeur | valeur brute | Preservee puis `UnsupportedLinkType` |

Les futurs decodeurs loopback/NULL, radiotap/802.11 et Bluetooth sont prepares
par l'architecture, mais leur implementation n'est pas requise dans ce sprint.

## API attendue

- `parse(LinkType, &[u8])` est l'entree explicite principale.
- `PacketFlow::try_from(&[u8])` reste un raccourci Ethernet documente.
- Avec la feature `parse_timing`, une entree
  `parse_timed(LinkType, &[u8], &mut ParseTiming)` offre le meme dispatch et le
  meme resultat fonctionnel que `parse`.
- Un LINKTYPE non supporte est rejete avant toute tentative de decodage des
  octets.
- Les chemins normal et instrumente utilisent les memes decodeurs et le meme
  pipeline de couches.

## Contrat d'erreur

- `UnsupportedLinkType` conserve la valeur numerique recue.
- Une liaison trop courte indique au minimum le LINKTYPE, la taille necessaire
  et la taille recue.
- Une liaison malformee est distinguee d'une liaison tronquee.
- Une corruption L3/L4 reconnue conserve la degradation gracieuse actuelle via
  `PacketFlow::corrupted` ; elle n'est pas transformee arbitrairement en erreur
  fatale de liaison.
- La condition de capture `caplen < wirelen` n'est pas deductible par cette
  crate et reste hors de son contrat.
- Les enums d'erreur destines a evoluer sont `#[non_exhaustive]`.

## Compatibilite et version

La generalisation de `PacketFlow`, `PacketFlowOwned`, de leur serialisation et
des erreurs publiques est une rupture de contrat. La cible de publication est
donc une version majeure `7.0.0`, sauf si l'ancien modele et l'ancien enum
d'erreur restent integralement inchanges derriere une API additive distincte.

Avant publication :

- le choix de migration doit etre explicite dans `CHANGELOG.md` ;
- les README anglais et francais doivent utiliser une version coherent avec
  l'API documentee ;
- les constructions par litteral, `match` exhaustifs et schemas JSON impactes
  doivent etre listes ;
- aucune API publique Ethernet-only ne doit etre presentee comme multi-DLT.

## Plan de travail

### Phase 1 - Stabiliser la frontiere de liaison

- [ ] Introduire la sortie normalisee du decodeur.
- [ ] Faire passer Ethernet par cette sortie sans changer son resultat.
- [ ] Generaliser le modele de liaison emprunte et owned.
- [ ] Fixer le schema de serialisation et la strategie de migration majeure.
- [ ] Remplacer les erreurs de liaison provisoires par le contrat final.

### Phase 2 - Fermer la compatibilite Ethernet

- [ ] Prouver `parse(LinkType::ETHERNET, bytes) == PacketFlow::try_from(bytes)`
  sur succes et erreur.
- [ ] Couvrir IPv4/UDP, IPv6, VLAN valide et tronque, EtherType inconnu,
  corruption L3/L4 et tunnels CAPWAP.
- [ ] Tester toutes les longueurs Ethernet de 0 a 13 octets.
- [ ] Prouver la parite du chemin `parse_timing`.

### Phase 3 - Ajouter RAW IP

- [ ] Ajouter les constantes et le decodeur LINKTYPE_RAW.
- [ ] Detecter IPv4/IPv6 depuis la version IP sans fabriquer d'EtherType.
- [ ] Tester IPv4, IPv6, paquet vide, version invalide et header tronque.
- [ ] Utiliser des paquets extraits de la fixture RAW synthetique ; le lecteur
  du conteneur PCAPNG reste un outil de test ou un test d'integration externe.
- [ ] Prouver que les slices retournees restent zero-copy.

### Phase 4 - Ajouter Linux SLL et SLL2

- [ ] Implementer les deux formats dans des modules distincts.
- [ ] Exposer leurs champs utiles sans les convertir en faux Ethernet.
- [ ] Router IPv4, IPv6, ARP et protocole inconnu correctement.
- [ ] Couvrir les tailles minimales, champs invalides et payloads tronques.
- [ ] Ajouter des fixtures minimales, synthetiques et anonymisees.

### Phase 5 - Capacites, documentation et durcissement

- [x] Exposer le preflight des LINKTYPE supportes.
- [x] Documenter la distinction DLT live / LINKTYPE fichier.
- [x] Ajouter la matrice de support dans les deux README.
- [ ] Completer `METHODE_AJOUT_PROTOCOLE.md` avec la methode d'ajout d'un
  decodeur de liaison.
- [ ] Completer `CHANGELOG.md` et preparer la version majeure.
- [ ] Ajouter les cas multi-decodeur aux cibles de fuzzing.

## Etat au demarrage

- [x] `LinkType(u32)` ouvert introduit dans le worktree.
- [x] Entree explicite `parse(LinkType, &[u8])` introduite.
- [x] Decodeur Ethernet isole derriere un dispatcher interne.
- [x] `TryFrom<&[u8]>` redirige vers Ethernet.
- [x] Tests publics minimaux pour l'equivalence Ethernet et la preservation
  d'un LINKTYPE inconnu.
- [x] Chemin Ethernet instrumente redirige vers le dispatcher interne.
- [x] Constantes canoniques ajoutees pour Ethernet, RAW, SLL, Bluetooth H4
  avec pseudo-en-tete et SLL2.
- [x] Preflight `is_supported` et entree `parse_timed` exposes depuis le meme
  catalogue de decodeurs que le chemin normal.
- [x] Refus ferme prouve : RAW ou une valeur inconnue ne retombe jamais sur le
  decodeur Ethernet.
- [x] Equivalence des erreurs Ethernet prouvee pour les longueurs 0 a 13.
- [ ] Modele de liaison generalise : non commence.
- [ ] RAW, SLL et SLL2 : non commences.

Cet etat decrit le worktree observe au cadrage ; les cases ne remplacent pas
les validations de la Definition de termine.

## Journal des micro-wins

### MW-01 - Frontiere LINKTYPE explicite fermee par defaut (2026-07-13)

Statut : valide localement ; ce journal et le code forment le commit dedie de
ce micro-win sur la branche `agent/multi-linktype-parser`.

- [x] `LinkType` est numerique, serialisable et preserve les valeurs futures.
- [x] `parse`, `parse_timed` et `is_supported` partagent un catalogue unique.
- [x] Ethernet conserve les chemins historique et instrumente.
- [x] Les LINKTYPE identifies sans decodeur restent explicitement refuses.
- [x] `ParseError` est prepare pour evoluer en 7.0 via `#[non_exhaustive]` ;
  l'alias `ParsedPacketError` est conserve.
- [x] README anglais/francais et `CHANGELOG.md` distinguent clairement la 6.0
  publiee de l'API 7.0 en cours.

Validations du micro-win :

- `cargo test` : 637 tests unitaires, 5 tests d'integration et 13 doctests ;
- `cargo test --features parse_timing` : 646 tests unitaires, 7 tests
  d'integration et 13 doctests ;
- `cargo clippy --all-targets --all-features -- -D warnings` : aucune alerte.

Limite volontaire du jalon : le modele public reste Ethernet-only. RAW, SLL et
SLL2 sont connus du catalogue public mais `is_supported` renvoie `false` et le
parsing retourne `UnsupportedLinkType`. La regle de livraison reste donc
active.

## Definition de termine

- [ ] Aucun chemin de parsing ne suppose Ethernet sans le demander
  explicitement.
- [ ] Ethernet, RAW, SLL et SLL2 produisent des representations fideles, sans
  MAC, EtherType ou metadonnees inventes.
- [ ] Un LINKTYPE inconnu ou non supporte echoue de facon deterministe en
  conservant son identifiant.
- [ ] Ajouter un futur LINKTYPE ne demande pas de modifier le pipeline
  L3/L4/L7 ni les consommateurs de `PacketFlow`.
- [ ] Les modeles emprunte et owned ainsi que leur serialisation representent
  les memes informations.
- [ ] Les chemins normal et `parse_timing` sont fonctionnellement identiques.
- [ ] Les tests de compatibilite Ethernet, RAW, SLL, SLL2, erreurs et zero-copy
  sont presents.
- [ ] La matrice de support et la migration sont documentees en anglais et en
  francais.
- [ ] `cargo fmt --check` passe.
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passe.
- [ ] `cargo test` passe.
- [ ] `cargo test --features parse_timing` passe.
- [ ] Les cibles de fuzzing du parsing paquet et des nouveaux decodeurs ne
  paniquent pas sur le corpus de regression.

## Hors perimetre

- Lecture ou ecriture des conteneurs PCAP/PCAPNG.
- Comptage des paquets, pertes noyau/application, timestamps et metadonnees
  d'interface.
- Atomicite de l'etat Sonar et presentation CLI/desktop du rapport.
- Parite exhaustive avec tous les dissecteurs Tshark.
- ABI stable pour charger des decodeurs tiers dynamiquement.
- Decodage complet Bluetooth, radiotap/802.11, NULL/loopback ou autres
  LINKTYPE non listes dans la matrice cible.

## Regle de livraison

Ne pas publier la nouvelle API tant que le modele de liaison public et owned
reste Ethernet-only. Le premier jalon acceptable est un refactor Ethernet sans
regression qui traverse la sortie normalisee ; RAW valide ensuite que
l'architecture est reellement extensible, puis SLL/SLL2 ferment le besoin du
consommateur Sonar.
