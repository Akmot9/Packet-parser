# Roadmap packet_parser

Etat au 2026-09-20 (soir) : la **11.1.0 est publiee**. Elle porte l'epic
#76 solde — les quatorze ruptures d'API en une majeure — et **UMAS** (#10),
sur une capture reelle trouvee dans le corpus nDPI. La 11.0.0 n'a jamais ete
publiee : UMAS est arrive avant que le tag ne soit pose, et la 11.1.0 la
contient entierement. L'affirmation ci-dessous « aucune trame
publique n'existe » etait fausse : `tests/cfgs/default/pcap/umas.pcap` en
porte 180. Le meme corpus comble quatre autres trous du depot — OPC UA,
PostgreSQL, S7CommPlus (dont le commentaire de `checks/application/s7comm.rs`
affirme aussi, a tort, qu'aucune trame 0x72 n'existe) et GTP-U pour #15.

Etat anterieur (2026-09-20) : la **11.0.0 est prete, pas publiee**. L'epic #76 est
solde en sept PR empilees (#84 a #89, puis la PR de release) vers la branche
`release/11.0.0` : GIOP complet en parite avec tshark, purge de la surface
publique, erreurs `non_exhaustive` et SYN+FIN conserve, `vlan_stack`, schema
JSON unique, zero copie mesure. Detail au §1 bis ; migration dans
`MIGRATION-11.md` ; `sonar-rust` compile contre la copie locale avec sept
lignes changees. Restent a la main du mainteneur : relecture et merge des PR,
tag, `cargo publish`, integration Sonar.

Point ouvert : sur le paquet de reference de verbench (IPv6/TCP chiffre,
aucune sonde L7 ne matche — le pire cas), la 11.0.0 est entre la parite et
+7 % selon la mesure (394 -> 424 ns au passage complet ; 412-435 contre
416-424 en A/B alterne ; `parse()` nu : 210 -> 219 ns). L4 y gagne 8 ns, L7
en perd 10 a 18, non attribues : une bissection par branche ne designe aucun
commit, deux formes de code equivalentes donnent 208 ou 219 ns, et `perf`
est verrouille sur la machine de mesure. Deux causes reelles ont ete
corrigees (garde GIOP a cout constant, anomalie TCP hors du chemin chaud).
Le trafic reconnu, lui, gagne 7 a 17 % (DNS, HTTP, EtherNet/IP, OPC UA).

Etat anterieur (2026-09-09) : la **10.5.0 est publiee** (mineure, additive : tunnels
VXLAN/Geneve depuis des captures produites au labo, et pile de tags VLAN
802.1ad / QinQ consommee entiere — #82, decouvert par SONAR sur une matrice
multi-VLAN). `vlan` retient le tag interne ; le champ `vlan_stack` qui
exposerait la pile complete rejoint le tableau de #76. verbench : 539 ns
sur le paquet de reference (532 en 10.4.0), l2 32 ns contre 31.

Etat anterieur (2026-08-20, soir) : la **10.4.0 est publiee** et la campagne de
resorption du backlog est terminee : **37 des 44 issues ouvertes sont
soldees** en trois jours et trois versions mineures (10.2.0, 10.3.0,
10.4.0), couverture de tests a 86,4 %. Les 7 issues restantes sont toutes
dans un etat documente : #76 et ses quatre ruptures phase-2 (#22, #26,
#27, #32) attendent la decision d'ouvrir la 11.0.0 — leur tableau a ete
enrichi de tous les transferts de la campagne (rdata DNS, Vec PostgreSQL,
Vec porteurs opcua/enip/http, variantes TcpError, body GiopReply,
IpType::Broadcast) — et #10 (UMAS) comme le volet VXLAN/GTP-U/Geneve de
#15 attendent des captures reelles que seul le labo peut produire.

Priorite suivante : produire ces captures (UMAS en tete, aucune trame
publique n'existe), puis decider de la fenetre 11.0.0.

Etat anterieur (2026-08-20) : la **10.3.0 est publiee**, et la campagne de resorption
du backlog a ferme 24 issues en deux jours — regression tshark generalisee
(Modbus/DNS/TLS, parite verifiee), quatre parseurs completes (DHCP, SRVLOC,
GIOP, QUIC Retry), detection hors port des verbes non-ambigus, corrections
NXDOMAIN/DNS-TCP/faux positifs NTP, et quatre nouveaux protocoles cables
depuis les trames reelles de The-Ultimate-PCAP : LLMNR, SSDP, NetBIOS
(NBNS/NBSS) et STP (BPDU en LLC, etiquetes au niveau flux). Post-10.3.0,
ces quatre parseurs partiront dans la 10.4.0.

Etat anterieur (2026-08-19) : la **10.2.0 est publiee**. La 10.0.0 avait ouvert une
**fenetre de stabilite** — tout ce qui suit est realisable sans nouvelle
version majeure, et l'objectif est de tenir 6 a 12 mois sans rupture d'API.
La 10.2.0 le confirme a son tour : `cargo semver-checks` la classe
« minor change », 196 controles, aucune rupture.

La 10.2.0 apporte le decodeur **IEEE 802.3br mPackets express** (LINKTYPE
274, #79) — les 10 667 trames du corpus decodent, zero erreur L2 restante —
et solde #31 : MSRV 1.88 declaree et verifiee, Cargo.lock versionne avec
`--locked` partout, cargo-deny bloquant sur chaque push/PR, job macOS, lints
anti-panic (unwrap/expect/panic) sur le code de production. La suite de
tests n'a plus aucune dependance systeme : les bindings natifs libpcap/Npcap
(`pcap`, `pnet`) sont remplaces par `pcap-file`, du Rust pur. Pas de job CI
Windows, par decision (licence OEM Npcap, aucune adherence voulue), mais la
suite y est portable.

Rien n'est en attente de publication a ce jour ; la section « Non publie » du
CHANGELOG est vide.

Chaque ajout suit la methode canonique (`METHODE_AJOUT_PROTOCOLE.md`) :
extract_* par champ dans checks, TryFrom lineaire, golden tests sur trames
reelles, choix documente de la voie de detection (probing aveugle si la
signature est forte, garde de port sinon).

## 1. Chantiers ouverts (issues GitHub)

Les epics et leurs sous-issues sont sur GitHub, chacune avec fichiers
concernes et critere d'acceptation.

| Epic | Sujet | Etat |
|---|---|---|
| #38 | Nettoyage d'API pour la 10.0.0 | ✅ clos (livre en 10.0.0) |
| #46 | Durcissements de validation (http, quic, dhcp, srvloc) | ouvert — #47 clos, #48 clos ; restent #49 et #50 |
| #51 | Completer les parseurs (dispatch GIOP, body SLPv2, Retry QUIC) | ouvert |
| #56 | Golden tests manquants (ethernet_ip, giop, quic) | ouvert — debloque, corpus partiellement rendu |
| #60 | Zero-copy integral (rdata DNS, Vec postgresql/opcua/http) | ouvert |
| #64 | Detection hors port standard : API « Decode As » + verbes non-ambigus FTP/SMTP/NNTP | ouvert |
| #67 | Nouveaux protocoles : LLMNR (#68) et SSDP (#69) | ouvert |
| #70 | Generaliser la regression tshark (modbus, dns, tls) | ouvert — debloque, corpus partiellement rendu |
| #79 | Decodeur IEEE 802.3br mPackets (LINKTYPE 274) | ouvert |

**#74 est clos le 2026-08-15.** `scan_pcaps` resout desormais le LINKTYPE par
paquet au lieu d'appeler `get_datalink()` une fois par fichier. Trois captures
sortent de l'invisibilite, pas une seule : `The-Ultimate-PCAP.pcapng`
(0 -> 51 328 trames), `capwap-only.pcapng` et `capwap-association-valid.pcapng`
(0 -> 2 chacune). Les comptes correspondent exactement a tshark.

**#79 est clos le 2026-08-19, livre en 10.2.0.** Le corpus est desormais
**entierement rendu** : les 10 667 trames LINKTYPE 274 decodent (decouverte
en route : 102 d'entre elles ont un preambule raccourci a 6 octets, ce qui a
impose de localiser le SMD dynamiquement plutot qu'a offset fixe). Ces
trames portent 2 403 ICMPv6, 1 841 ICMP, 1 237 TCP, 818 VRRP, 777 GLBP,
678 IS-IS et 599 NTP — autant de sources de trames reelles nouvelles pour
#56.

Priorite : **#56**, dette vis-a-vis de la regle « trames reelles
obligatoires », desormais sans prealable.

#55 a ete ferme le 2026-08-12 : il decrivait un etat perime. La detection
TLS est cablee depuis le commit 5b12cf7 (2025-11-20) par probing aveugle
dans `Application::try_from`, verifiee sur 568 trames reelles du corpus
`pcaps_exemple/protocols/tls/`. Ce qui manque — golden tests de
verrouillage et oracle negatif — releve de #56.

Les 12 trames `Unknown` de tls1.3-ech.pcapng ne sont pas un defaut : ce
sont des segments TCP de continuation (seq > 1) portant le milieu ou la fin
d'un record dont l'en-tete etait dans un segment anterieur. Tshark en
etiquette 7 « TCP » comme nous ; les 5 autres ne deviennent TLS que par
reassemblage TCP (tcp.segment.count 2 a 4), hors de portee d'un parseur
stateless. Meme frontiere que le QUIC Short Header documente dans
`src/parse/mod.rs`. Rien a voir avec ECH.

## 1 bis. Ruptures soldees par la 11.0.0 (#76)

L'epic **#76** regroupait les ruptures d'API accumulees pendant la fenetre
de stabilite 10.x. Elles partent toutes dans la 11.0.0, lot par lot (design :
`docs/superpowers/specs/2026-09-19-api-11-0-0-design.md` ; migration :
`MIGRATION-11.md`) :

| Lot | Contenu | PR |
|---|---|---|
| GIOP | les huit types de message, GIOP 1.0/1.1/1.2, parite tshark message par message | #84 |
| B — purge | `checks` interne (#32), `parse_timing` additive (#26), `to_owned_flow` (#27), `QuicPacketType::Unknown` (#48) | #85 |
| A — erreurs | `non_exhaustive` sur les 46 enums d'erreur (#21), SYN+FIN conserve et signale (#24), un seul chemin d'erreur de liaison (reliquat sprint_02) | #86 |
| C — champs | `vlan_stack` (#82), `IpType::Broadcast` (#9), `non_exhaustive` etendu a 124 types | #87 |
| E — JSON | un seul schema, celui du modele owned (#22) | #88 |
| D — zero copie | DNS (#61), HTTP / EtherNet/IP / OPC UA (#63), chacun mesure sur trafic reel | #89 |

**Retire, mesure a l'appui : PostgreSQL (#62).** Sur 8 209 trames reelles,
emprunter les `Vec` de Parse/Bind/Startup ne gagne que 1,5 %. La rupture ne
se justifie pas ; a rouvrir seulement si un profil reel montre autre chose.

Rien d'autre n'est connu comme bloque par une rupture d'API.

## 2. Nouveaux protocoles proposes

Criteres de priorisation : coherence avec le positionnement ICS/OT et
analyse securite, force de la signature wire, disponibilite des captures,
synergie avec le code existant.

### Tier 1 — les evidences (captures deja dans le repo ou dossier prepare)

| Protocole | Detection | Notes |
|---|---|---|
| ICMP / ICMPv6 detaille | protocole IP 1/58, pas de probing | Captures deja presentes (`pcaps_exemple/protocols/icmp/`). Trou fonctionnel : reconnu au transport mais jamais decode (echo, unreachable, TTL exceeded, neighbor discovery). |
| NetBIOS-NS / Datagram | UDP 137/138, format proche DNS | Dossier `protocols/netbios/` prepare ; omniprésent dans les captures Windows (deja visible dans mDNS3.cap et smtp.pcap). |
| RADIUS | UDP 1812/1813, en-tete code+id+length+authenticator | Capture deja presente (pcap CAPWAP « + radius a partir de la ligne 33003 »). Coherent avec le travail CAPWAP. |
| OpenVPN | garde de port (1194) + opcode/session id | Dossier `protocols/openvpn/` prepare. |
| STP (BPDU) | couche L2 (LLC DSAP 0x42), pas la chaine applicative | Dossier `protocols/stp/` prepare ; se branche cote data_link comme Profinet. |

### Tier 2 — cœur de cible ICS/OT (le differenciateur de la crate)

| Protocole | Detection | Notes |
|---|---|---|
| DNP3 | TCP/UDP 20000 ; octets de depart 0x05 0x64 + CRC par bloc → **probing aveugle possible** | LE protocole du secteur electrique nord-americain. Meme doctrine que S7comm : signature d'enveloppe assez forte pour se passer du port. |
| IEC 60870-5-104 | TCP 2404 ; start 0x68 + longueur APDU → garde de port | L'equivalent europeen de DNP3. |
| BACnet/IP | UDP 47808 ; BVLC 0x81 + fonction + longueur exacte | Building automation. |
| GOOSE / Sampled Values (IEC 61850) | EtherTypes L2 0x88B8 / 0x88BA | Se branche dans la couche internet a cote de Profinet, pas dans la chaine applicative. |

Captures publiques disponibles (Wireshark wiki, corpus Netresec) ; verifier
d'abord si `4SICS-GeekLounge-151020.pcap` contient deja du DNP3/IEC104.

### Tier 3 — indispensables analyse securite IT

| Protocole | Detection | Notes |
|---|---|---|
| SSH | banniere litterale `SSH-2.0-...` → probing aveugle trivial | Le meilleur ratio valeur/effort de la liste ; expose la version serveur. |
| SMB2/3 | magic 0xFE 'S' 'M' 'B' → signature forte | Incontournable pour l'analyse d'incidents Windows. |
| RDP | TPKT + COTP (X.224 CR, cookie mstshash), port 3389 | Reutilisation directe du chantier COTP de la 10.0.0. |
| DTLS | decalque du parseur TLS + epoch/sequence, UDP | Utile pour WebRTC et CAPWAP-DTLS (deja croise dans les captures du repo). |
| WireGuard | UDP ; type 1-4 + 3 octets reserves a zero | Signature correcte, tres demande. |
| SIP | UDP/TCP 5060, texte a la HTTP | Reutilise les briques request-line/headers de http. |

## 3. Ordre recommande

Livres et **publies en 10.1.0** depuis le cadrage de cette liste :

- **ICMP** — ICMPv4 et ICMPv6, dont Router Solicitation / Advertisement.
- **SSH** — sur les trames de banniere. Limite connue consignee au
  CHANGELOG : un parseur stateless en identifie huit sur les 542 trames
  qu'un dissecteur a etat etiquette SSH dans `The-Ultimate-PCAP`.

Reste a faire, dans l'ordre :

1. **#79** — decodeur 802.3br, ce qui reste du deblocage de corpus (voir §1).
   Additif, et l'architecture de `sprint_02` prevoit ce point d'extension.
2. **DNP3** — ouvre le secteur energie.
3. **RDP** — rentabilise TPKT/COTP.
4. RADIUS, NetBIOS, LLMNR (#68), SSDP (#69) au fil de l'eau.
6. Tier 2 restant (IEC 104, BACnet, GOOSE/SV), puis Tier 3 restant.

En parallele des protocoles : solder #56 (golden tests manquants), qui est
de la dette plus que de la feature.

Sprints : `sprint_01.md` (methode de travail) et `sprint_02.md`
(architecture multi-LINKTYPE) sont tous deux soldes sur leur definition de
termine. Aucun sprint actif. Le seul reliquat de sprint_02 — l'unification des
deux chemins d'erreur de liaison — est une rupture d'API et vit desormais dans
#76 (§1 bis).

## 4. Regles de la fenetre de stabilite

- Aucune rupture d'API sans necessite majeure. Depuis la 11.0.0, **ajouter
  un champ a une struct de decodage, une variante a un enum de protocole ou
  une variante d'erreur est additif** : ces types sont `#[non_exhaustive]`.
  La regle, ses exceptions motivees et le test qui la verrouille :
  `tests/public_types_are_non_exhaustive.rs`.
- Une nouvelle variante d'enum sans donnees s'ajoute **en fin d'enum** : les
  discriminants historiques sont une surface publique (`as u8`).
- `checks` est interne : une regle de validation se refactore librement.
- Une rupture motivee par la performance est **mesuree sur du trafic reel**
  avant d'etre ecrite (borne superieure du gain en neutralisant le code
  vise), et retiree si elle ne gagne rien.
- Tout nouveau parseur arrive complet : errors + checks + parse + cablage
  detection + golden tests sur trames reelles + entree CHANGELOG. Une sonde
  tentee sur tout le trafic d'un transport passe derriere une garde a cout
  constant (magic, octets d'en-tete) avant son decodeur.
- Les protocoles a grande surface (DNP3, SMB2) recoivent une cible de fuzz
  et, si des captures riches existent, une regression tshark — par trame
  (`tshark_regression`) ou, mieux, message par message
  (`giop_tshark_regression`).
- L'integration aval (Sonar_desktop_app) se fait par version mineure :
  la procedure est documentee et rodee (sonar-flows-core, vendor,
  cargo-vet, snapshots). Pour une majeure, compiler une copie de
  `sonar-rust` contre la copie locale donne la liste exacte des lignes a
  migrer (voir `MIGRATION-11.md` §Impact Sonar).
