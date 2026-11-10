# Roadmap packet_parser

Etat au 2026-11-03 : la **11.8.0 est publiee** (tag `v11.8.0`, publication
par le workflow, semver-checks vert). Mineure : le decodeur **Valmet DNA**
(8ffdec1) — le reseau de process des systemes de controle distribue
Metso/Valmet, protocole proprietaire sans specification ni dissecteur public,
decode a partir de la seule observation du trafic, en lecture seule, sur une
capture du mainteneur anonymisee versee au corpus. En-tete, telegramme d'etat
(adresse du noeud, horloge BCD, compteurs), message a etiquette, balise ;
sonde de port tolerante sur UDP 2517/4516/4517, sonde aveugle stricte apres
RTPS, `DecodeAsProtocol::ValmetDna` ; faute d'oracle tshark, le golden
verifie la structure contre les en-tetes IP et la coherence des horloges et
des compteurs. `cargo audit` au vert (#227). Aucune rupture. Restent a faire :
le livre et la montee de Sonar_desktop_app (11.6.0 -> 11.8.0). Le seul
chantier ouvert reste l'epopee **#207** (§1).

Etat anterieur (2026-11-03, avant la 11.8.0) : la **11.7.0** est toujours la derniere version publiee
(2026-10-18). La section « Non publie » du CHANGELOG est vide et aucune PR
n'est ouverte. Les epopees #103, #105 et #177 ont ete fermees le 2026-10-18,
sans etre soldees : leur reliquat est consigne au §3, a rouvrir protocole par
protocole quand les captures existent. Le seul chantier ouvert est l'epopee
**#207** (§1) : une API L7 typee et la crate rangee. Ses correctifs sans
rupture passent d'abord, et la 12.0 ne partira pas avant mars 2027. Hors de
ce depot, le livre (epopee `Akmot9/packet-parser-book#66`) et
Sonar_desktop_app sont encore epingles en 11.6.0.

Etat anterieur (2026-10-18) : la **11.7.0 est publiee** (tag `v11.7.0`, publication
par le workflow, semver-checks vert). Mineure : les constats de la relecture
du livre 11.6.0 soldes — reponses HTTP reconnues et decodees (#176), sondes
sur le payload entier au-dela de `PROBE_CAP` (#184, #185), noms DNS bornes
(#196), HEADER_EXTENSION RTPS 2.5 (#186), correlation info RDP (#187), IKE
et BACnet alignes sur les registres (#189, #190), RADIUS complet jusqu'au
type 190 avec les noms IANA de 124 et 125 en constantes (#191, #192), DNP3
(#180, #181, #182), ordre JSON du modele borrowed (#193), errata de la
documentation (#194, #188). Deprecie : `AttributeType::MipHomeAgentAddress`
et `MipHomeAgentHost`, a renommer sur place en 12.0 (#191). Aucune rupture.
Restent a faire : le livre et l'integration Sonar. Restent ouvertes : les
epopees #103 (DTLS, SIP, SMB2/3), #105 et #177 (S7CommPlus, MELSOFT).

Etat anterieur (2026-10-16) : la **11.6.0 est publiee** (tag `v11.6.0`, publication
par le workflow, semver-checks vert). Mineure : le lot defense (#125 : IKE
et ESP, DIS, STANAG 5066 SIS, RTPS, ASTERIX multi-categories) et l'epopee
#102 (IEC 60870-5-104, BACnet/IP, GOOSE) soldes, DNP3 (#99), RDP (#100),
RADIUS (#101), WireGuard (#103), PPPoE (#172) et LLDP (#177), chacun en
parite avec tshark sur trames reelles ; corrections des faux positifs NTP
(#161, #162, #164, #165) et Modbus (#167), des paquets TSO (#168), de
PROFINET (#133, #141), de PostgreSQL (#98) et de FTP, SMTP et NNTP (#109).
Aucune rupture. Restent a faire : le livre et l'integration Sonar. Restent
ouvertes : les epopees #103 (DTLS, SIP, SMB2/3), #105 et #177 (S7CommPlus,
MELSOFT), et #176 (reponses HTTP).

Etat anterieur (2026-10-09) : la **11.5.0 est publiee** (tag `v11.5.0`, publication
par le workflow, semver-checks vert). Mineure : **PTP** (#121, premier
protocole du lot defense), sur UDP 319/320 et en couche 2 (EtherType
`0x88F7`), en parite exacte avec tshark sur les 3 328 messages du corpus,
plus quatre corrections : Char Encoding SLPv1 (#131), classification
`IpType` (#136), `Display` de `VlanTag` (#134) et README (#135). Une
depreciation, `SrvlocHeaderV1::encoding`, aucune rupture. Restent a faire :
les mesures, le livre et l'integration Sonar. Reste ouverte : #133
(Profinet), pour une patch.

Etat anterieur (2026-10-08) : la **11.4.0 est publiee** (tag `v11.4.0`,
publication par le workflow, semver-checks vert). Mineure de correction :
deux faux positifs reveles par le corpus du lot defense, **SRVLOC** (#117,
829 PTPv2 Delay_Req lus comme des en-tetes SLPv1) et **DNS** (#118, 37
datagrammes radar acceptes par la sonde aveugle). Reste a faire : les
mesures.

Etat anterieur (2026-09-30) : la **11.3.0 est publiee** (tag `v11.3.0`,
publication par le workflow, semver-checks vert).
Strictement additive : **ASTERIX** (EUROCONTROL, surveillance aerienne),
CAT 048, 034 et 021 ed. 2.x, reconnu par sa seule structure, 303 trames
reelles en parite exacte avec tshark, capture du mainteneur anonymisee
avant depot et deux echantillons CroatiaControlLtd (GPL-2.0, a valider).
Nouvelle cible de fuzz `parse_asterix` dans la matrice nocturne.
Mesures faites le 2026-09-30 (verbench, 37 versions publiees + copie
locale) : 544 ns sur le paquet de reference en 11.3.0, contre 569 en 11.2.0
et 534 en 11.1.0 dans le meme run. Un A/B alterne des trois binaires (cinq
passes) donne 526-549 pour la 11.3.0, 543-586 pour la 11.2.0 et 532-578
pour la 11.1.0 : la 11.3.0 est a la parite, l'ecart de la 11.2.0 dans le
run complet est du bruit, et ASTERIX ne coute rien sur ce pire cas TCP
(sa regle est gardee par UDP). Les valeurs absolues de ce run sont ~30 %
au-dessus de celles du 20 septembre pour toutes les versions : machine
differente, pas regression — comparer a l'interieur d'un run seulement.
Reste a faire : l'integration Sonar.

Etat anterieur (2026-09-25) : la **11.2.0 est publiee** (tag `v11.2.0`).
Strictement additive : **GTP-U** (#15, dernier tunnel de l'issue) et
**LINKTYPE_NULL** (#95, loopback BSD et macOS, avec la premiere capture
OPC UA reelle du depot). Le fuzzing nocturne repasse au vert sur les huit
cibles le 25 septembre : oracle FTP realigne et dote de graines (#107),
`parse_giop` enfin planifiee, catalogue de `parse_linktype` tire de
`is_supported` (#110), qui atteint enfin le decodeur NULL. Restent
ouvertes : #108 (dette d'infrastructure du fuzz) et #109 (CR et LF nus
acceptes par le parseur FTP). Restent a faire : les mesures de
performance (`perf_by_version.json` n'a ni la 11.1.0 ni la 11.2.0) et
l'integration Sonar.

A surveiller au fuzz nocturne : la couverture de `parse_linktype`, partie
de 327 le 25 septembre parce que #110 a change le sens de son selecteur
(elle etait a 6 263 la veille, avec l'ancien), et le debit de
`parse_packetflow`, divise par deux ce jour-la sans cause identifiee dans
le code.

Etat anterieur (2026-09-20, soir) : la **11.1.0 est publiee**. Elle porte l'epic
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
concernes et critere d'acceptation. Au 2026-11-03, une seule epopee est
ouverte : **#207**, « Une API L7 a la hauteur de la verification, et la
crate rangee ». Elle se divise en quatre features, et aucune de leurs
taches n'est commencee.

| Feature | Sujet | Priorite | Taches |
|---|---|---|---|
| #208 | Correctifs immediats | P1, patch ou mineure | ~~#212~~ memoisation des sondes sur 128 bits (fait, non publie), #213 `cargo semver-checks` sur chaque PR (il ne tourne qu'au publish), #214 bench criterion sur le corpus, `perf_by_version` regenere ou retire, #215 schemas mermaid rendus sur docs.rs, #216 `Application::try_from` derive de `RULES` |
| #210 | Forme du code | P2, aucun chemin public ne change | #221 decouper `parse/mod.rs` (2 886 lignes) et `dispatch.rs` (1 948), #222 mesurer la triplication parse/checks/errors |
| #211 | Depot range, README reduit, releve preparee | P2 | #223 sortir l'etabli de la racine, #224 README en deux ecrans, #225 `CONTRIBUTING.md` |
| #209 | 12.0 : API L7 typee, une seule table, les noms justes | P1, pas avant mars 2027 | #217 enum `ApplicationProtocol`, #218 `details` au L7, #219 retrait de `TryFrom<&[u8]> for Application`, #220 renommages groupes (`copt`, `mac_addres`, `NatDetection`, RADIUS 124 et 125) et `MIGRATION-12.md` |

Ordre fixe par #207 : #208 d'abord, puis #210 et #211, enfin #209 en une
seule majeure quand la fenetre de stabilite ouverte par la 11.0.0 le
permet. Le guide de migration sera ecrit avant le premier renommage.

Les epopees de l'ete 2026 qui occupaient ce tableau sont toutes closes :
#38 le 2026-08-03 (10.0.0), #46, #51, #70 et #79 le 2026-08-19, #56, #60,
#64 et #67 le 2026-08-20. Les paragraphes ci-dessous sont gardes pour
l'historique des comptes de trames.

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

Priorite d'alors : **#56**, dette vis-a-vis de la regle « trames reelles
obligatoires ». Elle est soldee le 2026-08-20.

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

Au 2026-11-03, tous les protocoles de ces trois tableaux sont livres, sauf
quatre : Sampled Values (Tier 2), SMB2/3, DTLS et SIP (Tier 3). Leur
reliquat est decrit au §3.

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

La liste qui suit etait l'ordre de travail du 2026-09-20. Chaque ligne
porte son issue : le suivi vit sur GitHub, pas dans ce fichier.

> Liste rafraichie deux fois le 2026-09-20. D'abord parce que **#79** y
> figurait en tete alors qu'il etait livre et ferme, et que la numerotation
> sautait de 4 a 6. Puis parce que la ligne « au fil de l'eau » citait
> **NetBIOS, LLMNR (#68) et SSDP (#69)** comme restant a faire : les trois
> sont livres, et les deux issues fermees depuis. Seul RADIUS en restait.
> Une liste de priorites fausse coute plus cher que le temps de la relire.
> Rafraichie de nouveau le 2026-11-03 : les six lignes sont livrees ou
> fermees.

1. **PostgreSQL** (#98) — golden sur trames reelles, a partir du corpus de
   Zeek (dix-huit captures, dont deux negatifs construits expres :
   `http-on-port-5432.pcap` et `mysql-on-port-5432.pcap`). Livre en 11.6.0.
2. **DNP3** (#99) — sondage aveugle TCP et UDP par les CRC. Livre en
   11.6.0, puis corrige en 11.7.0 (#180, #181, #182).
3. **RDP** (#100) — sur TPKT/COTP, avec la bascule en TLS. Livre en 11.6.0.
4. **RADIUS** (#101) — livre en 11.6.0, registre complet jusqu'au type 190
   en 11.7.0 (#191, #192).
5. **Tier 2 restant** (#102) : IEC 104, BACnet/IP et GOOSE livres en
   11.6.0. Sampled Values est ecarte, faute de capture redistribuable.
6. **Tier 3 restant** (#103) : WireGuard livre en 11.6.0. SMB2/3, DTLS et
   SIP ne sont pas faits ; l'epopee est fermee le 2026-10-18 (voir
   ci-dessous).

**Lot defense** (epopee #125, 2026-10-08) : solde. PTP (#121) est publie en
11.5.0. ASTERIX multi-categories (#119), RTPS (#120), STANAG 5066 SIS
(#122), DIS (#123) et IKE/ESP (#124) sont publies en 11.6.0. Le choix et
ses ecartes sont argumentes dans `docs/protocoles-defense.md`. Les 34
captures sont versees et comptees par `tests/golden_pcaps.rs`. En les
versant, deux faux positifs sont apparus, #117 (SRVLOC) et #118 (DNS),
corriges en 11.4.0.

### Reliquat des epopees fermees le 2026-10-18

Les trois epopees ont ete fermees « not planned » a la 11.7.0. Ce qui suit
n'a pas d'issue ouverte. Quand une capture reelle existe, on ouvre une
issue par protocole.

- **SMB2/3** (#103). Signature forte (magic `0xFE 'S' 'M' 'B'`), mais
  plusieurs PDU peuvent tenir dans un meme segment (voir #105).
- **DTLS** (#103). Une conception a ete faite le 2026-10-15, mais pas
  versee : elle est a reverifier avant d'ecrire du code. Elle prevoyait :
  - une sonde aveugle sur les records classiques ;
  - les records `tls12_cid`, dont le CID est deduit du pavage ;
  - l'en-tete unifie de DTLS 1.3 (C=0, S=1, L=1) ;
  - des regles de port pour CAPWAP (5246/5247), CoAP sur DTLS (5684) et
    EtherNet/IP securise (2221) ;
  - une place dans `RULES` apres BACnet/IP et avant DNS.
- **SIP** (#103). La brique d'en-tete existe depuis #205 : `HttpHeaders`
  et `split_start_line`.
- **S7CommPlus et MELSOFT** (#177). Ils attendent des captures reelles du
  banc ICS, car la regle du depot interdit tout golden sans trame reelle.
- **Sampled Values** (#102), EtherType `0x88BA`. Aucune capture
  redistribuable n'existe : mgadelha/Sampled_Values est sans licence, et
  4SICS comme l'Ultimate PCAP n'en ont pas. Le point d'entree est le meme
  que GOOSE et PTP : `NetworkProtocol::from_link_protocol`, puis
  `Internet::try_from_network_parts`.
- **Couche a etat optionnelle** (#105). Rien n'a ete mesure ni concu. Les
  huit limitations du parseur sans etat restent vraies :
  - SSH : 8 trames reconnues sur 542 ;
  - GTP-U : 32 G-PDU fragmentes sur 68 ;
  - TLS 1.3 : records a cheval sur plusieurs segments ;
  - S7Comm : 63 retransmissions etiquetees la ou tshark en compte 38 ;
  - IEEE 802.3br : fragments preemptibles refuses ;
  - IPv4 fragmente : pas de `payload_protocol` ;
  - QUIC : Short Header indecidable hors contexte ;
  - PostgreSQL : reponses d'un seul octet.

  A la reouverture, on mesure d'abord le gain sur `The-Ultimate-PCAP` :
  trames gagnees, et flux simultanes a tenir en memoire. Ensuite seulement,
  on tranche l'eviction, la concurrence, l'empoisonnement de l'epinglage,
  la bascule de protocole (STARTTLS, RDP vers TLS) et la frontiere d'API.
  Le coeur de la crate reste sans etat, car Sonar en depend.

**GTP-U est livre** (#15 close, 2026-09-20), et avec lui le dernier tunnel
de l'issue. Il vient du corpus de **Zeek** (BSD 3-clause) et non de nDPI,
pour une raison etroite et mesuree : sur les cinq captures GTP de nDPI,
**aucun G-PDU ne transporte de paquet IPv4** — le seul a porter une chaine
d'extension a un T-PDU vide, et `ipv6_in_gtp.pcap` ne porte que de l'IPv6.
Rien a peler, donc rien a figer dans un golden de peeling. Zeek en donne 32
pelables dans un seul fichier.

Ce n'est pas un reproche au corpus de nDPI, qui repartit delibere ses cinq
captures sur les variantes du protocole — GTP-U, plan de controle, GTP',
IPv6, faux positif — et couvre les chaines d'extension que Zeek n'a, lui,
que sous forme fragmentee. Sept trames y couvrent plus de cas de figure que
nos 108. C'est une lecon de conception de corpus a retenir : plusieurs
petites captures ciblees valent mieux qu'un gros fichier.

Deux corpus de tests valent donc d'etre consultes avant de conclure qu'une
trame n'existe pas — **nDPI** (LGPL-3.0), qui a comble UMAS (#10),
S7CommPlus (#93) et OPC UA (#95) en une journee, et **Zeek** (BSD 3-clause),
qui a comble GTP-U et tient les captures PostgreSQL ci-dessus. Trois
affirmations du depot sur l'inexistence d'une trame se sont revelees fausses.

Une mise en garde sur Zeek : le `README` de son dossier `Traces` signale
qu'une partie de ses captures est **generee par scapy ou par un LLM**, l'une
etant annotee « Not real traffic ». La regle du depot les interdit. Verifier
la provenance sur les octets — horodatage, checksums, MAC, TTL — avant de
verser quoi que ce soit.

#56 (golden tests manquants), qui etait de la dette plus que de la
feature, est solde le 2026-08-20.

Sprints : `sprint_01.md` (methode de travail) et `sprint_02.md`
(architecture multi-LINKTYPE) sont tous deux soldes sur leur definition de
termine. Aucun sprint actif. Le seul reliquat de sprint_02, l'unification
des deux chemins d'erreur de liaison, etait une rupture d'API. Elle est
soldee en 11.0.0 (#76, lot A, PR #86, §1 bis). Le rangement de ces fichiers
hors de la racine est la tache #223.

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
