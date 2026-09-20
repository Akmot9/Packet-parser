# Provenance

Les cinq captures proviennent du corpus de tests du projet
[Zeek](https://github.com/zeek/zeek), dossier
`testing/btest/Traces/tunnels/gtp/`.

- Téléchargées le 2026-09-20 depuis la branche `master`.
- Licence du dépôt source : **BSD 3-clause** (The Regents of the University
  of California, Lawrence Berkeley National Laboratory et International
  Computer Science Institute). Permissive, compatible avec la licence MIT de
  cette crate, sous réserve d'attribution — c'est l'objet de ce fichier.

| Fichier | SHA-256 |
| --- | --- |
| `gtp1_gn_normal_incl_fragmentation.pcap` | `b5749b5f03cb5e3cce78973daf0dac661b2ef9296306e2943c60046ddc26a1bc` |
| `gtp7_ipv6.pcap` | `a893f783e557541729543f64f0d91e4af2603abefcd6e0ac2472a92b4e51c4ab` |
| `gtp_ext_header.pcap` | `a079b869288b7d402a8e24aeb76659ac9c937b74eede771c3d994f285458c094` |
| `gtp3_false_gtp.pcap` | `788042165250742d82b96fc1c6085ef1a45928d9fbc9f5f5c28d7f14b7a473ff` |
| `gtp10_not_0xff.pcap` | `34c99bc77f398902eb74b4745f3be00ce961b57474f8352aaf54c05531be0790` |

Elles closent l'issue #15 : GTP-U en était la dernière case, et le dossier
n'a longtemps contenu qu'un `.gitkeep`.

## Pourquoi celles-ci, et pas le corpus nDPI

Le `ROADMAP.md` indiquait qu'une capture GTP-U existait dans le corpus de
tests de nDPI. Elle existe, mais elle ne portait que **deux trames utiles et
aucun G-PDU transportant de l'IPv4** — là où VXLAN et Geneve ont six golden
chacun. Le corpus de Zeek donne 32 G-PDU pelables dans un seul fichier, plus
l'IPv6, une chaîne d'extension headers et deux négatifs construits exprès.

## Ces trames sont-elles réelles ?

Le `README` du dossier `Traces` de Zeek avertit que beaucoup de ses captures
sont **générées par scapy ou par un LLM** — l'une est annotée « Not real
traffic ». La règle de ce dépôt les interdit, donc la question a été
tranchée sur les octets et non sur la parole du README :

- aucun fichier `.py` n'accompagne les traces GTP, alors que c'est la
  convention de Zeek pour signaler une capture générée ;
- elles ont été ajoutées en 2012 et 2013, avec le décapsulage GTPv1 ;
- `gtp1` porte des MAC virtuelles **HSRP** (`00:00:0c:07:ac:e8`) et **VRRP**
  (`00:00:5e:00:01:de`), des TTL à 61 et 63 — donc des distances de saut
  différentes —, des checksums IP tous valides, un horodatage irrégulier à
  la microseconde, et du HTTP réel dans le tunnel.

C'est du trafic de production capturé, pas une fabrication.

## Contenu (vérifié avec tshark 4.6.6)

### `gtp1_gn_normal_incl_fragmentation.pcap` — le cas nominal

108 trames, UDP 2152 ↔ 2152, interface Gn d'un cœur GPRS. 68 G-PDU selon
tshark, **32 selon cette crate**, et l'écart est entièrement expliqué :

- 32 datagrammes entiers ;
- 40 premiers fragments ;
- 36 fragments suivants, que tshark recolle — d'où son 32 + 36 = 68.

Sur un premier fragment, UDP annonce 1496 octets quand 1480 sont présents :
la couche transport se retire avant même qu'on arrive à GTP. Ce parseur ne
réassemble pas les fragments IP, par choix documenté ; le tunnel ne peut pas
être plus complet que le datagramme qui le porte. Interne : TCP, dont une
requête HTTP.

### `gtp7_ipv6.pcap` — l'interne n'est pas annoncé

2 trames, 2 G-PDU dont l'interne est de l'**IPv6** : `fe80::224c:4fff:fe43:414c`
vers `ff02::1:3` (LLMNR, UDP 5355) et `ff02::2` (ICMPv6 Router Solicitation).
L'en-tête GTP-U est identique à celui du cas IPv4 — rien n'y dit ce qui
suit, la version se lit sur le quartet de tête du paquet encapsulé.

### `gtp_ext_header.pcap` — la chaîne d'extension

2 trames, un seul G-PDU, et le **seul en-tête d'extension de tout le corpus
Zeek** : flags `0x36` (E et S posés), type de première extension `0xc0`
(PDCP PDU number), chaîne `01 09 04 00` — longueur d'un mot de quatre
octets, contenu `09 04`, suivant `00` qui la ferme. Interne : TCP vers le
port 6005 (X11).

Son datagramme est fragmenté, donc **aucun golden de bout en bout ne peut
l'atteindre**. La chaîne est testée là où elle est atteignable, sur le
peleur directement, avec les octets réels de cette trame
(`parse::tunnel::tests`).

### `gtp3_false_gtp.pcap` — le port ne fait pas le protocole

1 trame, et ce n'est **pas** du GTP : une requête DNS dont le port source
vaut 2152, avec un tag VLAN par-dessus le marché. Le premier octet de la
charge UDP est `0x6b`, soit une version GTP 3 qui n'existe pas. La règle de
port déclenche ; le contenu doit la désavouer.

### `gtp10_not_0xff.pcap` — tout le GTP ne porte pas un paquet

3 trames de GTP authentique sur 2152, mais aucune n'est un G-PDU :
Supported Extension Headers Notification (`0x1a`), Echo Request (`0x01`),
Echo Response (`0x02`). Le flag S est posé, donc l'en-tête fait 12 octets.
Seul le message type 255 porte un paquet utilisateur.

## Ce que ces captures ne contiennent pas

- **aucun G-PDU à extension non fragmenté** : tout le corpus Zeek n'en porte
  qu'un, et il est fragmenté (voir ci-dessus) ;
- **aucun flag PN seul** : les flags rencontrés sont `0x30` (192 trames),
  `0x32` (29), `0x36` (1) et `0x1e` (12, du GTPv0 que le peleur refuse) ;
- **aucun GTP-C sur 2123** dans les fichiers retenus — le plan de contrôle
  n'est pas un tunnel et n'est pas pelé.
