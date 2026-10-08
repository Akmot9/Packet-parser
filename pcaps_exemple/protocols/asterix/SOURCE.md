# Provenance

Neuf fichiers, trois origines : la capture du mainteneur, les échantillons
de Croatia Control, et des pièces jointes du tracker Wireshark versées avec
le lot défense (#119, épopée #125, rapport `docs/protocoles-defense.md`).

## `cat048_multicast.pcap` — capture du mainteneur, anonymisée

Capture Ethernet fournie par le mainteneur (Dumpcap/Wireshark 4.6.6 sous
Windows 11, le 2026-09-30, 4,98 s) : deux émetteurs diffusent des rapports
radar **CAT 048** en multicast UDP, sur les ports 46227 → 8611 et 8612 →
8612 — pas le port 8600 que Wireshark propose par défaut, ce qui fait de
cette capture le cas « ASTERIX sans port connu » que la sonde structurelle
doit reconnaître.

**Anonymisée avant dépôt** (script scapy, vérifié avec tshark) :

- adresses MAC sources remplacées par des adresses administrées localement
  (`02:00:00:00:02:0b`, `02:00:00:00:02:12`) ;
- IP sources renumérotées dans `10.0.2.0/24`, groupes multicast dans
  `239.192.0.0/16`, adresses MAC multicast de destination recalculées en
  conséquence ;
- checksums IP et UDP recalculés (`ip.checksum.status` et
  `udp.checksum.status` : aucun `bad`) ;
- conversion pcapng → pcap : les métadonnées de capture (nom d'interface,
  machine, système, application) disparaissent ;
- cinq trames ARP étrangères au flux (un poste tiers sur un autre réseau)
  retirées.

Les **203 datagrammes UDP sont identiques octet pour octet** à l'original
(comparaison des `udp.payload`), ports compris. SHA-256 du fichier déposé :
`7c5a3c0187ad3f3e882566cc71a1dabf47d5e814d979a038f6d8615b50ff3d52`.

### Contenu (vérifié avec tshark 4.6.6, `-d udp.port==8611-8612,asterix`)

203 trames, 203 data blocks CAT 048 d'un record chacun, aucune erreur
d'analyse :

- 50 datagrammes de l'émetteur `10.0.2.11` (41 de 49 octets, 9 de 35) et
  153 de `10.0.2.18` (123 de 50 octets, 30 de 36) ;
- FSPEC `ff c3 3f 78` (19 items : 010, 140, 020, 040, 070, 090, 130, 220,
  240, 170, 080, 100, 110, 120, 230, 055, 050, 065, 060) pour les longs,
  `f7 c3 0e` (12 items, sans 070, 080, 100 ni 050/055/060/065) pour les
  courts ;
- SAC 0 / SIC 2 sur 164 records, SAC 0 / SIC 0 sur les 39 records sans
  détection (`TYP` 0) ; adresses aéronef `0x00000a` à `0x0000e6`,
  identifications numériques (`0001000`...), Mode 3/A de 0070 à 7777 ;
- les items composés I048/130 et I048/120 y ont un primary subfield vide
  (un octet `0x00`) : le cas limite « composé sans sous-champ » est donc
  couvert par une trame réelle.

## `cat_034_048.pcap`, `cat21_re.ast` et `cat_062_065.pcap` — échantillons CroatiaControlLtd

Fichiers `install/sample_data/cat_034_048.pcap` et
`install/sample_data/cat21_re.ast` du dépôt
[CroatiaControlLtd/asterix](https://github.com/CroatiaControlLtd/asterix)
(décodeur ASTERIX de Croatia Control Ltd).

- Commit épinglé : `5988f544994b8776c62617bfbaf97d99644a83c9` ; URL :
  `https://raw.githubusercontent.com/CroatiaControlLtd/asterix/5988f544994b8776c62617bfbaf97d99644a83c9/install/sample_data/<fichier>`.
- Téléchargés le 2026-09-30 ; SHA-256 :
  `7f4e9a37641bfa27022ee95ba52f178e68260c1b7e83d6a0e4720a96b3a2cc3d`
  (`cat_034_048.pcap`) et
  `9979def457ecc7a8b70a6252cc59d52f60f686e6e84c32b0d83fbca6f2273f5a`
  (`cat21_re.ast`).
- Licence du dépôt source : **GPL-2.0**. Les fichiers sont redistribués tels
  quels, sans modification ni anonymisation (trafic multicast d'un réseau
  `10.17.58.0/24` vers `232.1.0.0/16` et `232.2.0.0/16`, capturé le
  2016-05-05). Un quatrième échantillon du même dossier, `cat048.raw` (48
  octets, un record CAT 048 complet, SHA-256
  `17481bd2955d046e…`), n'est pas déposé : ses octets sont embarqués en hex
  dans les tests unitaires de `src/parse/application/protocols/asterix/cat048.rs`.

### `cat_034_048.pcap` (vérifié avec tshark 4.6.6, `-d udp.port==20000-23000,asterix`)

100 trames Ethernet/IPv4/UDP, 14 conversations multicast (ports 20114 à
21174 → 21111 à 22135), aucune erreur d'analyse :

- **80 datagrammes d'un data block, 20 de deux** (CAT 048 puis CAT 034 dans
  le même datagramme) ;
- **289 data blocks CAT 048** portant **331 records** (jusqu'à trois par
  bloc) et **34 data blocks CAT 034** d'un record chacun ;
- items CAT 048 attestés : 010, 020, 040, 042, 070, 090, 110, 130 (avec
  sous-champs SRL, SRR, SAM), 140, 161, 170, 200, 220, 230, 240, 250
  (registres BDS, répétitif) ; CAT 034 : 000 (types 1 et 2), 010, 020, 030,
  041, 050, 060, 120 ;
- trafic réel : SAC 25 / SIC 11 à 13, identifications de vols commerciaux
  (`THY9TX`, `RYR22SB`, `WZZ548`...).

### `cat21_re.ast`

Flux brut de 91 octets, **deux data blocks CAT 021** (44 et 47 octets) d'un
record chacun, édition 2.x (FSPEC de sept octets, FRN 48 = RE). Items : 010,
040 (deux octets), 130, 080, 073, 074, 090, 210, 020, 016, 132, 295 (Data
Ages, primary subfield d'un à trois octets) et RE. Ce n'est pas une
capture : le collecteur du corpus ignore l'extension `.ast`, et le golden
`tests/asterix_golden.rs` lit le fichier comme un buffer. Décodé par tshark
sans erreur après encapsulation dans un pcap UDP 8600 (envelope fabriquée
pour la vérification seulement, non déposée).

### `cat_062_065.pcap` (versé le 2026-10-08)

Même dépôt, même commit épinglé, même licence (GPL-2.0). SHA-256
`fc250f563ec96369d10f960f870a305041b85e05842d987e68dbd3c4d079df13`.
Une trame du 2014-02-25 (émetteur Cisco vers `227.0.6.1:10001`) : un bloc
CAT 062 et un bloc CAT 065 dans le **même datagramme**, décodés par tshark
4.6.6 sans erreur.

Deux autres échantillons du dossier ne sont pas déposés :

- `asterix.pcap` (100 trames CAT 062, 2008) : tshark 4.6.6 en déclare 64
  malformées sous **toutes** les éditions CAT 062 qu'il propose (1.16 à
  1.21) — une édition plus ancienne ou une variante, qu'aucun oracle ne
  permet de vérifier ;
- `cat_001_002.pcap` (une trame) : le datagramme commence par un en-tête
  d'enregistrement de six octets avant le premier bloc. Ce n'est pas de
  l'ASTERIX brut sur UDP.

## Pièces jointes du tracker Wireshark (lot défense)

Captures jointes par leurs auteurs à des issues publiques du projet
Wireshark (<https://gitlab.com/wireshark/wireshark>), téléchargées le
2026-10-08 et redistribuées telles quelles, sans modification ni
anonymisation. Aucune licence explicite n'accompagne ces pièces jointes ;
elles sont publiques depuis leur dépôt. Comptes vérifiés avec tshark 4.6.6,
en forçant le décodage ASTERIX sur les flux concernés.

| Fichier | Issue | Fichier d'origine | SHA-256 |
|---|---|---|---|
| `wireshark_8579_radardata.pcap` | [#8579](https://gitlab.com/wireshark/wireshark/-/issues/8579) | `radardata.pcap` | `3498e617fb72021da6f608324156c04e45ded5d5da85e86665713fe25dd72fee` |
| `wireshark_9953_cat021023.pcap` | [#9953](https://gitlab.com/wireshark/wireshark/-/issues/9953) | `cat021023.pcap` | `38f4d7dd0ec50b303e2a0b98516116dfd16601e3172487b2c85babc4fdbfd291` |
| `wireshark_9624_cat62_re.pcap` | [#9624](https://gitlab.com/wireshark/wireshark/-/issues/9624) | `Cat62_RE.pcap` | `95a8834d1c50648be1b7beca1f39eef2c67dafd4a64a0c986d46cb1a7621e956` |
| `wireshark_9239_cat008only.pcap` | [#9239](https://gitlab.com/wireshark/wireshark/-/issues/9239) | `cat008only.pcap` | `84d9f2891cce19310c154f857e7bdfe7a66042fb546cbfc1f0fa9ed665d7e668` |
| `wireshark_9239_cat008only-2.pcap` | [#9239](https://gitlab.com/wireshark/wireshark/-/issues/9239) | `cat008only-2.pcap` | `9e5d6f3cb9f5c0508ae54cebde29b196a727685228ea544f318abafd0d64dbe0` |

- **`wireshark_8579_radardata.pcap`** — 50 000 trames sur 190 s, le
  2011-11-25, jointes à l'issue qui a créé le dissecteur ASTERIX de
  Wireshark : un réseau de contrôle aérien (plusieurs radars et un système
  de pistes), d'origine non documentée.
  - **41 928 datagrammes ASTERIX** sur 18 flux multicast, portant 29 706
    blocs CAT 001, 19 694 CAT 002, 7 879 CAT 034, 7 195 CAT 048, 7 090
    CAT 062, 1 271 CAT 065, 307 CAT 063 et 48 CAT 008 ;
  - 15 088 datagrammes portent plusieurs blocs (jusqu'à 18), dont **14 416
    mêlent plusieurs catégories** — CAT 001 et 002 dans 10 952 d'entre eux ;
  - tshark déclare 70 trames CAT 001/002 malformées, quelle que soit
    l'édition CAT 001 retenue (1.2 à 1.4) ;
  - le reste de la capture : 1 530 fragments IPv4, des flux multicast et
    broadcast de formats que tshark n'identifie pas (dont
    `225.10.1.1:20201`, source du faux positif DNS #118), 95 BPDU STP,
    92 IGMP, 3 DHCP et une requête SLPv2.

  La crate en étiquette aujourd'hui **11 881** — exactement les datagrammes
  qui ne portent que du CAT 034/048 ; les 30 047 autres sortent `Unknown`
  (#119).
- **`wireshark_9953_cat021023.pcap`** — 1 588 datagrammes d'un bloc chacun
  (émetteur vers `239.1.20.1:56610`), le 2014-04-01 : **1 555 CAT 021**
  d'édition 2.x (décodés sans erreur par tshark avec son édition par défaut,
  2.7), 30 CAT 023 et 3 CAT 247. Ce sont les premières trames CAT 021 du
  corpus dans de vrais datagrammes ; la crate étiquette déjà ASTERIX les
  1 555 datagrammes CAT 021, la parité item par item reste à établir.
- **`wireshark_9624_cat62_re.pcap`** — 668 datagrammes vers
  `239.255.250.226:8600`, le 2013-12-04 : 668 blocs CAT 062, avec leur
  Reserved Expansion Field, dont 254 suivis d'un bloc CAT 065.
- **`wireshark_9239_cat008only.pcap`** et **`-2.pcap`** — 9 et 10
  datagrammes CAT 008 (météo) vers `239.1.20.1:56520`, les 2013-10-07 et
  2013-10-10.

## Ce que ce corpus ne contient pas

- aucune capture d'une édition 0.2x de CAT 021 (UAP d'ordre différent, non
  supporté) ;
- aucune capture de CAT 010, 019, 020 ou 240 ;
- les catégories 001, 002, 008, 023, 062, 063, 065 et 247 y sont, mais la
  crate ne les décode pas encore (#119).
