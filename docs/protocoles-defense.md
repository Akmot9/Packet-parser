# Protocoles du domaine de la défense — quoi ajouter à `packet_parser`

> Réalisé le 8 octobre 2026 sur le commit `7ca255b` (11.3.0).
>
> **Question.** Quels protocoles du domaine de la défense ajouter à la crate ?
>
> **Critères**, ceux du dépôt : une spec publique, puisque la crate est sous
> licence MIT et publiée ; des trames réelles et redistribuables, jamais
> d'octets fabriqués ; une signature assez forte pour la détection ; un
> décodage possible sans état.
>
> **Méthode.**
> 1. Inventaire des ~240 captures locales, celles du dépôt et celles de
>    travail : aucune ne porte de protocole défense en dehors d'ASTERIX.
> 2. Recherche de captures publiques : wiki, tracker et `test/captures` de
>    Wireshark, corpus nDPI et Zeek, liste Netresec, GitHub.
> 3. Vérification de chaque capture retenue avec tshark 4.6.6 (trames,
>    encapsulation, horodatages, adresses MAC, protocole visé).
> 4. Passage de la crate (`examples/scan_pcaps.rs`) pour mesurer ce qu'elle
>    en fait aujourd'hui.
>
> **Suite donnée.**
> - épopée #125 ;
> - 34 captures versées dans `pcaps_exemple/protocols/`, chacune documentée
>   dans le `SOURCE.md` de son dossier ;
> - une issue par protocole retenu, #119 à #124 ;
> - deux faux positifs révélés en route, #117 et #118, corrigés depuis.

## Synthèse

| § | Protocole | Usage défense | Captures réelles | Suite |
|---|---|---|---|---|
| 1 | ASTERIX CAT 001/002, 062/063/065, 008 | surveillance aérienne, C2 | 41 928 datagrammes dans une seule capture, plus quatre autres sources | #119 |
| 2 | DDS / RTPS | systèmes de combat, véhicules (NGVA), ROS 2 | 8 captures, 6 implémentations | #120 |
| 3 | PTP (IEEE 1588) | synchronisation des radars, des systèmes de combat, de l'avionique | 8 captures, 3 330 trames | #121 |
| 3 | STANAG 5066 SIS | radio HF au-delà de l'horizon | 4 captures, dont le banc de l'agence C3 de l'OTAN | #122 |
| 3 | DIS (IEEE 1278.1) | simulation, entraînement | 5 captures, versions 4 à 7 | #123 |
| 3 | IKE / ESP | chiffreurs IP | 3 captures, plus celles déjà au dépôt | #124 |
| 4 | CoT/TAK, NMEA/IEC 61162-450/AIS, MAVLink, SAPIENT, FMTP, ED-137 | situation tactique, naval, drones, anti-drones, contrôle aérien | aucune exploitable | à capturer |
| 5 | Link 16, JREAP-C, VMF, SIMPLE, DMP, STANAG 4586, KLV/4609, 4607 | — | — | écartés |

## 1. Étendre ASTERIX — le meilleur rapport valeur/effort (#119)

**Catégories à ajouter :**

- CAT 001/002 : radars d'ancienne génération ;
- CAT 062/063/065 : pistes système du tracker, état des capteurs, état du
  service SDPS ;
- CAT 008 : météo.

**Le chiffre qui le justifie.** `wireshark_8579_radardata.pcap` est la pièce
jointe de l'issue Wireshark qui a créé le dissecteur ASTERIX : 50 000
trames, en 2011, d'un réseau de contrôle aérien. Ses 18 flux ASTERIX portent
**41 928 datagrammes**, dont 14 416 mêlent plusieurs catégories (jusqu'à 18
blocs par datagramme). La crate en reconnaît **11 881**, exactement ceux qui
ne portent que du CAT 034/048. Les **30 047** autres sortent `Unknown`.

La cause est la règle de reconnaissance actuelle : un datagramme n'est
étiqueté que si tous ses blocs sont d'une catégorie supportée. C'est un
choix sain — un bloc d'une catégorie inconnue n'est pas vérifiable — mais
sur un vrai site, les catégories se mélangent : CAT 001 et 002 partagent
10 952 datagrammes dans cette seule capture.

**Effort.** Le moteur UAP existe déjà : il s'agit surtout d'ajouter des
tables. La spec est gratuite chez EUROCONTROL, et il en existe une version
lisible par machine (`zoranbosnjak/asterix-specs`, BSD-3).

**Deux bonus.**

- `wireshark_9953_cat021023.pcap` apporte 1 555 datagrammes CAT 021 réels,
  le manque que notait `asterix/SOURCE.md` (seul un flux brut attestait la
  catégorie).
- `cat048_multicast.pcap`, la capture anonymisée du mainteneur, porte
  I048/050 et I048/055 sur ses 164 records longs : les codes IFF
  **militaires** Mode 2 et Mode 1. Ils sont découpés mais pas encore
  décodés en valeurs typées.

**Captures versées** (`pcaps_exemple/protocols/asterix/`) : `radardata`
(001, 002, 008, 034, 048, 062, 063, 065), `cat62_re` (CAT 062 avec son
Reserved Expansion Field, sur le port 8600), `cat008only` (deux fichiers),
`cat_062_065` (Croatia Control), `cat021023` (021, 023, 247).

**Réserves.**

- L'origine de `radardata.pcap` n'est pas documentée.
- Les pièces jointes du tracker Wireshark n'ont pas de licence explicite,
  comme les captures GIOP déjà au dépôt.
- tshark déclare 70 trames CAT 001/002 malformées, quelle que soit
  l'édition retenue : à comprendre avant de figer l'oracle sur elles.
- L'échantillon CAT 062 de Croatia Control (2008) est écarté : 64 trames sur
  100 sont malformées pour tshark sous toutes ses éditions CAT 062.

## 2. DDS / RTPS — le successeur de CORBA dans les systèmes de combat (#120)

**Usage.** DDS est le middleware de NGVA (STANAG 4754), de la GVA
britannique (Def Stan 23-009), des systèmes de combat navals et de ROS 2.
La crate décode déjà GIOP/MIOP ; RTPS, son protocole filaire, en est la
génération suivante.

**Détection.** La spec (OMG DDSI-RTPS 2.5) est gratuite. L'en-tête commence
par le magic `RTPS`, et les sous-messages doivent remplir exactement le
datagramme : probing aveugle derrière une garde à coût constant, la même
doctrine que S7comm. Le port ne suffirait pas : Cyclone DDS et Connext Micro
emploient des ports unicast aléatoires.

**Captures versées** (`pcaps_exemple/protocols/rtps/`) : huit fichiers, six
implémentations (RTI Connext et Connext Micro, Cyclone DDS, OpenDDS,
OpenSplice, CoreDX). Parmi eux, une session ROS 2 en LINKTYPE_NULL
(`foxglove/rtps`, MIT), la découverte RTI du wiki Wireshark, le fichier du
corpus nDPI et des DATA_FRAG. 231 trames sont décodables sans réassemblage
IP.

**À prévoir.** La surface est grande : une cible de fuzz, comme le veut la
règle du `ROADMAP` (§4).

## 3. Rapides, avec captures réelles

### PTP — IEEE 1588 (#121)

**Usage.** PTP synchronise les radars, les systèmes de combat et
l'avionique TSN (802.1AS) ; côté OT, les postes électriques (profil
C37.238).

**Détection.** L'EtherType `0x88F7` est déjà nommé dans la table de la
crate, mais rien ne décode PTP. Deux transports : la couche 2, à brancher
comme Profinet, et UDP 319/320. Le champ `messageLength` égale le payload
UDP.

**Captures versées** : huit équipements ou profils (Hirschmann,
Symmetricom en IPv6, NodeB Nokia / Alcatel-Lucent, White Rabbit, SEL,
Meinberg, 802.1AS, un PTPv1), 3 330 trames dont 107 en couche 2.

### STANAG 5066 SIS (#122)

**Usage.** STANAG 5066 est la pile de données des liaisons radio HF de
l'OTAN, au-delà de l'horizon (liaisons navire-terre). Sa couche SIS relie
les applications au nœud HF.

**Détection.** TCP 5066 (port IANA) et un préambule `90 EB 00` en tête de
chaque S_PDU.

**Spec.** Le texte ratifié de l'Ed. 4 n'est pas public. Son **brouillon
v1.6**, marqué « Releasable to the Public », l'est (publié par Isode) :
implémenter à partir de lui seul.

**Captures versées** : le banc HF Chat de l'agence C3 de l'OTAN (2005, bloc
RIPE `NC3A-NL`) et deux captures en boucle locale, dont une qui transporte
de l'ACP 142 (P_MUL, la diffusion fiable de la messagerie militaire).

### DIS — IEEE 1278.1 (#123)

**Usage.** DIS relie les simulateurs militaires : entraînement, exercices.

**Détection.** Un en-tête de 12 octets, mais pas de port IANA (3000 par
usage ; 6993 et 22999 aussi dans le corpus). La longueur déclarée et la
famille ne sont pas fiables sur toutes les captures réelles : il faut une
garde de port, ou une sonde tolérante.

**Captures versées** : cinq fichiers, versions 4 à 7, dont la capture
radio du dépôt Wireshark.

**Écartées** : les captures `DIS_EntityState_*` du wiki. Tout indique des
PDU rejouées : même machine, même jour, en rafales, la veille d'un commit
Wireshark qui précise que les enregistrements n'ont pas pu être partagés.

### IKE / ESP (#124)

**Usage.** Sur un réseau de défense, le côté « noir » des chiffreurs IP
est fait d'IKE et d'ESP. ESP est déjà reconnu au transport, mais IKE sur
UDP 500/4500 sort `Unknown`. Étiqueter IKE et exposer les SPI suffit à
cartographier qui chiffre avec qui.

**Captures versées** : IKEv1, IKEv2, ESP natif et NAT-T. `The-Ultimate-PCAP`
en porte aussi 1 600 ESP et 719 ISAKMP.

## 4. Spec ouverte, mais pas de capture publique exploitable

Ces protocoles sont pertinents, mais rien de public ne satisfait la règle
des trames réelles. Une capture de labo, produite par de vrais logiciels,
la satisfait.

- **Cursor on Target / TAK** (ATAK, WinTAK, TAK Server) — situation
  tactique.
  - Signature : XML `<event version="2.0" …>`, ou TAK Protocol v1 : magic
    `BF 01 BF` suivi d'un protobuf en maillage, `BF` et une longueur varint
    en flux.
  - Ports : diffusion de situation sur `239.2.3.1:6969`, TLS 8089 vers TAK
    Server.
  - Captures : aucune dans les corpus Wireshark, nDPI ou Zeek, ni sur
    GitHub.
  - Piste : ATAK-CIV et TAK Server sont open source, une capture de labo
    convient. Écrire le décodeur à partir du texte de la spec : les `.proto`
    d'ATAK-CIV sont en GPL-3.0.
- **NMEA 0183 / IEC 61162-450 / AIS** — réseau de passerelle des navires,
  surveillance maritime.
  - Signature : le jeton `UdPbC\0` d'IEC 61162-450 permet le probing
    aveugle ; les phrases NMEA ont un checksum `*hh`.
  - Spec : NMEA et IEC sont payantes, le format AIS (ITU-R M.1371) est
    gratuit.
  - Captures : aucune propre. Le seul pcap trouvé (issue Wireshark #20695)
    vient vraisemblablement d'un émulateur.
  - Piste : AIS-catcher avec une clé RTL-SDR.
- **MAVLink** — drones ArduPilot/PX4, lutte anti-drones.
  - Signature : STX `0xFE`/`0xFD`, longueur, CRC avec un `CRC_EXTRA` par
    message ; idéal pour un parseur sans état.
  - Captures : seules de minuscules captures pymavlink (LGPL) existent.
  - Piste : une capture en simulation (SITL ArduPilot ou PX4) suffit ; des
    journaux de vol réels sous CC BY 4.0 peuvent aussi être rejoués.
- **SAPIENT** (BSI Flex 335) — interface anti-drones britannique, que
  l'OTAN a annoncé vouloir adopter.
  - Spec : les `.proto` sont sous Apache-2.0.
  - Transport : TCP, longueur u32 little-endian suivie d'un protobuf.
  - Captures : aucune.
- **FMTP et ED-137** — contrôle aérien : coordination OLDI entre centres,
  radio sur IP.
  - Wireshark décode les deux.
  - FMTP : le seul échantillon public (issue #8407) fait 17 trames et ne
    porte aucun message opérationnel.
  - ED-137 : aucune capture trouvée.
  - Piste : des captures de site, à anonymiser comme `cat048_multicast.pcap`.

## 5. Écartés

- **Link 16, JREAP-C, VMF, SIMPLE** — specs à diffusion restreinte :
  MIL-STD-6016 est en Distribution C, STANAG 5516 et 5518 ne sont pas
  publics. Seuls des échantillons fabriqués à la main circulent (horodatage
  zéro, MAC nulles). C'est incompatible avec une crate MIT publiée. Si un
  client en a besoin, cela relève d'un module privé, hors de la crate.
- **DMP** (STANAG 4406 annexe E) — pas de spec libre, et le seul
  échantillon est fabriqué.
- **STANAG 4586** (contrôle de drones) — aucune capture nulle part.
- **KLV / STANAG 4609** (métadonnées vidéo des drones) — la spec MISB est
  gratuite, mais un paquet KLV s'étale sur plusieurs paquets TS et
  datagrammes, ce qui ne convient pas à un parseur sans état, et il n'existe
  aucun pcap.
- **STANAG 4607** (GMTI) — une seule capture plausible (26 trames), et le
  caractère public de la spec n'est pas vérifié.
- **Essais en vol** (IENA, iNET-X, IRIG 106 chapitre 10, AFDX) — faisables
  (captures sous MIT ou BSD dans `diarmuidcwc/AcraNetwork` et `atac/c10-tools`),
  mais utiles seulement pour auditer des bancs d'essais ou de l'avionique.

## 6. Défauts révélés par le nouveau corpus

Verser ces captures a exposé deux faux positifs des sondes existantes,
corrigés depuis :

- **#117 — SRVLOC.** Un PTP Delay_Req (`01 02 00 2c …`) a exactement la forme
  d'un en-tête SLPv1 : version 1, fonction 2, longueur 44 égale au
  datagramme, et un champ langue accepté parce qu'il est de l'UTF-8 valide.
  La sonde SRVLOC n'a pas de garde de port : 829 trames de la NodeB sont
  étiquetées SRVLOC. RFC 2165 impose deux lettres ASCII pour la langue :
  c'est désormais vérifié.
- **#118 — DNS.** La sonde UDP aveugle accepte un en-tête aux quatre
  compteurs nuls et ignore les octets qui suivent la dernière section : 37
  datagrammes d'un flux radar de 132 octets passent pour du DNS. Hors port
  53, la sonde exige désormais des sections qui consomment tout le
  datagramme et au moins un enregistrement.

## Sources

- [Issue Wireshark #8579 (`radardata.pcap`)](https://gitlab.com/wireshark/wireshark/-/issues/8579)
- [Issue Wireshark #9953 (`cat021023.pcap`)](https://gitlab.com/wireshark/wireshark/-/issues/9953)
- [Spécifications ASTERIX, EUROCONTROL](https://www.eurocontrol.int/asterix)
- [zoranbosnjak/asterix-specs](https://github.com/zoranbosnjak/asterix-specs)
- [CroatiaControlLtd/asterix](https://github.com/CroatiaControlLtd/asterix)
- [OMG DDSI-RTPS](https://www.omg.org/spec/DDSI-RTPS/)
- [foxglove/rtps](https://github.com/foxglove/rtps)
- [Wireshark SampleCaptures](https://wiki.wireshark.org/SampleCaptures)
- [Captures de test nDPI](https://github.com/ntop/nDPI/tree/dev/tests/cfgs/default/pcap)
- [Brouillon public de STANAG 5066 Ed. 4 (Isode)](https://www.isode.com/wp-content/uploads/2024/04/full-annex-doc-1-6.pdf)
- [MIL-STD-6016 (EverySpec)](https://everyspec.com/MIL-STD/MIL-STD-3000-9999/MIL-STD-6016C_NOTICE-2_22648/)
- [dstl/SAPIENT-Proto-Files](https://github.com/dstl/SAPIENT-Proto-Files)
- [Spécification FMTP, EUROCONTROL](https://www.eurocontrol.int/publication/eurocontrol-specification-interoperability-and-performance-requirements-flight-message)
- [Issue Wireshark #8407 (FMTP)](https://gitlab.com/wireshark/wireshark/-/issues/8407)
- [Champs ED-137 dans Wireshark](https://www.wireshark.org/docs/dfref/r/rtp.ext.ed137.html)
