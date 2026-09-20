# Provenance

`corba.pcap` provient du corpus de tests du projet
[nDPI](https://github.com/ntop/nDPI) (ntop), fichier
`tests/cfgs/default/pcap/corba.pcap`.

- URL exacte (commit épinglé) :
  <https://raw.githubusercontent.com/ntop/nDPI/0b6e261523f6d8ff66ae711922fc266bb6baa07c/tests/cfgs/default/pcap/corba.pcap>
- Commit d'origine : `0b6e2615` « Improve CORBA detection (#2167) »
  (2023-11-27), qui fusionne les anciens `ziop.pcap` et `miop.pcap` du même
  corpus en un seul `corba.pcap`.
- Téléchargé le 2026-08-20 ; SHA-256 :
  `a4a0bfa2a212dc460da2a9ca01fa9c1fc562e7d24c7b2fd8d7424e6b85cd3289`.
- Licence du dépôt source : LGPL-3.0 (licence de nDPI ; le fichier est
  redistribué tel quel, sans modification ni anonymisation — le trafic est
  du loopback/labo : 127.0.1.1 et 10.95.28.46, MAC nulles).

## Contenu (vérifié avec tshark 4.6.6)

28 trames, deux conversations :

- trames 1-18 : session TCP loopback (ports éphémères 42717/56899),
  GIOP 1.2 big-endian — Request `echo` (trames 4, 10), Reply « No
  Exception » (trames 6, 12) ; la trame 18 est un message **ZIOP**
  (GIOP compressé, magic `ZIOP`) ; les messages des trames 10/12
  débordent du segment TCP (s=4152/4017).
- trames 19-28 : datagrammes UDP **MIOP** (Unreliable Multicast IOP,
  magic `MIOP`) encapsulant des Request GIOP 1.2 **little-endian**
  `receiveReliableData` vers 10.95.28.46:15984 (TaggedProfile
  TAG_UIPMC).

Les golden tests (`tests/giop_golden.rs`) embarquent le hex complet des
trames 4, 6 et 19.

# Captures ajoutées pour la 11.0.0 (epic #76)

Ajoutées le 2026-09-19 pour couvrir tout GIOP — les huit types de message,
les versions 1.0, 1.1 et 1.2, les deux endianness, les fragments. Chaque
message de chaque capture est comparé à tshark 4.6.6 par
`tests/giop_tshark_regression.rs` (oracle : `tools/giop_oracle.sh`).

## Pièces jointes du tracker Wireshark

Captures de trafic réel jointes par leurs auteurs à des rapports de bug
publics du projet Wireshark (<https://gitlab.com/wireshark/wireshark>),
redistribuées telles quelles, sans modification ni anonymisation — adresses
RFC 1918 uniquement. Aucune licence explicite n'accompagne ces pièces
jointes ; elles sont publiques depuis leur dépôt.

| Fichier | Issue | Fichier d'origine | SHA-256 |
|---|---|---|---|
| `wireshark_11616_locate_fragment.pcap` | [#11616](https://gitlab.com/wireshark/wireshark/-/issues/11616) (2015) | `clab021node05-20150922-2.cap` | `5b50a978104092800a018b734b4856a6724a2cb4f43e9e5ca05736719e4e8120` |
| `wireshark_12495_giop10_forward.pcap` | [#12495](https://gitlab.com/wireshark/wireshark/-/issues/12495) (2016) | `Eric_airtel_pun_1.pcap` | `604766d0243c0301682fbf17c65f14a1b928d15cf8fe06d3a500fee64bece672` |
| `wireshark_7785_ping.pcap` | [#7785](https://gitlab.com/wireshark/wireshark/-/issues/7785) (2012) | `ping.pcap` | `82185aeb4f0cf44775b45f025ff35529758a27f899e3edf21299c9b51fca8ee5` |

- **#11616** (216 trames, 44 messages GIOP 1.2, les deux endianness) :
  LocateRequest (trame 3) et LocateReply `OBJECT_HERE` (trame 7) ; un Request
  `push` de 8 180 octets fragmenté (trame 41, flags `0x03`) dont les messages
  Fragment démarrent **au milieu** d'un segment TCP de continuation (trames
  48 et 57, offsets 952 et 456 du payload) — le cas qui motive
  `find_giop_message` ; 10 requêtes HTTP sans rapport.
- **#12495** (12 trames, 10 messages) : GIOP 1.0 little-endian avec Reply
  `LOCATION_FORWARD` dont l'IOR porte un profil IIOP (10.20.57.171:49254,
  trame 2), puis CosNaming en GIOP 1.2 avec un Reply `USER_EXCEPTION`
  (`NamingContext/NotFound`, trame 11).
- **#7785** (7 trames, 2 messages) : `ping` GIOP 1.2 little-endian.

## Captures du labo omniORB (`lab_*.pcap`)

Produites localement par `tools/capture_giop.sh` : un vrai ORB — omniORB
4.3.3, paquets Debian trixie — fait tourner un serveur et une série de
clients dans un conteneur éphémère, sur son loopback, capturé par tcpdump.
Sources du labo : `tools/giop_lab/` (IDL, serveur et client C++). La recette
est rejouable ; elle régénère des captures équivalentes, pas identiques à
l'octet (ports éphémères, horodatages, numéros de séquence).

| Fichier | Ce qu'un vrai ORB y émet |
|---|---|
| `lab_giop12_basic.pcap` | GIOP 1.2 : LocateRequest/LocateReply, Request (dont un `oneway`), Reply `NO_EXCEPTION`, `USER_EXCEPTION` (`IDL:Lab/Failure:1.0`), `LOCATION_FORWARD` ; Request et Reply de 20 Ko fragmentés, Fragment **avec** request id ; CloseConnection |
| `lab_giop11_basic.pcap` | le même scénario en GIOP 1.1 : Fragment **sans** request id |
| `lab_giop10_basic.pcap` | le même scénario en GIOP 1.0 (`requesting_principal`, pas de fragments) |
| `lab_system_exception.pcap` | LocateReply `UNKNOWN_OBJECT`, puis Reply `SYSTEM_EXCEPTION` (`OBJECT_NOT_EXIST`, minor `0x4f4d0001`, `COMPLETED_NO`) |
| `lab_close_connection.pcap` | CloseConnection émis par le serveur sur une connexion oisive |
| `lab_message_error.pcap` | MessageError du serveur (trame 6) |
| `lab_client_timeout.pcap` | timeout client : Request sans Reply à temps, puis Reply tardif |

Seul message du corpus qui ne sorte pas d'un ORB : la trame 4 de
`lab_message_error.pcap`, le Request tronqué que `tools/giop_lab/garbage.py`
envoie pour provoquer le MessageError. Elle est exclue nommément des
comparaisons.

## Ce que le corpus ne contient pas

Aucun ORB à portée ne les émet ; ils sont décodés selon la spécification et
couverts par les tests unitaires du module, pas par des trames réelles :

- **CancelRequest** — omniORB abandonne un appel en timeout sans l'émettre ;
- LocateReply `OBJECT_FORWARD`, `OBJECT_FORWARD_PERM`,
  `LOC_SYSTEM_EXCEPTION`, `LOC_NEEDS_ADDRESSING_MODE` ;
- Reply `LOCATION_FORWARD_PERM` et `NEEDS_ADDRESSING_MODE` ;
- `TargetAddress::ReferenceAddr` ;
- GIOP 1.0 et 1.1 en big-endian (le big-endian est couvert en 1.2).

## Corpus local non redistribué

Trop volumineux pour le dépôt, rejoués par le test `#[ignore]`
`extra_corpus_decodes_like_tshark` (`GIOP_EXTRA_CORPUS=<dossier>`) —
1 641 messages, aucune divergence avec tshark le 2026-09-19 :

- [#15208](https://gitlab.com/wireshark/wireshark/-/issues/15208)
  `giop_filtered.pcapng.gz` (21 Mo, 900 messages GIOP 1.2) ;
- [#3238](https://gitlab.com/wireshark/wireshark/-/issues/3238)
  `miop_giop_dump.gz` (99 Mo, 703 Request sous MIOP), `ziop_giop_dump.gz`
  et `ziop_giop_traffic.dump.gz` (18 messages chacun) ;
- [#9915](https://gitlab.com/wireshark/wireshark/-/issues/9915)
  `fuzz_gsm_giop_f43.pcap` (2 messages).

La capture [#200](https://gitlab.com/wireshark/wireshark/-/issues/200)
`editcap.4294256e.pcap` est un fichier **muté** par le fuzzer de Wireshark :
ses octets sont altérés, tshark lui-même y déclare les trames malformées.
Elle ne sert pas d'oracle, seulement de test d'absence de panique.
