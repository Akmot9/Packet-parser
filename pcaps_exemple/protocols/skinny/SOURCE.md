# Provenance

Six captures **Skinny** (SCCP, *Skinny Client Control Protocol*, la
signalisation des téléphones IP Cisco, sur TCP 2000) versées le 2026-11-23
pour l'issue #370. Aucune n'est modifiée : ni anonymisée, ni tronquée.

Contenu vérifié avec tshark 4.6.9, rendu sans état comme la crate :
réassemblage TCP et Skinny coupés, analyse des numéros de séquence coupée
pour que les retransmissions soient disséquées (`tools/skinny_oracle.sh`,
oracle `tests/data/skinny_tshark_oracle.tsv`). Un « segment Skinny » est un
segment TCP qui s'ouvre sur un en-tête Skinny.

| Fichier | Trames | Segments Skinny | Messages | Versions d'en-tête | Contenu | Source | SHA-256 |
|---|---|---|---|---|---|---|---|
| `ndpi_skinny.pcap` | 200 | 40 | 62 | 0x14 | un appel entre deux postes Cisco 7941, le 2011-10-05 : sonnerie, décroché, ouverture des canaux de voix, et 135 paquets RTP | corpus de tests nDPI, `tests/cfgs/default/pcap/skinny.pcap`, commit `446ae50ac067dcf9e26f49d807ebc5090817cce1` | `78e99887665ac184f359cbfdb5e09c853ebf3fc6cc9d7ebf892a291b161d412e` |
| `ndpi_sccp_hw_conf_register.pcapng` | 17 | 8 | 9 | 0x00, 0x12 | l'enregistrement d'un pont de conférence matériel auprès de son serveur d'appel, le 2019-05-06 : RegisterReq, RegisterAck, échange des capacités | corpus de tests nDPI, `tests/cfgs/default/pcap/sccp_hw_conf_register.pcapng`, même commit | `64ea1b5c5338046f13a0a69bc87d744557cc536fa4b51a72effe51eac59e5bce` |
| `wireshark_6041_cm7_type_b_more.pcap` | 85 | 85 | 327 | 0x11 | ce qu'un serveur d'appel envoie à sept postes en 46 minutes, le 2010-04-26 : états d'appel, sonneries, affichages ; 53 segments portent plusieurs messages | issue Wireshark 6041, « Skinny protocol - message CM5CallInfoMessage », pièce jointe `cm7_type_b_more.pcap` | `650f5764c535d7e1d77c7dbf020420bcb73c668d8aa8b998ee139eeba318a6b5` |
| `wireshark_8616_100030.pcap` | 178 | 67 | 70 | 0x00, 0x11, 0x16 | le démarrage d'un poste Cisco, le 2013-04-27 : configuration par TFTP, puis deux connexions d'enregistrement ; 37 types de message | issue Wireshark 8616, « Update Skinny Dissection Code (CM7.1 + / SPCP Message) », pièce jointe `100030.pcap` | `bfca7df0067c1204da7ce5898bd84f356c8523db252c428d1b901ade5406cbd6` |
| `wireshark_8805_packets.cap` | 759 | 415 | 417 | 0x00, 0x13 | 94 minutes d'un poste Cisco et de son serveur, le 2013-05-26 : 63 KeepAlive et leurs accusés, des appels, des touches du clavier | issue Wireshark 8805, « Wireshark not recognizing skinny version 19 », pièce jointe `packets.cap` | `c2af8db87835a15e283d59347bb0bcb410ead7665493c5de92b048957fc322b0` |
| `wireshark_10262_7911_CUCM_registration_RFC2833.pcapng` | 239 | 41 | 48 | 0x00, 0x15 | l'enregistrement d'un poste Cisco 7911 auprès d'un CUCM, le 2014-07-07 : configuration par HTTP sur TCP 6970, puis 32 types de message ; autour, le trafic d'un poste Windows (SSDP, NetBIOS, DHCP, LLMNR) | issue Wireshark 10262, « skinny: support ProtocolVersion 0x15, message updates », pièce jointe `7911_CUCM_registration_RFC2833.pcapng` | `dd27894f500baf3df685c6c413df1c2d59e033d3ef8ac288736a089a73acf081` |

Au total 656 segments Skinny, 933 messages de 70 types, en versions
d'en-tête 0x00 et 0x11 à 0x16.

URL des pièces jointes : `https://gitlab.com/wireshark/wireshark` suivi de

- `/uploads/c8fd986cb4d81561d5991d66bbbfab40/cm7_type_b_more.pcap` ;
- `/uploads/1685dd86989d80a7e5ed926f5e6d3456/100030.pcap` ;
- `/uploads/2927efaf394a22d9b9f7c066ff2a40fa/packets.cap` ;
- `/uploads/f717fc84740279218a7e97dc22be9c84/7911_CUCM_registration_RFC2833.pcapng`.

## Ce que ces captures montrent des limites sans état

- **Cinq messages coupés** par leur segment (longueurs annoncées de 1 076 à
  2 124 octets, dans des segments de 512 à 1 340 octets) : trois dans
  `wireshark_8616_100030.pcap`, deux dans
  `wireshark_10262_7911_CUCM_registration_RFC2833.pcapng`. La crate rend
  l'en-tête et le début du corps, `is_truncated()` vaut `true`.
- **Onze segments de suite**, sans en-tête : ils sortent `Unknown`, pour la
  crate comme pour tshark sans réassemblage.
- Les trames 43 et 106 de `wireshark_8616_100030.pcap` finissent un message
  coupé puis portent un RegisterReq entier. Il faut l'état du flux pour en
  trouver le début : tshark le trouve quand son analyse des numéros de
  séquence est active, la crate non.
- `wireshark_6041_cm7_type_b_more.pcap` a été prise sur le serveur : 38 de
  ses 85 trames sont la retransmission de la précédente. La crate les nomme
  comme les autres.
- `wireshark_8805_packets.cap` finit au milieu d'un enregistrement : six
  octets suivent sa trame 759. Les lecteurs lisent les 759 trames puis
  signalent l'erreur (tshark sort en erreur, `pcap-file` rend une erreur).
  Le fichier est versé tel qu'il a été joint à l'issue.

## Ces trames sont-elles réelles ?

Aucune de ces captures n'a de checksum TCP faux, et toutes montrent du
matériel Cisco.

- `ndpi_skinny.pcap` : trois cartes Cisco (`00:1e:7a`, `00:1d:45`,
  `00:14:f2`), deux postes en `192.168.195.x`, TTL 64, et un serveur en
  `192.168.193.12` qui arrive avec un TTL de 63. C'est la version que nDPI a
  réduite (sa PR 2243) de `call_between_two_7941.pcap`, pièce jointe de
  l'issue Wireshark 6590, qui compte 2 975 trames dont 2 871 de RTP.
- `ndpi_sccp_hw_conf_register.pcapng` : une carte Cisco (`b8:38:61`), TTL
  255, face à un serveur sur VMware (`00:50:56`), TTL 64 ; 244 millisecondes,
  dont une vraie retransmission (la trame 16 répète la 15).
- `wireshark_6041_cm7_type_b_more.pcap` : un serveur IBM (`e4:1f:13`) en
  `10.40.0.11` vers sept postes en `10.40.10.x`, derrière une carte Cisco.
- `wireshark_8616_100030.pcap` : capture Linux « cooked », un poste Cisco
  (`44:d3:ca`, dont le nom `SEP44D3CA71987E` reprend l'adresse) et un serveur
  sur une carte Hon Hai (`d0:27:88`) ; le poste télécharge ses fichiers
  `CTLSEP44D3CA71987E.tlv` et `ITLFile.tlv` par TFTP avant de s'enregistrer.
- `wireshark_8805_packets.cap` : un poste Cisco (`00:17:95`) en
  `10.111.32.82`, qui arrive avec un TTL de 254, et un serveur sur VMware
  (`00:0c:29`) ; un KeepAlive toutes les 90 secondes pendant 94 minutes.
- `wireshark_10262_7911_CUCM_registration_RFC2833.pcapng` : un poste Cisco
  (`00:26:99`, `SEP002699432206`), un CUCM sur VMware (`00:0c:29`), un
  routeur Cisco (`00:1a:e3`, TTL 254) qui écoute lui aussi sur TCP 2000, et
  un poste Dell (`bc:30:5b`) ; 101 secondes.

**Écartées** :
- `test/captures/skinny_coverage.pcap.gz` du dépôt Wireshark : 978 trames à
  une par seconde, tous les checksums TCP faux, aucune adresse MAC réelle.
  C'est une capture fabriquée pour couvrir le dissecteur, et la règle du
  dépôt interdit les captures générées.
- L'archive `skinny.tar.gz` de l'issue Wireshark 11358 : des captures
  passées par un fuzzer.
- `SRTP.pcap` de l'issue Wireshark 3933 : la signalisation y est chiffrée,
  aucune trame Skinny.
- Le wiki Wireshark (page SampleCaptures) n'a aucune capture Skinny : son
  « SCCP » est celui de SS7.
- D'autres pièces jointes réelles restent disponibles si le corpus doit
  grandir : issues Wireshark 6590, 3202, 3192, 5443, et les autres fichiers
  des issues 6041 et 10262.

## Licences

- `ndpi_*` : nDPI est sous LGPL v3, © 2011-2026 ntop.org. Texte dans
  `../../LICENSES/LGPL-3.0.txt`, et celui de la GPL v3, qu'elle incorpore,
  dans `../../LICENSES/GPL-3.0.txt`.
- `wireshark_<issue>_*` : pièces jointes d'utilisateurs à des rapports de
  bug publics, sans licence explicite. Position du dépôt dans
  `../../LICENSES/README.md` : les redistribuer telles quelles comme données
  de test publiques, avec l'issue d'origine, le nom du fichier joint et son
  SHA-256, et retirer toute capture dont l'auteur le demanderait.

Les fichiers sont redistribués tels quels, sans modification.
