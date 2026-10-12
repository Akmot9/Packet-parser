# Provenance

Cinq captures **IEC 60870-5-104** versées le 2026-10-12 pour l'épopée #102
(Tier 2 restant). Aucune n'est modifiée : ni anonymisée, ni tronquée.

| Fichier | Trames | Contenu | Origine | SHA-256 |
|---|---|---|---|---|
| `wireshark_iec104.pcap` | 105 | une session complète (2013) : TESTFR, STARTDT, interrogation générale, fin d'initialisation, informations simples, doubles, positions de prise, chaînes de bits, mesures normalisées, échelonnées et flottantes, avec et sans CP56Time2a, commandes simples, doubles, de réglage et de consigne (types 1 à 13, 30 à 36, 45 à 51, 70, 100) ; 18 segments à plusieurs APDU | wiki Wireshark, `iec104.pcap` | `a78aa971adc51e54413a865937f1799ef57118d397cef57ccd93a358ed5b85d6` |
| `wireshark_IEC104_SQ.pcapng` | 1 | un segment de quatre ASDU M_SP_NA_1 **en séquence** (SQ = 1, seize informations chacun), le cas que le wiki documente | wiki Wireshark, `IEC104_SQ.pcapng` | `f855a11326f7aa4f719b1fbb65e5f8dfe3d9d194185a8f5faf5b5dc3cb831227` |
| `iti_090813_diverse.pcap` | 173 | un maître et une station simulés sur une même machine (2009) : interrogation, mesures flottantes, informations simples horodatées, commandes simples, doubles et de consigne, **avec horodatage CP56Time2a** (types 58, 59, 61, 63) | ITI/ICS-Security-Tools, `pcaps/IEC60870-5-104/090813_diverse.pcap`, commit `9b826091e7ba3fbdd5997d31e116f29e09cbbb48` | `07b9a0879dc83e420c4cf83b37fb5830d1d8fb5f6ac6edc435896f70b0fc6bc7` |
| `iti_JavaRMI_and_IEC_Misc.pcap` | 357 | trois hôtes (2008) : interrogations répétées, réponses en séquence (42 ASDU SQ = 1), 20 segments à plusieurs APDU, une retransmission | ITI/ICS-Security-Tools, `pcaps/IEC60870-5-104/JavaRMI_and_IEC_Misc.pcap`, même commit | `f8ede9d4f45f4884493ea0c5d35ed156d347aeeb656d77b28e77f2c6ef24c7bd` |
| `ndpi_IEC104.pcap` | 15 | mesures flottantes horodatées (M_ME_TF_1, type 36) et acquittements S (2011) | corpus de tests nDPI, `tests/cfgs/default/pcap/IEC104.pcap`, commit `5915c399c0690be7ba252d32a741d1bf7ea07846` | `340727cb7887ad139483b234e888bb6d25fec1fd21aa470bceb572a7f193b038` |

URL du wiki :
`https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/<fichier>`.

## Ces trames sont-elles réelles ?

- `wireshark_iec104.pcap` : une carte Giga-Byte (`00:16:d1`) face à une ASUS
  (`00:22:15`), TTL 128 et 255, ports éphémères Linux (46413) et le port
  2404 ; la session suit la norme à la lettre (TESTFR avant STARTDT,
  interrogation générale, réponses en cause 20, commandes activées puis
  confirmées), avec les numéros de séquence qui se répondent — deux
  logiciels réels sur un réseau de laboratoire ;
- `wireshark_IEC104_SQ.pcapng` : une carte Cisco (`d0:72:dc`), TTL 125, un
  segment d'un équipement en production (adresse commune 1054, port
  éphémère 4446) ;
- `ndpi_IEC104.pcap` : une carte Siemens (`00:12:00`) et une carte Lenovo
  (`78:2b:cb`), TTL 125 et 128, des mesures flottantes horodatées d'un
  automate vers un poste — du trafic réel de 2011 ;
- `iti_090813_diverse.pcap` : l'adaptateur de bouclage Microsoft
  (`02:00:4c:4f:4f:50`, « LOOP »), `10.0.0.10` vers lui-même, port 1075 vers
  2404 : deux logiciels réels sur un même poste, dont les commandes
  horodatées se répondent ;
- `iti_JavaRMI_and_IEC_Misc.pcap` : quatre cartes (deux Sagem `00:e0:ab`, une
  Cisco `00:1c:11`, une Dell `00:15:c5`), TTL 59, 64 et 128, `192.168.1.x`
  et `10.209.13.145`, un maître qui interroge en boucle une station qui
  répond en séquence — un réseau réel, avec sa retransmission.

**Écartée** : `tests/cfgs/default/pcap/iec60780-5-104.pcap` du corpus nDPI
(2008, identique octet pour octet à `TestDissectIec104.pcap` chez ITI). Ses 147 trames mêlent une session réelle et des segments fabriqués
— `03 03 03 68 01 13 13 13`, `04 04 04 04 68 02 14 14 14`, des motifs
d'octets croissants qu'aucun équipement n'émet, que tshark signale « APDU
less than 4 bytes » — : la règle du dépôt interdit les captures générées,
et une capture mixte ne se trie pas.

## Oracle tshark

`tests/data/iec104_tshark_oracle.tsv` est produit par `tools/iec104_oracle.sh`
(tshark 4.6.6, `tcp.desegment_tcp_streams:FALSE`, la vue d'un parseur sans
état) : une ligne par segment à payload, pour chaque APDU sa longueur, son
format, sa fonction U ou ses numéros de séquence, et pour chaque ASDU son
type, SQ, nombre d'objets, cause, adresses d'origine et commune, et les
adresses de ses objets. `tests/iec104_golden.rs` rejoue l'oracle (#102) :
parité APDU par APDU, séquences comprises.

## Licences

- captures du wiki Wireshark : licence du wiki (GNU GPL v2+, en pied de page
  de <https://wiki.wireshark.org> ; texte dans `pcaps_exemple/LICENSES/GPL-2.0.txt`) ;
- `ndpi_IEC104.pcap` : LGPL-3.0, licence du dépôt nDPI (texte :
  `pcaps_exemple/LICENSES/LGPL-3.0.txt`) ;
- `iti_*.pcap` : CC-BY-4.0, licence du dépôt ITI/ICS-Security-Tools
  (Information Trust Institute, University of Illinois ; texte :
  `pcaps_exemple/LICENSES/CC-BY-4.0.txt`) — attribution conservée ici.

Aucun de ces fichiers n'entre dans le paquet publié sur crates.io (#104).
