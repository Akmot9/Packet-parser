# Provenance

Deux captures **BACnet/IP** (ASHRAE 135, annexe J) versées le 2026-10-12 pour
l'épopée #102 (Tier 2 restant). Aucune n'est modifiée : ni anonymisée, ni
tronquée.

| Fichier | Trames | Contenu | Origine | SHA-256 |
|---|---|---|---|---|
| `iti_bacnet_test.pcap` | 26 | un poste (`10.1.1.167`) qui interroge un automate Johnson Controls (`10.1.1.165`, `MS-NAE4510-2`, 2015) : neuf readProperty et leurs ComplexACK (nom, description, version, modèle de l'objet device), une lecture de table de distribution, un enregistrement de dispositif étranger et deux résultats BVLC ; quatre datagrammes UDP vides | ITI/ICS-Security-Tools, `pcaps/BACnet/bacnet_test.pcap`, commit `9b826091e7ba3fbdd5997d31e116f29e09cbbb48` | `973724800eef38e1131368d4ebce0eafc6593ccb4763916b8ee69b3b1328d8ff` |
| `ndpi_bacnet.pcap` | 23 | neuf readProperty que des scanners d'Internet (`162.142.125.x`, `198.235.24.x`, `64.62.197.x`…) envoient à un équipement exposé (`90.147.69.x`), puis un réseau local (`204.172.177.x`) : Who-Is et I-Am en broadcast vers le réseau 65535, une erreur, deux messages de routage (I-Am-Router-To-Network, 0x13) | corpus de tests nDPI, `tests/cfgs/default/pcap/bacnet.pcap`, commit `5915c399c0690be7ba252d32a741d1bf7ea07846` | `e64557f7fa94c8cb9f3335cf5f893089cf664d97316feb9504c2be71028e0922` |

## Ces trames sont-elles réelles ?

- `iti_bacnet_test.pcap` : une carte Cisco (`00:19:07`) côté automate
  (`10.1.1.165`, TTL 119) et une Intel (`3c:a9:f4`) côté poste
  (`10.1.1.167`, TTL 128), les ports éphémères Windows 64087, 64088, 54668
  et 54669 pour les quatre datagrammes vides du poste (TTL 56, 41, 52 et
  54), puis 47808 vers 47808 ; des réponses dont le contenu est celui d'un
  vrai automate (chaînes UTF-16, version de firmware) ;
- `ndpi_bacnet.pcap` : la première moitié vient d'Internet — TTL 36, 39,
  52, 54, 56 selon la source, identifiants d'invocation variés (169, 146,
  220), sources connues de balayage —, la seconde d'un segment local
  (TTL 64, broadcast `204.172.177.255`, adresse source d'un routeur BACnet
  avec son compte de sauts 255). Deux cartes réelles (`00:1a:2b` et
  `3c:94:d5`).

`4SICS-GeekLounge-151020.pcap` et `The-Ultimate-PCAP.pcapng` ne portent
aucun BVLC (vérifié avec tshark). Le wiki Wireshark n'a que
`bacnet-arcnet-linux.cap`, en trames ARCNET que la crate ne lit pas.

## Oracle tshark

`tests/data/bacnet_tshark_oracle.tsv` est produit par `tools/bacnet_oracle.sh`
(tshark 4.6.6) : un datagramme par ligne, BVLC (fonction, longueur), NPDU
(version, contrôle, adresses de destination et de source, compte de sauts,
type de message réseau) et APDU (type, invocation, service).
`tests/bacnet_golden.rs` rejoue l'oracle (#102) : parité sur les 45
datagrammes, port 47808 ou sonde aveugle, altérations d'un octet rejetées.

## Licences

- `iti_bacnet_test.pcap` : CC-BY-4.0, licence du dépôt ITI/ICS-Security-Tools
  (Information Trust Institute, University of Illinois ; texte :
  `pcaps_exemple/LICENSES/CC-BY-4.0.txt`) — attribution conservée ici ;
- `ndpi_bacnet.pcap` : LGPL-3.0, licence du dépôt nDPI (texte :
  `pcaps_exemple/LICENSES/LGPL-3.0.txt`).

Aucun de ces fichiers n'entre dans le paquet publié sur crates.io (#104).
