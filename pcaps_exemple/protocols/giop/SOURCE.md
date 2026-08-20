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
