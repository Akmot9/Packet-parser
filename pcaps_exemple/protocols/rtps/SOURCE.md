# Provenance

Huit captures de **RTPS** (DDSI-RTPS, le protocole filaire de DDS), versées
le 2026-10-08 pour l'issue #120 (épopée #125, rapport
`docs/protocoles-defense.md`). Aucune n'est modifiée : ni anonymisée, ni
tronquée. Elles couvrent **six implémentations**, identifiées par le
`vendorId` de l'en-tête RTPS.

Contenu vérifié avec tshark 4.6.6 (`-Y rtps`).

| Fichier | Trames | Implémentation (vendorId) | Origine | SHA-256 |
|---|---|---|---|---|
| `talker-listener-rtps.pcapng` | 87 | Eclipse Cyclone DDS (`0x0110`) | [foxglove/rtps](https://github.com/foxglove/rtps), `docs/` | `0e02a1b18805d3c56c11d73f430d353e1d966def8df860a00a3b00653478c8ee` |
| `RTPS_Discovery.pcapng` | 109 | RTI Connext (`0x0101`) | wiki Wireshark | `78fcd4cf3f6895fc15c97d3758661fb2e0ff10fdd4a4119f1d76336039654cbc` |
| `rtps.pcap` | 29 | RTI Connext (`0x0101`) | corpus de tests nDPI | `d2c6509464281cac39fa9f522e10b772c2da9b8937d67c13b1213199bd0a1683` |
| `wireshark_15227_reassembly_one_each.pcapng` | 6 | RTI Connext (`0x0101`) | [#15227](https://gitlab.com/wireshark/wireshark/-/issues/15227) | `ae1ac7142ff5226a5f2bd9c9abee9e40109d85931d2772cd6bbeaf809cb46eed` |
| `wireshark_15868_micro_2_4_11.pcapng` | 1 | RTI Connext Micro (`0x010a`) | [#15868](https://gitlab.com/wireshark/wireshark/-/issues/15868) | `4b242c86206528db8cf4188412540692d1efa89df95bb0ec700b7e70ccb01695` |
| `wireshark_6449_opendds_messenger.pcap` | 13 | OpenDDS (`0x0103`) | [#6449](https://gitlab.com/wireshark/wireshark/-/issues/6449) | `c6ca2932fdcd6a8ae79f05635567099a1c7e8d98dcb343fe4b71770deceac0a6` |
| `wireshark_9378_ddsi.pcapng` | 1 | OpenSplice (`0x0102`) | [#9378](https://gitlab.com/wireshark/wireshark/-/issues/9378) | `27c49be416d74bfeedb8465d31f41f41da61a83f661882f0dbfa81ba4f7ed252` |
| `wireshark_17630_default_multicast_locator.pcapng` | 1 | CoreDX (`0x0106`) | [#17630](https://gitlab.com/wireshark/wireshark/-/issues/17630) | `f3c95b2c57db381b39ea50d83a57ff57c390099c0ff315d84d62066c70563d2d` |

## Détail

- **`talker-listener-rtps.pcapng`** — démo ROS 2 talker/listener sur Cyclone
  DDS, capturée le 2021-07-10 sur la boucle locale macOS : encapsulation
  **LINKTYPE_NULL**. Cyclone emploie des ports unicast aléatoires : la
  plupart des trames ne sont reconnaissables que par le magic `RTPS`.
  Commit épinglé `33cd4d493818c9fe8a876bc34526d29fcb556c97`, URL
  `https://raw.githubusercontent.com/foxglove/rtps/33cd4d493818c9fe8a876bc34526d29fcb556c97/docs/talker-listener-rtps.pcapng`.
- **`RTPS_Discovery.pcapng`** — découverte RTI Connext (Shapes Demo, domaine
  116), capturée le 2018-09-12 sur un réseau de labo (cartes VirtualBox,
  Dell, HP). 16 trames sont des **fragments IPv4** : tshark les réassemble et
  compte 99 trames RTPS ; un parseur sans état en voit 93. URL
  `https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/RTPS_Discovery.pcapng`.
- **`rtps.pcap`** — RTI Connext sur `127.0.0.1:7410`, 2017-06-21. Commit
  nDPI épinglé `6ac6e1ec2547d23e4f1b60c4f8a81698dff5895f`, chemin
  `tests/cfgs/default/pcap/rtps.pcap`.
- **`wireshark_15227_reassembly_one_each.pcapng`** — six datagrammes de
  quelque 60 Ko en boucle locale (LINKTYPE_NULL, 2018-10-19), un exemple de
  chaque cas de **DATA_FRAG**, joints par un ingénieur RTI. La même issue
  porte `reassembly.pcapng` (965 trames, 2 Mo), non versé : il n'apporte pas
  de sous-message absent des autres captures.
- **`wireshark_15868_micro_2_4_11.pcapng`** — Connext Micro 2.4.11 sur une
  carte Infineon (2019-06-19), unicast vers le port **21914** : un port hors
  de la plage 7400.
- **`wireshark_6449_opendds_messenger.pcap`** — exemple Messenger d'OpenDDS
  vers `239.255.0.1:7401`, 2011-10-10.
- **`wireshark_9378_ddsi.pcapng`** — OpenSplice (interface virtuelle QEMU),
  2013-11-06.
- **`wireshark_17630_default_multicast_locator.pcapng`** — CoreDX, 2021-09-15,
  annonce portant un `PID_DEFAULT_MULTICAST_LOCATOR`.

Fichiers d'origine des pièces jointes : `captured_messenger_rtps.pcap`
(#6449), `ddsi.pcapng` (#9378), `reassembly_one_each.pcapng` (#15227),
`Micro-2.4.11.pcapng` (#15868), `PID_DEFAULT_MULTICAST_LOCATOR.pcapng`
(#17630).

## Écartés

- `rtps_cooked.pcapng` du wiki Wireshark : la page le dit généré à la main ;
- les captures des issues #18737, #19085, #21154 et #21156 : fichiers de
  fuzzing ou de preuve de concept ;
- les captures de `rticommunity/rticonnextdds-examples` : leur licence ne
  permet la redistribution que pour un usage avec les produits RTI.

## Licences

- `talker-listener-rtps.pcapng` : licence MIT du dépôt foxglove/rtps ;
- `RTPS_Discovery.pcapng` : licence de la wiki Wireshark (GNU GPL v2+, en
  pied de page de <https://wiki.wireshark.org>) ;
- `rtps.pcap` : LGPL-3.0, licence du dépôt nDPI ;
- pièces jointes du tracker Wireshark : aucune licence explicite, publiques
  depuis leur dépôt.

Aucun de ces fichiers n'entre dans le paquet publié sur crates.io (liste
`include` de `Cargo.toml`). Le texte des licences n'accompagne pas encore les
captures : voir #104.
