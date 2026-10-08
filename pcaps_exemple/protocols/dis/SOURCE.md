# Provenance

Cinq captures de **DIS** (Distributed Interactive Simulation, IEEE 1278.1),
versées le 2026-10-08 pour l'issue #123 (épopée #125, rapport
`docs/protocoles-defense.md`). Elles couvrent les versions 4 à 7 du
protocole. Aucune n'est modifiée, hormis la décompression de
`wireshark_8185_dis_ua.pcapng` (voir plus bas).

Contenu vérifié avec tshark 4.6.6 (`-d udp.port==1-65535,dis`) : les 393
trames portent du DIS, aucune n'est malformée.

| Fichier | Trames | Version, PDU | Origine | SHA-256 |
|---|---|---|---|---|
| `dis_voice_sample.pcap` | 111 | v6, Signal + Transmitter | `test/captures` de Wireshark | `df0effa23abcbf912d882af78ae1e527c64eb8a216c9edbb2f333d4b6021a9db` |
| `DIS_signal_and_transmitter.pcapng` | 253 | v5, Signal + Transmitter | wiki Wireshark | `c2e9f0d9fc28b1c06df47d5b9e033b0399fa111a7d0fe3334b6134f713fa2ce2` |
| `wireshark_8185_dis_ua.pcapng` | 16 | v5, Underwater Acoustic | [#8185](https://gitlab.com/wireshark/wireshark/-/issues/8185) | `b792170738e5ec57b0901b80042d43bd56a37ca84542ad79f21f0bb69c8d2668` |
| `wireshark_12043_dis_v7_transmitter.pcap` | 10 | v7, Transmitter | [#12043](https://gitlab.com/wireshark/wireshark/-/issues/12043) | `f74b20b6aed8d1a29059c7977074a27965d9cc58e8cc8d21cad08be54e4a787c` |
| `wireshark_3492_dis_test2.pcap` | 3 | v4, gestion de données | [#3492](https://gitlab.com/wireshark/wireshark/-/issues/3492) | `3cdaea959eccf3bb95081fcacb0d6cd1ce7cb6023587af5c80aa05f2d9a8079d` |

## Détail

- **`dis_voice_sample.pcap`** — radio simulée (PDU Signal et Transmitter,
  famille 4) en diffusion sur UDP **6993**, enregistrée le 2010-01-06.
  Versée dans le dépôt Wireshark par le commit
  `1f078b66fdcfcc82194b0624c7cc9365bd97182c` (2026-04-24) ; URL
  `https://gitlab.com/wireshark/wireshark/-/raw/1f078b66fdcfcc82194b0624c7cc9365bd97182c/test/captures/dis_voice_sample.pcap`.
- **`DIS_signal_and_transmitter.pcapng`** — même type de trafic sur UDP
  **3000**, le 2015-12-27, avec une **famille à 0** au lieu de 4 : non
  conforme, mais réel — une sonde ne doit pas s'appuyer sur la famille. URL
  `https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/DIS_signal_and_transmitter.pcapng`.
- **`wireshark_8185_dis_ua.pcapng`** — PDU Underwater Acoustic (type 29) en
  diffusion sur UDP **22999**, le 2013-01-16. Joint à l'issue sous la forme
  `dis-ua.pcapng.gz` (SHA-256
  `67f53620e5f6dbf74504a9bdbc3211d68c76f006741d61d453333a39e91707d2`) et
  versé décompressé par `gzip -d` : le collecteur des tests ne lit pas les
  `.gz`.
- **`wireshark_12043_dis_v7_transmitter.pcap`** — DIS v7 (champ PDU status),
  UDP 3000, le 2016-01-24. Fichier d'origine `dis_v7_transmitter.pcap`.
- **`wireshark_3492_dis_test2.pcap`** — trois PDU de gestion de données
  (types 18 à 20, famille 5), le 2009-05-26. **La longueur déclarée vaut 48
  pour un datagramme de 160 octets** : c'est la seule capture du dossier où
  elle ne couvre pas le payload UDP. Fichier d'origine `dis_test2.pcap`.

## Écartés

- `DIS_EntityState_1.pcapng`, `DIS_EntityState_2.pcapng`,
  `DIS_EnvironmentalProcess.pcapng` et `DIS_Signal.pcapng` (wiki) : capturés
  le 2015-09-29 depuis une même machine (`10.0.0.102`), en rafales — 287
  trames en 22 ms pour le premier. C'est la veille du commit Wireshark
  `99406bafe1`, qui ajoute au dissecteur les PDU de l'IDF BattleLab et
  précise : « because of information security, we couldn't share recorded
  captures […] However, we brought basic PDU record outside ». Le
  rapprochement est une déduction, mais tout indique des PDU rejouées, pas un
  enregistrement d'exercice.
- `pdu_status_test.pcapng` (#12043) : le champ longueur vaut 0 dans toutes
  ses PDU.

## Licences

- `dis_voice_sample.pcap` : GPL-2.0-or-later, licence du dépôt Wireshark ;
- `DIS_signal_and_transmitter.pcapng` : licence de la wiki Wireshark (GNU
  GPL v2+, en pied de page de <https://wiki.wireshark.org>) ;
- pièces jointes du tracker Wireshark : aucune licence explicite, publiques
  depuis leur dépôt.

Aucun de ces fichiers n'entre dans le paquet publié sur crates.io. Le texte
des licences n'accompagne pas encore les captures : voir #104.
