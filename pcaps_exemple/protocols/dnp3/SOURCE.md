# Provenance

Seize captures **DNP3** (IEEE 1815) versées le 2026-10-12 pour l'issue #99.
Toutes viennent du corpus de tests de [Zeek](https://github.com/zeek/zeek),
dossier `testing/btest/Traces/dnp3/`, branche `master` au commit
`66194af53d66b0d7b70f45321fbf47ad6451c34d` (2026-10-12). Aucune n'est
modifiée : ni anonymisée, ni tronquée.

Contenu vérifié avec tshark 4.6.6 (`-Y dnp3`, reassemblage TCP coupé,
décodage forcé sur le port 20001) : 218 trames de liaison DNP3 sur 220
segments ou datagrammes à payload — 16 trames de liaison seules (demande
d'état de liaison et sa réponse), 159 fragments applicatifs tenant dans une
trame, 43 trames d'un fragment réparti sur plusieurs.

| Fichier | Trames | Contenu | SHA-256 |
|---|---|---|---|
| `dnp3.pcap` | 214 | trois sessions TCP 20000 (2004) : lectures de classes, écritures, select/operate, redémarrages, confirmations, réponses sollicitées et non sollicitées | `7a30496184c93b12ef57fd0877acbead85975b20a8db35d8ac7b5c45e4f9f305` |
| `dnp3_read.pcap` | 10 | lecture des classes 1, 2, 3 et 0, réponse avec entrées binaires, sorties binaires et analogiques | `1e39be441983fcf9acb4ee4a60ee986c4a9009bd8c1cc1f1de1b40e4e70fad65` |
| `dnp3_read_p20001.pcap` | 10 | mêmes octets que `dnp3_read.pcap`, port réécrit en 20001 : la preuve du sondage sans port | `e17324b454c07ea1112077db39af36eb20c9667429d3acc083c745ae462b3a9f` |
| `dnp3_write.pcap` | 10 | écriture (g80v1, remise à zéro de l'indication de redémarrage) | `8e8c08175097d5b04a824ec10d5e02daff89f2fba1aa0763ecacb2131ddbf28f` |
| `dnp3_select_operate.pcap` | 13 | select puis operate d'une commande binaire (g12v1, CROB) | `06de51c8d6f32fb5991c547c7ba94fc824daf34422ebb86cbb5e07fd4be93ba1` |
| `dnp3_en_spon.pcap` | 10 | activation des messages non sollicités (g60v2-4) | `d5c33a7d99bfe60fa7f5afa9bddee52afcba8a9ed6065e309fb8878209f2266c` |
| `dnp3_del_measure.pcap` | 10 | mesure de délai, réponse g52v2 | `83e398ef4d8b908a76a582ef761e53f8ae029d3595ced3f80cdf700fc9ff62e0` |
| `dnp3_rec_time.pcap` | 10 | enregistrement de l'heure courante | `4e4d464d75e33790d4b62a99361843ec439e01666d5f20add2e4218db4951375` |
| `dnp3_file_read.pcap` | 30 | ouverture, lecture par blocs (g70v5, objets préfixés par leur taille), fermeture | `3c75fc6e9378a793ab80b6bd7a555497f9c7bf74419c87bc596f7d38efe7b982` |
| `dnp3_file_write.pcap` | 22 | écriture d'un fichier | `169f828684c38cf20964a435f9a69580f8470fa032cbaf8f52a1b21f568c1c72` |
| `dnp3_file_del.pcap` | 10 | suppression d'un fichier | `de903a543056985d94eaaa19a7d42cf64a9f2d3c992bf316f2d18396e62cdfb2` |
| `dnp3_link_only.pcap` | 35 | demandes d'état de liaison, puis une lecture dont la réponse de 2 300 octets tient en dix trames de liaison de 255 octets | `1f71b67c07836072d522fbdc8688199a2482093aeef2c406e39b9f7b5991f254` |
| `dnp3_udp_read.pcap` | 23 | la même lecture sur UDP 20000 | `4787acb645e088ddabfcec437c3adeee30b51a445c064b62c0a85c48280ee8ba` |
| `dnp3_udp_write.pcap` | 2 | écriture sur UDP | `62ff4d916c295ab81825d3d22419c44855d528529ed72c9f76b88567f6b07219` |
| `dnp3_udp_select_operate.pcap` | 10 | select/operate sur UDP, avec confirmations applicatives | `152cf07ee031b6c85a854ff1a3005e3ddc7612e109d380f1093ee66f85e3321a` |
| `dnp3_udp_en_spon.pcap` | 4 | messages non sollicités sur UDP | `6e2d07f5ee3d5c2545456b5612565b604fcc13d9aab30192bab64ff233f2a650` |

## Ces trames sont-elles réelles ?

Le `README` du dossier `Traces` de Zeek avertit que beaucoup de ses captures
sont **générées par scapy ou par un LLM**, et signale par un `.py` homonyme
celles qui le sont. La règle de ce dépôt les interdit, donc la question a été
tranchée sur les octets :

- **`dnp3_*.pcap` de décembre 2011** (`read`, `write`, `select_operate`,
  `en_spon`, `del_measure`, `rec_time`, `file_*`) : un poste Intel
  (`00:1b:21:0b:15:24`) et un Dell (`b8:ac:6f:ab:45:7a`), TTL 128 des deux
  côtés, ports éphémères Windows (49404 à 51006) ; un maître et une station
  réels sur un réseau de laboratoire, les CRC de liaison tous justes ;
- **`dnp3_link_only.pcap` (2013) et `dnp3_udp_*.pcap` (2014)** : une carte
  Intel (`00:16:76:c7:ce:db`, TTL 128) face à un équipement embarqué
  (`00:50:c2:4f:94:64`, bloc IEEE RA, TTL 64) sur le port 1128 ; la station
  répond par des fragments de 2 300 octets en trames de 255 octets, la
  signature d'une vraie RTU ;
- **`dnp3.pcap` (2004)** : trois sessions entre `10.0.0.3`, `10.0.0.8`,
  `10.0.0.9`, `192.168.66.33` et `192.168.66.34`, quatre cartes (Intel,
  Apple, 3Com), TTL 128 ; des requêtes variées dont six (trames 154, 156,
  163, 166, 174 et 176) portent un qualificatif `0xed` (bit 7 réservé mis
  à 1, code de plage 13) que la norme ne définit pas — ce qu'un générateur
  ne produirait pas et qu'un vieux maître produit ; tshark ne le montre que
  dans les deux premières, les quatre autres étant des arrêts d'application
  (fonction 18), dont il ne lit pas les objets ;
- **`dnp3_read_p20001.pcap`** : les octets de `dnp3_read.pcap`, port
  réécrit ; gardé parce que l'issue demande de prouver le sondage sans port.

**Écartée** : `dnp3-flowbuffer-overflow-assert.pcap`, générée par le script
scapy `dnp3-flowbuffer-overflow-assert.pcap.py` qui l'accompagne (MAC
`02:00:00:00:00:02`, 2026-08-10).

`4SICS-GeekLounge-151020.pcap`, à la racine de `pcaps_exemple/`, ne porte
aucune trame DNP3 (vérifié avec tshark, 246 137 trames).

## Oracle tshark

`tests/data/dnp3_tshark_oracle.tsv` est produit par `tools/dnp3_oracle.sh`
(tshark 4.6.6, `tcp.desegment_tcp_streams:FALSE`, DNP3 forcé sur le port
20001) : une ligne par segment ou datagramme à payload, la couche liaison
(longueur, contrôle, fonction, adresses, CRC d'en-tête), le transport
(contrôle, premier, dernier, séquence) et, pour les fragments qui tiennent
dans une trame, l'application (contrôle, fonction, IIN, en-têtes d'objets
avec préfixes et plages). tshark réassemble les fragments répartis sur
plusieurs trames et ne montre l'application que sur la dernière :
`tests/dnp3_golden.rs` compare l'application sur les fragments d'une trame
et vérifie que les suites de fragment n'en ont pas.

## Licence

Zeek est distribué sous licence **BSD 3-clause** (The Regents of the
University of California, Lawrence Berkeley National Laboratory,
International Computer Science Institute) ; le texte complet, avec la notice
de copyright que la licence oblige à reproduire, est dans
`pcaps_exemple/LICENSES/BSD-3-Clause-Zeek.txt` (#104). Aucun de ces fichiers
n'entre dans le paquet publié sur crates.io.
