# Provenance

Captures ajoutées par Cyprien (2026-07-12) pour durcir la détection MQTT
(faux positifs du probing à l'aveugle). Provenance exacte à confirmer par
Cyprien (échantillons publics, d'après les noms de fichiers).

Les quatre fichiers contiennent la même session MQTT v3.1 (« MQIsdp ») :
un client Paho (10.0.1.4:49327) vers le broker public m2m.eclipse.org:1883 —
CONNECT, CONNACK, SUBSCRIBE « SampleTopic », SUBACK, PUBLISH retain
« Hello from the Paho blocking client », PINGREQ/PINGRESP.

| Fichier | Contenu |
|---|---|
| `mqtt_packets.pcapng` | session complète, 19 trames |
| `mqtt_packets_tcpdump.pcap` | même session au format pcap classique, 19 trames — **source des golden tests** (trames 1, 2, 3, 5, 6) |
| `mqtt_packets_RedHat61_tcpdump.pcap` | 1 trame : le CONNECT avec un en-tête Ethernet décalé/tronqué (capture défectueuse, cas dégradé) |
| `mqtt_packets_Windows.cap` | format NetXRay/Sniffer — **illisible par libpcap**, conservé pour archive |

## Captures MQTT 5 du tracker Wireshark

Quatre pièces jointes versées le 2026-11-17 pour l'issue #291, que la
crate n'avait jamais confrontée à du MQTT 5 réel. Leur auteur, Roger Light
(auteur de Mosquitto), les a jointes à deux rapports de bug du dissecteur
MQTT de Wireshark. Ce sont des échanges entre un client et un broker
Mosquitto sur la boucle locale (`127.0.0.1`, MAC nulles), enregistrés le
jour même de chaque rapport. Aucune n'est modifiée : ni anonymisée, ni
tronquée.

| Fichier | Trames | Contenu | Origine | SHA-256 |
|---|---|---|---|---|
| `wireshark_15257_mqtt-malformed.pcapng` | 12 | 2018-11-01, `55644 -> 1883` : CONNECT v5 à Will et propriétés, CONNACK, SUBSCRIBE, SUBACK, UNSUBSCRIBE à User Property, UNSUBACK. Le nom vient du rapport : c'est le dissecteur de 2018 qui se trompait, pas les paquets. | tracker Wireshark, issue #15257 (« MQTT dissector incorrectly handling some MQTT 5 packets »), pièce jointe `mqtt-malformed.pcapng` | `2648766ce0fdb4e6cfc6997f158ddddf5faed2440f7ffff8a1b10c6a4da3db70` |
| `wireshark_15428_v5-puback.pcapng` | 152 | 2019-01-17, port 1888, huit connexions : toutes les variantes de PUBACK v5 (packet id seul, reason code, propriétés) | tracker Wireshark, issue #15428 (« MQTT v5 dissector not handling short PUB* packets »), pièce jointe `v5-puback.pcapng` | `49a31311110337562632a56e038d9ece4f0332453bd94abc81386bdab72aecfd` |
| `wireshark_15428_v5-pubrec-pubcomp.pcapng` | 168 | même jour, mêmes formes pour PUBREC et PUBCOMP | même issue, pièce jointe `v5-pubrec-pubcomp.pcapng` | `17faf3071aa8702f67d5e7d7774b436020338374f18ef8f4dccb680209fb6f86` |
| `wireshark_15428_v5-pubrel.pcapng` | 88 | même jour, mêmes formes pour PUBREL | même issue, pièce jointe `v5-pubrel.pcapng` | `108e582c1c798ac8a47161f4e6d411f70fba2a81b4dfd0cf2a67be3719968e7a` |

tshark 4.6.9 y lit 150 paquets MQTT (`tools/mqtt_oracle.sh`, avec
`-d tcp.port==1888,mqtt` pour le port 1888), figés dans
`tests/data/mqtt_tshark_oracle.tsv` et vérifiés paquet par paquet par
`tests/mqtt_golden.rs`. Un seul n'est pas reconnu, la trame 11 de
`wireshark_15257_mqtt-malformed.pcapng` : un UNSUBACK sans reason code,
que la spec interdit (MQTT 5.0 §3.11.3, un code par topic filter) et que la
crate refuse. Avant #291, la trame 10 (UNSUBSCRIBE à propriétés) sortait
aussi Unknown.

Conditions : pièces jointes de rapports de bug publics, sans licence
explicite ; redistribuées telles quelles comme données de test publiques,
avec l'issue d'origine, le nom du fichier joint et son SHA-256, et retirées
si leur auteur le demande (position du dépôt,
`pcaps_exemple/LICENSES/README.md`).
