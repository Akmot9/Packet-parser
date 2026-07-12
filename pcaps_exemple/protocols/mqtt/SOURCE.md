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
