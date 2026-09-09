# Provenance — captures VLAN (802.1Q, 802.1ad / QinQ)

## pppoe-over-qinq.pcap

- Échantillon public fourni par Cyprien le **2026-09-09** (issue #82), nom
  identique à l'échantillon Wireshark « pppoe-over-qinq ». Déjà anonymisé à
  la source : MAC `00:00:00:00:00:00` / `00:00:00:00:00:01` /
  `bc:d1:77:17:75:0d`, adresses IP `1.1.1.1` ↔ `2.2.2.2`.
- Encapsulation **Ethernet** (LINKTYPE 1), 86 trames, toutes en **double tag
  802.1Q** : tag externe `0x8100` VID **3704**, tag interne `0x8100` VID
  **2474**, puis **PPPoE session** (`0x8864`, session 0x0f07) portant du PPP
  IPv4 (`0x0021`) — une session TCP 1.1.1.1:443 ↔ 2.2.2.2.
- Sert de source au golden test `tests/qinq_golden.rs` : la pile de tags est
  consommée entière, `vlan` retient le tag interne (2474) et l'EtherType
  atteint est PPPoE. PPPoE lui-même n'est pas décodé (hors périmètre de #82).
- Aucune capture réelle 802.1ad (`0x88a8`) n'est disponible à ce jour : ce
  cas est couvert par les tests unitaires de `parse/data_link/mod.rs` sur
  octets fabriqués, faute de mieux.
