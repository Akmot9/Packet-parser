# Provenance

`umas.pcap` provient du corpus de tests du projet
[nDPI](https://github.com/ntop/nDPI) (ntop), fichier
`tests/cfgs/default/pcap/umas.pcap`.

- URL exacte (commit épinglé) :
  <https://raw.githubusercontent.com/ntop/nDPI/359f1a5638810c9990106ff0b036cc9064aa3923/tests/cfgs/default/pcap/umas.pcap>
- Téléchargé le 2026-09-20 ; SHA-256 :
  `bd9ddf4762e77426640b875b45351beb1bdf7c59ffd5a370e4d7669717900b32`.
- Licence du dépôt source : LGPL-3.0 (licence de nDPI ; le fichier est
  redistribué tel quel, sans modification ni anonymisation — le trafic est
  du labo, sur un réseau 192.168.63.0/24).

Cette capture lève le blocage de l'issue #10, que la ROADMAP décrivait
comme en attente d'une trame que « seul le labo peut produire, aucune trame
publique n'existe ».

## Contenu (vérifié avec tshark 4.6.6)

191 trames, une seule conversation TCP entre `192.168.63.100:7718`
(logiciel d'ingénierie) et `192.168.63.253:502` (automate Modicon) :

- **180 trames UMAS**, c'est-à-dire du Modbus/TCP portant le code fonction
  **0x5A** réservé à Schneider Electric (`tshark -Y 'modbus.func_code == 90'`
  en compte exactement 180, aucune exception 0xDA) ;
- 11 trames TCP sans charge utile (poignée de main et acquittements).

Détail des 180 trames UMAS :

- **deux sessions**, `0x00` et `0x01` ;
- **quatorze valeurs distinctes** en deuxième octet du PDU : `0xFE` pour
  les 90 réponses de l'automate, et treize codes de requête — `0x01`,
  `0x02`, `0x03`, `0x04`, `0x0A`, `0x10`, `0x12`, `0x20`, `0x33`, `0x34`,
  `0x35`, `0x50`, `0x58` ;
- la réponse de la trame 6 porte la chaîne ASCII `140 CPU 311 10`, le
  modèle de l'automate interrogé — c'est l'assertion de contenu du golden
  test.

**tshark ne décode pas UMAS** : il s'arrête à Modbus/TCP. L'oracle des
golden tests est donc double — les champs MBAP sont recoupés avec tshark
(`mbtcp.trans_id`, `mbtcp.unit_id`, `mbtcp.len`, `modbus.func_code`), et
les octets du PDU UMAS sont lus sur le wire et documentés dans
`tests/umas_golden.rs`.

## Ce que cette capture ne contient pas

- aucune réponse d'erreur : les 90 réponses portent toutes `0xFE`. La
  valeur `0xFD`, que la rétro-ingénierie publique décrit comme un échec,
  n'est attestée par aucune trame du dépôt et n'est donc pas nommée dans
  [`UmasFunction`](../../../src/parse/application/protocols/umas.rs) ;
- aucune trame UMAS hors du port 502.

Une trame UMAS supplémentaire vit ailleurs dans le corpus :
`protocols/modbus/MODBUS-TestDataPart2.pcap` trame 229, une requête 0x5A
adressée à un automate qui la refuse — sa réponse, code fonction `0xDA`
(`0x5A | 0x80`, exception Modbus « fonction illégale »), reste étiquetée
ModbusTCP.
