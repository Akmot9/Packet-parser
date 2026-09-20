# Provenance

`opcua_loopback.pcap` provient du corpus de tests du projet
[nDPI](https://github.com/ntop/nDPI) (ntop), fichier
`tests/cfgs/default/pcap/opc-ua.pcap`, renommé pour dire son encapsulation.

- URL exacte (commit épinglé) :
  <https://raw.githubusercontent.com/ntop/nDPI/359f1a5638810c9990106ff0b036cc9064aa3923/tests/cfgs/default/pcap/opc-ua.pcap>
- Téléchargé le 2026-09-20 ; SHA-256 :
  `46eff2793ee3105a7d478fc425a99e4cea9946a16194a2c3d95876300b2cf197`.
- Licence du dépôt source : LGPL-3.0 (licence de nDPI ; redistribué tel
  quel — le trafic est du loopback, 127.0.0.1 de part et d'autre).

C'est la **première capture OPC UA du dépôt**. Le décodeur était publié
depuis plusieurs versions sans qu'aucune trame réelle ne l'exerce.

## Encapsulation : LINKTYPE_NULL

La capture est en **LINKTYPE_NULL (0)**, l'encapsulation loopback BSD :
quatre octets portant la famille d'adresses, puis le paquet IP. Ici
`02 00 00 00`, soit `AF_INET` en little-endian — l'ordre d'octets est celui
de la machine qui a capturé, et le format n'en garde aucune trace.

C'est elle qui a motivé le décodeur de liaison correspondant (issue #95) :
avant lui, les 381 trames échouaient toutes en `UnsupportedLinkType`.

## Contenu (vérifié avec tshark 4.6.6)

381 trames, `127.0.0.1:57420` ↔ `127.0.0.1:4840` (port OPC UA standard) :

- **187 trames OPC UA**, parité exacte avec `tshark -Y opcua` :

  | Type | Nombre | Rôle |
  |---|---|---|
  | `HEL` | 1 | Hello, porte l'URL `opc.tcp://localhost:4840` |
  | `ACK` | 1 | Acknowledge |
  | `OPN` | 2 | OpenSecureChannel |
  | `MSG` | 182 | Message |
  | `CLO` | 1 | CloseSecureChannel |

- 194 trames TCP sans charge utile (poignée de main, acquittements).

Chaque message tient dans un segment : aucun chunk n'est fragmenté, et
aucun segment n'en enchaîne deux — le golden le vérifie.

## Ce que cette capture ne contient pas

- **aucun chunk fragmenté** (`C` ou `A` en quatrième octet) : le chemin
  `OpcuaPayload::Partial` n'est pas couvert par une trame réelle ;
- aucune trame IPv6, donc aucune famille `AF_INET6` réelle — les quatre
  valeurs connues (10, 24, 28, 30) sont couvertes par des tests unitaires ;
- aucun trafic `LINKTYPE_LOOP` (108), le jumeau OpenBSD en ordre réseau,
  que le décodeur ne traite volontairement pas.
