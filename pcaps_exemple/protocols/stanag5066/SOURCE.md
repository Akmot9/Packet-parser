# Provenance

Quatre captures de **STANAG 5066 SIS** (Subnetwork Interface Sublayer, TCP
5066), la couche qui relie les applications au nœud radio HF. Versées le
2026-10-08 pour l'issue #122 (épopée #125, rapport
`docs/protocoles-defense.md`). Aucune n'est modifiée : ni anonymisée, ni
tronquée.

Contenu vérifié avec tshark 4.6.6 (`-Y s5066sis`) : 34 trames portent au
moins un S_PDU ; les autres sont des segments TCP sans payload ou de
continuation.

| Fichier | Trames (S_PDU) | Origine | SHA-256 |
|---|---|---|---|
| `S5066-HFChat-1.pcap` | 44 (6) | wiki Wireshark | `abf4f64e44d64023e5470651d79354e1a415a576d8d4ab0dd245afc254355ab8` |
| `S5066-HFChat-Rejected.pcap` | 19 (5) | wiki Wireshark | `5e415965b04c6b4890478c7946943a72284806585280a483f777d7a39d7a5d9f` |
| `S5066-Expedited.pcap` | 13 (13) | wiki Wireshark | `dd5349fdcdb960d65c89f070ac2e08426d53566698a899ca300537614b8a4f70` |
| `wireshark_10827_sis_acp142.pcap` | 10 (10) | [#10827](https://gitlab.com/wireshark/wireshark/-/issues/10827) | `b321dde9ed775dff26601403c4f8642d0ff9cd9e6da4ba8300c1050301fce010` |

## Détail

- **`S5066-HFChat-1.pcap`** et **`S5066-HFChat-Rejected.pcap`** — un client
  HF Chat face à un nœud STANAG 5066 (`192.168.64.22:5066`), le 2005-10-26.
  L'adresse du client, `195.169.112.105`, appartient au bloc RIPE `NC3A-NL`
  (« NATO C3 Agency NL, Unclassified Internet LAN ») : le banc de référence
  de l'agence C3 de l'OTAN. La seconde capture montre une connexion refusée.
  URL `https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/<fichier>`.
- **`S5066-Expedited.pcap`** — données expédiées en boucle locale, le
  2006-09-12 ; même URL de base.
- **`wireshark_10827_sis_acp142.pcap`** — SIS portant de l'**ACP 142**
  (P_MUL, la diffusion fiable de la messagerie militaire) en boucle locale,
  le 2015-01-02. Fichier d'origine `before.pcap`, joint à l'issue qui a
  ajouté au dissecteur le transport ACP 142 et DMP.

Les captures en boucle locale portent des adresses MAC nulles : c'est
l'encapsulation Ethernet que Linux donne à l'interface `lo`, pas un indice de
fabrication.

Un S_PDU peut être coupé entre deux segments TCP, et un segment peut en
porter plusieurs : un parseur sans état décode le premier S_PDU complet.

## Non versés

- `Stanag5066-RAW-ENCAP-Bftp-Exchange-tx.pcap` (wiki) : couche DTS en
  LINKTYPE 237, que la crate ne lit pas ;
- `Stanag5066-TCP-ENCAP-Bftp-Exchange-tx-rx.pcapng` (wiki) : couche DTS
  encapsulée sur TCP 5067-5069, hors du périmètre SIS de #122.

## Licences

- captures de la wiki Wireshark : licence de la wiki (GNU GPL v2+, en pied de
  page de <https://wiki.wireshark.org>) ;
- pièce jointe du tracker Wireshark : aucune licence explicite, publique
  depuis son dépôt.

Aucun de ces fichiers n'entre dans le paquet publié sur crates.io. Le texte
des licences n'accompagne pas encore les captures : voir #104.
