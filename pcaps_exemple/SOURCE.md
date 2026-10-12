# Provenance — captures à la racine

Les captures rangées directement dans `pcaps_exemple/` (hors `protocols/`)
précèdent la convention « un sous-dossier par protocole ». Ce fichier comble
leur provenance manquante.

## sll.pcap

- Capture locale de Cyprien, **2026-07-14 15:07 (+0200)**, versionnée le jour
  même par `bd03272 test: golden tests SLL/SLL2 sur captures réelles`.
- Encapsulation **Linux cooked-mode capture v1** (LINKTYPE_LINUX_SLL, 113) —
  capture sur l'interface `any` d'un hôte Linux.
- 2 702 paquets : navigation web ordinaire (TCP/TLS vers plusieurs hôtes,
  résolution DNS) et **une session QUIC v1 sur IPv6** vers un serveur Google
  (`2a00:1450:4006:818::200a:443`), trames 1712 à ~1780.
- Sert de source aux golden tests SLL (`tests/public_parse_api.rs`) et QUIC
  (`tests/quic_golden.rs`, issue #59) : trame 1716 Initial, 1730 Handshake,
  1731 Short header.

## capture_sll2.pcap

- Capture locale de Cyprien, **2026-07-14 15:24 (+0200)**, même commit.
- Encapsulation **Linux cooked-mode capture v2** (LINKTYPE_LINUX_SLL2, 276).
- 779 paquets, même profil : TCP/TLS, DNS, et 32 trames QUIC.
- Sert de source aux golden tests SLL2.

## À compléter par Cyprien

- Quel hôte et quelle interface (`tcpdump -i any` ?), et quel navigateur a
  généré le trafic QUIC — utile pour savoir quelle implémentation QUIC est
  figée dans les goldens.
- **Point de confidentialité** : ces deux captures contiennent l'adresse IPv6
  globale réelle du client (préfixe `2001:8613:fc79:b00b::/64`) et son
  historique de navigation en clair au niveau DNS. Elles ne sont pas
  anonymisées, contrairement à ce que demande le README de ce dossier. À
  arbitrer : anonymiser et regénérer les fixtures, ou assumer le dépôt en
  l'état.

## 4SICS-GeekLounge-151020.pcap

- Capture du « Geek Lounge » de la conférence 4SICS 2015 (Stockholm),
  réalisée par **Netresec** dans le labo ICS (automates, RTU, équipements
  réseau industriels) le 2015-10-20 : 246 137 trames, 25 711 082 octets.
- Source : <https://www.netresec.com/?page=PCAP4SICS>, fichier
  `4SICS-GeekLounge-151020.pcap`, lien de téléchargement
  `https://share.netresec.com/s/xYj2qCNbsLEAd6M/download/4SICS-GeekLounge-151020.pcap`.
  Copie identique à l'octet près au fichier publié (SHA-256
  `8c6ee02dc26b1b52…`, vérifié le 2026-10-12). Versée le 2026-07-13
  (`6a6b1f6`).
- Conditions (page Netresec, pas de licence formelle) : « We kindly ask you
  to credit CS3Sthlm, for allowing the network traffic from the 4SICS lab to
  be captured and shared, if you will re-distribute this dataset or use it
  as part of a training. We would also appreciate a link back to this
  page. » → **créditer CS3Sthlm et Netresec**, avec le lien ci-dessus.

## The-Ultimate-PCAP.pcapng

- « The Ultimate PCAP » de **Johannes Weber** (weberblog.net) : fusion de
  captures réelles de 2009 à 2026 couvrant des dizaines de protocoles,
  version **v20260710** (commentaire de section du pcapng), 51 328 trames.
- Source : <https://weberblog.net/the-ultimate-pcap/>, fichier
  `https://weberblog.net/wp-content/uploads/2020/02/The-Ultimate-PCAP.pcapng.gz`
  (6 255 186 octets compressés). Décompressé, identique à l'octet près à la
  copie du dépôt (SHA-256 `ecbca543fbe011a8…`, vérifié le 2026-10-12).
  Versée le 2026-07-14 (`058e9c5`).
- Conditions : la page n'énonce aucune licence ; le fichier est publié pour
  téléchargement libre. Redistribué tel quel, avec citation de l'auteur et
  de la page.
- Source de nombreux golden tests (LLMNR, NBNS, SSDP, SSH, STP, ICMPv6,
  DNS…) : voir les commentaires `pcaps_exemple/The-Ultimate-PCAP.pcapng`
  dans `src/` et `tests/`.

## ftp.pcap

- Fichier `ftp.pcap` des captures d'accompagnement de *Practical Packet
  Analysis* (1re édition, No Starch Press, 2007) de **Chris Sanders** :
  session FTP du 2006-12-16 (`USER csanders`), 38 trames.
- Source : <https://nostarch.com/download/ppa-capture-files.zip> (archive de
  40 fichiers, 20 634 632 octets, SHA-256 `7d9e0305d745b6f4…`) ; `ftp.pcap`
  y est identique à l'octet près à la copie du dépôt (SHA-256
  `da51ae8149772233…`, vérifié le 2026-10-12). Versée le 2026-07-30
  (`e9b1027`).
- Conditions : Chris Sanders publie ses captures « free to download and use
  … with no restrictions », en demandant de **citer leur origine**
  (<https://chrissanders.org/packet-captures/>) — même règle que les dossiers
  « source Chris Sanders » (voir le README).
- Sert aux tests de `src/parse/mod.rs` (trames 4 et 5 : bannière et `USER`).

## capwap-only.pcap, capwap-only.pcapng, capwap-association-valid.pcapng

- Les mêmes **deux trames** (Ethernet/IPv4/UDP 5247, CAPWAP data portant une
  Association Request 802.11, SSID « Prova », 2014-02-10 et 2014-04-14,
  trafic loopback 127.0.0.1 du projet SmartCAPWAP), extraites de
  `The-Ultimate-PCAP.pcapng` : trames **1555** et **1568**, octets identiques
  (les deux pcapng gardent l'en-tête de section et le commentaire de fusion
  de l'original). La première est aussi la trame 12 de `smartcapwap.pcap`,
  pièce jointe de l'issue Wireshark
  [#9752](https://gitlab.com/wireshark/wireshark/-/issues/9752) (2014-02-12).
- Versées le 2026-07-14 (`058e9c5`, `capwap-association-valid.pcapng`) et le
  2026-07-30 (`e9b1027`, les deux `capwap-only`). Les deux pcapng ne
  diffèrent que par leurs blocs de métadonnées.
- Conditions : celles de The Ultimate PCAP ci-dessus.
- `capwap-only.pcap` sert au test de `src/parse/tunnel/mod.rs` (trame 1).

## vlan0--packet-capture CAPWAP a partir de ligne 520  (Ap = 192_168.0.104 ) + radius _ partir de la ligne 33003 .cap

- Capture d'un réseau de test le **2016-06-20** (10:11 à 10:16, +0200) :
  réseau 192.168.0.0/24 où un point d'accès Zyxel (192.168.0.104,
  `4c:9e:ff:82:6e:38`) dialogue en CAPWAP/DTLS avec un contrôleur
  (192.168.0.101, Zyxel), avec un serveur RADIUS, un poste HP et un poste
  ASUS, des BPDU STP d'un commutateur Cisco (`fc:fb:fb:f8:cc:01`) et un
  service sur AWS (52.28.53.20) ; 3 584 trames (TLS, DTLS, RADIUS, STP, ARP,
  ICMP, NBNS), dont 288 CAPWAP.
- Le nom du fichier (en français, « à partir de la ligne 520 … 33003 »)
  désigne un extrait d'une capture plus longue, annoté pour un lecteur.
  Versée le 2026-07-14 (`058e9c5`, message « pcap ») sans provenance.
- **Origine non documentée** : capture tierce probable ; auteur et conditions
  à confirmer par Cyprien. Sert au test de `src/parse/data_link/stp.rs`
  (BPDU de `fc:fb:fb:f8:cc:01`).

## Retirés le 2026-10-12

- `capwap-multi-wtp.pcap` (24 trames, 2024-07-03) : **fabriqué** — les deux
  trames CAPWAP ci-dessus rejouées avec des MAC `aa:bb:cc:…`, des adresses
  192.168.50.x et des horodatages ronds (toutes les 0,4 s et 1 s).
  Contraire à la règle du corpus (trames réelles uniquement) ; aucun test ne
  s'en servait.
- `protocols/http/simple-http-request.pcap` (1 trame) : **fabriqué** — MAC
  `00:11:22:33:44:55` → `66:77:88:99:aa:bb`, epoch 1 710 000 000 exactement,
  IP id `0x1234`, `User-Agent: SampleClient/1.0`. Même raison ;
  l'histogramme golden perd une trame HTTP (72 → 71).
- `capwap.pcap.out` : sortie texte d'`ndpiReader` sur un `capwap.pcap` absent
  du dépôt, pas une capture.
