# Provenance

Dix captures versées le 2026-10-13 pour les issues #164 et #165 : huit du
corpus de tests de **nDPI** — deux vrais datagrammes NTP, et six captures
dont l'ancienne sonde NTP aveugle de la crate prenait 31 datagrammes pour du
NTP —, une pièce jointe du tracker Wireshark, des NTP à MAC SHA-1, SHA-256
et SHA-512, et la capture de test NTP de tcpdump, des requêtes de chrony aux
horodatages aléatoires. Le décodeur assoupli par #165 accepte d'autres
datagrammes de ces captures (KCP, QUIC, CryNet) : la sonde aveugle les
refuse. Aucune n'est modifiée : ni anonymisée, ni tronquée. Les captures
nDPI viennent de `tests/cfgs/default/pcap/` du dépôt `ntop/nDPI`, commit
`5915c399c0690be7ba252d32a741d1bf7ea07846`, et y sont depuis le commit
indiqué (`7714507f816b`, 2023-04-06, est celui qui a déplacé les captures
plus anciennes dans ce dossier).

| Fichier | Trames | Contenu | Depuis | Blob git | SHA-256 |
|---|---|---|---|---|---|
| `ndpi_NTPv3.pcap` | 1 | réponse NTPv3 d'un serveur (`175.144.140.29:123` vers le port 80, stratum 0, poll 4, précision -6), 2015 | `7714507f816b` | `483e349a` | `ee7234a164f697a8e88648ada0b620b443c39684843412d1faf64e6dfd8d04c5` |
| `ndpi_NTPv4.pcap` | 1 | requête de client NTPv4, `123 -> 123` (stratum 2, poll 7, précision -21), 2015 | `7714507f816b` | `6f91a111` | `b17f4994000bb98646018a698af61f2f5cebc036ff4ee5fe1fd9330a6024368b` |
| `ndpi_quic_interop_V.pcapng` | 246 | QUIC vers des serveurs d'interopérabilité (UDP 443, 4433, 4434, IPv4 et IPv6), version réservée `0x0a0a0a0a` qui force une négociation de version, 2020 ; **15 faux positifs**, et des datagrammes que le décodeur assoupli accepte (trame 27…) | `7714507f816b` | `19c4f072` | `af2f6ac0fdfb71fe6aa5b1fbce28c57afba7a7725be2368cc9a2e7724b934329` |
| `ndpi_crynet.pcap` | 235 | client CryNet vers ses relais UDP (ports éphémères), onze journées de 2022, 2023 et 2025 ; **11 faux positifs** (du 2025-09-01 au 2025-09-06), dont huit en-têtes nuls | `7714507f816b` (60 trames de 2022), complétée par `25c54dd6d7ae` (2023-10-22), `1c1894720e38` (2025-09-08, #2959, les 11 faux positifs) et `043fe06c1b07` (2025-09-15, #2965) | `5a105a5b` | `b3d0bc5f0cc7fd2af122e9d7651d9b0f2c8abac0c8301c279eeadd4553453a6d` |
| `ndpi_kcp.pcap` | 50 | KCP (ARQ sur UDP) sur la boucle locale IPv6, `47356 <-> 8000`, 2024 ; **2 faux positifs**, et des segments que le décodeur assoupli accepte (trames 3, 24… : `01 00 00 00` au stratum 0) | `0aea509e23e0` (2024-01-12, #2257) | `a27a6601` | `1c7a1cf755d7f023194b05f94dc0000fc209009fcfff2718517bf31302bdb82a` |
| `ndpi_pfcp.pcapng` | 11 | PFCP (5G, N4) sur UDP 8805 entre `127.0.0.1` et `127.0.0.2`, IP brut, 2024 ; **1 faux positif** | `8fad77991dcf` (2024-03-13, #2342) | `99853063` | `1361a620741a0d1bacf11149eace4182f90a1bc41f989d695bb18bf92ff02925` |
| `ndpi_line.pcap` | 290 | appel LINE (UDP, RTCP) et TLS vers `147.92.165.194`, 2022 ; **1 faux positif** | `7714507f816b` | `2720b7cc` | `d319d2f719db4657aced52eda2063dc6bd35114dc138799fcb8db543d38fc945` |
| `ndpi_openvpn_obfuscated.pcapng` | 177 | OpenVPN obfusqué (UDP 1214, TCP 443 et 465), 2024 ; **1 faux positif** | `0ddbda1f829a` (2024-09-16, #2547) | `439c2091` | `2706a55f369f452611261c196242ff13928e8494c68a04af2fb9b543a60e5d26` |
| `wireshark_16640_NTP-with-mac.pcap` | 13 | ntpd entre deux machines VMware (`192.168.3.5` et `.1`, `123 -> 123`), 2020-06-03 : requêtes et réponses NTPv4 à MAC SHA-1 (identifiant de clé 12), une requête à MAC SHA-256, deux à MAC SHA-512, une réponse NTPv3 à MAC SHA-512 | tracker Wireshark, issue #16640 (« Incorrect parsing of NTP datagrams with SHA512 based message authentication code (MAC) », 2020), pièce jointe `NTP-with-mac.pcap` (« pcap with sha1,sha256,sha512 ») | — | `69884cedccecade4774f0b28fd42e2a72297b39d93fd6d9e1ae0dd736f723957` |
| `tcpdump_ntp.pcap` | 8 | chrony et ntpd entre deux machines d'essai (`192.168.100.2` et `.1`), 2017-06-19 : requêtes de chrony (précision 32, Receive et Transmit aléatoires, MAC SHA-1 à identifiant de clé 8), un Kiss-o'-Death `STEP` suivi d'un crypto-NAK, une requête à la ntpdate, des réponses de stratum 2, un échange symétrique `123 -> 123` à MAC MD5 | dépôt tcpdump, `tests/ntp.pcap`, commit `57768afc4cffbaa17faad7808f106bc325ada417` (blob `2fd5937e`, versé par Miroslav Lichvar, auteur de chrony, `fdd0cf43a6fa`, 2017-06-19) | `2fd5937e` | `a858f6d32e82516b67fa98edb9304ca7872493e0bede8decc5637b7e6fc882d3` |

Les numéros des 31 faux positifs sont dans `FORMER_FALSE_POSITIVES` de
`tests/ntp_golden.rs`, ceux de datagrammes que le décodeur assoupli accepte
dans `LENIENT_LOOKALIKES`. Des douze autres faux positifs du corpus nDPI,
dix ne sont pas versés parce que leurs captures sont volumineuses (350 Ko à
2,5 Mo : `1kxun.pcap`, datagrammes NetBIOS sur UDP 138, `gnutella.pcap`,
`telegram.pcap`, `tinc.pcap`) — les mêmes contraintes les rejettent ; celui
de `nordvpn.pcap` viendra avec WireGuard (#103), et celui de `msgpack.pcap`
est écarté (ci-dessous).

## Ces trames sont-elles réelles ?

- `ndpi_NTPv3.pcap`, `ndpi_NTPv4.pcap` : trafic d'Internet — adresses
  publiques, TTL 55 derrière un routeur Juniper (`00:26:88`), horodatages
  NTP cohérents avec la date de capture (2015-07-14).
- `ndpi_quic_interop_V.pcapng` : un poste (carte Intel `3c:a9:f4`) qui joint
  de vrais serveurs QUIC d'Internet (TTL de 28 à 226 au retour) ; 31
  erreurs ICMP et ICMPv6 citent des datagrammes QUIC, 19 reçues par le
  poste, 12 émises par lui.
- `ndpi_crynet.pcap` : des postes de réseaux locaux (`192.168.1.94`,
  `192.168.2.100`, TTL 127) et des relais d'Internet (TTL 52 à 57) ; des
  sessions de onze journées (2022-09-13, 2023-07-30, 2025-05-29, puis du
  2025-09-01 au 2025-09-13), versées par quatre commits.
- `ndpi_line.pcap` : **mixte** — une machine virtuelle VirtualBox derrière le
  NAT de l'hyperviseur (`08:00:27`, `52:54:00:12:35:02`, horodatages relatifs
  à 1970) et un second poste ; le contenu (RTCP, TLS vers les serveurs de
  LINE) est celui d'une vraie application.
- `ndpi_openvpn_obfuscated.pcapng` : un client (TTL 64) et des serveurs
  d'Internet (TTL 49 à 53), sur trois jours.
- `ndpi_kcp.pcap`, `ndpi_pfcp.pcapng` : **laboratoire** — trafic produit par
  de vrais logiciels (une démo KCP, un cœur 5G) sur la boucle locale, l'un
  repris avec des MAC nulles, l'autre en IP brut ; rien n'est fabriqué à la
  main.

- `wireshark_16640_NTP-with-mac.pcap` : deux machines virtuelles VMware
  (`00:0c:29`), TTL 64, un ntpd client et un serveur à clés symétriques ;
  capture du 2020-06-03, jointe le 2020-06-19 à un rapport de bug sur le
  décodage des MAC SHA-512 par Wireshark. Les MAC sont ceux que calcule
  ntpd, non tronqués.

- `tcpdump_ntp.pcap` : **laboratoire** — trafic de vrais chrony et ntpd
  entre deux machines d'essai (TTL 64, une même adresse MAC sur les deux
  sens, celle de l'interface de capture), versé par l'auteur de chrony pour
  le décodeur NTP de tcpdump. Sa trame 3, une requête de chrony dont
  Receive suit Transmit, est la seule que la sonde aveugle refuse hors du
  port 123.

`msgpack.pcap`, qui porte aussi un faux positif, est **écarté** : ses
datagrammes `31337 -> 1337` sur `127.0.0.1` ont un TTL qui change d'un
datagramme à l'autre (120 à 190) et deux trames partagent horodatage et
identifiant IP ; il est construit, pas capturé.

## Oracle tshark

`tests/data/ntp_tshark_oracle.tsv` est produit par `tools/ntp_oracle.sh`
(tshark 4.6.6) sur ce dossier, `goose/iti_Sample_File_MMS_and_GOOSE.pcap`,
`iec104/iti_JavaRMI_and_IEC_Misc.pcap` et, lues en place,
`The-Ultimate-PCAP.pcapng` et `4SICS-GeekLounge-151020.pcap`.
`tests/ntp_golden.rs` y vérifie la parité champ par champ, qu'aucune autre
trame de `pcaps_exemple/` ne sort NTP — les 31 faux positifs d'hier et les
datagrammes que le décodeur assoupli accepte compris —, et que les vrais
datagrammes déplacés hors du port 123 sont reconnus par la sonde aveugle
(#164, #165).

## Licences

- `ndpi_*` : LGPL-3.0, licence du dépôt nDPI (© ntop.org ; texte :
  `pcaps_exemple/LICENSES/LGPL-3.0.txt`, qui incorpore
  `pcaps_exemple/LICENSES/GPL-3.0.txt`) ;
- `tcpdump_ntp.pcap` : BSD (trois clauses), licence du dépôt tcpdump (texte :
  `pcaps_exemple/LICENSES/BSD-3-Clause-tcpdump.txt`) ;
- `wireshark_16640_NTP-with-mac.pcap` : pièce jointe d'un rapport de bug
  public, sans licence explicite ; redistribuée telle quelle comme donnée de
  test publique, avec l'issue d'origine, le nom du fichier joint et son
  SHA-256, et retirée si son auteur le demande (position du dépôt,
  `pcaps_exemple/LICENSES/README.md`).

Fichiers redistribués tels quels. Aucun n'entre dans le paquet publié sur
crates.io (#104).
