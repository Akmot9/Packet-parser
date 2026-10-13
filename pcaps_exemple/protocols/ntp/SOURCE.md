# Provenance

Huit captures du corpus de tests de **nDPI** versées le 2026-10-13 pour
l'issue #164 : deux vrais datagrammes NTP, et six captures dont l'ancienne
sonde NTP aveugle de la crate prenait 31 datagrammes pour du NTP, plus un
que le décodeur assoupli par #165 laisserait passer. Aucune
n'est modifiée : ni anonymisée, ni tronquée. Toutes viennent de
`tests/cfgs/default/pcap/` du dépôt `ntop/nDPI`, commit
`5915c399c0690be7ba252d32a741d1bf7ea07846`, et y sont depuis le commit
indiqué (`7714507f816b`, 2023-04-06, est celui qui a déplacé les captures
plus anciennes dans ce dossier).

| Fichier | Trames | Contenu | Depuis | Blob git | SHA-256 |
|---|---|---|---|---|---|
| `ndpi_NTPv3.pcap` | 1 | réponse NTPv3 d'un serveur (`175.144.140.29:123` vers le port 80, stratum 0, poll 4, précision -6), 2015 | `7714507f816b` | `483e349a` | `ee7234a164f697a8e88648ada0b620b443c39684843412d1faf64e6dfd8d04c5` |
| `ndpi_NTPv4.pcap` | 1 | requête de client NTPv4, `123 -> 123` (stratum 2, poll 7, précision -21), 2015 | `7714507f816b` | `6f91a111` | `b17f4994000bb98646018a698af61f2f5cebc036ff4ee5fe1fd9330a6024368b` |
| `ndpi_quic_interop_V.pcapng` | 246 | QUIC vers des serveurs d'interopérabilité (UDP 443, 4433, 4434, IPv4 et IPv6), version réservée `0x0a0a0a0a` qui force une négociation de version, 2020 ; **15 faux positifs** | `7714507f816b` | `19c4f072` | `af2f6ac0fdfb71fe6aa5b1fbce28c57afba7a7725be2368cc9a2e7724b934329` |
| `ndpi_crynet.pcap` | 235 | client CryNet vers ses relais UDP (ports éphémères), 2022 et 2025 ; **11 faux positifs**, dont huit en-têtes nuls | `7714507f816b`, complétée par `043fe06c1b07` (2025-09-15) | `5a105a5b` | `b3d0bc5f0cc7fd2af122e9d7651d9b0f2c8abac0c8301c279eeadd4553453a6d` |
| `ndpi_kcp.pcap` | 50 | KCP (ARQ sur UDP) sur la boucle locale IPv6, `47356 <-> 8000`, 2024 ; **2 faux positifs**, et la trame 24 (`01 00 00 00` au stratum 0) que le décodeur assoupli laisserait passer | `0aea509e23e0` (2024-01-12, #2257) | `a27a6601` | `1c7a1cf755d7f023194b05f94dc0000fc209009fcfff2718517bf31302bdb82a` |
| `ndpi_pfcp.pcapng` | 11 | PFCP (5G, N4) sur UDP 8805 entre `127.0.0.1` et `127.0.0.2`, IP brut, 2024 ; **1 faux positif** | `8fad77991dcf` (2024-03-13, #2342) | `99853063` | `1361a620741a0d1bacf11149eace4182f90a1bc41f989d695bb18bf92ff02925` |
| `ndpi_line.pcap` | 290 | appel LINE (UDP, RTCP) et TLS vers `147.92.165.194`, 2022 ; **1 faux positif** | `7714507f816b` | `2720b7cc` | `d319d2f719db4657aced52eda2063dc6bd35114dc138799fcb8db543d38fc945` |
| `ndpi_openvpn_obfuscated.pcapng` | 177 | OpenVPN obfusqué (UDP 1214, TCP 443 et 465), 2024 ; **1 faux positif** | `0ddbda1f829a` (2024-09-16, #2547) | `439c2091` | `2706a55f369f452611261c196242ff13928e8494c68a04af2fb9b543a60e5d26` |

Les numéros des 32 trames sont dans `FORMER_FALSE_POSITIVES` de
`tests/ntp_golden.rs`. Des douze autres faux positifs du corpus nDPI, dix
ne sont pas versés parce que leurs captures sont volumineuses (350 Ko à
2,5 Mo : `1kxun.pcap`, datagrammes NetBIOS sur UDP 138, `gnutella.pcap`,
`telegram.pcap`, `tinc.pcap`) — les mêmes contraintes les rejettent ; celui
de `nordvpn.pcap` viendra avec WireGuard (#103), et celui de `msgpack.pcap`
est écarté (ci-dessous).

## Ces trames sont-elles réelles ?

- `ndpi_NTPv3.pcap`, `ndpi_NTPv4.pcap` : trafic d'Internet — adresses
  publiques, TTL 55 derrière un routeur Juniper (`00:26:88`), horodatages
  NTP cohérents avec la date de capture (2015-07-14).
- `ndpi_quic_interop_V.pcapng` : un poste (carte Intel `3c:a9:f4`) qui joint
  de vrais serveurs QUIC d'Internet (TTL 42 au retour), dont 31 erreurs ICMP
  et ICMPv6 qui citent ses datagrammes.
- `ndpi_crynet.pcap` : des postes de réseaux locaux (`192.168.1.94`,
  `192.168.2.100`, TTL 127) et des relais d'Internet (TTL 52 à 57) ; deux
  sessions, de 2022 et de 2025, réunies dans un même fichier.
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

`msgpack.pcap`, qui porte aussi un faux positif, est **écarté** : ses
datagrammes `31337 -> 1337` sur `127.0.0.1` ont un TTL qui change d'un
datagramme à l'autre (120 à 190) et deux trames partagent horodatage et
identifiant IP ; il est construit, pas capturé.

## Oracle tshark

`tests/data/ntp_tshark_oracle.tsv` est produit par `tools/ntp_oracle.sh`
(tshark 4.6.6) sur ce dossier, `goose/iti_Sample_File_MMS_and_GOOSE.pcap`,
`iec104/iti_JavaRMI_and_IEC_Misc.pcap` et, lues en place,
`The-Ultimate-PCAP.pcapng` et `4SICS-GeekLounge-151020.pcap`.
`tests/ntp_golden.rs` y vérifie la parité champ par champ, que les 31 faux
positifs d'hier et la trame 24 de `ndpi_kcp.pcap` ne sont pas NTP, et que
les vrais datagrammes déplacés hors du port 123 sont reconnus par la sonde
aveugle (#164, #165).

## Licences

LGPL-3.0, licence du dépôt nDPI (© ntop.org ; texte :
`pcaps_exemple/LICENSES/LGPL-3.0.txt`, qui incorpore
`pcaps_exemple/LICENSES/GPL-3.0.txt`). Fichiers redistribués tels quels.

Aucun de ces fichiers n'entre dans le paquet publié sur crates.io (#104).
