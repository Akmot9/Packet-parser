# Provenance

Quatre captures **SIP** (RFC 3261) versées le 2026-11-19 pour l'issue #342,
avec les 21 trames SIP de `../../The-Ultimate-PCAP.pcapng`, déjà dans le
dépôt. Aucune n'est modifiée : ni anonymisée, ni tronquée. Toutes portent du
SIP sur UDP 5060 ; aucune capture SIP sur TCP réelle et redistribuable n'a
été trouvée.

Contenu vérifié avec tshark 4.6.9, réassemblage IP et TCP coupé
(`tools/sip_oracle.sh`, oracle `tests/data/sip_tshark_oracle.tsv`) :

| Fichier | Trames | Trames SIP | Contenu | Source | SHA-256 |
|---|---|---|---|---|---|
| `wireshark_aaa.pcap` | 691 | 81 | un téléphone logiciel (Nero SIPPS 2.0.51.16) chez l'opérateur danois Cybercity, le 2005-07-04 : REGISTER, 401 et 407, INVITE, CANCEL, 100, 183, 200, 403, 408, 480 ; autour, du DNS, du NetBIOS, du DHCP, une session FTP et du RTP | wiki Wireshark, page SampleCaptures, section « SIP and RTP » | `da24856f4c9943b93926ebcec9e9b28bd5b4eaf14274aad72a3f5d612cfaef2e` |
| `wireshark_FAX-Call-t38-CA-TDM-SIP-FB-1.pcap` | 7 217 | 92 | « Fax call from TDM to SIP over Mediagateway with declined T38 request, megaco H.248 », le 2008-12-05 : INVITE, OPTIONS, BYE, 100, 180, 200, 488 entre des passerelles Arcor ; MEGACO, RTP et T.38 autour | wiki Wireshark, page SampleCaptures, même section | `a14f0315bfb60252cb2b8cd678a3152f4603927c1f7814a33c1240d785be46c3` |
| `ndpi_sip_hello.pcapng` | 30 | 8 | REGISTER, 401 et 200 face à un Huawei SoftX3000 V300R011, le 2022-02-22, et 22 keep-alive `hello` sur UDP 5060 | corpus de tests nDPI, `tests/cfgs/default/pcap/sip_hello.pcapng`, commit `3a3f995adad91c1f8ab947785f893830a5ac9ef9` | `7d8d5ff7392d7c056d6c2ed7341fb5811ef473a956527919ba8aa3d3ad2a50d0` |
| `ndpi_http_on_sip_port.pcap` | 4 | 0 | **négatif** : une requête HTTP `GET` et sa réponse 403, sur TCP 5060, le 2021-04-18 | corpus de tests nDPI, `tests/cfgs/default/pcap/http_on_sip_port.pcap`, même commit | `f4a2dc4fdc582cf4fd2b3d30505e1aa6a33a5178f9b1da4314de53472a2196a5` |

URL du wiki :
`https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/<fichier>`.

## Ces trames sont-elles réelles ?

- `wireshark_aaa.pcap` : une carte Silicom (`00:e0:ed`) en `192.168.1.2`,
  TTL 128, derrière un routeur Castlenet (`00:30:54`) ; le serveur SIP
  `212.242.33.35` (Cybercity) arrive avec un TTL de 55, le serveur FTP
  `147.234.1.253` (ECI Telecom) avec un TTL de 57. Vingt-six minutes de
  trafic d'un poste Windows réel : résolutions DNS, annonces NetBIOS,
  enregistrements refusés puis acceptés, appels annulés, et des keep-alive
  de cinq espaces vers le serveur SIP.
- `wireshark_FAX-Call-t38-CA-TDM-SIP-FB-1.pcap` : huit cartes d'équipements
  d'opérateur, deux contrôleurs de session Acme Packet (`00:08:25`), deux
  Cisco (`00:18:18`, `00:16:46`), deux Italtel (`00:01:5b`) et deux HP
  (`00:11:0a`), TTL 253, 64, 62 et 61, dans les plans `10.35.x.x` et
  `10.23.x.x` ; 109 secondes d'un appel fax : 92 messages SIP, 130 MEGACO,
  4 985 paquets RTP et 2 010 T.38.
- `ndpi_sip_hello.pcapng` : un client derrière une carte Cisco (`00:05:00`),
  TTL 64, face à un serveur qui s'annonce `Huawei SoftX3000 V300R011` et
  arrive par une carte Net & Sys (`00:02:00`), TTL 253 et 252 ; le client se
  réenregistre au bout de cinq minutes, la moitié de l'`Expires: 600`
  accordé, et répète l'authentification 401 puis 200.
- `ndpi_http_on_sip_port.pcap` : deux adresses publiques, TTL 62 et 51, une
  URL `m3u8` à jeton : du trafic réel, que seul son port rend intéressant.

**Écartées** :
- `testing/btest/Traces/sip/wireshark.pcap` du corpus Zeek : ses 81 trames
  sont, octet pour octet, les trames SIP de `aaa.pcap`. L'original est
  versé ici.
- `tests/cfgs/default/pcap/sip.pcap` de nDPI : les mêmes 81 trames, avec
  31 trames RTP.
- La copie de `FAX-Call-t38-CA-TDM-SIP-FB-1.pcap` chez nDPI, 1 552 des
  7 217 trames : l'original est versé ici.
- Les traces Zeek `invalid-content-length.pcap` et
  `sip-long-request-response-paths.pcap` sont générées par le script
  `.pcap.py` publié à côté d'elles, et `sip-junk-before-request.pcap` est
  fabriquée : MAC `00:00:00:00:00:01`, `1.1.1.1` vers `1.1.1.2`. La règle du
  dépôt interdit les captures générées.

## Licences

- `wireshark_*` : le wiki Wireshark publie ses pièces jointes sous la GPL
  (<https://wiki.wireshark.org/License>). Texte dans
  `../../LICENSES/GPL-2.0.txt`.
- `ndpi_*` : nDPI est sous LGPL v3, © 2011-2026 ntop.org. Texte dans
  `../../LICENSES/LGPL-3.0.txt`, et celui de la GPL v3, qu'elle incorpore,
  dans `../../LICENSES/GPL-3.0.txt`.

Les fichiers sont redistribués tels quels, sans modification.
