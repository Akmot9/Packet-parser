# Provenance

Huit captures de **PTP** (IEEE 1588), versées le 2026-10-08 pour l'issue
#121 (épopée #125, rapport `docs/protocoles-defense.md`). Aucune n'est
modifiée : ni anonymisée, ni tronquée. Elles viennent de huit équipements ou
profils différents, en UDP 319/320 comme en couche 2 (EtherType `0x88F7`).

Contenu vérifié avec tshark 4.6.6 (`-Y ptp`) : 3 330 trames PTP, dont 107 en
couche 2. Deux d'entre elles sont des ICMP qui citent un datagramme PTP
(`wireshark_6126_nodeb_startup.pcap`) : il reste 3 328 messages PTP propres.

| Fichier | Trames | Équipement / profil | Origine | SHA-256 |
|---|---|---|---|---|
| `ptpv2.pcap` | 39 | Hirschmann, PTPv2, UDP (25) et couche 2 (14) | wiki Wireshark | `2160864200325c734990264d4b5e92670e12a98f989db97edce95762b958cd6f` |
| `PTP_sync.pcap` | 4 | Fujitsu Siemens, **PTPv1** | wiki Wireshark | `5738c421ea155ea9261345798f5ebbb13e3d3547367221439d6aa9f9573f18aa` |
| `ndpi_ptpv2.pcap` | 14 | Symmetricom, PTPv2 sur **IPv6** | corpus de tests nDPI | `e658246863c47fa16ea876ae4502223ef40240a090f43f3f25a04c0c314cc12f` |
| `wireshark_6126_nodeb_startup.pcap` | 3 179 | NodeB Nokia / Alcatel-Lucent, profil télécom | [#6126](https://gitlab.com/wireshark/wireshark/-/issues/6126) | `91fc608a39e81706d728b05ab32e5885d92f5275ecb61dca46b19fa11e007fdf` |
| `wireshark_14578_white_rabbit.pcap` | 85 | Seven Solutions, White Rabbit, couche 2 | [#14578](https://gitlab.com/wireshark/wireshark/-/issues/14578) | `6770868e120427febb2c29e170fdea38f93616564ee207f9a9a800a3cd8df709` |
| `wireshark_7694_c37_238.pcap` | 1 | SEL, profil électrique IEEE C37.238, couche 2 | [#7694](https://gitlab.com/wireshark/wireshark/-/issues/7694) | `165e182fe36bec08abdae6c33a89566ae0e84528d4d8f1b242390c93065ce0de` |
| `wireshark_12264_st2059_mgt.pcap` | 1 | Meinberg, management SMPTE ST 2059-2 | [#12264](https://gitlab.com/wireshark/wireshark/-/issues/12264) | `06e107d88491b9dc1242f3dcbea6173fe37f826310891880827dca76f7f52c69` |
| `wireshark_4761_802_1as.pcap` | 7 | Marvell, IEEE 802.1AS (gPTP), couche 2 | [#4761](https://gitlab.com/wireshark/wireshark/-/issues/4761) | `2e5139ffe905cc4d5aa62b8ec22efa9ac26b61d425207f3db22fcfc7ec520a45` |

## Détail

- **`ptpv2.pcap`** — capturé le 2007-08-08 ; même fichier que la pièce
  jointe de l'issue Wireshark #1733. URL
  `https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/ptpv2.pcap`.
- **`PTP_sync.pcap`** — quatre messages PTPv1 (2006-11-15) vers
  `224.0.1.129:319/320`. URL
  `https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/PTP_sync.pcap`.
- **`ndpi_ptpv2.pcap`** — fichier `ptpv2.pcap` du corpus nDPI (commit épinglé
  `6ac6e1ec2547d23e4f1b60c4f8a81698dff5895f`, chemin
  `tests/cfgs/default/pcap/ptpv2.pcap`), renommé pour ne pas entrer en
  collision avec celui du wiki ; capturé le 2011-09-16.
- **`wireshark_6126_nodeb_startup.pcap`** — démarrage d'une NodeB (station de
  base 3G), 2011-07-07 : 933 Sync, 829 Delay_Req, 829 Delay_Resp, 562
  Announce, 26 Signaling. Ses 829 Delay_Req étaient étiquetés SRVLOC par la
  crate : faux positif corrigé par #117.
- **`wireshark_14578_white_rabbit.pcap`** — deux équipements Seven Solutions.
  Horodatages au 1970-01-01, mais intervalles réguliers et réalistes sur
  16,8 s : vraisemblablement une capture prise sur un équipement sans horloge
  temps réel (hypothèse, non documentée par l'issue).
- **`wireshark_7694_c37_238.pcap`** et **`wireshark_12264_st2059_mgt.pcap`** —
  une trame chacune, portant les TLV propres à leur profil.
- **`wireshark_4761_802_1as.pcap`** — 802.1AS d'avant la norme finale (2010) ;
  tshark déclare malformé le seul message Signaling.

Fichiers d'origine des pièces jointes : `1588_on_nodeb3_startup.pcap`
(#6126), `wr_transmit2.pcap` (#14578), `IEEE_C37.238_TLV.pcap` (#7694),
`st2059-2_mgt_message.pcap` (#12264), `ASPackets.pcap` (#4761).

## Licences

- captures de la wiki Wireshark : licence de la wiki (GNU GPL v2+, en pied de
  page de <https://wiki.wireshark.org>) ;
- `ndpi_ptpv2.pcap` : LGPL-3.0, licence du dépôt nDPI ;
- pièces jointes du tracker Wireshark : aucune licence explicite, publiques
  depuis leur dépôt.

Aucun de ces fichiers n'entre dans le paquet publié sur crates.io. Le texte
des licences n'accompagne pas encore les captures : voir #104.
