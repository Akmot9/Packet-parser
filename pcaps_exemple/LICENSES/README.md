# Licences des captures redistribuées

Les captures de `pcaps_exemple/` viennent pour la plupart de corpus publics,
et nommer leur licence ne suffit pas à s'y conformer : toute redistribution
doit conserver la notice de copyright et joindre le texte de la licence (BSD,
MIT, CC-BY), ou le texte complet et la mention des modifications (GPL, LGPL).
Ce dossier réunit ces textes, une copie par licence ; chaque `SOURCE.md`
dit lequel couvre ses fichiers et ce qu'il impose (#104).

Aucun de ces fichiers n'entre dans le paquet publié sur crates.io :
`pcaps_exemple/` est hors de la liste `include` de `Cargo.toml`
(`cargo package --list` ne le cite pas). L'obligation porte sur le dépôt git.

## Les textes

| Fichier | Licence | Texte repris de | SHA-256 | Titulaires | Dossiers couverts |
|---|---|---|---|---|---|
| `LGPL-3.0.txt` | GNU LGPL v3 | <https://www.gnu.org/licenses/lgpl-3.0.txt> | `e3a994d82e644b03a792a930f574002658412f62407f5fee083f2555c5f23118` | nDPI, © 2011-2026 ntop.org | `umas`, `opcua`, `giop` (`corba.pcap`), `s7comm` (`s7comm_plus.pcap`), `ptp` (`ndpi_ptpv2.pcap`), `rtps` (`rtps.pcap`), `ipsec` (`ipsec_isakmp_esp.pcap`) |
| `GPL-3.0.txt` | GNU GPL v3 | <https://www.gnu.org/licenses/gpl-3.0.txt> | `3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986` | miguelob/ICS-Hacking ; incorporée par la LGPL v3 | `profinet` (`miguelob_*.pcapng`), et les fichiers LGPL ci-dessus |
| `GPL-2.0.txt` | GNU GPL v2 (« ou ultérieure » pour Wireshark) | <https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt> | `edaef632cbb643e4e7a221717a6c441a4c1a7c918e6e4d56debc3d8739b233f6` | Croatia Control Ltd (dépôt `asterix`) ; projet Wireshark (dépôt et wiki) | `asterix` (`cat_034_048.pcap`, `cat21_re.ast`, `cat_062_065.pcap`) ; dépôt Wireshark : `dis` (`dis_voice_sample.pcap`), `tls` (`tls12-dsb.pcapng`) ; wiki Wireshark : `openvpn`, `ptp` (`ptpv2.pcap`, `PTP_sync.pcap`), `rtps` (`RTPS_Discovery.pcapng`), `ipsec`, `dis` (`DIS_signal_and_transmitter.pcapng`), `stanag5066`, et les extraits `ftp`, `smtp`, `nntp`, `mdns_llmnr_ssdp` ; `s7comm` si l'origine wiki se confirme |
| `CC-BY-4.0.txt` | Creative Commons Attribution 4.0 | <https://creativecommons.org/licenses/by/4.0/legalcode.txt> | `9ba9550ad48438d0836ddab3da480b3b69ffa0aac7b7878b5a0039e7ab429411` | ITI/ICS-Security-Tools (Information Trust Institute, University of Illinois) | `ethernet_ip`, `modbus` (`MODBUS-TestDataPart2.pcap`), `profinet` (`iti_*.pcap`) |
| `BSD-3-Clause-CISA.txt` | BSD 3-Clause | `LICENSE.txt` de cisagov/icsnpp-profinet-io-cm | `73a28a4fb94ee6149eb201a4fa2b8cbd228252f4cfb1df912cc27795c7d016a1` | Battelle Energy Alliance, LLC (2024) | `profinet` (`cisagov_*.pcap`) |
| `MIT-foxglove.txt` | MIT | `LICENSE` de foxglove/rtps | `da11235665c17d4c1634072dae92b8ba1b38d6fdde2ccf19a6bbede33253f58d` | Foxglove Technologies Inc | `rtps` (`talker-listener-rtps.pcapng`) |
| `BSD-3-Clause-Zeek.txt` | BSD 3-Clause | `COPYING` de zeek/zeek (copie de `../tunnels/gtp_u/LICENSE-ZEEK.txt`, versé par #97 avant ce dossier) | `1f984adb6b5cd93d5035c2a87c2df5f38922649fbea90c7bd79ff321d17333aa` | Regents of the University of California, LBNL, ICSI | `tunnels/gtp_u`, `postgresql` |

Les textes GNU et Creative Commons sont les textes canoniques de leurs
éditeurs, à l'URL indiquée ; ceux de la CISA et de foxglove sont les
fichiers des dépôts, parce qu'ils portent la notice de copyright que ces
licences obligent à reproduire.

## Ce que chaque licence impose ici

- **LGPL v3 et GPL v3** (nDPI, miguelob) : conserver les notices, joindre le
  texte de la licence et signaler toute modification (GPL v3 §4 et §5, que
  la LGPL v3 reprend). Les captures sont redistribuées **telles quelles**,
  sans modification ni anonymisation ; une capture n'est liée à aucun
  programme, seule la redistribution du fichier compte.
- **GPL v2** (Croatia Control, Wireshark) : même logique, §1 et §2. Les
  fichiers de Croatia Control, du dépôt Wireshark et la plupart des samples
  du wiki sont repris tels quels ; les extraits `ftp`, `smtp`, `nntp` et
  `mdns_llmnr_ssdp` sont **modifiés** (trames extraites avec `editcap` le
  2026-08-03, authentifications et corps de messages retirés), et leur
  `SOURCE.md` tient lieu de la mention de modification que la licence exige.
- **CC-BY 4.0** (ITI) : attribution obligatoire, citer *ITI/ICS-Security-Tools
  — ICS PCAPs, developed as a community asset*
  (<https://github.com/ITI/ICS-Security-Tools>), et indiquer les
  modifications : aucune.
- **BSD 3-Clause** (CISA, Zeek) et **MIT** (foxglove) : reproduire la notice
  de copyright, la liste des conditions et le disclaimer, ce que le fichier
  copié fait.

## Captures sans texte de licence

- **Pièces jointes du tracker Wireshark** (`wireshark_<issue>_*.pcap*` dans
  `asterix`, `dis`, `giop`, `ptp`, `rtps`, `stanag5066`) : contributions
  d'utilisateurs à des rapports de bug publics, sans licence explicite. Le
  projet Wireshark ne les couvre pas de sa GPL, et le statut d'une pièce
  jointe n'est pas celui du projet qui l'héberge. Position du dépôt : les
  redistribuer telles quelles comme données de test publiques, avec l'issue
  d'origine, le nom du fichier joint et son SHA-256 dans chaque `SOURCE.md`,
  et retirer toute capture dont l'auteur le demanderait.
- **Captures de Chris Sanders** (`arp`, `dhcp`, `dns`, `icmp`, `ieee80211`,
  `ip`, `tcp`) : « free to use », à condition de citer l'auteur — voir les
  crédits du [README du corpus](../README.md).
- **4SICS** (`4SICS-GeekLounge-151020.pcap`) : capture Netresec du labo ICS de
  4SICS 2015, sans licence formelle ; la page demande de **créditer
  CS3Sthlm** et de lier <https://www.netresec.com/?page=PCAP4SICS>.
- **The Ultimate PCAP** (`The-Ultimate-PCAP.pcapng`, et ses extraits
  `capwap-only.pcap`, `capwap-only.pcapng`, `capwap-association-valid.pcapng`) :
  Johannes Weber, <https://weberblog.net/the-ultimate-pcap/>, aucune licence
  énoncée, publié pour téléchargement libre ; cité.
- **Practical Packet Analysis** (`ftp.pcap`) : Chris Sanders, fichiers
  d'accompagnement du livre (No Starch Press) ; « free to use », citer
  l'origine.
- **`protocols/modbus/Modbus.pcap`** : copie de la collection
  automayt/ICS-pcap, sans licence et sans origine nommée ; aucune licence
  attribuable tant que l'origine première n'est pas établie.
- **Captures du mainteneur** (`asterix/cat048_multicast.pcap`, `mqtt`,
  `tls/dump.pcapng`, le labo omniORB de `giop`, `vlan`, `tunnels/vxlan`,
  `tunnels/geneve`, `sll.pcap` et `capture_sll2.pcap` à la racine) : sous la
  licence MIT du dépôt.
- **Provenance à confirmer** : `vlan0--packet-capture CAPWAP…cap` (capture
  tierce de 2016, voir le `SOURCE.md` de la racine) ; l'origine première de
  `Modbus.pcap` ci-dessus. Les fichiers fabriqués `capwap-multi-wtp.pcap` et
  `protocols/http/simple-http-request.pcap` ont été retirés le 2026-10-12.
