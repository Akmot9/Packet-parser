# Provenance

Sept captures de **PROFINET** (IEC 61158-6-10, EtherType `0x8892`), versées
le 2026-10-12 pour l'issue #133 : jusque-là le dépôt n'avait aucune trame
PROFINET réelle, et le validateur DCP de la couche internet n'avait jamais
rencontré autre chose que du DCP. Aucune n'est modifiée : ni anonymisée, ni
tronquée. Le trafic est du labo (adresses privées, pas de données sensibles).

Contenu vérifié avec tshark 4.6.6 (`-Y pn_rt`) : 2 685 trames, dont **232
PN-RT** — DCP Identify et Set, trafic cyclique RT_CLASS_1 (`0x8000`,
`0x8010`) et `0xC000`/`0xC002`, alarmes `0xFE01`, PTCP `0xFF40`,
fragments `0xFF85`–`0xFF8D` — plus 1 000 datagrammes DCE/RPC du
PROFINET IO-CM sur UDP 34964, que le dispatch ne nomme pas.

| Fichier | Trames | PN-RT | Contenu PROFINET | Origine | SHA-256 |
|---|---|---|---|---|---|
| `cisagov_profinet_io_cm_mixed_1.pcap` | 1 635 | 164 | 19 DCP Identify (18 req `0xFEFE`, 1 resp `0xFEFF`), 102 cycliques `0xC000`/`0xC002`, 41 PTCP `0xFF40`, 2 alarmes `0xFE01` ; 38 DCE/RPC IO-CM ; bruit Windows (NBNS, LLMNR, SSDP, DHCP, Dropbox) et 201 LLDP | CISA, [icsnpp-profinet-io-cm](https://github.com/cisagov/icsnpp-profinet-io-cm) | `e03c1937c33e95922e899d1e65a858292b61ca4a24040906de2c87935ba05f84` |
| `cisagov_profinet_io_cm.pcap` | 960 | 10 | 10 fragments `0xFF85`–`0xFF8D` ; 950 DCE/RPC IO-CM (connect, read, write, control, release) | idem | `20ad38583549a2444f2eedcf6eb8b222794dced6982ba4999afa05d5006db4c1` |
| `iti_ChangeIPUsingDCP.pcap` | 6 | 4 | DCP Identify req/resp puis **Set** req/resp (`0xFEFD`, bloc IP) ; 2 ARP | wiki Wireshark, page PROFINET/DCP, via [ITI/ICS-Security-Tools](https://github.com/ITI/ICS-Security-Tools) | `aaba0d1492ca2cae77dcac3ae311bcc5c63b72e79b2a8fd04389c0f9d1d01c98` |
| `iti_PROFINET-RT.pcap` | 14 | 14 | 14 DCP Identify requests multicast | [CloudShark 76038eaa4a3b](https://www.cloudshark.org/captures/76038eaa4a3b), via ITI | `55ceb6e5c1ca1490c24d51d23084a554cecb95bdd9e9ae82e04b97c237798bbb` |
| `iti_profinet-wireshark-bug.pcap` | 4 | 4 | les mêmes Identify + Set, **taguées VLAN** | pièce jointe d'un rapport de bug Wireshark, via ITI | `ebb4ac34bda04ce0f3acadb947ff9be14fe07b0bb17a3bbbfff17223288caea5` |
| `miguelob_pn.pcapng` | 48 | 18 | 10 cycliques RT_CLASS_1 `0x8000`/`0x8010` taguées VLAN, 4 alarmes `0xFE01`, 4 DCP ; 12 DCE/RPC IO-CM, LLDP, mDNS | labo de l'auteur de [miguelob/ICS-Hacking](https://github.com/miguelob/ICS-Hacking) (automate TIA Portal) | `54d6f995cfd460c8e9307b1b59798e74c9c14dba532f438e5f3efd7eb91bb3a1` |
| `miguelob_pn_dcp.pcapng` | 18 | 18 | 15 Identify responses, 3 Identify requests (dont une trame sortante de 32 octets, non bourrée, plus courte que sa longueur DCP) | idem | `8b22b084b89e38605611ad24250488e2d2cc832b5f3fa55d4c7ecd32a9c72aa4` |

## Sources et licences

- **cisagov/icsnpp-profinet-io-cm** — traces de test du parseur Zeek
  ICSNPP de la CISA (INL), `testing/traces/`. Licence BSD-3-Clause.
  Commit épinglé `833a78c04c2f623f6afcda6d3dc72cc288cb11d8` (2026-05-14) :
  <https://raw.githubusercontent.com/cisagov/icsnpp-profinet-io-cm/833a78c04c2f623f6afcda6d3dc72cc288cb11d8/testing/traces/profinet_io_cm_mixed_1.pcap>
  et `…/profinet_io_cm.pcap`. Le dépôt ne documente pas l'origine des
  traces ; `profinet_io_cm_mixed_2.pcapng` est le même trafic en pcapng et
  n'est pas repris.
- **ITI/ICS-Security-Tools** — `pcaps/profinet/`, collection « captures
  PROFINET du monde réel » de l'Information Trust Institute (UIUC), licence
  CC-BY-4.0 (citer ITI). Commit épinglé
  `9b826091e7ba3fbdd5997d31e116f29e09cbbb48` (2025-04-15) :
  <https://raw.githubusercontent.com/ITI/ICS-Security-Tools/9b826091e7ba3fbdd5997d31e116f29e09cbbb48/pcaps/profinet/PROFINET-RT-DCP/ChangeIPUsingDCP.pcap>,
  `…/PROFINET-RT-DCP/PROFINET-RT.pcap`, `…/profinet-wireshark-bug.pcap`.
  Le RTF joint par ITI cite la page wiki Wireshark PROFINET/DCP comme
  origine de `ChangeIPUsingDCP.pcap`, et son `README.txt` la capture
  CloudShark pour `PROFINET-RT.pcap`. Les deux autres fichiers du dossier
  ne sont pas repris : `profinet.pcap` (2 trames DCE/RPC, identique à
  `profinet-io-le.pcap` du corpus nDPI) et `Profinet_Failed.pcap` (aucune
  trame PN-RT).
- **miguelob/ICS-Hacking** — `Profinet & Profibus/pcaps/`, captures du labo
  de l'auteur (Miguel), dépôt sous **GPL-3.0** : les fichiers sont
  redistribués tels quels avec cette mention ; ils ne sont liés à aucun
  binaire. Commit épinglé `e9a3b212395e857df086ed74930f84053c3a2ad0`
  (2022-10-31) :
  <https://raw.githubusercontent.com/miguelob/ICS-Hacking/e9a3b212395e857df086ed74930f84053c3a2ad0/Profinet%20%26%20Profibus/pcaps/pn.pcapng>
  et `…/pn_dcp.pcapng`. Ce sont les seules trames **RT_CLASS_1** (`0x8000`)
  du corpus ; `pn_dcp_full.pcapng` (1 064 PTCP, 2,9 Mo) et
  `camara.pcapng` (66 cycliques) ne sont pas repris.

Écartés : `EmreEkin/ICS-Pcaps` (copies md5-identiques des fichiers ITI,
sans licence), `f0rw4rd/oida` (copies ITI/CISA/nDPI),
`StefRoo/ICSMitreAnomalyParser` (`PNIO-CM_meting.pcapng`, 2 276 cycliques
VLAN + 100 PTCP, sans licence), `automayt/ICS-pcap` (pas de PROFINET).
Téléchargements du 2026-10-12.

## Ce que la crate en fait aujourd'hui (11.5.0)

`tests/profinet_corpus.rs` fige l'état de départ de #133 sur les 232 trames
PN-RT : 103 ressortent `internet = Profinet`, **129 en `corrupted`**,
presque toutes saines :

- 67 `UnknownFrameId` : 10 RT_CLASS_1, 41 PTCP, 6 alarmes, 10 fragments ;
- 56 `InvalidDcpBlockLength` : les cycliques `0xC000`/`0xC002` de
  `mixed_1` dont les données lues comme un bloc DCP ne tiennent pas dans
  la trame (les 46 autres passent, avec des champs DCP qui sont du bruit) ;
- 5 `InvalidNameOfStation` : 2 DCP de `ChangeIPUsingDCP` (le Set request
  dont le premier bloc est le bloc IP, l'Identify response dont le premier
  bloc est DeviceOptions) et 3 Identify responses de `pn_dcp` — le
  validateur lit le *premier* bloc comme le NameOfStation ;
- 1 `PacketTooShort` : la trame sortante de 32 octets de `pn_dcp`, dont le
  champ DCPDataLength annonce 4 octets de blocs absents de la capture.
