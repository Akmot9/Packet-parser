# Provenance

Quatre captures **GOOSE** (IEC 61850-8-1) versées le 2026-10-12 pour
l'épopée #102 (Tier 2 restant), depuis le dépôt
[ITI/ICS-Security-Tools](https://github.com/ITI/ICS-Security-Tools)
(Information Trust Institute, University of Illinois), dossier
`pcaps/IEC61850/`, commit `9b826091e7ba3fbdd5997d31e116f29e09cbbb48`.
Aucune n'est modifiée : ni anonymisée, ni tronquée.

| Fichier | Trames | Contenu | Chemin d'origine | SHA-256 |
|---|---|---|---|---|
| `iti_GOOSE.pcap` | 8 | un relais GE F650 (2008) qui répète son message `gcb01` toutes les secondes, sqNum 10 à 17, huit booléens et chaînes de bits | `GOOSE/GOOSE.pcap` | `746619df546905feb6f1217ee40750004a1ca1d85fe7be1740bacdf52dca6850` |
| `iti_GOOSE_DEMO.pcap` | 1 | une trame étiquetée VLAN 10 (2011), APPID 0x2000, dix booléens | `GOOSE/GOOSE_DEMO.pcap` | `41cb05f4c7843b884ab40fb503471fba7a5f09ee1ffebc441da7cfcdab6877b7` |
| `iti_Sample_File_GOOSE.pcap` | 451 | trois IED d'un poste (2008, `AA1C1Q01A1LD0`, `Q05`, `Q07`), étiquette VLAN 0, stNum à 36 705, vingt-cinq entrées par message, les rafales de retransmission après chaque changement d'état | `GOOSE/Sample_File_GOOSE.pcap` | `7d0ab6ea4580e337e399878ee4c244c69df78c48a5310087d9636fab677c8293` |
| `iti_Sample_File_MMS_and_GOOSE.pcap` | 301 | les mêmes IED, 34 trames GOOSE sans VLAN au milieu de MMS, NTP et TCP | `Sample_File_MMS_and_GOOSE.pcap` | `50e405f9dbca335dcf457424a8e8ad04caa6fc85b81671e7ddb5ba8a99567c30` |

## Ces trames sont-elles réelles ?

- `iti_GOOSE.pcap` : une carte GE Multilin (`00:a0:f4`) vers l'adresse
  multicast `01:a0:f4:08:2f:77`, le nom de contrôle `GEDeviceF650/LLN0$GO$gcb01`
  et l'horodatage d'un relais dont l'horloge est restée au 2 janvier 2000 ;
- `iti_GOOSE_DEMO.pcap` : une carte Hewlett-Packard (`00:17:a4`), VLAN 10,
  l'adresse multicast IEC `01:0c:cd:01:00:01` — un simulateur réel ;
- `iti_Sample_File_GOOSE.pcap` et `iti_Sample_File_MMS_and_GOOSE.pcap` :
  trois émetteurs `0a:bb:fe:10:c9:0x` (bloc local d'un constructeur de
  protection), un quatrième `00:00:23:06:30:fe` (ABB), des numéros d'état
  élevés et des séquences qui reprennent à zéro à chaque changement :
  un poste réel en 2008.

Aucune capture **Sampled Values** (IEC 61850-9-2, EtherType 0x88BA)
redistribuable n'a été trouvée : le dépôt `mgadelha/Sampled_Values` que cite
le wiki Wireshark n'a pas de licence ; `4SICS-GeekLounge-151020.pcap` et
`The-Ultimate-PCAP.pcapng` n'en portent pas (vérifié avec tshark).

## Oracle tshark

`tests/data/goose_tshark_oracle.tsv` est produit par `tools/goose_oracle.sh`
(tshark 4.6.6) : une trame par ligne, VLAN, APPID, longueur, réservés,
gocbRef, timeAllowedtoLive, datSet, goID, stNum, sqNum, simulation,
confRev, ndsCom, numDatSetEntries, nombre et codes des éléments de allData.
`tests/goose_golden.rs` rejoue l'oracle (#102) : parité sur les 494 trames.

Le trafic IPv4 du poste dans `iti_Sample_File_MMS_and_GOOSE.pcap` sert aussi
d'oracle **NTP** : `tests/data/ntp_tshark_oracle.tsv` est produit par
`tools/ntp_oracle.sh` (tshark 4.6.6), un datagramme NTP par ligne (52 ici :
requêtes et réponses, v4 et v1, plus l'échange de
`protocols/iec104/iti_JavaRMI_and_IEC_Misc.pcap`), rejoué par
`tests/ntp_golden.rs` (#161, #162).

## Licence

CC-BY-4.0, licence du dépôt ITI/ICS-Security-Tools (texte :
`pcaps_exemple/LICENSES/CC-BY-4.0.txt`) — attribution conservée ici (#104).
Aucun de ces fichiers n'entre dans le paquet publié sur crates.io.
