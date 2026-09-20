# Provenance

Les noms de fichiers correspondent aux samples publics du **wiki Wireshark**
(page S7comm, <https://wiki.wireshark.org/S7comm>) : sessions libnodave demo,
lecture d'état PLC, téléchargement de bloc DB1, etc.

- Provenance exacte à confirmer par Cyprien (téléchargement wiki Wireshark ou
  capture locale équivalente), avec la date de récupération.

| Fichier | Contenu |
|---|---|
| `s7comm_downloading_block_db1.pcap` | téléchargement du bloc DB1 vers le PLC |
| `s7comm_program_blocklist_onlineview.pcap` | liste des blocs programme (vue en ligne) |
| `s7comm_reading_plc_status.pcap` | lecture de l'état du PLC |
| `s7comm_reading_setting_plc_time.pcap` | lecture/réglage de l'horloge PLC |
| `s7comm_varservice_libnodavedemo.pcap` | services variables via libnodave (démo) |
| `s7comm_varservice_libnodavedemo_bench.pcap` | idem, session de bench |

## `s7comm_plus.pcap` (S7CommPlus, issue #93)

Provient du corpus de tests du projet [nDPI](https://github.com/ntop/nDPI)
(ntop), fichier `tests/cfgs/default/pcap/s7comm-plus.pcap`, renommé pour
suivre la convention du dossier.

- URL exacte (commit épinglé) :
  <https://raw.githubusercontent.com/ntop/nDPI/359f1a5638810c9990106ff0b036cc9064aa3923/tests/cfgs/default/pcap/s7comm-plus.pcap>
- Téléchargé le 2026-09-20 ; SHA-256 :
  `b38ccaf183673619e7f5d69476293a01da743076a281c96e949f0f29a42d1650`.
- Licence du dépôt source : LGPL-3.0 (licence de nDPI ; redistribué tel
  quel, trafic de labo sur 192.168.25.0/24).

### Contenu (vérifié avec tshark 4.6.6)

79 trames, une seule conversation TCP `192.168.25.177:53162` ↔
`192.168.25.131:102` (ISO-TSAP) :

- **36 trames S7CommPlus** — TPKT + COTP DT puis protocol id `0x72` : trois
  de type PDU `0x01` (Connect) et trente-trois de type `0x02` (Data) ;
- **aucune trame S7Comm** (`0x32`) : `tshark -Y s7comm` rend zéro.

C'est la première trame `0x72` réelle du dépôt. Elle remplace la fixture
synthétique qui couvrait seule
`S7CommPacket::detect_protocol_version`.

### Deux pièges de vérification

**`tshark -Y s7comm-plus` rend zéro sur cette capture** alors qu'elle en est
pleine : le filtre ne matche pas ce protocole. C'est cette méthode qui avait
conduit à conclure, à tort, qu'aucune trame `0x72` n'existait. Pour en
chercher, lire les octets :

```sh
tshark -r s7comm_plus.pcap -T fields -e tcp.payload | grep -cE '^0300[0-9a-f]{4}02f08072'
```

**La capture porte 26 retransmissions TCP**, dont 25 rejouent un TPKT
valide. tshark suit les numéros de séquence et ne redissèque pas un segment
déjà vu — il en compte 38 en COTP, là où ce parseur, sans état, en étiquette
63 : `38 + 25 = 63`. Douze de ces retransmissions portent du `0x72`, d'où 24
originaux et 12 rejeux parmi les 36 trames S7CommPlus.
