# Provenance

Trois fichiers, deux origines.

## `cat048_multicast.pcap` — capture du mainteneur, anonymisée

Capture Ethernet fournie par le mainteneur (Dumpcap/Wireshark 4.6.6 sous
Windows 11, le 2026-09-30, 4,98 s) : deux émetteurs diffusent des rapports
radar **CAT 048** en multicast UDP, sur les ports 46227 → 8611 et 8612 →
8612 — pas le port 8600 que Wireshark propose par défaut, ce qui fait de
cette capture le cas « ASTERIX sans port connu » que la sonde structurelle
doit reconnaître.

**Anonymisée avant dépôt** (script scapy, vérifié avec tshark) :

- adresses MAC sources remplacées par des adresses administrées localement
  (`02:00:00:00:02:0b`, `02:00:00:00:02:12`) ;
- IP sources renumérotées dans `10.0.2.0/24`, groupes multicast dans
  `239.192.0.0/16`, adresses MAC multicast de destination recalculées en
  conséquence ;
- checksums IP et UDP recalculés (`ip.checksum.status` et
  `udp.checksum.status` : aucun `bad`) ;
- conversion pcapng → pcap : les métadonnées de capture (nom d'interface,
  machine, système, application) disparaissent ;
- cinq trames ARP étrangères au flux (un poste tiers sur un autre réseau)
  retirées.

Les **203 datagrammes UDP sont identiques octet pour octet** à l'original
(comparaison des `udp.payload`), ports compris. SHA-256 du fichier déposé :
`7c5a3c0187ad3f3e882566cc71a1dabf47d5e814d979a038f6d8615b50ff3d52`.

### Contenu (vérifié avec tshark 4.6.6, `-d udp.port==8611-8612,asterix`)

203 trames, 203 data blocks CAT 048 d'un record chacun, aucune erreur
d'analyse :

- 50 datagrammes de l'émetteur `10.0.2.11` (41 de 49 octets, 9 de 35) et
  153 de `10.0.2.18` (123 de 50 octets, 30 de 36) ;
- FSPEC `ff c3 3f 78` (19 items : 010, 140, 020, 040, 070, 090, 130, 220,
  240, 170, 080, 100, 110, 120, 230, 055, 050, 065, 060) pour les longs,
  `f7 c3 0e` (12 items, sans 070, 080, 100 ni 050/055/060/065) pour les
  courts ;
- SAC 0 / SIC 2 sur 164 records, SAC 0 / SIC 0 sur les 39 records sans
  détection (`TYP` 0) ; adresses aéronef `0x00000a` à `0x0000e6`,
  identifications numériques (`0001000`...), Mode 3/A de 0070 à 7777 ;
- les items composés I048/130 et I048/120 y ont un primary subfield vide
  (un octet `0x00`) : le cas limite « composé sans sous-champ » est donc
  couvert par une trame réelle.

## `cat_034_048.pcap` et `cat21_re.ast` — échantillons CroatiaControlLtd

Fichiers `install/sample_data/cat_034_048.pcap` et
`install/sample_data/cat21_re.ast` du dépôt
[CroatiaControlLtd/asterix](https://github.com/CroatiaControlLtd/asterix)
(décodeur ASTERIX de Croatia Control Ltd).

- Commit épinglé : `5988f544994b8776c62617bfbaf97d99644a83c9` ; URL :
  `https://raw.githubusercontent.com/CroatiaControlLtd/asterix/5988f544994b8776c62617bfbaf97d99644a83c9/install/sample_data/<fichier>`.
- Téléchargés le 2026-09-30 ; SHA-256 :
  `7f4e9a37641bfa27022ee95ba52f178e68260c1b7e83d6a0e4720a96b3a2cc3d`
  (`cat_034_048.pcap`) et
  `9979def457ecc7a8b70a6252cc59d52f60f686e6e84c32b0d83fbca6f2273f5a`
  (`cat21_re.ast`).
- Licence du dépôt source : **GPL-2.0**. Les fichiers sont redistribués tels
  quels, sans modification ni anonymisation (trafic multicast d'un réseau
  `10.17.58.0/24` vers `232.1.0.0/16` et `232.2.0.0/16`, capturé le
  2016-05-05). Un quatrième échantillon du même dossier, `cat048.raw` (48
  octets, un record CAT 048 complet, SHA-256
  `17481bd2955d046e…`), n'est pas déposé : ses octets sont embarqués en hex
  dans les tests unitaires de `src/parse/application/protocols/asterix/cat048.rs`.

### `cat_034_048.pcap` (vérifié avec tshark 4.6.6, `-d udp.port==20000-23000,asterix`)

100 trames Ethernet/IPv4/UDP, 14 conversations multicast (ports 20114 à
21174 → 21111 à 22135), aucune erreur d'analyse :

- **80 datagrammes d'un data block, 20 de deux** (CAT 048 puis CAT 034 dans
  le même datagramme) ;
- **289 data blocks CAT 048** portant **331 records** (jusqu'à trois par
  bloc) et **34 data blocks CAT 034** d'un record chacun ;
- items CAT 048 attestés : 010, 020, 040, 042, 070, 090, 110, 130 (avec
  sous-champs SRL, SRR, SAM), 140, 161, 170, 200, 220, 230, 240, 250
  (registres BDS, répétitif) ; CAT 034 : 000 (types 1 et 2), 010, 020, 030,
  041, 050, 060, 120 ;
- trafic réel : SAC 25 / SIC 11 à 13, identifications de vols commerciaux
  (`THY9TX`, `RYR22SB`, `WZZ548`...).

### `cat21_re.ast`

Flux brut de 91 octets, **deux data blocks CAT 021** (44 et 47 octets) d'un
record chacun, édition 2.x (FSPEC de sept octets, FRN 48 = RE). Items : 010,
040 (deux octets), 130, 080, 073, 074, 090, 210, 020, 016, 132, 295 (Data
Ages, primary subfield d'un à trois octets) et RE. Ce n'est pas une
capture : le collecteur du corpus ignore l'extension `.ast`, et le golden
`tests/asterix_golden.rs` lit le fichier comme un buffer. Décodé par tshark
sans erreur après encapsulation dans un pcap UDP 8600 (envelope fabriquée
pour la vérification seulement, non déposée).

## Ce que ce corpus ne contient pas

- aucune trame CAT 021 dans un datagramme réel : seul le flux brut
  ci-dessus atteste la catégorie ;
- aucune capture d'une édition 0.2x de CAT 021 (UAP d'ordre différent, non
  supporté) ;
- aucune trame sur le port 8600 ;
- aucune catégorie autre que 021, 034 et 048 (les blocs CAT 062 de
  `asterix.pcap`, du même dépôt, ne sont pas décodés par cette crate — la
  capture n'est pas déposée).
