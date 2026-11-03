# Provenance

Une capture **Valmet DNA** — le réseau de process d'un système de contrôle
distribué Metso/Valmet, protocole propriétaire sans spécification ni
dissecteur public — versée le 2026-11-03 : capture du mainteneur, anonymisée.

## `valmet-dna-multicast-anon.pcap` — capture du mainteneur, anonymisée

Capture Ethernet (pcapng, 212 s, 13 471 trames) faite le 2026-11-03 sur le
port miroir d'un réseau de process en exploitation, réduite ici aux **douze
premières secondes du trafic DNA** : 720 datagrammes UDP, tous vers le
groupe multicast `239.0.171.1` (dont les deux derniers octets sont la magie
`AB 01` du protocole) —

- **719 sur UDP 2517 → 2517** : 319 télégrammes d'état (126 octets, un
  toutes les 640 ms par nœud, 17 nœuds `0x8008` à `0x802D`) et 400 messages
  à étiquette (82 à 116 octets, 14 nœuds émetteurs, étiquettes de 10 à 44
  octets : 360 de la forme `:e:<classe>:<chemin>`, classes `di` 286, `pr` 57,
  `sn` 9, `hw` 6, `li` 2, et 40 de dix octets qui ne sont pas du texte) ;
- **1 sur UDP 4516 → 4517** : la balise de 42 octets qu'un nœud émet toutes
  les 30 s (`00 00 00 00 AB CC`, un code, un compteur, l'horloge BCD et
  l'adresse du nœud).

**Anonymisée avant dépôt** (script scapy 2.5.0, vérifié avec tshark 4.6.6) :

- adresses MAC unicast remplacées par des adresses administrées localement
  (`02:00:00:00:00:01` à `02:00:00:00:00:12`), MAC multicast conservée ;
- adresses IPv4 unicast renumérotées dans `10.0.2.0/24` par ordre
  d'apparition (17 adresses), groupe multicast conservé ; l'adresse du nœud
  recopiée dans la charge (offset 36 des télégrammes d'état, 38 de la
  balise) renumérotée de même, pour rester égale à la source IP ;
- étiquettes : le marqueur `:e:` et la classe générique à deux lettres sont
  conservés, le chemin qui suit (propre au site) est substitué lettre par
  lettre et chiffre par chiffre par une permutation aléatoire non conservée,
  longueur et délimiteurs inchangés ;
- horloges BCD (offset 42 des télégrammes d'état, 28 de la balise)
  réécrites sur l'horodatage neutre de leur trame ; horodatages rebasés au
  2020-01-01 00:00:00 UTC, écarts conservés ;
- sommes de contrôle IP et UDP recalculées (aucun `bad`) ; conversion
  pcapng → pcap, les métadonnées de capture disparaissent.

Tout le reste des charges — en-têtes, familles, longueurs, compteurs,
champs non identifiés — est **identique octet pour octet** à l'original.
SHA-256 du fichier déposé :
`92b9c7bd81f3fab9ecb5c39d895c6a8c217eac7511e6bf0a655c1455ce770ec4`.

### Ce que la capture d'origine a établi

- l'ordre des champs de l'horloge BCD (fraction en mot little-endian, puis
  secondes, minutes, heure, jour de la semaine, jour, mois, année en mot
  little-endian) : les secondes passent de 59 à 00 avec report sur les
  minutes, l'heure et le jour de la semaine sont ceux du jour de la capture,
  la fraction avance de 6 400 par télégramme ; l'horloge des nœuds était
  décalée de vingt-neuf minutes par rapport à l'heure légale, identiquement
  sur tous les nœuds ;
- les deux compteurs de 32 bits du télégramme d'état (offsets 106 et 110) :
  le second est le premier du télégramme précédent, et ils avancent de
  640 000 ± 2 000 par période de 640 ms — des microsecondes.

## Oracle

tshark n'a pas de dissecteur pour ce protocole : pas d'oracle TSV.
`tests/valmet_dna_golden.rs` vérifie la structure contre ce que la capture
porte par ailleurs — adresse du nœud égale à la source IP, groupe égal à la
destination IP, numéro de nœud égal à l'octet bas de l'identifiant, horloge
qui avance de 640 ms d'un télégramme au suivant pour chaque nœud, compteur
« précédent » égal au compteur courant du télégramme d'avant — et fige les
comptes (familles, nœuds, classes, longueurs d'étiquette).

## Licence

Capture du mainteneur : sous la licence MIT du dépôt (voir
`pcaps_exemple/LICENSES/README.md`). `pcaps_exemple/` n'entre pas dans le
paquet publié sur crates.io.
