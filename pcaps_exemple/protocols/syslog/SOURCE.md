# Provenance

Deux captures **syslog** (RFC 3164, RFC 5424, RFC 6587) versées le
2026-11-23 pour l'issue #374. Elles viennent du corpus de tests de nDPI
(`tests/cfgs/default/pcap/`, branche `dev`, commit
`446ae50ac067dcf9e26f49d807ebc5090817cce1`). Aucune n'est modifiée : seul le
préfixe `ndpi_` est ajouté au nom.

Elles complètent `../../The-Ultimate-PCAP.pcapng`, déjà dans le dépôt, qui
porte 250 charges syslog : 12 datagrammes sur UDP 514 (un routeur Cisco, un
pare-feu NetScreen), 147 segments sur TCP 514 (rsyslog en messages terminés
par LF, FortiGate en comptage d'octets) et 91 sur TCP 601 (Palo Alto). Ce
qu'elles apportent et qu'il n'a pas :

- le format de la **RFC 5424** (version `1` et en-tête de cinq champs), sur
  UDP et sur TCP ;
- des segments TCP de **plusieurs messages** terminés par LF, et un segment
  de suite ;
- une douzaine d'autres émetteurs sur UDP 514, sous VLAN, PPPoE et tunnel
  IPv6 sur IPv4.

Contenu vérifié avec tshark 4.6.9, rendu sans état comme la crate
(`tools/syslog_oracle.sh`, oracle `tests/data/syslog_tshark_oracle.tsv`).

| Fichier | Trames | Charges syslog | Contenu | SHA-256 |
|---|---|---|---|---|
| `ndpi_syslog.pcap` | 94 | 84 | 83 datagrammes sur UDP 514, de 2013 à 2022 : commutateurs, routeurs Cisco, pare-feu NetScreen et pfSense (Suricata, RFC 5424), box d'opérateur, `snmpd`, noyau Linux ; un message de la RFC 5424 sur TCP 52173 (trame 81) | `f53a4f5de002f385107fb0077d898107ce041e5e11105b53ea051b57156d1c4b` |
| `ndpi_rsh-syslog-false-positive.pcap` | 8 | 7 | un serveur OpenLDAP qui journalise sur TCP 514, le 2016-05-24 : sept segments d'un à six messages terminés par LF, puis un segment de suite | `b3bfa76f9730625bbdcd22bc1b3dd401c14bdd246865021c595d53594ae607c9` |

URL : `https://github.com/ntop/nDPI/blob/446ae50ac067dcf9e26f49d807ebc5090817cce1/tests/cfgs/default/pcap/`
suivi du nom d'origine (`syslog.pcap`, `rsh-syslog-false-positive.pcap`).

## Ce que ces captures montrent des limites

- **TCP 514 est aussi le port de `rsh`.** tshark y lit du RSH, et nDPI
  s'y trompait : c'est le sens du nom `rsh-syslog-false-positive`. La
  crate juge le contenu : un segment qui s'ouvre par une priorité est du
  syslog.
- **Un segment de suite** : la trame 8 de
  `ndpi_rsh-syslog-false-positive.pcap` commence au milieu d'un message
  (`RESULT tag=101 …`), puis en porte trois entiers. Elle sort `Unknown` :
  il faut l'état du flux pour savoir que ses premiers octets finissent un
  message.
- **Deux trames coupées par la capture** : les trames 6 et 7 de la même
  capture ne gardent que 1 010 octets, moins que ce qu'annonce leur en-tête
  IPv4. La crate s'arrête à la couche réseau ; tshark lit ce qui reste.
- **Un port hors standard** : le message de la trame 81 de
  `ndpi_syslog.pcap`, sur TCP 52173, n'est nommé qu'une fois ce port
  déclaré par Decode As.
- **Plusieurs messages par segment** : tshark ne sépare que les trames à
  comptage d'octets ; d'un segment de messages terminés par LF, il ne lit
  que le premier. La crate les sépare.

## Ces trames sont-elles réelles ?

- `ndpi_syslog.pcap` est un **assemblage** : des datagrammes pris sur une
  douzaine de réseaux, de 2013 à 2022, réunis en un fichier (deux trames
  d'une box sans horloge sont datées de 1970). Les messages sont ceux
  d'équipements réels, dans leurs formats propres ; tous les checksums UDP
  et TCP calculables sont justes. Une partie des adresses MAC a été
  réécrite (`00:07:00:00:00:06`, `00:08:00:e6:87:1c`), et les routeurs
  Cisco sont des instances virtuelles (`aa:bb:cc`). Six trames (26 à 31)
  sont celles du pare-feu NetScreen de `The-Ultimate-PCAP.pcapng`.
- `ndpi_rsh-syslog-false-positive.pcap` : huit segments d'une connexion,
  en IP brut, sur 82 millisecondes ; les checksums TCP des six trames
  entières sont justes.

## Licences

nDPI est distribué sous LGPL-3.0 (© 2011-2026 ntop.org). Position du dépôt
et texte de la licence : `../../LICENSES/README.md`,
`../../LICENSES/LGPL-3.0.txt` et `../../LICENSES/GPL-3.0.txt`.

Les fichiers sont redistribués tels quels, sans modification.
