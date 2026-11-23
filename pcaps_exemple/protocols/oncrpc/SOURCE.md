# Provenance

Quatre captures **ONC RPC** (RFC 5531, ports 111 et 2049 en UDP et en TCP)
versées le 2026-11-23 pour l'issue #381. Aucune n'est modifiée : seul un
préfixe est ajouté au nom, `ndpi_` ou `wireshark_` selon l'origine.

Elles sont le corpus ONC RPC du dépôt : avant elles, il n'en portait que
trois appels au portmapper sur UDP 111, restés sans réponse, dans
`../goose/iti_Sample_File_MMS_and_GOOSE.pcap`.

Contenu vérifié avec tshark 4.6.9, rendu sans état comme la crate :
réassemblage TCP et ONC RPC coupés, analyse des numéros de séquence coupée
(`tools/oncrpc_oracle.sh`, oracle `tests/data/oncrpc_tshark_oracle.tsv`).

| Fichier | Trames | Messages ONC RPC | Contenu | SHA-256 |
|---|---|---|---|---|
| `ndpi_nfsv2.pcap` | 156 | 156 | un client et un serveur NFS version 2 sur UDP, le 1999-12-03 : 3 appels au portmapper (rpcbind version 3, GETADDR), 2 à `mountd` (MNT, UMNT) sur un port annoncé, 73 à NFS (16 des 18 procédures de la version 2 : toutes sauf ROOT et WRITECACHE, obsolètes), et autant de réponses | `a7a0624f8afcdfcc2c2ae0e4990b15511da86c52570cb0fe21edfe4608f4032c` |
| `ndpi_nfsv3.pcap` | 128 | 128 | les mêmes machines une minute plus tard, en NFS version 3 : 3 appels au portmapper, 3 à `mountd` (versions 1 et 3), 58 à NFS (19 des 22 procédures), et autant de réponses | `ee65d22b22d998c1f53003619d905d77efd2aaad8371a98db54a6d924a5ec5e4` |
| `wireshark_getsetacl.cap` | 88 | 56 | un portable et son serveur sur TCP 2049, le 2010-11-06 : 22 appels à NFS version 3 (GETATTR, ACCESS, READDIRPLUS) et 6 à NFS_ACL (programme 100227 : GETACL, SETACL), et autant de réponses. Quatre réponses READDIRPLUS de 3 à 4 ko dépassent leur segment ; huit segments portent leur suite | `fcb0bb81bd8d29fcdd9840a01cfa4ce5d89a95a543e7edb1aea4f4fc643b00d1` |
| `wireshark_nfsv4.1_pnfs.cap` | 81 | 66 | un client et un serveur NFS version 4.1 (pNFS) sur TCP 2049, le 2019-04-25 : 32 appels à NFS version 4 (NULL et COMPOUND), un appel du serveur au programme de rappel du client (0x40000000) sur la même connexion, et autant de réponses | `0e89d8f550e0c5cc0adf5fdedc647999dc776056973ff11ad214cd5f97ea096a` |

Au total 453 trames et 406 messages : 396 sur les ports 111 et 2049, dix
de `mountd` sur un port que le portmapper annonce.

URL :

- nDPI, corpus de tests (`tests/cfgs/default/pcap/`, branche `dev`, commit
  `446ae50ac067dcf9e26f49d807ebc5090817cce1`) :
  `https://github.com/ntop/nDPI/blob/446ae50ac067dcf9e26f49d807ebc5090817cce1/tests/cfgs/default/pcap/`
  suivi de `nfsv2.pcap` ou `nfsv3.pcap` ;
- wiki Wireshark, page SampleCaptures :
  `https://wiki.wireshark.org/uploads/f44766777e18d287025137ceab7df83e/getsetacl.cap`
  et
  `https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/nfsv4.1_pnfs.cap`.

## Captures écartées

- `nfs_bad_stalls.cap` (wiki Wireshark, 7 038 trames) : la capture coupe
  ses trames à 96 octets, et 4 661 sont tronquées. La crate n'y lit pas la
  couche transport. Elle a servi hors dépôt à chercher des faux positifs
  dans 4 448 segments de suite de TCP 2049 : aucun.
- `rquota.pcap.gz` (wiki Wireshark) : la page la dit fabriquée.

## Ce que ces captures couvrent, et ce qu'elles ne couvrent pas

- Les **deux transports** : 284 datagrammes UDP, 122 enregistrements TCP.
- Des **appels** de cinq programmes : le portmapper (100000), NFS (100003,
  versions 2, 3 et 4), `mountd` (100005), NFS_ACL (100227) et le programme
  de rappel de NFSv4.1 (0x40000000). Deux saveurs d'authentification :
  `AUTH_NONE` et `AUTH_SYS`.
- Des **réponses acceptées, toutes en succès**. Aucun refus (`MSG_DENIED`),
  aucune erreur (`PROG_UNAVAIL`, `PROG_MISMATCH`...) : le décodeur les lit
  d'après la RFC, et ne les teste que sur des octets synthétiques, dits
  tels.
- **Aucun enregistrement en plusieurs fragments** : toutes les marques
  portent le bit du dernier fragment. Les fragments de suite ne sont
  testés que sur des octets synthétiques.
- **Aucun segment ne porte deux enregistrements.**
- `RPCSEC_GSS`, `AUTH_DH` : absents.

## Ce que ces captures montrent des limites sans état

- **Une réponse ne dit ni son programme ni sa procédure.** tshark les
  retrouve par l'appel de même identifiant ; la crate ne garde rien d'une
  trame à l'autre et ne rend que l'état de la réponse.
- **Quatre enregistrements dépassent leur segment** : la crate lit l'en-tête
  et ce que le premier segment porte des résultats, comme tshark sans
  réassemblage, et les huit segments de suite sortent `Unknown`.
- **Un segment de suite peut ressembler à une réponse.** La trame 33 de
  `wireshark_getsetacl.cap` s'ouvre au milieu d'une entrée de répertoire :
  « une entrée suit » (1), le haut d'un identifiant de fichier (0), son bas
  et la longueur d'un nom tombent où une réponse acceptée porte son type,
  son état, la saveur de son vérifieur et sa longueur. Le décodeur l'écarte
  parce que la saveur n'est pas un numéro attribué du registre IANA ; c'est
  la raison de cette vérification.
- **`mountd`, `statd`, `lockd` n'ont pas de port fixe.** Leurs dix messages
  sortent `Unknown` par défaut, et `ONC RPC` une fois le port déclaré
  (`DecodeAsProtocol::OncRpc`).

## Ces trames sont-elles réelles ?

Tous les checksums IP, UDP et TCP sont justes. Les deux captures de nDPI
viennent du même banc de 1999 : des cartes ZNYX, des TTL de 255 et de 64,
une horloge à dix millisecondes. Celles du wiki montrent un portable et son
serveur (cartes Wistron et USI, 2010), puis une machine virtuelle VMware et
un Mac (2019). Les noms de machines et les chemins exportés qu'elles
portent sont ceux des fichiers publics d'origine.

## Licences

nDPI est sous **LGPL-3.0-or-later**, © 2011-2026 ntop.org. Le wiki
Wireshark publie son contenu sous la GNU General Public License. Position
du dépôt et textes des licences : `../../LICENSES/README.md`,
`../../LICENSES/LGPL-3.0.txt`, `../../LICENSES/GPL-3.0.txt` et
`../../LICENSES/GPL-2.0.txt`.

Les fichiers sont redistribués tels quels, sans modification.
