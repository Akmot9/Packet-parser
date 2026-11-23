# Provenance

Une capture du **service de datagrammes NetBIOS** (NBDS, RFC 1002 §4.4, UDP
138) versée le 2026-11-23 pour l'issue #377. Elle vient du wiki Wireshark,
page SampleCaptures, section « Browser Elections ». Elle n'est pas
modifiée : ni anonymisée, ni tronquée.

Le dépôt portait déjà 14 datagrammes NBDS, épars dans quatre captures
versées pour d'autres protocoles (`sip/wireshark_aaa.pcap`,
`skinny/wireshark_10262_7911_CUCM_registration_RFC2833.pcapng`,
`profinet/cisagov_profinet_io_cm_mixed_1.pcap`,
`iec104/iti_090813_diverse.pcap`) : des annonces d'hôtes du service Browser.
Celle-ci apporte le volume, d'autres messages du service Browser (élections,
annonces de domaine, demandes de liste) et le nom de groupe
`\x01\x02__MSBROWSE__\x02<01>`, fait d'octets non imprimables.

Contenu vérifié avec tshark 4.6.9 (`tools/nbds_oracle.sh`, oracle
`tests/data/nbds_tshark_oracle.tsv`).

| Fichier | Trames | Datagrammes NBDS | Contenu | SHA-256 |
|---|---|---|---|---|
| `smb-browser-elections.pcapng` | 223 | 165 | deux postes Windows d'un même réseau local, le 2005-03-29, sur 36 minutes : 92 demandes d'élection, 39 annonces (maître local, hôte), 28 demandes d'annonce, 3 annonces de domaine, 3 demandes de liste de secours ; 42 trames NBNS (UDP 137) et 16 ARP | `6a02c9cdcca22c91a1b04cf1be1caefe1dbada592111f36ca8bf1fd682b821bc` |

URL : `https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/smb-browser-elections.pcapng`

Le wiki la décrit ainsi : un poste dont le pare-feu bloque UDP 138 en
entrée ne trouve pas de maître explorateur et relance sans cesse des
élections.

## Ce que cette capture couvre, et ce qu'elle ne couvre pas

- Tous les datagrammes sont de **type 0x11** (datagramme de groupe),
  drapeaux 0x02 : nœud B, premier et seul fragment. Les quatre autres
  captures ajoutent les drapeaux 0x0e. Les données utilisateur sont du SMB
  sur mailslot (`\MAILSLOT\BROWSE`), que la crate ne décode pas.
- **Aucune capture publique trouvée** ne porte les autres types de la RFC :
  datagramme direct à un nom unique (0x10), diffusion (0x12), erreur (0x13),
  requêtes au serveur de datagrammes (0x14 à 0x16). Ils sont testés sur des
  octets synthétiques, dits tels dans les tests.
- Aucun datagramme n'est fragmenté.

## Ces trames sont-elles réelles ?

Deux cartes ASUSTek (`00:0c:6e`, `00:0e:a6`), TTL 128, adresses
`192.168.123.1` et `192.168.123.2`. Tous les checksums UDP sont justes. Les
identifiants de datagramme croissent poste par poste, et les élections
suivent les délais du protocole.

## Licences

Le wiki Wireshark publie son contenu sous la GNU General Public License,
sans numéro de version (<https://wiki.wireshark.org/License>). Position du
dépôt et texte de la licence : `../../LICENSES/README.md` et
`../../LICENSES/GPL-2.0.txt`.

Le fichier est redistribué tel quel, sans modification.
