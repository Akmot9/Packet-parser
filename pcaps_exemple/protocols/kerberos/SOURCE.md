# Provenance

Dix captures **Kerberos V5** (RFC 4120, UDP 88 et TCP 88) versées le
2026-11-23 pour l'issue #379. Elles viennent du corpus de tests de nDPI
(`tests/cfgs/default/pcap/`, branche `dev`, commit
`446ae50ac067dcf9e26f49d807ebc5090817cce1`). Aucune n'est modifiée : seul le
préfixe `ndpi_` est ajouté au nom.

Elles complètent `../../The-Ultimate-PCAP.pcapng`, déjà dans le dépôt, qui
porte 134 messages sur TCP 88 (un domaine Active Directory), et deux
datagrammes de `../ldap/ldap-krb5-sign-seal-01.cap`. Ce qu'elles apportent et qu'ils n'ont
pas :

- le transport **UDP**, 36 datagrammes, dont une erreur
  `KRB_ERR_RESPONSE_TOO_BIG` (52), par laquelle un KDC renvoie son client
  vers TCP ;
- d'autres clients et d'autres KDC, de 2004 à 2023 ;
- des erreurs que la première n'a pas (7, 13, 14, 52, 68) et des types de
  noms qu'elle n'a pas non plus : 6 (nom X.500), 10 (nom d'entreprise) et
  −128 (un type de Microsoft) ;
- PKINIT (pré-authentification de types 15 et 16), S4U2Self (type 129) et
  un échange entre deux royaumes.

Contenu vérifié avec tshark 4.6.9, rendu sans état comme la crate
(`tools/kerberos_oracle.sh`, oracle `tests/data/kerberos_tshark_oracle.tsv`).

| Fichier | Trames | Messages Kerberos | Contenu | SHA-256 |
|---|---|---|---|---|
| `ndpi_kerberos.pcap` | 77 | 19 | un poste et le contrôleur de son domaine Active Directory, le 2019-02-05, sur TCP : 8 AS-REQ, 5 KRB-ERROR (25 et 13), 3 TGS-REQ, 3 TGS-REP ; 29 segments de suite ; puis LDAP, DCE/RPC et SMB2 | `f4bd1dcc33201c1609d9e4e58cf9db9746c6f6bbbfdf646c67040f946e1299d5` |
| `ndpi_kerberos2.pcap` | 505 | 230 | plusieurs postes d'un domaine Active Directory sur 36 minutes, le 2017-12-23, sur TCP : 42 AS-REQ, 21 AS-REP, 73 TGS-REQ, 61 TGS-REP, 33 KRB-ERROR (25, 7 et 13) ; 65 segments de suite ; puis LDAP, DCE/RPC et SMB2 | `d1c761014c581db0914def95660c2f2f878a2feb89a84142bcdbbf573b2589db` |
| `ndpi_kerberos-constrained-delegation.pcap` | 26 | 8 | délégation contrainte, d'après son nom chez nDPI, le 2006-02-15 : 4 datagrammes sur UDP (AS-REQ, AS-REP, TGS-REQ, TGS-REP) et 4 messages sur TCP, dont une KRB-ERROR 13 | `823ec1d3ad1be28f321503f8fcfcd0b2e61a2e3918c939b1f581310cea45c170` |
| `ndpi_kerberos-cross-realm.pcap` | 2 | 2 | un TGS-REQ et son TGS-REP sur UDP, le 2004-12-20 : le client d'un royaume demande un service du royaume parent | `7f13b13f071e50bfa87305edb05b1240bcf5b9d1a54cbfa79a97bc36d98af0a3` |
| `ndpi_kerberos-error.pcap` | 2 | 2 | un AS-REQ sur UDP et sa KRB-ERROR 52 (réponse trop grande pour UDP), le 2022-02-22 | `a7cf677e50ade6ec40a9fb71fdaef9af259e5dc1ce6ecbac4e981bc106e4c4d7` |
| `ndpi_kerberos-login.pcap` | 39 | 28 | 12 TGS-REQ et 12 TGS-REP sur UDP, 2 et 2 sur TCP ; l'horloge de la capture donne le 2000-01-01 | `bccc9bf683c262c7dacc455c73133980db6233066f8f24305213da85103496c2` |
| `ndpi_kerberos-pkinit.pcap` | 8 | 8 | ouverture de session par certificat (PKINIT), sur TCP, le 2018-12-28 : 3 AS-REQ, 2 KRB-ERROR 25, un AS-REP, un TGS-REQ, un TGS-REP | `644a6647c820ffa48764580da870f840fc760407bdf3a4485dfa00b5dc7fb2a1` |
| `ndpi_kerberos-s4u2self.pcap` | 14 | 14 | S4U2Self, sur TCP, le 2018-10-09 : 3 AS-REQ, 4 TGS-REQ, 4 TGS-REP, 3 KRB-ERROR (25 et 68, mauvais royaume) | `bf4a1ffe41502f32f2fa66cefae59a6e115f80e47660ca5acf08e53820dcb7d2` |
| `ndpi_kerberos-short-realm.pcap` | 4 | 4 | deux AS-REQ, une KRB-ERROR 14 (chiffrement non géré) et un AS-REP de 1 256 octets, sur UDP, le 2005-08-16 | `7442af7ea36edd4f73f0aa07f3aa2d1209fa6dab190cc38003087e860d5f9dbd` |
| `ndpi_kerberos-user.pcap` | 12 | 2 | un TGS-REQ et un TGS-REP sur TCP, chacun suivi d'un segment de suite, le 2023-03-07 | `b4e7405913eb7f5326fddf9478bcad04578a2496bd84bdc48b257d8026344bbf` |

URL : `https://github.com/ntop/nDPI/blob/446ae50ac067dcf9e26f49d807ebc5090817cce1/tests/cfgs/default/pcap/`
suivi du nom d'origine (`kerberos.pcap`, `kerberos2.pcap`,
`kerberos-constrained-delegation.pcap`...).

## Captures de nDPI écartées

Quatre captures Kerberos du même dossier ne sont **pas** versées : leurs
horodatages sont des nombres ronds (`1700000000,001`, `1762300000,010`...),
la marque d'un fichier fabriqué par un script et non d'un réseau.

- `kerberos-large-reply.pcap`
- `kerberos_names_encoding.pcap`
- `kerberos_reply_names.pcap`
- `kerberos-reply-prefix-overflow.pcap`

## Ce que ces captures couvrent, et ce qu'elles ne couvrent pas

- Les **cinq messages de l'échange avec le KDC** : AS-REQ (10), AS-REP
  (11), TGS-REQ (12), TGS-REP (13) et KRB-ERROR (30), sur les deux
  transports. Avec `The-Ultimate-PCAP.pcapng`, 453 messages.
- **AP-REQ** (14) : chaque TGS-REQ en porte un dans sa
  pré-authentification, 133 en tout. Le golden les lit sur ces octets.
- **AP-REP, KRB-SAFE, KRB-PRIV, KRB-CRED** (15, 20, 21, 22) : aucun sur le
  port 88, où ils n'ont pas leur place. Ils voyagent dans d'autres
  protocoles (GSS-API, kpasswd). Le décodeur les lit d'après la RFC ; ils ne
  sont testés que sur des octets synthétiques, dits tels.
- **150 messages de TCP sur 415 dépassent leur segment** : la crate lit ce
  que le premier segment porte, comme tshark sans réassemblage, et les 181
  segments de suite sortent `Unknown`.
- Aucun segment ne porte deux enregistrements.

## Ces trames sont-elles réelles ?

Tous les checksums UDP et TCP sont justes. Ceux d'IP aussi, sauf dans onze
trames de `ndpi_kerberos-pkinit.pcap` et `ndpi_kerberos-s4u2self.pcap`, où
ils sont nuls : la machine qui capturait les laissait à sa carte. Les
adresses MAC sont celles de cartes de PC (Dell, HP, ASUSTek, Acer, Biostar)
et de machines virtuelles (VMware, Microsoft). Les TTL sont surtout ceux de
Windows (128).

Trois de ces captures (`constrained-delegation`, `login`, `short-realm`)
partagent leurs machines : elles viennent du même banc.

## Licences

nDPI est sous **LGPL-3.0-or-later**, © 2011-2026 ntop.org. Position du
dépôt et texte de la licence : `../../LICENSES/README.md`,
`../../LICENSES/LGPL-3.0.txt` et `../../LICENSES/GPL-3.0.txt`.

Les fichiers sont redistribués tels quels, sans modification.
