# Provenance

Huit captures **LDAP** (RFC 4511, sur TCP 389) versées le 2026-11-23 pour
l'issue #372. Elles viennent toutes du wiki Wireshark, page SampleCaptures.
Aucune n'est modifiée : ni anonymisée, ni tronquée.

Elles complètent `../../The-Ultimate-PCAP.pcapng`, déjà dans le dépôt, qui
porte le gros du corpus LDAP (440 segments et datagrammes : un poste Windows
et le contrôleur de son domaine Active Directory, en 2024, avec CLDAP sur
UDP 389 et des tampons SASL sous jeton Kerberos de la RFC 4121). Ce qu'elles
apportent et qu'il n'a pas :

- les **longueurs BER sur un octet** d'un client et d'un serveur OpenLDAP
  (Active Directory écrit toutes ses longueurs sur cinq octets, `84 00 00
  00 xx`), et la **liaison simple** ;
- les tampons SASL sous **jeton Kerberos de la RFC 1964** (clés RC4 d'un
  domaine Windows Server 2003), signés puis chiffrés ;
- les tampons SASL sous **signature NTLMSSP**.

Contenu vérifié avec tshark 4.6.9, rendu sans état comme la crate :
réassemblage TCP et LDAP coupés, analyse des numéros de séquence coupée
(`tools/ldap_oracle.sh`, oracle `tests/data/ldap_tshark_oracle.tsv`). Un
« segment LDAP » est un segment TCP qui s'ouvre sur un message ou sur un
tampon SASL.

| Fichier | Trames | Segments LDAP | Contenu | SHA-256 |
|---|---|---|---|---|
| `ldap-and-search.pcap` | 13 | 5 | une connexion sur l'interface de bouclage, le 2005-11-15 : liaison simple anonyme, recherche à filtre `and`, `noSuchObject`, UnbindRequest | `ab9d335e270ee1326371922d5d2300e0875bd76531b5c01a328533ba6751ccb8` |
| `ldap-attribute-value-list.pcap` | 13 | 5 | la même, le 2005-11-16, filtre à liste de valeurs | `a3b2a055833e7ac52c1c8e1b32ef7040fb6537fd141ca6308a7799d48d9eb711` |
| `ldap-extensible-match.pcap` | 13 | 5 | la même, le 2005-11-16, filtre `extensibleMatch` | `9853e8c8674233912d45547f2fd2aa4aea8491fb26fdb8f677f134d29a4224fc` |
| `ldap-extensible-match-with-dn.pcap` | 13 | 5 | la même, le 2005-11-21, `extensibleMatch` avec `dnAttributes` | `dd1f59fda8c0b5e720f0f7b78146635f30f6c9f324ed299cabf96c161120d650` |
| `ldap-substring.pcap` | 26 | 10 | deux connexions, le 2005-11-15, filtres `substrings` | `23b842492d3e7ba86e20ddca690cb58785edd56094f286b5a935bb2f0563303e` |
| `ldap-controls-dirsync-01.cap` | 12 | 5 | un client et un contrôleur de domaine Windows Server 2003, le 2004-12-17 : liaison SASL GSS-SPNEGO (Kerberos), puis trois tampons **signés** (RFC 1964, HMAC, non chiffrés) qui portent une recherche avec le contrôle DirSync, son SearchResultDone et un UnbindRequest | `e0615ce697e93167f477b39b9a44d2cb3f68a86e796c84ec7e6282c8b6923f04` |
| `ldap-krb5-sign-seal-01.cap` | 40 | 24 | le même domaine, le 2004-12-20 : quatre messages en clair, puis vingt tampons **chiffrés** (RFC 1964, HMAC et RC4), et deux datagrammes Kerberos sur UDP 88 | `10a0076a7e43a3db6a1c9671140970a451c1131e7420ba4b309c2caad33d87ee` |
| `ntlm_ldap.pcapng` | 31 | 20 | un poste et un contrôleur de domaine du domaine `lab.lan`, le 2022-10-30 : deux recherches sur la racine, une liaison SASL GSS-SPNEGO en NTLM (deux allers-retours), puis douze tampons sous **signature NTLMSSP** | `d5d2fe0e4701b733ba97c9f6165b5bd4e2b685c81ffe853e4a8dddb9ea03f7ba` |

Au total 161 trames et 79 segments LDAP : 44 s'ouvrent sur un message en
clair (46 messages), 35 sur un tampon SASL, dont les trois signés portent
un message chacun.

URL : `https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/`
suivi du nom du fichier, sauf `ntlm_ldap.pcapng`, à
`https://wiki.wireshark.org/uploads/5fd073d53e914a16d5d40297b76893b1/ntlm_ldap.pcapng`.

## Ce que ces captures montrent des limites sans état

- **Tampons chiffrés** : la crate rend la longueur du tampon et l'en-tête de
  son jeton (`LdapSaslToken`), rien des messages. tshark n'en lit pas plus
  sans les clés.
- **Signature NTLMSSP** : seize octets qui ne disent pas si le message qui
  suit est chiffré, c'est la liaison qui l'a négocié. La crate ne lit donc
  rien derrière la signature, même quand le message est en clair. Le wiki
  indique que `ntlm_ldap.pcapng` se déchiffre avec le mot de passe `admin`.
- **Cinq tampons coupés** par leur segment (de 2 525 à 5 983 octets annoncés
  dans des segments de 1 460) : trois dans `ldap-krb5-sign-seal-01.cap`,
  deux dans `ntlm_ldap.pcapng`. `is_truncated()` vaut `true`.
- **Un message coupé** : le SearchResultEntry de la trame 5 de
  `ldap-krb5-sign-seal-01.cap` (2 177 octets annoncés, 1 460 présents).
- **Neuf segments de suite**, sans en-tête : six dans
  `ldap-krb5-sign-seal-01.cap` (trames 6, 14, 22, 23, 24 et 34), trois dans
  `ntlm_ldap.pcapng` (trames 17, 25 et 27). Ils sortent `Unknown`, pour la
  crate comme pour tshark sans réassemblage. La trame 6 finit le message
  coupé puis porte un SearchResultDone entier : il faut l'état du flux pour
  en trouver le début.

## Ces trames sont-elles réelles ?

Tous les checksums TCP et UDP de ces captures sont justes.

- Les cinq captures de 2005 sont prises sur l'**interface de bouclage** d'un
  poste Linux (`127.0.0.1`, adresses MAC nulles, TTL 64) : un vrai client
  et un vrai serveur LDAP sur la même machine, moins d'une milliseconde par
  connexion. Les longueurs BER sur un octet et l'ordre des messages sont
  ceux d'OpenLDAP. Elles illustrent sur le wiki les formes de filtre de
  recherche.
- `ldap-controls-dirsync-01.cap` et `ldap-krb5-sign-seal-01.cap` : deux
  machines virtuelles VMware (`00:0c:29`, et `00:50:56` pour l'hôte), TTL
  128 et 126, domaine `W2K3.VMNET1.VM.BASE`. Jetons Kerberos de la RFC 1964
  à l'OID `1.2.840.113554.1.2.2`, `SGN_ALG` 0x0011 (HMAC), `SEAL_ALG`
  0xFFFF puis 0x0010 (RC4).
- `ntlm_ldap.pcapng` : deux machines virtuelles Hyper-V (`00:15:5d`), TTL
  128, 18 secondes. Le numéro de séquence des signatures NTLMSSP compte de 0
  à 5 dans chaque sens.

**Écartées** :
- `c06-ldapv3-app-r1.pcap.gz` et `c06-ldapv3-enc-r1.pcap.gz` : le wiki les
  décrit comme la sortie de `c06-ldapv3-app-r1.jar` et
  `c06-ldapv3-enc-r1.jar`, les suites de tests PROTOS, qui fabriquent des
  messages malformés. La règle du dépôt interdit les captures générées.
- `ldap-ssl.pcapng` : du LDAPS, donc du TLS ; rien de LDAP n'y est lisible.

## Licences

Le wiki Wireshark publie son contenu sous la GNU General Public License,
sans numéro de version (<https://wiki.wireshark.org/License>). Position du
dépôt et texte de la licence : `../../LICENSES/README.md` et
`../../LICENSES/GPL-2.0.txt`.

Les fichiers sont redistribués tels quels, sans modification.
