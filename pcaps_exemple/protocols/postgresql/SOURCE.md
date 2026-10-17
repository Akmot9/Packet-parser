# Provenance

Quatorze captures **PostgreSQL** versées le 2026-10-12 pour l'issue #98 —
le plus long fichier de décodeur du dépôt, `postgresql.rs`, n'avait pas une
trame réelle pour l'exercer.
Toutes viennent du corpus de tests de [Zeek](https://github.com/zeek/zeek),
dossier `testing/btest/Traces/postgresql/`, branche `master` au commit
`66194af53d66b0d7b70f45321fbf47ad6451c34d` (2026-10-12). Aucune n'est
modifiée : ni anonymisée, ni tronquée.

Contenu vérifié avec tshark 4.6.6 (`-Y pgsql`, reassemblage coupé) : 276
segments PostgreSQL sur les douze captures positives, dont 8 réponses d'un
octet à SSLRequest ; les deux négatives portent 6 segments que tshark
étiquette `pgsql` à tort.

| Fichier | Trames | Contenu | SHA-256 |
|---|---|---|---|
| `greenhouse-app.pcap` | 230 | application « greenhouse » en conteneurs (Grafana loki-fundamentals), connexions, insertions, requêtes | `bf2728b95e8dd008220f801850fbc6b66d226c7def23a5fed6db7e6b311832ca` |
| `psql-aws-ssl-disable.pcap` | 17 | psql vers un PostgreSQL AWS, `sslmode=disable` : authentification par mot de passe, `select`, fin | `0c77e51a6539b92437f89418c3aa9d00e8f2989f2af3092581816e3ab15f3410` |
| `psql-aws-ssl-preferred.pcap` | 28 | même serveur, `sslmode=prefer` : SSLRequest, `S`, puis TLS | `dece562db2096351f278b95d4532d1bdd12a928bfb5b82a4a41a090e3f8cbaee` |
| `psql-aws-ssl-require.pcap` | 30 | même serveur, `sslmode=require` | `10c865115a2022839850ea4ef35499d88b552bf3730da8471b5798e69ae94d5e` |
| `psql-create-insert-select-delete-drop.pcap` | 29 | cycle DDL/DML complet, SCRAM | `d1c8697aa8355f72c34911e7f03f61d5d11e21d1203bde0475517b4a39c76211` |
| `psql-insert-fail-drop-fail.pcap` | 27 | deux erreurs SQL (`Error`), un `Notice` | `d8e648f400f002ec2b2b4f7a373c892d600c43c892675b7c8485d0a0d21c0f85` |
| `psql-login-fail.pcap` | 14 | SCRAM refusé (`Error`) | `2c61ff738835b8619c118cf10e04556ed7ecab1cfae56cb17b2cfa33df47b9f5` |
| `psql-login-no-role.pcap` | 18 | poste Windows vers un serveur distant, rôle inexistant | `b04fdce1928ccc2ae853a6855f07c37dec066b7d0d8a8ccc0a988d3b3a90a8e8` |
| `psql-login-no-sslrequest.pcap` | 30 | connexion sans SSLRequest, SCRAM, treize `ParameterStatus` | `31575179ffb6b6bca7b17e1956f034912efce3f563e7f5c10a07ed4c5cbb041b` |
| `psql-login.pcap` | 19 | SSLRequest, `N`, SCRAM | `223e7de531fdb07df4301d061538b58de0ce447c39ba4415c390ed15b4940561` |
| `psql-login-wrong.pcap` | 22 | mot de passe faux | `0cde7d79863a4e23ce9bd75474788b29ede58c90da19a9aa137def3105f13d5f` |
| `psql-select-now.pcap` | 27 | `select now()` : `RowDescription`, `DataRow`, `CommandComplete` | `839c3d793392bf10c4b3bd5ab72eb2773b5684890ee04dcf0c954944426d53d8` |
| `http-on-port-5432.pcap` | 14 | **négatif** : une requête HTTP et sa réponse, sur le port 5432 | `d178798db525bce8618183ac49ec61e2e849c1d7e6cd8d59b92639b53fa6e97c` |
| `mysql-on-port-5432.pcap` | 26 | **négatif** : un serveur MySQL 8.4.2 écoutant sur 5432 | `42094b42115230641e96820b626edbdb46fd7f53f94f6cb02cad80745391cb92` |

## Ces trames sont-elles réelles ?

Le `README` du dossier `Traces` de Zeek avertit que beaucoup de ses captures
sont **générées par scapy ou par un LLM**. La règle de ce dépôt les interdit,
donc la question a été tranchée sur les octets :

- **loopback** (`psql-login*`, `psql-select-now`, `psql-create-*`,
  `psql-insert-fail-*`, `mysql-on-port-5432`) : MAC nulles et TTL 64, la
  forme d'une capture sur `lo` ; un vrai `psql` (`application_name psql`,
  SCRAM-SHA-256 complet avec ses nonces) face à un vrai serveur
  (`server_version 14.5 (Debian 14.5-1.pgdg110+1)`, treize `ParameterStatus`
  dans l'ordre du serveur), entre le 2022-12-03 et le 2024-09-03 ;
- **VM vers AWS** (`psql-aws-ssl-*`) : MAC `52:54:00:*` (QEMU/KVM) côté
  client, TTL 235 côté serveur (`52.200.36.167`), le 2022-12-08 — un RDS
  réel, qui accepte ou refuse TLS selon `sslmode` ;
- **`greenhouse-app.pcap`** : documenté par le `README` de Zeek (tcpdump sur
  le port 5432 pendant l'exécution de l'application greenhouse de Grafana,
  insertion d'un utilisateur et d'une plante), MAC locales administrées de
  conteneurs, le 2026-03-13 ;
- **`psql-login-no-role.pcap`** : TTL 128 côté client (Windows) et 61 côté
  serveur, deux cartes réelles, le 2024-10-17 ;
- **`http-on-port-5432.pcap`** : du HTTP de 2013 (TTL 47 côté serveur, une
  carte Juniper et une Apple), rejoué sur le port 5432 — c'est son rôle de
  négatif, le piège exact (`GET ` commence par un octet imprimable) que le
  `ROADMAP` redoutait.

**Écartées** : `bad-backend-message-1.pcap` et `bad-startup-message-1.pcap`
(un `ReadyForQuery` de longueur 1 et un protocole 3.3 qu'aucun serveur
n'émet : des messages fabriqués pour tester le chemin d'erreur) ;
`psql-aws-ssl-disable-15432.pcap` et `psql-aws-ssl-require-15432.pcap`
(mêmes octets que leurs homonymes, port réécrit en 15432).

## Oracle tshark

`tests/data/postgresql_tshark_oracle.tsv` est produit par
`tools/postgresql_oracle.sh` (tshark 4.6.6, `tcp.desegment_tcp_streams:FALSE`,
la vue d'un parseur sans état) : une ligne par segment à payload, types et
longueurs des messages `pgsql`. `tests/postgresql_golden.rs` rejoue l'oracle
(#98) : parité sur les 276 segments PostgreSQL, et sur les négatifs la
mesure — six faux positifs chez tshark, aucun pour la crate. La réponse
d'un octet à SSLRequest est reconnue sur le port 5432 (ou par Decode As),
jamais à l'aveugle.

## Licence

Zeek est distribué sous licence **BSD 3-clause** (The Regents of the
University of California, Lawrence Berkeley National Laboratory,
International Computer Science Institute) ; le texte complet, avec la notice
de copyright que la licence oblige à reproduire, est dans
`pcaps_exemple/LICENSES/BSD-3-Clause-Zeek.txt` (#104). Aucun de ces fichiers
n'entre dans le paquet publié sur crates.io.
