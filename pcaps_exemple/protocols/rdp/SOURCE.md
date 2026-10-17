# Provenance

Cinq captures **RDP** (MS-RDPBCGR) versées le 2026-10-12 pour l'issue #100,
depuis le corpus de tests de [Zeek](https://github.com/zeek/zeek), dossier
`testing/btest/Traces/rdp/`, branche `master` au commit
`66194af53d66b0d7b70f45321fbf47ad6451c34d` (2026-10-12). Aucune n'est
modifiée : ni anonymisée, ni tronquée.

| Fichier | Trames | Contenu | SHA-256 |
|---|---|---|---|
| `rdp-x509.pcap` | 15 | connexion avec cookie `mstshash=JOHN-PC`, sécurité RDP standard retenue, Connect-Initial et Connect-Response MCS (2015) | `0173bcff16fd0fd86024f467ed2c7fe5df6930311981a03837545de221cf067b` |
| `rdp-unknown-keyboard.pcap` | 11 | mêmes hôtes, même ouverture, un Connect-Initial à la disposition de clavier inconnue | `1c0fc1b57d5ef83f379c483fa1e6e33aa3898e10a79f253e3de4a3b355b29955` |
| `rdp-no-cookie-mstshash.pcap` | 20 | connexion **sans cookie**, TLS, CredSSP et CredSSP-EX demandés, CredSSP-EX retenu, puis TLS (2025) | `2f4d62f26e793f5003b20125f39db8cb572e06a874261a75341031e672801c72` |
| `rdp-to-ssl.pcap` | 658 | cookie `mstshash=AWAKECODI`, CredSSP retenu, puis toute la session en TLS (2011) | `ff44d3567d2583bd17c1a6fdd765049b082c800f671481a4d01bdf70721654eb` |
| `rdp-proprietary-encryption.pcap` | 542 | sécurité RDP standard : toute la session MCS (Erect Domain, Attach User, Channel Join, 48 Send Data, Disconnect Provider Ultimatum), TPKT de 1 421 octets coupés en deux segments (2007) | `df7117b972ca63e1c334a543a2883a9d1dbceec50e371d6279e68ba1eafeb73f` |

## Ces trames sont-elles réelles ?

Le `README` du dossier `Traces` de Zeek avertit que beaucoup de ses captures
sont **générées par scapy ou par un LLM**. La question a été tranchée sur
les octets :

- `rdp-x509.pcap` et `rdp-unknown-keyboard.pcap` : une carte Intel
  (`00:17:c5`) et une VMware (`00:50:56`), TTL 128, le même client
  `JOHN-PC` deux fois à la même seconde — un poste réel face à un serveur
  virtualisé ;
- `rdp-no-cookie-mstshash.pcap` : une VMware et une carte Lenovo
  (`00:de:fb`), TTL 122 côté serveur (un vrai chemin réseau), un
  Connection Confirm aux drapeaux `0x1f` et un certificat X.509 dans le TLS ;
- `rdp-to-ssl.pcap` : deux machines VirtualBox (`08:00:27`), 477 segments
  TLS après la négociation, dont deux portent le certificat X.509 du
  serveur ;
- `rdp-proprietary-encryption.pcap` : un client Windows (`00:1b:2f`, TTL 125,
  port 1312) et un serveur IBM (`00:05:9a`), 2007, des TPKT de 1 421 octets
  que le réseau coupe en 1 260 + 161.

**Écartées** : `rdp-invalid-length.pcap` (MAC `00:00:00:00:00:01` et `02`,
2023, un TPKT à la longueur fausse et des octets fabriqués : le chemin
d'erreur est couvert par les tests unitaires du décodeur) ; les trois
`rdpeudp*.pcap` (transport RDP-UDP, MS-RDPEUDP, un autre protocole que
cette crate ne décode pas).

## Oracle tshark

`tests/data/rdp_tshark_oracle.tsv` est produit par `tools/rdp_oracle.sh`
(tshark 4.6.6, `tcp.desegment_tcp_streams:FALSE`, la vue d'un parseur sans
état) : une ligne par segment à payload, la couche la plus haute que tshark
y voit, le jeton X.224 et la négociation des Connection Request et Confirm,
le ConnectMCSPDU ou le DomainMCSPDU des PDU MCS, et le marqueur de
retransmission. `tests/rdp_golden.rs` rejoue l'oracle (#100) : parité sur
les 83 segments RDP (connexions et MCS) ; des 481 segments où tshark voit du
TLS, 449 sont étiquetés **TLS** — c'est la décision pour l'après-bascule —
et les 32 suites d'un record coupé restent inconnues ; les 287 suites de
TPKT coupés ou segments sans couche restent inconnus, comme chez tshark ;
les 10 retransmissions, que tshark ne dissèque pas, sont écartées de la
comparaison.

## Licence

Zeek est distribué sous licence **BSD 3-clause** (The Regents of the
University of California, Lawrence Berkeley National Laboratory,
International Computer Science Institute) ; le texte complet, avec la notice
de copyright que la licence oblige à reproduire, est dans
`pcaps_exemple/LICENSES/BSD-3-Clause-Zeek.txt` (#104). Aucun de ces fichiers
n'entre dans le paquet publié sur crates.io.
