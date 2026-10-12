# Provenance

Deux captures **RADIUS** (RFC 2865) versées le 2026-10-12 pour l'issue #101,
depuis le corpus de tests de [Zeek](https://github.com/zeek/zeek), dossier
`testing/btest/Traces/radius/`, branche `master` au commit
`66194af53d66b0d7b70f45321fbf47ad6451c34d` (2026-10-12). Aucune n'est
modifiée : ni anonymisée, ni tronquée.

| Fichier | Trames | Contenu | SHA-256 |
|---|---|---|---|
| `radius.pcap` | 4 | un commutateur Cisco (`00:19:06:ea:b8:c0`, port 1645) authentifie `John.McGuirk` en EAP auprès d'un serveur (port 1812) : Access-Request, Access-Challenge, Access-Request, Access-Accept | `50a03f558dc07d53e9059f60a2d03ba2ebe3f633148fde36cf59703d2bf05600` |
| `radius_localhost.pcap` | 19 | sur `lo` (LINKTYPE_NULL, 2015) : requêtes EAP vers le port 1812, Access-Challenge et Access-Reject | `4822c70dbd72d5501cb82ce0f829ed8b0c2ef7fd55b6a878419147e863e96958` |

`The-Ultimate-PCAP.pcapng`, à la racine de `pcaps_exemple/` (Johannes Weber,
voir le `SOURCE.md` de la racine), porte aussi **72 paquets RADIUS** de
décembre 2022 — un commutateur (`70:4c:a5:99:4a:b3`) et des machines
virtuelles VMware, Access-Request, Access-Accept et Access-Challenge avec
des Vendor-Specific Microsoft (311) — que `tests/radius_golden.rs` lit sur
place, sans les copier.

## Ces trames sont-elles réelles ?

Le `README` du dossier `Traces` de Zeek avertit que beaucoup de ses captures
sont **générées par scapy ou par un LLM**, et signale par un `.py` homonyme
celles qui le sont. Aucun `.py` ici, et les octets le confirment :
`radius.pcap` (2008) porte une carte Cisco et une carte réseau de serveur,
un TTL 255 côté commutateur et 64 côté serveur, un EAP-Message et un
Message-Authenticator cohérents, des identifiants de station au format
Cisco ; `radius_localhost.pcap` est une capture sur l'interface de bouclage
d'un poste (sept ports éphémères successifs du client EAP, 2015).

## Oracle tshark

`tests/data/radius_tshark_oracle.tsv` est produit par `tools/radius_oracle.sh`
(tshark 4.6.6) : un paquet par ligne, en-tête (code, identifiant, longueur,
authentificateur) et attributs (types, longueurs, identifiants de vendeur),
sur les deux captures et sur `The-Ultimate-PCAP.pcapng`. `tests/radius_golden.rs`
rejoue l'oracle (#101) : parité sur les 95 paquets, et aucune des 51 328
trames de l'Ultimate PCAP qui ne sont pas du RADIUS n'est étiquetée
RADIUS par la sonde aveugle.

## Licence

Zeek est distribué sous licence **BSD 3-clause** (The Regents of the
University of California, Lawrence Berkeley National Laboratory,
International Computer Science Institute) ; le texte complet, avec la notice
de copyright que la licence oblige à reproduire, est dans
`pcaps_exemple/LICENSES/BSD-3-Clause-Zeek.txt` (#104). Aucun de ces fichiers
n'entre dans le paquet publié sur crates.io.
