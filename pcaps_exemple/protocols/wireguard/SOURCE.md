# Provenance

Neuf captures **WireGuard** versées le 2026-10-13 pour l'épopée #103 :
128 messages réels de cinq implémentations et services, et deux captures
sans WireGuard dont l'heuristique de tshark prend 25 datagrammes pour du
WireGuard. Aucune n'est modifiée : ni anonymisée, ni tronquée.

| Fichier | Trames | Messages | Contenu | Origine | SHA-256 |
|---|---|---|---|---|---|
| `wireshark_wireguard-ping-tcp.pcap` | 22 | 22 | WireGuard de Linux entre deux espaces de noms, `10.9.0.1:43462 <-> 10.9.0.2:51820`, 2018 : deux handshakes (renouvellement de session à la trame 13), 18 Transport Data dont 2 keepalives et un message de 1 452 octets arrêté à la MTU | dépôt Wireshark, `test/captures/wireguard-ping-tcp.pcap`, commit `f93a73ebd1165bb74e81fd4b34c4d57a83817904` (blob `79255edb`), versé par Peter Wu, auteur du dissecteur (`cf9f1cac`) | `936b0dd7a9c71aa4f07b6d147e63d408c5c1cc39f011cfe3c793b21d4a0b2e4a` |
| `wireshark_wireguard-psk.pcap` | 4 | 4 | même banc avec clé pré-partagée, invisible sur le fil : deux handshakes, le second ouvert par l'autre pair | même dépôt, `test/captures/wireguard-psk.pcap`, même commit (blob `a38088b7`, versé par `e7549372`) | `079956bc2267b8845d00d96125f465100e59f43788cefa2118bf24ea1bae1b53` |
| `ndpi_nordvpn.pcap` | 143 | 22 | client NordVPN (NordLynx) sous Windows vers `138.199.54.231:51820` : handshake, keepalive, quatre messages de 1 452 octets ; et 43 datagrammes OpenVPN obfusqués vers UDP 1198, du TLS sur TCP 443 | corpus de tests nDPI, `tests/cfgs/default/pcap/nordvpn.pcap`, commit `5915c399c0690be7ba252d32a741d1bf7ea07846` (blob `b678b06e`, versé par `642cf5764aab`, 2025-02-04) | `5d888f7dc19a7f39f5b37dddafd9ec1db7682c9df7953e6946fe6f7de4cec958` |
| `ndpi_protonvpn.pcap` | 41 | 14 | client ProtonVPN vers `217.23.3.76:443`, le port de QUIC : handshake et données ; du TLS vers l'API de ProtonVPN | même corpus, `protonvpn.pcap`, même commit (blob `549438d4`, versé par `3e673e91a943`, 2023-06-08, #2006, complété par `bc91192a`) | `2210e106d6f645bdb87ee6ceb5d063cd77baebd558c6e93e93af50bb65ad14ff` |
| `ndpi_mullvad_wireguard.pcap` | 10 | 10 | dix Transport Data d'une session Mullvad en cours, sur UDP 5060, le port de SIP | même corpus, `mullvad_wireguard.pcap`, même commit (blob `df3f10d9`, versé par `1fbe8a23854f`, 2023-08-02, #2062) | `df702f4ff903fdd1b266726f88e5f21cf767b9300f54cc3006836168e1174ca7` |
| `ndpi_tunnelbear.pcap` | 433 | 10 | dix Transport Data d'un client TunnelBear vers `142.93.78.79:51820`, précédés de deux handshakes propres à TunnelBear (204 et 100 octets, que ni tshark ni la crate ne prennent pour du WireGuard) ; 421 trames TCP de l'application | même corpus, `tunnelbear.pcap`, même commit (blob `ec8bba3b`, partie WireGuard versée par `fc334d56c4e5`, 2024-07-01, #2485) | `cbe003da0b7753dee1a1d35c70cc70fa4570398ff97f9ea55c82802db4edc140` |
| `corelight_tailscale_linux.pcap` | 107 | 46 | Tailscale (wireguard-go) sous Linux, `41641 <-> 41641` : 46 Transport Data, sans handshake sur ce chemin UDP, et 61 messages « disco » de Tailscale sur le même port | corelight/zeek-spicy-wireguard, `testing/Traces/tailscale_linux.pcap` (« self-made » selon son `Readme.md`), commit `c235fe2a692d0b3865d5997c0b248eaf47ec5a71` (blob `19ec55c5`, versé par `35fb0520785b`, 2021-11-24) | `70ebb23b732666c8c2c49efbb06cb6076db57508f06837283b4e98d1df6b586d` |
| `ndpi_zoom2.pcap` | 342 | 0 | une session Zoom, 2022 : 22 datagrammes du serveur `144.195.73.154:8801` qui commencent par `04 00 00 00` et que l'heuristique de tshark accepte | corpus nDPI, `zoom2.pcap`, même commit (blob `1102b57a`, présent depuis `7714507f816b`) | `84750124c8d29288f77236e3fb19c6e7c02d2ffd95024f948e5b6b3117a7092e` |
| `ndpi_lol_wild_rift_udp.pcap` | 8 | 0 | League of Legends: Wild Rift, IP brut, 2024 : trois datagrammes que l'heuristique de tshark accepte | corpus nDPI, `lol_wild_rift_udp.pcap`, même commit (blob `32a7e2b1`, versé par `5b32c98a21b3`, 2024-03-26, #2356) | `ab26b04f6301bd04252dda5515d6c3047e467bac4752ac4a0a5defa9b99f00db` |

Aucune capture réelle ne porte de Cookie Reply (type 3), de WireGuard sur
IPv6 ou de datagramme de Cloudflare WARP aux octets réservés non nuls : le
décodeur les couvre par des tests unitaires synthétiques. `ndpi_wireguard.pcap`
(copie de la capture du dépôt Wireshark et 30 messages de plus) et
`corelight_wireguard.pcap` (172 messages d'une même session) n'apportent que
du volume ; `ossfuzz_seed_fake_traces_2.pcapng` de nDPI, le seul à porter
des Cookie Reply, est fabriqué (des trames du dépôt Wireshark réécrites).

## Ces trames sont-elles réelles ?

- Les deux captures du dépôt Wireshark : prouvé par le chiffrement — les
  clés publiées dans la suite de tests de Wireshark valident chaque
  handshake, et les horodatages TAI64N déchiffrés tombent moins de 0,4 ms
  avant la capture. Indices du noyau Linux : DSCP 0x88 sur les seuls
  handshakes, DF à 0, renouvellement de session après 140 s. Les sommes de
  contrôle UDP sont partielles (déchargement d'émission), pas fausses.
- `ndpi_nordvpn.pcap` : un client Windows dans VirtualBox (TTL 128,
  identifiants IP séquentiels) et un serveur WireGuard de Linux sur
  Internet (TTL 56, DSCP 0x88 sur sa réponse) ; horodatages relatifs à 1970
  (trace VirtualBox), fichier fusionné de quatre captures.
- `ndpi_protonvpn.pcap` : **mixte** — les trames 1 à 40, dont les 14
  messages WireGuard (27 à 40), viennent d'une machine VirtualBox derrière
  le NAT de l'hyperviseur ; la trame 41 a été retouchée à la main pour les
  tests de nDPI (adresse de sortie de ProtonVPN `2.58.241.67` en source,
  somme de contrôle TCP fausse d'une unité). Elle n'est pas du WireGuard.
- `ndpi_mullvad_wireguard.pcap` : deux cartes virtuelles, un serveur à TTL
  43 sur Internet, compteurs cohérents (19 à 24 et 15 à 18), capture du
  jour du commit.
- `ndpi_tunnelbear.pcap` : **mixte** — la partie WireGuard (trames 1 à 12)
  est une trace VirtualBox réelle ; la partie TCP (2022) est le trafic réel
  de l'application, mais ses en-têtes de liaison et IP ont été reconstruits
  par une application de capture Android (MAC `00:1a:11:00:00:01`/`02`, TTL
  16).
- `corelight_tailscale_linux.pcap` : machine VMware derrière un routeur
  MikroTik, pair sur AWS (TTL 48), heartbeat disco toutes les deux
  secondes ; les trames entrantes ont une somme de contrôle IPv4 nulle, un
  artefact du point de capture (leurs sommes UDP sont justes).
- `ndpi_zoom2.pcap` : un poste (TTL 64) et les serveurs de Zoom
  (`144.195.0.0/16`, TTL 47 à 49).
- `ndpi_lol_wild_rift_udp.pcap` : **mixte** — capturé par PCAPdroid sur
  Android : adresse virtuelle `10.215.173.1`, en-têtes IP reconstruits ; les
  charges utiles sont celles du jeu.

## Oracle tshark

`tests/data/wireguard_tshark_oracle.tsv` est produit par
`tools/wireguard_oracle.sh` (tshark 4.6.6, heuristique `wg` : tshark
n'enregistre WireGuard sur aucun port) : un message par ligne, ports,
longueur, type, octets réservés, index, compteur, clé éphémère, mac1, mac2,
nonce, cookie et keepalive. `tests/wireguard_golden.rs` y vérifie la parité
sur les 128 messages, nomme les 25 datagrammes Zoom et LoL que tshark
accepte à tort (compteur au-delà de 2^60 ou paquet clair ni complété à seize
octets ni arrêté à une MTU), vérifie que les voisins (disco de Tailscale,
handshakes de TunnelBear, OpenVPN de NordVPN, trame 41 de ProtonVPN) ne
sortent pas WireGuard, et rejoue les 128 messages hors de leur port, avec
des octets réservés non nuls, sur 51820 et sur un port déclaré par Decode As.

## Licences

- `wireshark_*` : GPL-2.0 ou ultérieure, licence du dépôt Wireshark (texte :
  `pcaps_exemple/LICENSES/GPL-2.0.txt`) ;
- `ndpi_*` : LGPL-3.0, licence du dépôt nDPI (texte :
  `pcaps_exemple/LICENSES/LGPL-3.0.txt`, qui incorpore `GPL-3.0.txt`) ;
- `corelight_tailscale_linux.pcap` : BSD 3-Clause, © 2021 Corelight, Inc.
  (texte : `pcaps_exemple/LICENSES/BSD-3-Clause-Corelight.txt`, le `LICENSE`
  du dépôt au commit cité) ; nDPI en distribue une copie identique,
  `tailscale.pcap`, sans que cela lève la notice de Corelight.

Fichiers redistribués tels quels. Aucun n'entre dans le paquet publié sur
crates.io (#104).
