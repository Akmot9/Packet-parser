# Provenance

Captures issues du dépôt public de **Chris Sanders** :
<https://github.com/chrissanders/packets> (chris@chrissanders.org).
Usage libre avec citation de l'auteur (README du dépôt).
Récupérées le 2026-07-12, non modifiées.

| Fichier | Contenu |
|---|---|
| `icmp_echo.pcapng` | echo request/reply (ping) |
| `icmp_traceroute.pcapng` | traceroute (TTL exceeded) |
| `icmpv6_neighbor_solicitation.pcapng` | NDP ICMPv6 (neighbor solicitation/advertisement) |

## icmp_destination_unreachable.pcapng

- Capture locale, **2026-08-12 22:26 (+0200)**, sur l'interface `lo` de
  `cyprien-pc` (Linux), via `dumpcap -i lo -f 'icmp or icmp6'`.
- Trafic provoque par trois envois UDP vers des ports fermes :
  `printf 'x' | nc -u -w1 127.0.0.1 9999`, la meme chose vers le port 65001,
  et `printf 'x' | nc -6 -u -w1 ::1 9999`.
- 3 paquets : deux ICMPv4 type 3 code 3 (port unreachable) et un ICMPv6
  type 1 code 4. Chacun cite le datagramme UDP fautif.
- **Aucune donnee personnelle** : uniquement du loopback (`127.0.0.1`, `::1`),
  adresses MAC nulles. Capture non anonymisee car il n'y a rien a anonymiser.
- Comble les deux branches « message d'erreur » que le corpus ne couvrait pas :
  Destination Unreachable ICMPv4, et l'ensemble de la branche erreur ICMPv6.

## icmp_mtu_exceeded.pcapng

- Capture locale, **2026-08-12 22:36 (+0200)**, sur `cyprien-pc` (Linux), via
  le script `capture_mtu_icmp.sh` : trois namespaces relies par deux paires
  `veth`, dont le lien de sortie est a MTU 1280 alors que l'entree est a 1500.

```
[root ns]              [ns ppr : routeur]           [ns ppd : cible]
 pp-h  --------------- pp-r1        pp-r2 --------- pp-d
 10.0.1.1/24           10.0.1.2/24  10.0.2.1/24     10.0.2.2/24
 fd00:1::1/64          fd00:1::2/64 fd00:2::1/64    fd00:2::2/64
 MTU 1500              MTU 1500     MTU 1280        MTU 1280
```

- Trafic provoque par `ping -M do -s 1400 10.0.2.2` et
  `ping -6 -s 1400 fd00:2::2` depuis le namespace racine.
- 13 paquets. Les trois exploites par les golden tests :
  - **trame 2** : ICMPv4 type 3 code 4 (fragmentation needed), MTU 1280 ;
  - **trame 5** : ICMPv6 type 2 (packet too big), MTU 1280 ;
  - **trame 13** : Neighbor Advertisement avec le flag Router pose (« rtr,
    sol »), le seul du corpus — la capture NDP existante n'a que des annonces
    non-routeur.
- Les trames 2 et 5 sont les **seules du corpus ou `rest_of_header` porte une
  valeur non nulle**. Le champ n'etait valide sur aucune trame reelle avant.
- **Aucune donnee personnelle** : adresses privees RFC 1918 et ULA `fd00::/8`,
  MAC generees par le noyau pour des veth ephemeres, namespaces detruits en
  fin de script. L'interface reelle `wlp4s0` n'est pas touchee.
