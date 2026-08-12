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
