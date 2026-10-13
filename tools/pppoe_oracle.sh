#!/usr/bin/env bash
# Regenere l'oracle tshark de tests/pppoe_golden.rs.
#
# Une ligne par trame de session PPPoE (tshark `pppoes`) de
# pcaps_exemple/The-Ultimate-PCAP.pcapng, lue en place : 6 795 trames passent
# par la session PPPoE d'un abonne (sous VLAN 7) (#172).
#
# Usage : tools/pppoe_oracle.sh > tests/data/pppoe_tshark_oracle.tsv
# Colonnes (tabulation) : trame, identifiant de session, longueur PPPoE,
# protocole PPP (hexadecimal), protocole qui suit le premier en-tete IP
# (`udp`, `tcp`, `icmp`, `icmpv6`, `ip` pour IPv4 dans IPv6, `-` sans IP),
# ports UDP ou TCP (le premier en-tete UDP ou TCP de la trame : celui du
# paquet IPv4 interne quand IPv6 le porte), `-` sinon.
#
# Profil Wireshark vide, sans reassemblage.
set -euo pipefail

capture="pcaps_exemple/The-Ultimate-PCAP.pcapng"
profile="$(mktemp -d)"
trap 'rm -rf "$profile"' EXIT
export WIRESHARK_CONFIG_DIR="$profile"

echo "# Genere par tools/pppoe_oracle.sh avec $(tshark --version | head -1) : une trame de session PPPoE"
echo "# de ${capture#pcaps_exemple/} par ligne."
echo "# Colonnes : trame, session, longueur, protocole PPP, transport, port source, port destination."
tshark -r "$capture" -o tcp.desegment_tcp_streams:FALSE -o ip.defragment:FALSE -o ipv6.defragment:FALSE \
    -Y "pppoes" -T fields -E separator='|' -E occurrence=f \
    -e frame.number -e pppoe.session_id -e pppoe.payload_length -e ppp.protocol \
    -e udp.srcport -e udp.dstport -e tcp.srcport -e tcp.dstport -e frame.protocols |
    LC_ALL=C awk -F'|' -v OFS='\t' '{
        n = split($9, layers, ":"); next_layer = "-"
        for (i = 1; i < n; i++) if (layers[i] == "ip" || layers[i] == "ipv6") { next_layer = layers[i + 1]; break }
        src = "-"; dst = "-"
        if (next_layer == "udp" || (next_layer == "ip" && $5 != "")) { src = $5; dst = $6 }
        else if (next_layer == "tcp" || (next_layer == "ip" && $7 != "")) { src = $7; dst = $8 }
        print $1, $2, $3, $4, next_layer, src, dst
    }'
