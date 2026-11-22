#!/usr/bin/env bash
# Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
#
# Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
# This file may not be copied, modified, or distributed except according to those terms.
#
# Regenere l'oracle tshark de tests/capwap_golden.rs.
#
# Une ligne par datagramme que tshark dissèque comme CAPWAP sur UDP 5246
# (controle) ou 5247 (donnees), dans les quatre captures du depot qui en
# portent.
#
# Usage : tools/capwap_oracle.sh > tests/data/capwap_tshark_oracle.tsv
# Colonnes (tabulation) : capture, trame, port CAPWAP, type de preambule
# (0 : en-tete CAPWAP, 1 : DTLS), HLEN en mots, WBID, drapeaux (hexadecimal),
# protocole le plus interne selon tshark ; `-` pour les champs absents.
set -euo pipefail

dir="${1:-pcaps_exemple}"
captures=(
    "$dir/capwap-only.pcap"
    "$dir/capwap-association-valid.pcapng"
    "$dir/The-Ultimate-PCAP.pcapng"
    "$dir/vlan0--packet-capture CAPWAP a partir de ligne 520  (Ap = 192_168.0.104 ) + radius _ partir de la ligne 33003 .cap"
)
echo "# Genere par tools/capwap_oracle.sh avec $(tshark --version | head -1) : un datagramme CAPWAP par ligne."
echo "# Colonnes : capture, trame, port, type de preambule, HLEN, WBID, drapeaux, protocole interne."
for capture in "${captures[@]}"; do
    tshark -r "$capture" -Y '(udp.port==5246 || udp.port==5247) && capwap.preamble.type' \
        -T fields -E separator='|' \
        -e frame.number -e udp.srcport -e udp.dstport -e capwap.preamble.type \
        -e capwap.header.length -e capwap.header.wbid -e capwap.header.flags -e _ws.col.Protocol |
        LC_ALL=C awk -F'|' -v OFS='\t' -v capture="$(basename "$capture")" '
            function dash(value) { return value == "" ? "-" : value }
            {
                port = ($2 == 5246 || $3 == 5246) ? 5246 : 5247
                print capture, $1, port, $4, dash($5), dash($6), dash($7), $8
            }'
done
