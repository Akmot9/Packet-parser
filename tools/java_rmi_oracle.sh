#!/usr/bin/env bash
# Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
#
# Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
# This file may not be copied, modified, or distributed except according to those terms.
#
# Regenere l'oracle tshark de tests/java_rmi_golden.rs.
#
# Une ligne par segment TCP a charge de pcaps_exemple/protocols/java_rmi/.
# tshark ne dissèque RMI que sur 1099 : les ports des objets (50050) et du
# connecteur JMX (50051) lui sont declares par -d.
#
# Usage : tools/java_rmi_oracle.sh > tests/data/java_rmi_tshark_oracle.tsv
# Colonnes (tabulation) : capture, trame, message, version, protocole,
# nom d'hote, port. Message : l'octet de type en hexadecimal, `4a` pour un
# en-tete de flux, `-` pour une « Continuation » ; `-` pour les champs
# absents.
set -euo pipefail

dir="${1:-pcaps_exemple/protocols/java_rmi}"
echo "# Genere par tools/java_rmi_oracle.sh avec $(tshark --version | head -1) : un segment a charge par ligne."
echo "# Colonnes : capture, trame, message, version, protocole, nom d'hote, port."
for capture in "$dir"/*.pcap; do
    tshark -r "$capture" -d tcp.port==50050,rmi -d tcp.port==50051,rmi -Y 'tcp.len > 0' \
        -T fields -E separator='|' \
        -e frame.number -e rmi.magic -e rmi.outputstream.message -e rmi.inputstream.message \
        -e rmi.version -e rmi.protocol -e rmi.endpoint_id.hostname -e rmi.endpoint_id.port |
        LC_ALL=C awk -F'|' -v OFS='\t' -v capture="$(basename "$capture")" '
            function dash(value) { return value == "" ? "-" : value }
            # tshark ecrit les octets en 0xNN : on garde NN.
            function hex(value) { return value == "" ? "-" : tolower(substr(value, 3)) }
            {
                if ($2 != "") message = "4a"
                else if ($3 != "") message = hex($3)
                else message = hex($4)
                protocol = hex($6)
                print capture, $1, message, dash($5), protocol, dash($7), dash($8)
            }'
done
